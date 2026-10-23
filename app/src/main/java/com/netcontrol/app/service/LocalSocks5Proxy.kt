package com.netcontrol.app.service

import com.netcontrol.app.data.RuleEntity
import com.netcontrol.app.model.FlowSnapshot
import com.netcontrol.app.network.FlowFacts
import com.netcontrol.app.network.RuleAction
import com.netcontrol.app.network.RuleDecision
import com.netcontrol.app.network.RuleEngine
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Loopback-only SOCKS5 server used by the embedded tun2socks engine.
 *
 * TCP CONNECT requests and UDP relay datagrams pass through NetControl's ordered rule matcher before
 * being sent to protected sockets on the underlying network. No external proxy is used. UDP SOCKS
 * fragmentation and SOCKS BIND are intentionally unsupported; a request that requires either is
 * rejected rather than silently misinterpreted.
 */
class LocalSocks5Proxy(
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagramSocket: (DatagramSocket) -> Boolean,
    private val resolveHost: (String) -> List<InetAddress>,
    private val rulesProvider: () -> List<RuleEntity>,
    private val onEvent: (String, String) -> Unit,
    private val onFlowCreated: (FlowSnapshot) -> Unit,
    private val onFlowBytes: (Long, Long, Long) -> Unit,
    private val onFlowEnded: (Long, String) -> Unit,
) : Closeable {
    data class Stats(
        val activeTcp: Int,
        val activeUdp: Int,
        val activeUdpFlows: Int,
        val bytesUploaded: Long,
        val bytesDownloaded: Long,
        val blockedFlows: Long,
        val errors: Long,
    )

    private data class Destination(val host: String, val port: Int, val isDomain: Boolean)
    private data class UdpRequest(val destination: Destination, val payload: ByteArray)
    private data class UdpFlowState(val id: Long, var lastSeenMs: Long)
    private data class UdpEndpointState(val flowIds: LinkedHashSet<Long> = LinkedHashSet(), var lastSeenMs: Long)
    private data class CachedAddress(val address: InetAddress, val expiresAtMs: Long)

    private val running = AtomicBoolean(false)
    private val nextFlowId = AtomicLong(1)
    private val activeTcp = AtomicInteger(0)
    private val activeUdp = AtomicInteger(0) // active SOCKS UDP associations
    private val activeUdpFlows = AtomicInteger(0)
    private val bytesUploaded = AtomicLong(0)
    private val bytesDownloaded = AtomicLong(0)
    private val blockedFlows = AtomicLong(0)
    private val errors = AtomicLong(0)
    private val connectedSockets = ConcurrentHashMap.newKeySet<Closeable>()
    private val dnsCache = ConcurrentHashMap<String, CachedAddress>()
    private val dnsCacheLock = Any()
    private val workerSlots = java.util.concurrent.Semaphore(MAX_SESSIONS)
    private val udpSlots = java.util.concurrent.Semaphore(MAX_UDP_ASSOCIATIONS)
    private val workers: ExecutorService = ThreadPoolExecutor(
        4, MAX_WORKERS, 30L, TimeUnit.SECONDS, ArrayBlockingQueue(MAX_QUEUED_HANDSHAKES),
        { runnable -> Thread(runnable, "NetControl-SOCKS-worker").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    ).apply { (this as? ThreadPoolExecutor)?.allowCoreThreadTimeOut(true) }

    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var acceptThread: Thread? = null

    fun start() {
        check(running.compareAndSet(false, true)) { "SOCKS5 proxy is already running" }
        var openedServer: ServerSocket? = null
        try {
            val server = ServerSocket()
            openedServer = server
            server.reuseAddress = false
            server.bind(InetSocketAddress(InetAddress.getByName(LOOPBACK), PORT), 32)
            serverSocket = server
            acceptThread = Thread({ acceptLoop(server) }, "NetControl-SOCKS-accept").apply {
                isDaemon = true
                start()
            }
            onEvent("vpn", "Local SOCKS5 endpoint is listening on 127.0.0.1:$PORT")
        } catch (failure: Throwable) {
            running.set(false)
            runCatching { openedServer?.close() }
            serverSocket = null
            throw failure
        }
    }

    fun snapshot(): Stats = Stats(
        activeTcp = activeTcp.get(),
        activeUdp = activeUdp.get(),
        activeUdpFlows = activeUdpFlows.get(),
        bytesUploaded = bytesUploaded.get(),
        bytesDownloaded = bytesDownloaded.get(),
        blockedFlows = blockedFlows.get(),
        errors = errors.get(),
    )

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null
        connectedSockets.toList().forEach { runCatching { it.close() } }
        connectedSockets.clear()
        dnsCache.clear()
        workers.shutdownNow()
        runCatching { workers.awaitTermination(PROXY_SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS) }
        val accept = acceptThread
        accept?.interrupt()
        if (accept != null && accept !== Thread.currentThread()) {
            runCatching { accept.join(PROXY_SHUTDOWN_TIMEOUT_MS) }
        }
        acceptThread = null
    }

    private fun acceptLoop(server: ServerSocket) {
        while (running.get()) {
            val client = try {
                server.accept().apply { tcpNoDelay = true }
            } catch (failure: SocketException) {
                if (running.get()) fail("SOCKS5 accept failed", failure)
                break
            } catch (failure: IOException) {
                if (running.get()) fail("SOCKS5 accept failed", failure)
                continue
            }
            if (!workerSlots.tryAcquire()) {
                runCatching { client.close() }
                continue
            }
            connectedSockets.add(client)
            try {
                workers.execute { handleClient(client) }
            } catch (_: RuntimeException) {
                connectedSockets.remove(client)
                workerSlots.release()
                runCatching { client.close() }
            }
        }
    }

    private fun handleClient(client: Socket) {
        var flowId: Long? = null
        var remote: Socket? = null
        var udpLocalRelay: DatagramSocket? = null
        var udpUpstreamRelay: DatagramSocket? = null
        var udpSlotAcquired = false
        try {
            client.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = DataInputStream(BufferedInputStream(client.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(client.getOutputStream()))
            if (negotiate(input, output) != true) return
            val version = input.readUnsignedByte()
            val command = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val destination = readDestination(input)
            if (version != SOCKS_VERSION) {
                reply(output, REP_GENERAL_FAILURE)
                return
            }
            client.soTimeout = 0

            when (command) {
                CMD_CONNECT -> {
                    if (destination.port !in 1..65535) {
                        reply(output, REP_ADDRESS_NOT_SUPPORTED)
                        return
                    }
                    val resolved = resolve(destination.host)
                    val decision = evaluate("TCP", destination, resolved)
                    if (decision.action == RuleAction.BLOCK) {
                        blockedFlows.incrementAndGet()
                        val id = nextFlowId.getAndIncrement()
                        onFlowCreated(snapshotFor(id, "TCP", destination, decision, active = false, state = "BLOCKED"))
                        onFlowEnded(id, "BLOCKED")
                        onEvent("block", "Blocked TCP ${destination.host}:${destination.port} — ${decision.explanation}")
                        reply(output, REP_RULESET_DENIED)
                        return
                    }

                    val outboundSocket = Socket()
                    remote = outboundSocket
                    connectedSockets.add(outboundSocket)
                    if (!protectSocket(outboundSocket)) {
                        reply(output, REP_GENERAL_FAILURE)
                        fail("Android refused to protect outbound TCP socket", IllegalStateException("VpnService.protect(Socket) returned false"))
                        return
                    }
                    outboundSocket.tcpNoDelay = true
                    outboundSocket.connect(InetSocketAddress(resolved, destination.port), CONNECT_TIMEOUT_MS)
                    reply(output, REP_SUCCEEDED)
                    val id = nextFlowId.getAndIncrement()
                    flowId = id
                    activeTcp.incrementAndGet()
                    onFlowCreated(snapshotFor(id, "TCP", destination, decision, active = true, state = "ACTIVE"))
                    if (destination.isDomain) onEvent("domain", "TCP connection requested for ${destination.host}:${destination.port}")
                    relayTcp(client, outboundSocket, id)
                }
                CMD_UDP_ASSOCIATE -> {
                    if (!udpSlots.tryAcquire()) {
                        reply(output, REP_GENERAL_FAILURE)
                        return
                    }
                    udpSlotAcquired = true
                    // Keep the loopback SOCKS endpoint separate from the protected upstream
                    // socket. A network-bound/protected DatagramSocket must not also be relied on
                    // to receive local loopback traffic: Android Network binding can constrain
                    // its route/source network. The SOCKS endpoint is local-only; only the second
                    // socket is protected and bound to the selected underlying Network.
                    val localRelaySocket = DatagramSocket(null)
                    udpLocalRelay = localRelaySocket
                    localRelaySocket.reuseAddress = false
                    localRelaySocket.bind(InetSocketAddress(InetAddress.getByName(LOOPBACK), 0))

                    val upstreamRelaySocket = DatagramSocket(null)
                    udpUpstreamRelay = upstreamRelaySocket
                    if (!protectDatagramSocket(upstreamRelaySocket)) {
                        reply(output, REP_GENERAL_FAILURE)
                        fail("Android refused to protect outbound UDP socket", IllegalStateException("VpnService.protect(DatagramSocket) returned false"))
                        return
                    }
                    upstreamRelaySocket.reuseAddress = false
                    upstreamRelaySocket.bind(InetSocketAddress(0))
                    connectedSockets.add(localRelaySocket)
                    connectedSockets.add(upstreamRelaySocket)

                    val bindAddress = InetAddress.getByName(LOOPBACK).address
                    output.writeByte(SOCKS_VERSION)
                    output.writeByte(REP_SUCCEEDED)
                    output.writeByte(0)
                    output.writeByte(ATYP_IPV4)
                    output.write(bindAddress)
                    output.writeShort(localRelaySocket.localPort)
                    output.flush()

                    val clientInput = input
                    // Transfer both sockets and the UDP slot to the association owner. It releases
                    // the slot and counters from one finally block, even if worker startup fails.
                    udpLocalRelay = null
                    udpUpstreamRelay = null
                    udpSlotAcquired = false
                    relayUdpAssociation(localRelaySocket, upstreamRelaySocket, client, clientInput)
                }
                else -> {
                    reply(output, REP_COMMAND_NOT_SUPPORTED)
                }
            }
        } catch (_: EOFException) {
            // A normal SOCKS control-channel close must not be reported as an engine error.
        } catch (failure: SocketTimeoutException) {
            errors.incrementAndGet()
            onEvent("warning", "SOCKS5 handshake timed out")
        } catch (failure: Throwable) {
            if (running.get()) fail("SOCKS5 session failed", failure)
        } finally {
            flowId?.let {
                activeTcp.updateAndGet { value -> (value - 1).coerceAtLeast(0) }
                onFlowEnded(it, "CLOSED")
            }
            runCatching { remote?.close() }
            remote?.let { connectedSockets.remove(it) }
            runCatching { udpLocalRelay?.close() }
            runCatching { udpUpstreamRelay?.close() }
            if (udpSlotAcquired) udpSlots.release()
            connectedSockets.remove(client)
            runCatching { client.close() }
            workerSlots.release()
        }
    }

    private fun negotiate(input: DataInputStream, output: DataOutputStream): Boolean? {
        val version = input.readUnsignedByte()
        val count = input.readUnsignedByte()
        if (version != SOCKS_VERSION || count == 0) {
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), NO_ACCEPTABLE_METHODS.toByte()))
            output.flush()
            return null
        }
        var supportsNoAuth = false
        repeat(count) { if (input.readUnsignedByte() == METHOD_NO_AUTH) supportsNoAuth = true }
        output.write(byteArrayOf(SOCKS_VERSION.toByte(), (if (supportsNoAuth) METHOD_NO_AUTH else NO_ACCEPTABLE_METHODS).toByte()))
        output.flush()
        return supportsNoAuth
    }

    private fun readDestination(input: DataInputStream): Destination {
        val addressType = input.readUnsignedByte()
        val host = when (addressType) {
            ATYP_IPV4 -> readExact(input, 4).let { InetAddress.getByAddress(it).hostAddress }
            ATYP_IPV6 -> readExact(input, 16).let { InetAddress.getByAddress(it).hostAddress }
            ATYP_DOMAIN -> {
                val size = input.readUnsignedByte()
                if (size == 0) throw IOException("Empty SOCKS5 destination hostname")
                readExact(input, size).toString(Charsets.US_ASCII).trimEnd('.').lowercase(Locale.ROOT)
                    .also { if (it.isBlank() || it.any(Char::isWhitespace)) throw IOException("Invalid SOCKS5 hostname") }
            }
            else -> throw UnsupportedAddressTypeException("Unsupported SOCKS5 address type: $addressType")
        }
        val port = input.readUnsignedShort()
        return Destination(host, port, isDomainName(host))
    }

    private fun resolve(host: String): InetAddress {
        if (isIpLiteral(host)) return InetAddress.getByName(host)
        val key = host.lowercase(Locale.ROOT)
        val now = System.currentTimeMillis()
        dnsCache[key]?.let { if (it.expiresAtMs > now) return it.address else dnsCache.remove(key, it) }
        val address = resolveHost(host).firstOrNull { !it.isAnyLocalAddress && !it.isLoopbackAddress }
            ?: throw IOException("Unable to resolve destination hostname: $host")
        synchronized(dnsCacheLock) {
            dnsCache.entries.removeIf { it.value.expiresAtMs <= now }
            if (!dnsCache.containsKey(key) && dnsCache.size >= MAX_DNS_CACHE_ENTRIES) {
                dnsCache.entries.minByOrNull { it.value.expiresAtMs }?.let { dnsCache.remove(it.key, it.value) }
            }
            dnsCache[key] = CachedAddress(address, now + DNS_CACHE_TTL_MS)
        }
        return address
    }

    private fun evaluate(protocol: String, destination: Destination, resolvedAddress: InetAddress, dnsQuestion: String? = null): RuleDecision {
        val domain = when {
            dnsQuestion != null -> dnsQuestion
            destination.isDomain -> destination.host
            else -> null
        }
        return RuleEngine.evaluate(
            rulesProvider(),
            FlowFacts(
                protocol = protocol,
                destinationIp = resolvedAddress.hostAddress.substringBefore('%'),
                destinationPort = destination.port,
                uid = null, // SOCKS5 does not carry the originating Android UID.
                domain = domain,
            ),
        )
    }

    private fun relayTcp(client: Socket, remote: Socket, flowId: Long) {
        val directions = java.util.concurrent.CountDownLatch(2)
        fun pump(source: Socket, destination: Socket, uploaded: Boolean) {
            try {
                copyStream(source.getInputStream(), destination.getOutputStream()) { count ->
                    if (uploaded) {
                        bytesUploaded.addAndGet(count)
                        onFlowBytes(flowId, count, 0)
                    } else {
                        bytesDownloaded.addAndGet(count)
                        onFlowBytes(flowId, 0, count)
                    }
                }
                // Preserve TCP half-close semantics: EOF in one direction should not discard
                // bytes that may still be flowing in the opposite direction.
                runCatching { destination.shutdownOutput() }
            } catch (_: IOException) {
                // The peer may close at any point; the opposite pump is allowed to finish.
            } finally {
                directions.countDown()
            }
        }
        val upload = Thread({ pump(client, remote, true) }, "NetControl-TCP-up")
            .apply { isDaemon = true; start() }
        val download = Thread({ pump(remote, client, false) }, "NetControl-TCP-down")
            .apply { isDaemon = true; start() }
        try {
            // Keep long-lived TCP sessions alive; proxy shutdown closes the sockets and unblocks
            // both pumps. A fixed per-connection deadline would break WebSockets and other streams.
            directions.await()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            runCatching { client.close() }
            runCatching { remote.close() }
            if (upload.isAlive) upload.interrupt()
            if (download.isAlive) download.interrupt()
        }
    }

    private fun copyStream(source: java.io.InputStream, destination: java.io.OutputStream, countBytes: (Long) -> Unit) {
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        while (running.get()) {
            val length = source.read(buffer)
            if (length < 0) return
            if (length == 0) continue
            destination.write(buffer, 0, length)
            destination.flush()
            countBytes(length.toLong())
        }
    }

    private fun relayUdpAssociation(
        localRelaySocket: DatagramSocket,
        upstreamSocket: DatagramSocket,
        controlSocket: Socket,
        input: DataInputStream,
    ) {
        val associationRunning = AtomicBoolean(true)
        val lastClient = AtomicReference<InetSocketAddress?>(null)
        val stateLock = Any()
        // All map operations happen under stateLock because client request and upstream response
        // workers run concurrently. The maps describe SOCKS destination flows, not native IP flows.
        val flowByKey = LinkedHashMap<String, UdpFlowState>(16, 0.75f, true)
        val blockedKeys = LinkedHashMap<String, Long>(16, 0.75f, true)
        val flowRemoteEndpoints = LinkedHashMap<InetSocketAddress, UdpEndpointState>(16, 0.75f, true)
        var activeCounterIncremented = false

        fun removeUdpFlowLocked(key: String, state: UdpFlowState, reason: String) {
            flowByKey.remove(key)
            val emptyEndpoints = ArrayList<InetSocketAddress>()
            flowRemoteEndpoints.forEach { (endpoint, endpointState) ->
                endpointState.flowIds.remove(state.id)
                if (endpointState.flowIds.isEmpty()) emptyEndpoints += endpoint
            }
            emptyEndpoints.forEach(flowRemoteEndpoints::remove)
            onFlowEnded(state.id, reason)
            activeUdpFlows.updateAndGet { value -> (value - 1).coerceAtLeast(0) }
        }

        fun expireUdpStateLocked(nowMs: Long) {
            val expiredFlows = flowByKey.entries
                .filter { nowMs >= it.value.lastSeenMs && nowMs - it.value.lastSeenMs > UDP_FLOW_IDLE_TIMEOUT_MS }
                .map { it.key to it.value }
            expiredFlows.forEach { (key, state) -> removeUdpFlowLocked(key, state, "IDLE_TIMEOUT") }
            blockedKeys.entries.removeIf { nowMs >= it.value && nowMs - it.value > UDP_FLOW_IDLE_TIMEOUT_MS }
            // Endpoint keys are a subset of active flows' remote IP/ports. Since flowByKey is
            // capped, this map is bounded too; do not evict a live endpoint arbitrarily.
        }

        fun ensureUdpFlowCapacityLocked() {
            if (flowByKey.size < MAX_UDP_FLOWS_PER_ASSOCIATION) return
            val eldest = flowByKey.entries.iterator().next()
            removeUdpFlowLocked(eldest.key, eldest.value, "EVICTED_CAPACITY")
        }

        fun ensureBlockedKeyCapacityLocked() {
            if (blockedKeys.size < MAX_UDP_FLOWS_PER_ASSOCIATION) return
            blockedKeys.remove(blockedKeys.entries.iterator().next().key)
        }

        fun stopAssociationOnReaderFailure(message: String, failure: Throwable) {
            if (associationRunning.compareAndSet(true, false)) {
                if (running.get()) fail(message, failure)
                // Close both data sockets and the control connection to wake every reader/owner.
                runCatching { localRelaySocket.close() }
                runCatching { upstreamSocket.close() }
                runCatching { controlSocket.close() }
            }
        }

        val localReader = Thread({
            val buffer = ByteArray(MAX_UDP_DATAGRAM)
            try {
                localRelaySocket.soTimeout = UDP_POLL_TIMEOUT_MS
                while (running.get() && associationRunning.get() && !localRelaySocket.isClosed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        localRelaySocket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        synchronized(stateLock) { expireUdpStateLocked(System.currentTimeMillis()) }
                        continue
                    }
                    if (!packet.address.isLoopbackAddress) {
                        onEvent("warning", "Dropped SOCKS5 UDP datagram not originating from loopback")
                        continue
                    }
                    val clientEndpoint = packet.socketAddress as? InetSocketAddress ?: continue
                    val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val request = try {
                        parseUdpRequest(data)
                    } catch (failure: Throwable) {
                        onEvent("warning", "Dropped malformed SOCKS5 UDP datagram: ${failure.message}")
                        continue
                    }
                    val dest = request.destination
                    if (dest.port !in 1..65535 || request.payload.isEmpty()) continue
                    lastClient.set(clientEndpoint)
                    val dnsQuestion = if (dest.port == 53) parseDnsQuestion(request.payload) else null
                    if (dnsQuestion != null) onEvent("dns", "Observed DNS question $dnsQuestion via ${dest.host}:53")
                    val address = try {
                        resolve(dest.host)
                    } catch (failure: IOException) {
                        fail("UDP destination resolution failed for ${dest.host}", failure)
                        continue
                    }
                    val decision = evaluate("UDP", dest, address, dnsQuestion)
                    val now = System.currentTimeMillis()
                    val flowKey = "UDP|${address.hostAddress}|${dest.port}|${dest.host}"
                    val endpoint = InetSocketAddress(address, dest.port)
                    var blocked = false
                    var newlyBlockedFlowId: Long? = null
                    var selectedState: UdpFlowState? = null
                    synchronized(stateLock) {
                        expireUdpStateLocked(now)
                        if (decision.action == RuleAction.BLOCK) {
                            blocked = true
                            if (!blockedKeys.containsKey(flowKey)) {
                                ensureBlockedKeyCapacityLocked()
                                blockedKeys[flowKey] = now
                                blockedFlows.incrementAndGet()
                                newlyBlockedFlowId = nextFlowId.getAndIncrement()
                            } else {
                                blockedKeys[flowKey] = now // refresh TTL and access order
                            }
                        } else {
                            blockedKeys.remove(flowKey)
                            val state = flowByKey[flowKey] ?: run {
                                ensureUdpFlowCapacityLocked()
                                UdpFlowState(nextFlowId.getAndIncrement(), now).also {
                                    flowByKey[flowKey] = it
                                    activeUdpFlows.incrementAndGet()
                                    onFlowCreated(snapshotFor(it.id, "UDP", dest, decision, active = true, state = "ACTIVE"))
                                    if (dest.isDomain) onEvent("domain", "UDP connection requested for ${dest.host}:${dest.port}")
                                }
                            }
                            state.lastSeenMs = now
                            val endpointState = flowRemoteEndpoints.getOrPut(endpoint) { UdpEndpointState(lastSeenMs = now) }
                            endpointState.flowIds.add(state.id)
                            endpointState.lastSeenMs = now
                            selectedState = state
                        }
                    }
                    if (blocked) {
                        newlyBlockedFlowId?.let { id ->
                            onFlowCreated(snapshotFor(id, "UDP", dest, decision, active = false, state = "BLOCKED"))
                            onFlowEnded(id, "BLOCKED")
                            onEvent("block", "Blocked UDP ${dest.host}:${dest.port} — ${decision.explanation}")
                        }
                        continue
                    }
                    val state = selectedState ?: continue
                    try {
                        val outgoing = DatagramPacket(request.payload, request.payload.size, address, dest.port)
                        upstreamSocket.send(outgoing)
                        bytesUploaded.addAndGet(request.payload.size.toLong())
                        onFlowBytes(state.id, request.payload.size.toLong(), 0)
                    } catch (failure: Throwable) {
                        if (running.get() && associationRunning.get()) fail("UDP send failed to ${dest.host}:${dest.port}", failure)
                    }
                }
            } catch (failure: Throwable) {
                stopAssociationOnReaderFailure("SOCKS5 UDP local-reader failed", failure)
            }
        }, "NetControl-UDP-client").apply { isDaemon = true }

        val upstreamReader = Thread({
            val buffer = ByteArray(MAX_UDP_DATAGRAM)
            try {
                upstreamSocket.soTimeout = UDP_POLL_TIMEOUT_MS
                while (running.get() && associationRunning.get() && !upstreamSocket.isClosed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        upstreamSocket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        synchronized(stateLock) { expireUdpStateLocked(System.currentTimeMillis()) }
                        continue
                    }
                    val source = packet.socketAddress as? InetSocketAddress ?: continue
                    val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val clientEndpoint = lastClient.get() ?: continue
                    var attributedFlowId: Long? = null
                    val knownEndpoint = synchronized(stateLock) {
                        expireUdpStateLocked(System.currentTimeMillis())
                        val endpointState = flowRemoteEndpoints[source] ?: return@synchronized false
                        endpointState.lastSeenMs = System.currentTimeMillis()
                        attributedFlowId = endpointState.flowIds.singleOrNull()?.let { id ->
                            flowByKey.values.firstOrNull { it.id == id }?.also { it.lastSeenMs = endpointState.lastSeenMs }?.id
                        }
                        true
                    }
                    // Do not pass unsolicited upstream datagrams into the local SOCKS client.
                    if (!knownEndpoint) continue
                    val encoded = encodeUdpResponse(packet.address, packet.port, data)
                    try {
                        localRelaySocket.send(DatagramPacket(encoded, encoded.size, clientEndpoint))
                        bytesDownloaded.addAndGet(data.size.toLong())
                        attributedFlowId?.let { onFlowBytes(it, 0, data.size.toLong()) }
                    } catch (failure: Throwable) {
                        if (running.get() && associationRunning.get()) fail("UDP response relay failed", failure)
                    }
                }
            } catch (failure: Throwable) {
                stopAssociationOnReaderFailure("SOCKS5 UDP upstream-reader failed", failure)
            }
        }, "NetControl-UDP-upstream").apply { isDaemon = true }

        try {
            localReader.start()
            upstreamReader.start()
            activeUdp.incrementAndGet()
            activeCounterIncremented = true
            // RFC 1928 keeps the TCP control connection open for the lifetime of the UDP association.
            while (running.get() && associationRunning.get() && !controlSocket.isClosed && input.read() != -1) {
                // Control bytes beyond EOF have no meaning; connection close terminates the association.
            }
        } catch (_: IOException) {
            // Proxy shutdown or peer closure terminates the association.
        } finally {
            associationRunning.set(false)
            runCatching { localRelaySocket.close() }
            runCatching { upstreamSocket.close() }
            runCatching { controlSocket.close() }
            localReader.interrupt()
            upstreamReader.interrupt()
            if (localReader.isAlive && localReader !== Thread.currentThread()) runCatching { localReader.join(1_000) }
            if (upstreamReader.isAlive && upstreamReader !== Thread.currentThread()) runCatching { upstreamReader.join(1_000) }
            synchronized(stateLock) {
                val flowCount = flowByKey.size
                flowByKey.values.forEach { onFlowEnded(it.id, "CLOSED") }
                flowByKey.clear()
                blockedKeys.clear()
                flowRemoteEndpoints.clear()
                activeUdpFlows.updateAndGet { value -> (value - flowCount).coerceAtLeast(0) }
            }
            connectedSockets.remove(localRelaySocket)
            connectedSockets.remove(upstreamSocket)
            if (activeCounterIncremented) activeUdp.updateAndGet { value -> (value - 1).coerceAtLeast(0) }
            udpSlots.release()
        }
    }

    private fun parseUdpRequest(packet: ByteArray): UdpRequest {
        if (packet.size < 4 || packet[0].toInt() != 0 || packet[1].toInt() != 0) {
            throw IOException("Invalid SOCKS5 UDP header")
        }
        if (packet[2].toInt() != 0) throw IOException("Fragmented SOCKS5 UDP is not supported")
        var offset = 3
        val atyp = packet[offset++].toInt() and 0xff
        val host = when (atyp) {
            ATYP_IPV4 -> {
                if (packet.size < offset + 4 + 2) throw IOException("Truncated IPv4 UDP header")
                InetAddress.getByAddress(packet.copyOfRange(offset, offset + 4)).hostAddress.also { offset += 4 }
            }
            ATYP_IPV6 -> {
                if (packet.size < offset + 16 + 2) throw IOException("Truncated IPv6 UDP header")
                InetAddress.getByAddress(packet.copyOfRange(offset, offset + 16)).hostAddress.also { offset += 16 }
            }
            ATYP_DOMAIN -> {
                if (packet.size <= offset) throw IOException("Truncated domain UDP header")
                val size = packet[offset++].toInt() and 0xff
                if (size == 0 || packet.size < offset + size + 2) throw IOException("Invalid domain UDP header")
                packet.copyOfRange(offset, offset + size).toString(Charsets.US_ASCII).trimEnd('.').lowercase(Locale.ROOT).also { offset += size }
            }
            else -> throw UnsupportedAddressTypeException("Unsupported UDP address type: $atyp")
        }
        val port = ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
        offset += 2
        return UdpRequest(Destination(host, port, isDomainName(host)), packet.copyOfRange(offset, packet.size))
    }

    private fun encodeUdpResponse(source: InetAddress, port: Int, payload: ByteArray): ByteArray {
        val sourceBytes = source.address
        val atyp = when (source) {
            is Inet4Address -> ATYP_IPV4
            is Inet6Address -> ATYP_IPV6
            else -> throw IOException("Unsupported UDP response address family")
        }
        val result = ByteArray(3 + 1 + sourceBytes.size + 2 + payload.size)
        result[0] = 0
        result[1] = 0
        result[2] = 0
        result[3] = atyp.toByte()
        sourceBytes.copyInto(result, 4)
        val portOffset = 4 + sourceBytes.size
        result[portOffset] = ((port ushr 8) and 0xff).toByte()
        result[portOffset + 1] = (port and 0xff).toByte()
        payload.copyInto(result, portOffset + 2)
        return result
    }

    private fun snapshotFor(
        id: Long,
        protocol: String,
        destination: Destination,
        decision: RuleDecision,
        active: Boolean,
        state: String,
    ) = FlowSnapshot(
        id = id,
        protocol = protocol,
        destination = destination.host,
        port = destination.port,
        domain = destination.host.takeIf { destination.isDomain },
        action = decision.action.name,
        matchedRuleId = decision.matchedRuleId,
        startedAtMs = System.currentTimeMillis(),
        bytesUploaded = 0,
        bytesDownloaded = 0,
        active = active,
        state = state,
        explanation = decision.explanation,
    )

    private fun reply(output: DataOutputStream, code: Int) {
        output.writeByte(SOCKS_VERSION)
        output.writeByte(code)
        output.writeByte(0)
        output.writeByte(ATYP_IPV4)
        output.write(byteArrayOf(0, 0, 0, 0))
        output.writeShort(0)
        output.flush()
    }

    private fun fail(message: String, failure: Throwable) {
        errors.incrementAndGet()
        onEvent("error", "$message: ${failure.message ?: failure.javaClass.simpleName}")
    }

    private fun readExact(input: DataInputStream, length: Int): ByteArray {
        val bytes = ByteArray(length)
        input.readFully(bytes)
        return bytes
    }

    private fun parseDnsQuestion(data: ByteArray): String? {
        if (data.size < 17) return null
        val questionCount = ((data[4].toInt() and 0xff) shl 8) or (data[5].toInt() and 0xff)
        if (questionCount == 0) return null
        var offset = 12
        val labels = ArrayList<String>()
        var totalLength = 0
        while (offset < data.size) {
            val length = data[offset++].toInt() and 0xff
            if (length == 0) break
            if ((length and 0xc0) != 0 || length > 63 || offset + length > data.size) return null
            totalLength += length + if (labels.isEmpty()) 0 else 1
            if (totalLength > 253) return null
            labels += data.copyOfRange(offset, offset + length).toString(Charsets.US_ASCII)
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > data.size) return null
        return labels.joinToString(".").lowercase(Locale.ROOT)
    }

    private fun isDomainName(host: String): Boolean = !isIpLiteral(host)

    private fun isIpLiteral(host: String): Boolean {
        if (host.isBlank()) return false
        if (host.contains(':')) return host.matches(Regex("[0-9a-fA-F:.%]+"))
        val parts = host.split('.')
        return parts.size == 4 && parts.all { it.toIntOrNull()?.let { octet -> octet in 0..255 } == true }
    }

    private class UnsupportedAddressTypeException(message: String) : IOException(message)

    companion object {
        private const val LOOPBACK = "127.0.0.1"
        private const val PORT = 1080
        private const val MAX_SESSIONS = 48
        private const val MAX_WORKERS = 32
        private const val MAX_QUEUED_HANDSHAKES = 96
        private const val MAX_UDP_ASSOCIATIONS = 8
        private const val MAX_UDP_DATAGRAM = 65_535
        private const val STREAM_BUFFER_SIZE = 16 * 1024
        private const val HANDSHAKE_TIMEOUT_MS = 15_000
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val UDP_POLL_TIMEOUT_MS = 1_000
        private const val PROXY_SHUTDOWN_TIMEOUT_MS = 1_250L
        private const val DNS_CACHE_TTL_MS = 60_000L
        private const val MAX_DNS_CACHE_ENTRIES = 512
        private const val MAX_UDP_FLOWS_PER_ASSOCIATION = 256
        private const val UDP_FLOW_IDLE_TIMEOUT_MS = 60_000L

        private const val SOCKS_VERSION = 5
        private const val METHOD_NO_AUTH = 0
        private const val NO_ACCEPTABLE_METHODS = 0xff
        private const val CMD_CONNECT = 1
        private const val CMD_UDP_ASSOCIATE = 3
        private const val ATYP_IPV4 = 1
        private const val ATYP_DOMAIN = 3
        private const val ATYP_IPV6 = 4
        private const val REP_SUCCEEDED = 0
        private const val REP_GENERAL_FAILURE = 1
        private const val REP_RULESET_DENIED = 2
        private const val REP_COMMAND_NOT_SUPPORTED = 7
        private const val REP_ADDRESS_NOT_SUPPORTED = 8
    }
}
