package com.netcontrol.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.content.pm.ServiceInfo
import android.system.Os
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.netcontrol.app.MainActivity
import com.netcontrol.app.capture.PacketCaptureStore
import com.netcontrol.app.data.DiagnosticEventLogger
import com.netcontrol.app.data.NetControlDatabase
import com.netcontrol.app.model.EnginePhase
import com.netcontrol.app.network.NativePacketBatcher
import hev.htproxy.TProxyService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancelAndJoin
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

/** Local, no-root VPN. Traffic enters Android TUN, goes through hev tun2socks to the local SOCKS5
 * policy point, and is then sent to the underlying network through protected sockets. */
class NetworkVpnService : VpnService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val database by lazy { NetControlDatabase.get(applicationContext) }

    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var engineTun: ParcelFileDescriptor? = null
    @Volatile private var packetBridge: TunPacketBridge? = null
    @Volatile private var socksProxy: LocalSocks5Proxy? = null
    @Volatile private var bridgeSocketForCleanup: FileDescriptor? = null
    @Volatile private var rulesJob: Job? = null
    @Volatile private var statsJob: Job? = null
    @Volatile private var startJob: Job? = null
    @Volatile private var cachedRules = emptyList<com.netcontrol.app.data.RuleEntity>()
    @Volatile private var tunnelStarted = false
    @Volatile private var tunnelStartAttempted = false
    @Volatile private var foregroundStarted = false
    @Volatile private var shutdownStarted = false
    private val lifecycleLock = Any()
    @Volatile private var underlyingNetwork: Network? = null
    @Volatile private var underlyingNetworkAttached: Boolean = false
    @Volatile private var networkLossJob: Job? = null
    private val connectivityManager by lazy { getSystemService(ConnectivityManager::class.java) }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val old = underlyingNetwork
            underlyingNetwork = network
            val phase = EngineRuntime.status.value.phase
            if (phase == EnginePhase.RUNNING || phase == EnginePhase.DEGRADED || phase == EnginePhase.STARTING) {
                val accepted = runCatching { setUnderlyingNetworks(arrayOf(network)) }.getOrDefault(false)
                underlyingNetworkAttached = accepted
                if (!accepted) {
                    if (phase == EnginePhase.RUNNING || phase == EnginePhase.DEGRADED) {
                        EngineRuntime.update(EnginePhase.DEGRADED, "Android did not accept the replacement underlying network")
                        recordEvent("error", "Could not bind the VPN to the replacement underlying network; stopping unless binding recovers")
                        scheduleNetworkDetachStop()
                    }
                } else {
                    if (old != network) {
                        recordEvent("network", "Underlying network changed; new upstream sockets will use the selected network. Existing TCP/UDP sessions may fail and reconnect at the application layer.")
                    }
                    // After onLost(), old is null. Recovery must depend on successful attachment,
                    // not on old != null, or the session stays DEGRADED forever after a handover.
                    val nativeAlive = tunnelStarted && runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
                    if (phase == EnginePhase.DEGRADED && nativeAlive && packetBridge?.isRunning == true) {
                        EngineRuntime.update(EnginePhase.RUNNING, "VPN attached to an underlying network; existing flows may need application-level reconnect")
                    }
                    networkLossJob?.cancel()
                    networkLossJob = null
                }
            }
        }

        override fun onLost(network: Network) {
            if (underlyingNetwork != network) return // A replacement network has already arrived.
            underlyingNetwork = null
            underlyingNetworkAttached = false
            val phase = EngineRuntime.status.value.phase
            if (phase == EnginePhase.RUNNING || phase == EnginePhase.DEGRADED) {
                EngineRuntime.update(EnginePhase.DEGRADED, "Underlying network lost; waiting briefly for Wi-Fi/mobile handover")
                recordEvent("network", "Underlying network lost; waiting for an alternate network")
                scheduleNetworkDetachStop()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        runCatching { connectivityManager.registerDefaultNetworkCallback(networkCallback) }
            .onFailure { recordEvent("error", "Could not monitor underlying network changes: ${it.message}") }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                serviceScope.launch { stopVpn("Stopped by user") }
                return START_NOT_STICKY
            }
            ACTION_START_VPN, ACTION_START_DIAGNOSTIC -> {
                val phase = EngineRuntime.status.value.phase
                if (phase == EnginePhase.RUNNING || phase == EnginePhase.STARTING ||
                    phase == EnginePhase.STOPPING || startJob?.isActive == true) {
                    return START_STICKY
                }
                try {
                    startAsForeground("Starting local VPN firewall")
                    foregroundStarted = true
                } catch (failure: Throwable) {
                    recordEvent("error", "Unable to start foreground service: ${failure.message}")
                    EngineRuntime.update(EnginePhase.STOPPED, "Android did not allow the foreground VPN service to start")
                    stopSelf(startId)
                    return START_NOT_STICKY
                }
                synchronized(lifecycleLock) { shutdownStarted = false }
                startJob = serviceScope.launch { startVpn() }
            }
            else -> {
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    private suspend fun startVpn() {
        if (EngineRuntime.status.value.phase == EnginePhase.RUNNING) return
        EngineRuntime.resetSession()
        EngineRuntime.update(EnginePhase.STARTING, "Preparing the local packet-processing engine")
        try {
            if (VpnService.prepare(this) != null) {
                val detail = "VPN permission is missing. Return to NetControl and authorize the VPN prompt."
                recordEvent("vpn", detail)
                EngineRuntime.update(EnginePhase.STOPPED, detail)
                finishForegroundAndStop()
                return
            }

            underlyingNetwork = connectivityManager.activeNetwork
                ?: throw IOException("No active underlying network is available")
            cachedRules = database.ruleDao().observeRules().first()
            rulesJob?.cancel()
            rulesJob = serviceScope.launch {
                database.ruleDao().observeRules().collect { cachedRules = it }
            }

            val proxy = LocalSocks5Proxy(
                protectSocket = ::protectAndBindTcpSocket,
                protectDatagramSocket = ::protectAndBindDatagramSocket,
                resolveHost = ::resolveOnUnderlyingNetwork,
                rulesProvider = { cachedRules },
                onEvent = ::recordEvent,
                onFlowCreated = EngineRuntime::flowCreated,
                onFlowBytes = EngineRuntime::flowBytes,
                onFlowEnded = EngineRuntime::flowEnded,
            )
            proxy.start()
            socksProxy = proxy

            // Open a bounded PCAP before routes become active. The capture is local-only.
            PacketCaptureStore.start(this)
            NativePacketBatcher.reset()

            val vpnInterface = Builder()
                .setSession("NetControl local firewall")
                .setMtu(VPN_MTU)
                .addAddress(VPN_IPV4, 15)
                .addAddress(VPN_IPV6, 126)
                .addDnsServer(MAP_DNS_ADDRESS)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .establish() ?: throw IOException("Android failed to establish the VPN interface")
            tun = vpnInterface
            var attachedNetwork = underlyingNetwork
                ?: throw IOException("Underlying network disappeared while the VPN interface was being established")
            if (!setUnderlyingNetworks(arrayOf(attachedNetwork))) {
                throw IOException("Android refused to associate VPN with the active underlying network")
            }
            underlyingNetworkAttached = true
            // A network callback can race with interface establishment. Re-attach to the latest
            // selected network rather than marking a stale Network as usable.
            val latestNetwork = underlyingNetwork
                ?: throw IOException("Underlying network was lost while attaching the VPN interface")
            if (latestNetwork != attachedNetwork) {
                if (!setUnderlyingNetworks(arrayOf(latestNetwork))) {
                    underlyingNetworkAttached = false
                    throw IOException("Android refused to attach the VPN to the replacement network")
                }
                attachedNetwork = latestNetwork
                underlyingNetworkAttached = true
            }
            if (underlyingNetwork != attachedNetwork || !underlyingNetworkAttached) {
                throw IOException("Underlying network changed during VPN startup")
            }

            // A SOCK_DGRAM socketpair behaves like a packet-oriented TUN endpoint. One side is
            // passed to hev; the other side is mirrored by TunPacketBridge so we can inspect and
            // record exactly the IP packets entering and leaving the VPN interface.
            val engineSocket = FileDescriptor()
            val bridgeSocket = FileDescriptor()
            Os.socketpair(
                OsConstants.AF_UNIX,
                OsConstants.SOCK_DGRAM,
                0,
                engineSocket,
                bridgeSocket,
            )
            bridgeSocketForCleanup = bridgeSocket
            val engineDescriptor = try {
                ParcelFileDescriptor.dup(engineSocket)
            } finally {
                // engineSocket is transferred only through dup; the original descriptor is always
                // closed, including when dup() throws during startup.
                runCatching { Os.close(engineSocket) }
            }
            engineTun = engineDescriptor

            val config = createTunnelConfig()
            tunnelStartAttempted = true
            val started = TProxyService.TProxyStartService(config.absolutePath, engineDescriptor.fd)
            if (!started) throw IOException("hev-socks5-tunnel rejected its configuration or file descriptor")
            tunnelStarted = true

            // The JNI entrypoint returns as soon as it creates the worker thread; give it a short
            // startup window to detect configuration/FD errors before announcing the VPN as ready.
            repeat(10) {
                delay(100)
                if (!TProxyService.TProxyIsRunning()) throw IOException("hev-socks5-tunnel exited during startup")
            }

            val bridge = TunPacketBridge(
                vpnTun = vpnInterface,
                bridgeFd = bridgeSocket,
                onFailure = { message, failure ->
                    recordEvent("error", "$message: ${failure.message ?: failure.javaClass.simpleName}")
                    serviceScope.launch { stopVpn("Packet bridge failed; VPN was stopped to avoid a network black hole") }
                },
                onObservationFailure = { message, failure ->
                    EngineRuntime.recordTransportError()
                    recordEvent("capture", "$message: ${failure.message ?: failure.javaClass.simpleName}")
                },
            )
            bridgeSocketForCleanup = null // bridge owns this descriptor now
            packetBridge = bridge
            bridge.start()
            delay(BRIDGE_HEALTH_CHECK_MS)
            bridge.failure?.let { throw IOException("Packet bridge failed during startup", it) }
            if (!TProxyService.TProxyIsRunning()) throw IOException("Tunnel core exited before datapath became active")

            EngineRuntime.update(
                EnginePhase.RUNNING,
                "VPN routes and the TUN/tun2socks bridge are attached. End-to-end Internet reachability is not yet verified.",
            )
            updateNotification("VPN routes active · datapath attached")
            recordEvent("vpn", "VPN started; IPv4/IPv6 default routes installed and local SOCKS5 policy proxy attached. Device-level reachability remains unverified.")
            // Cover an onLost callback delivered during the last STARTING instructions. Once phase
            // becomes RUNNING, future losses are handled directly by NetworkCallback.onLost().
            if (underlyingNetwork == null || !underlyingNetworkAttached) {
                EngineRuntime.update(EnginePhase.DEGRADED, "Underlying network disappeared during startup; waiting briefly for handover")
                scheduleNetworkDetachStop()
            }
            statsJob?.cancel()
            statsJob = serviceScope.launch {
                while (isActive && (EngineRuntime.status.value.phase == EnginePhase.RUNNING ||
                            EngineRuntime.status.value.phase == EnginePhase.DEGRADED)) {
                    delay(STATS_INTERVAL_MS)
                    if (tunnelStarted && !runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)) {
                        recordEvent("error", "Embedded tun2socks core exited while VPN routes were active")
                        serviceScope.launch {
                            stopVpn("Tunnel core exited; VPN stopped to avoid losing network connectivity")
                        }
                        break
                    }
                    NativePacketBatcher.flush()
                    val proxyStats = socksProxy?.snapshot()
                    if (proxyStats != null) {
                        EngineRuntime.updateProxyStats(
                            activeFlows = proxyStats.activeTcp + proxyStats.activeUdpFlows,
                            bytesUploaded = proxyStats.bytesUploaded,
                            bytesDownloaded = proxyStats.bytesDownloaded,
                            blockedFlows = proxyStats.blockedFlows,
                            errors = proxyStats.errors,
                        )
                    }
                    if (PacketCaptureStore.isLimitReached) {
                        updateNotification("VPN active · PCAP reached 64 MiB limit")
                    } else if (proxyStats != null) {
                        updateNotification("VPN active · ${proxyStats.activeTcp + proxyStats.activeUdpFlows} flows")
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            // A stop request may cancel startup while resources have already been allocated.
            // Release those resources before the stop coroutine continues.
            stopComponents()
            throw cancelled
        } catch (failure: Throwable) {
            recordEvent("error", "VPN startup failed: ${failure.message ?: failure.javaClass.simpleName}")
            stopComponents()
            EngineRuntime.update(EnginePhase.STOPPED, "VPN failed to start: ${failure.message ?: failure.javaClass.simpleName}")
            finishForegroundAndStop()
        }
    }

    private fun protectAndBindTcpSocket(socket: java.net.Socket): Boolean {
        if (!protect(socket)) return false
        val network = underlyingNetwork ?: return false
        return runCatching { network.bindSocket(socket); true }.getOrDefault(false)
    }

    private fun protectAndBindDatagramSocket(socket: java.net.DatagramSocket): Boolean {
        if (!protect(socket)) return false
        val network = underlyingNetwork ?: return false
        return runCatching { network.bindSocket(socket); true }.getOrDefault(false)
    }

    private fun resolveOnUnderlyingNetwork(host: String): List<java.net.InetAddress> {
        val network = underlyingNetwork ?: throw IOException("Underlying network disappeared")
        return network.getAllByName(host).toList()
    }

    private fun createTunnelConfig(): File {
        val directory = File(filesDir, "tunnel")
        check(directory.exists() || directory.mkdirs()) { "Could not create tunnel configuration directory" }
        val config = File(directory, "hev-socks5-tunnel.yml")
        config.writeText(
            """tunnel:
  name: tun0
  mtu: $VPN_MTU
  ipv4: $VPN_IPV4
  ipv6: '$VPN_IPV6'
  icmp: 'reply'
socks5:
  address: 127.0.0.1
  port: ${LocalSocks5Port.VALUE}
  udp: 'udp'
  pipeline: false
mapdns:
  address: $MAP_DNS_ADDRESS
  port: 53
  network: 100.64.0.0
  netmask: 255.192.0.0
  cache-size: 10000
misc:
  max-session-count: 256
  connect-timeout: 10000
  tcp-read-write-timeout: 300000
  udp-read-write-timeout: 60000
  log-level: warn
""".trimIndent(),
        )
        return config
    }

    private fun scheduleNetworkDetachStop() {
        networkLossJob?.cancel()
        networkLossJob = serviceScope.launch {
            delay(NETWORK_HANDOVER_GRACE_MS)
            if ((!underlyingNetworkAttached || underlyingNetwork == null) &&
                EngineRuntime.status.value.phase == EnginePhase.DEGRADED
            ) {
                stopVpn("No usable underlying network became available; VPN routes were removed")
            }
        }
    }

    private suspend fun stopVpn(reason: String) {
        val shouldStop = synchronized(lifecycleLock) {
            if (shutdownStarted) false else {
                shutdownStarted = true
                true
            }
        }
        if (!shouldStop) return

        EngineRuntime.update(EnginePhase.STOPPING, reason)
        recordEvent("vpn", reason)

        // Do not close descriptors while startVpn is still creating them. Cancellation is handled
        // by startVpn's cleanup branch; join it before performing final, idempotent cleanup.
        val pendingStart = startJob
        if (pendingStart?.isActive == true) {
            pendingStart.cancelAndJoin()
        }
        stopComponents()
        EngineRuntime.update(EnginePhase.STOPPED, "Local VPN stopped")
        finishForegroundAndStop()
    }

    @Synchronized
    private fun stopComponents() {
        networkLossJob?.cancel()
        networkLossJob = null
        statsJob?.cancel()
        statsJob = null
        rulesJob?.cancel()
        rulesJob = null

        // Stop producers before storage/native consumers. Polling in TunPacketBridge means a
        // blocked read observes running=false within a bounded interval; closing the VPN TUN then
        // releases any OS read already in progress. Wait again after TUN close before final flush.
        val bridge = packetBridge
        runCatching { bridge?.stop() }
        packetBridge = null
        runCatching { tun?.close() }
        tun = null
        val bridgeStopped = runCatching { bridge?.awaitStopped(BRIDGE_FINAL_JOIN_TIMEOUT_MS) ?: true }.getOrDefault(false)
        if (!bridgeStopped) recordEvent("error", "Packet bridge thread did not exit within the cleanup deadline")

        runCatching { NativePacketBatcher.flush() }
        // Stop is attempted even if start returned false: some native wrappers can partially create
        // worker state before reporting startup failure. The official stop entrypoint is idempotent.
        if (tunnelStartAttempted) {
            runCatching { TProxyService.TProxyStopService() }
            tunnelStarted = false
            tunnelStartAttempted = false
        }
        runCatching { bridgeSocketForCleanup?.let { Os.close(it) } }
        bridgeSocketForCleanup = null
        runCatching { engineTun?.close() }
        engineTun = null
        runCatching { socksProxy?.close() }
        socksProxy = null
        runCatching { setUnderlyingNetworks(emptyArray()) }
        runCatching { PacketCaptureStore.stop() }
        underlyingNetwork = null
        underlyingNetworkAttached = false
    }

    private fun finishForegroundAndStop() {
        if (foregroundStarted) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
            foregroundStarted = false
        }
        stopSelf()
    }

    private fun startAsForeground(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun recordEvent(type: String, detail: String) {
        DiagnosticEventLogger.record(applicationContext, type, detail)
    }

    override fun onRevoke() {
        serviceScope.launch {
            stopVpn("VPN permission revoked by Android or user")
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        // Cancel startup and wait for its cleanup before closing descriptors a second time.
        // The startup coroutine runs on Dispatchers.IO; cancellation joins avoid races with fd setup.
        runCatching {
            runBlocking(Dispatchers.IO) {
                startJob?.cancelAndJoin()
                stopComponents()
            }
        }
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        serviceScope.cancel()
        if (EngineRuntime.status.value.phase != EnginePhase.STOPPED) {
            EngineRuntime.update(EnginePhase.STOPPED, "VPN service destroyed")
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "NetControl VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun buildNotification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, NetworkVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("NetControl")
            .setContentText(text)
            .setContentIntent(openApp)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "Stop", stopIntent)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    companion object {
        const val ACTION_START_VPN = "com.netcontrol.app.action.START_VPN"
        // Kept as an alias so older UI code invoking the previous action remains compatible.
        const val ACTION_START_DIAGNOSTIC = "com.netcontrol.app.action.START_DIAGNOSTIC_TUN"
        const val ACTION_STOP = "com.netcontrol.app.action.STOP_TUN"
        private const val CHANNEL_ID = "netcontrol_network"
        private const val NOTIFICATION_ID = 4071
        private const val VPN_MTU = 1500
        private const val VPN_IPV4 = "198.18.0.1"
        private const val VPN_IPV6 = "fc00::1"
        private const val MAP_DNS_ADDRESS = "198.18.0.2"
        private const val STATS_INTERVAL_MS = 1_000L
        private const val BRIDGE_HEALTH_CHECK_MS = 50L
        private const val BRIDGE_FINAL_JOIN_TIMEOUT_MS = 700L
        private const val NETWORK_HANDOVER_GRACE_MS = 2_500L

        fun start(context: android.content.Context) {
            val intent = Intent(context, NetworkVpnService::class.java).setAction(ACTION_START_VPN)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: android.content.Context) {
            context.startService(Intent(context, NetworkVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}

/** Keeps the SOCKS port in one place so the generated native config matches the server binding. */
private object LocalSocks5Port {
    const val VALUE = 1080
}
