import com.netcontrol.app.data.RuleEntity
import com.netcontrol.app.service.LocalSocks5Proxy
import com.netcontrol.app.model.FlowSnapshot
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicLong

/** Host-only exercise of the production SOCKS5 UDP association over real loopback sockets. */
fun main() {
    val loopback = InetAddress.getByName("127.0.0.1")
    val echo = DatagramSocket(null)
    echo.reuseAddress = false
    echo.bind(InetSocketAddress(loopback, 0))
    val echoThread = Thread {
        val buffer = ByteArray(2_048)
        while (!echo.isClosed) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                echo.receive(packet)
                echo.send(DatagramPacket(packet.data, packet.offset, packet.length, packet.socketAddress))
            } catch (_: Exception) {
                if (!echo.isClosed) throw IllegalStateException("UDP echo worker unexpectedly failed")
            }
        }
    }.apply { isDaemon = true; start() }

    val uploaded = AtomicLong()
    val downloaded = AtomicLong()
    val proxy = LocalSocks5Proxy(
        protectSocket = { true },
        protectDatagramSocket = { true },
        resolveHost = { host -> InetAddress.getAllByName(host).toList() },
        rulesProvider = { emptyList<RuleEntity>() },
        onEvent = { _, _ -> },
        onFlowCreated = { _: FlowSnapshot -> },
        onFlowBytes = { _, up, down -> uploaded.addAndGet(up); downloaded.addAndGet(down) },
        onFlowEnded = { _, _ -> },
    )

    var control: Socket? = null
    var clientUdp: DatagramSocket? = null
    try {
        proxy.start()
        control = Socket(loopback, 1080).apply { soTimeout = 3_000 }
        val input = DataInputStream(control.getInputStream())
        val output = DataOutputStream(control.getOutputStream())

        output.write(byteArrayOf(5, 1, 0))
        output.flush()
        check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 0) { "SOCKS5 no-auth negotiation failed" }

        // Request a UDP relay. The advertised endpoint must be the local loopback receiver,
        // not the upstream socket whose route is bound/protected to the underlying network.
        output.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()
        val associateReply = ByteArray(10)
        input.readFully(associateReply)
        check(associateReply[0].toInt() == 5 && associateReply[1].toInt() == 0 && associateReply[3].toInt() == 1) {
            "SOCKS5 UDP ASSOCIATE failed: ${associateReply.joinToString { (it.toInt() and 0xff).toString() }}"
        }
        val relayPort = ((associateReply[8].toInt() and 0xff) shl 8) or (associateReply[9].toInt() and 0xff)
        check(relayPort in 1..65535) { "Invalid local UDP relay port: $relayPort" }

        clientUdp = DatagramSocket(null).apply {
            bind(InetSocketAddress(loopback, 0))
            soTimeout = 3_000
        }
        val payload = "netcontrol-udp-roundtrip".toByteArray(Charsets.US_ASCII)
        val request = ByteArray(10 + payload.size)
        request[0] = 0; request[1] = 0; request[2] = 0; request[3] = 1
        loopback.address.copyInto(request, 4)
        request[8] = ((echo.localPort ushr 8) and 0xff).toByte()
        request[9] = (echo.localPort and 0xff).toByte()
        payload.copyInto(request, 10)
        clientUdp.send(DatagramPacket(request, request.size, loopback, relayPort))

        val responseBuffer = ByteArray(2_048)
        val response = DatagramPacket(responseBuffer, responseBuffer.size)
        clientUdp.receive(response)
        check(response.address.isLoopbackAddress && response.port == relayPort) { "Response did not originate from advertised local SOCKS relay" }
        check(response.length >= 10 && response.data[0].toInt() == 0 && response.data[1].toInt() == 0 && response.data[2].toInt() == 0 && response.data[3].toInt() == 1) {
            "Invalid SOCKS5 UDP response envelope"
        }
        val replyPort = ((response.data[8].toInt() and 0xff) shl 8) or (response.data[9].toInt() and 0xff)
        check(replyPort == echo.localPort) { "Wrong upstream source port in SOCKS5 UDP response: $replyPort" }
        val returned = response.data.copyOfRange(10, response.length)
        check(returned.contentEquals(payload)) { "UDP payload did not survive the SOCKS5 relay roundtrip" }
        check(uploaded.get() >= payload.size && downloaded.get() >= payload.size) {
            "Proxy payload counters did not count both directions (up=${uploaded.get()}, down=${downloaded.get()})"
        }
        println("PASS: real SOCKS5 UDP ASSOCIATE -> separate loopback/upstream sockets -> UDP echo -> SOCKS5 response; payload counters verified")
    } catch (failure: SocketTimeoutException) {
        throw AssertionError("SOCKS5 UDP response timed out; local and upstream UDP sockets may be incorrectly coupled", failure)
    } finally {
        runCatching { control?.close() }
        runCatching { clientUdp?.close() }
        proxy.close()
        echo.close()
        echoThread.interrupt()
    }
}
