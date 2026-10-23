package com.netcontrol.app.service

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileDescriptor
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import com.netcontrol.app.capture.PacketCaptureStore
import com.netcontrol.app.network.NativePacketBatcher

/**
 * Mirrors packet-preserving datagrams between Android's real TUN fd and the private socketpair
 * endpoint consumed by hev-socks5-tunnel. The bridge has exactly one reader for each endpoint.
 * Polling with a finite timeout makes stop observable even if no packet arrives; Thread.interrupt
 * alone does not reliably interrupt a native Os.read call.
 */
class TunPacketBridge(
    private val vpnTun: ParcelFileDescriptor,
    private val bridgeFd: FileDescriptor,
    private val onFailure: (String, Throwable) -> Unit,
    private val onObservationFailure: (String, Throwable) -> Unit = { _, _ -> },
) {
    private val running = AtomicBoolean(false)
    private val firstFailure = AtomicReference<Throwable?>(null)
    val isRunning: Boolean get() = running.get() && firstFailure.get() == null
    val failure: Throwable? get() = firstFailure.get()
    @Volatile private var fromAppsThread: Thread? = null
    @Volatile private var toAppsThread: Thread? = null

    fun start() {
        check(running.compareAndSet(false, true)) { "Packet bridge is already running" }
        fromAppsThread = Thread({ forwardAppsToEngine() }, "NetControl-TUN-in").apply { isDaemon = true; start() }
        toAppsThread = Thread({ forwardEngineToApps() }, "NetControl-TUN-out").apply { isDaemon = true; start() }
    }

    /** Idempotently requests shutdown and closes only the bridge-owned socketpair endpoint. */
    @Synchronized
    fun stop() {
        if (running.compareAndSet(true, false)) {
            // Closing this endpoint wakes the engine-facing loop. The VPN-owned TUN is not closed
            // here; NetworkVpnService owns it and may close it after stopping the bridge.
            runCatching { Os.shutdown(bridgeFd, OsConstants.SHUT_RDWR) }
            runCatching { Os.close(bridgeFd) }
            fromAppsThread?.interrupt()
            toAppsThread?.interrupt()
        }
        awaitStopped(STOP_JOIN_TIMEOUT_MS)
    }

    /** Waits again after the service closes the TUN, which also releases a pending TUN poll/read. */
    @Synchronized
    fun awaitStopped(timeoutMillis: Long = STOP_JOIN_TIMEOUT_MS): Boolean {
        joinBounded(fromAppsThread, timeoutMillis)
        joinBounded(toAppsThread, timeoutMillis)
        val inputDone = fromAppsThread?.isAlive != true
        val outputDone = toAppsThread?.isAlive != true
        if (inputDone) fromAppsThread = null
        if (outputDone) toAppsThread = null
        return inputDone && outputDone
    }

    private fun joinBounded(thread: Thread?, timeoutMillis: Long) {
        if (thread == null || thread === Thread.currentThread()) return
        try {
            thread.join(timeoutMillis.coerceAtLeast(0L))
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun forwardAppsToEngine() {
        val buffer = ByteArray(MAX_PACKET_SIZE)
        try {
            while (running.get()) {
                if (!awaitReady(vpnTun.fileDescriptor, OsConstants.POLLIN)) break
                val length = Os.read(vpnTun.fileDescriptor, buffer, 0, buffer.size)
                if (length <= 0) throw IOException("Android TUN returned EOF/invalid read length: $length")
                val packet = buffer.copyOf(length)
                observe(packet)
                awaitWritable(bridgeFd)
                if (!running.get()) break
                val written = Os.write(bridgeFd, buffer, 0, length)
                if (written != length) throw IOException("Short write into tunnel socketpair: $written/$length")
            }
        } catch (failure: Throwable) {
            if (running.get()) {
                firstFailure.compareAndSet(null, failure)
                onFailure("Reading Android TUN or forwarding packet into tunnel", failure)
            }
        }
    }

    private fun forwardEngineToApps() {
        val buffer = ByteArray(MAX_PACKET_SIZE)
        try {
            while (running.get()) {
                if (!awaitReady(bridgeFd, OsConstants.POLLIN)) break
                val length = Os.read(bridgeFd, buffer, 0, buffer.size)
                if (length <= 0) throw IOException("Tunnel socketpair returned EOF/invalid read length: $length")
                val packet = buffer.copyOf(length)
                observe(packet)
                awaitWritable(vpnTun.fileDescriptor)
                if (!running.get()) break
                val written = Os.write(vpnTun.fileDescriptor, buffer, 0, length)
                if (written != length) throw IOException("Short write into Android TUN: $written/$length")
            }
        } catch (failure: Throwable) {
            if (running.get()) {
                firstFailure.compareAndSet(null, failure)
                onFailure("Reading tunnel response or writing packet to Android TUN", failure)
            }
        }
    }

    /** Poll at bounded intervals so shutdown never depends solely on interrupting native I/O. */
    private fun awaitReady(fd: FileDescriptor, requestedEvent: Int): Boolean {
        val descriptor = StructPollfd().apply {
            this.fd = fd
            events = requestedEvent.toShort()
        }
        while (running.get()) {
            descriptor.revents = 0
            val ready = try {
                Os.poll(arrayOf(descriptor), IO_POLL_TIMEOUT_MS)
            } catch (failure: ErrnoException) {
                if (failure.errno == OsConstants.EINTR) continue
                if (!running.get()) return false
                throw IOException("poll() failed for packet bridge", failure)
            }
            if (!running.get()) return false
            if (ready == 0) continue
            val returnedEvents = descriptor.revents.toInt() and 0xffff
            val fatalEvents = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
            if ((returnedEvents and fatalEvents) != 0) {
                throw IOException("Packet bridge descriptor poll failed (events=0x${returnedEvents.toString(16)})")
            }
            if ((returnedEvents and requestedEvent) != 0) return true
        }
        return false
    }

    private fun awaitWritable(fd: FileDescriptor): Boolean = awaitReady(fd, OsConstants.POLLOUT)

    private fun observe(packet: ByteArray) {
        val now = System.currentTimeMillis()
        // Observation failures must not interrupt packet forwarding. PCAP is diagnostic storage,
        // not part of the forwarding path; the native parser likewise has its own failure boundary.
        runCatching { PacketCaptureStore.writePacket(now, packet) }
            .onFailure { onObservationFailure("PCAP write failed; forwarding continues", it) }
        runCatching { NativePacketBatcher.offerOwned(packet, now) }
            .onFailure { onObservationFailure("Native packet observation failed; forwarding continues", it) }
    }

    companion object {
        private const val MAX_PACKET_SIZE = 65_535
        private const val IO_POLL_TIMEOUT_MS = 200
        private const val STOP_JOIN_TIMEOUT_MS = 450L
    }
}
