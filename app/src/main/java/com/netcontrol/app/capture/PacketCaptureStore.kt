package com.netcontrol.app.capture

import android.content.Context
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile

/**
 * Process-local bounded PCAP session. Packets are raw IP packets observed in both directions at
 * the Android VPN TUN boundary (DLT_RAW), not wire-level packets from the physical interface.
 * Writes and exports share a lock so an export is a consistent record-boundary snapshot.
 *
 * The capture path is fail-closed for the file, not for forwarding: an IO failure disables further
 * capture, rolls the file back to the last successfully flushed record boundary and is surfaced to
 * diagnostics. TunPacketBridge catches that failure and keeps packet forwarding alive.
 */
object PacketCaptureStore {
    private const val MAX_CAPTURE_BYTES = 64L * 1024L * 1024L
    private const val FLUSH_EVERY_PACKETS = 16L

    private val lock = Any()
    private var captureFile: File? = null
    private var output: BufferedOutputStream? = null
    private var writer: PcapWriter? = null
    private var packetsSinceFlush = 0L
    private var packetsWritten = 0L
    private var committedPackets = 0L
    private var committedBytes = 0L
    private var captureLimitReached = false
    private var captureError: String? = null

    val packetCount: Long
        get() = synchronized(lock) { packetsWritten }

    val isLimitReached: Boolean
        get() = synchronized(lock) { captureLimitReached }

    val lastError: String?
        get() = synchronized(lock) { captureError }

    val isActive: Boolean
        get() = synchronized(lock) { writer != null && output != null && captureError == null }

    fun start(context: Context) = synchronized(lock) {
        closeLocked()
        val dir = File(context.applicationContext.filesDir, "captures")
        check(dir.exists() || dir.mkdirs()) { "Unable to create capture directory" }
        val file = File(dir, "latest.pcap")
        captureFile = file
        packetsWritten = 0L
        committedPackets = 0L
        committedBytes = 0L
        packetsSinceFlush = 0L
        captureLimitReached = false
        captureError = null
        var stream: BufferedOutputStream? = null
        try {
            stream = BufferedOutputStream(FileOutputStream(file, false), 64 * 1024)
            val activeWriter = PcapWriter(stream)
            stream.flush() // Commit the global header before accepting packets.
            output = stream
            writer = activeWriter
            committedBytes = activeWriter.bytesWritten
        } catch (failure: Throwable) {
            runCatching { stream?.close() }
            failLocked("Unable to create PCAP file", failure)
            throw failure
        }
    }

    fun writePacket(timestampMillis: Long, packet: ByteArray) = synchronized(lock) {
        val activeWriter = writer ?: return@synchronized
        val activeOutput = output ?: return@synchronized
        if (captureLimitReached || captureError != null || packet.isEmpty()) return@synchronized
        val recordBytes = 16L + minOf(packet.size, 65_535).toLong()
        if (activeWriter.bytesWritten + recordBytes > MAX_CAPTURE_BYTES) {
            try {
                activeOutput.flush()
                committedBytes = activeWriter.bytesWritten
                committedPackets = activeWriter.packetCount
                packetsWritten = committedPackets
                captureLimitReached = true
                packetsSinceFlush = 0L
            } catch (failure: Throwable) {
                failLocked("PCAP flush failed at capture limit", failure)
                throw failure
            }
            return@synchronized
        }

        try {
            activeWriter.writePacket(timestampMillis, packet)
            packetsWritten = activeWriter.packetCount
            packetsSinceFlush++
            if (packetsSinceFlush >= FLUSH_EVERY_PACKETS) {
                activeOutput.flush()
                committedBytes = activeWriter.bytesWritten
                committedPackets = activeWriter.packetCount
                packetsSinceFlush = 0L
            }
        } catch (failure: Throwable) {
            failLocked("PCAP record write/flush failed", failure)
            throw failure
        }
    }

    /** Copies a consistent snapshot to an Android document-provider stream. */
    fun exportTo(context: Context, destination: OutputStream): Long = synchronized(lock) {
        val activeWriter = writer
        val activeOutput = output
        if (activeWriter != null && activeOutput != null) {
            try {
                activeOutput.flush()
                committedBytes = activeWriter.bytesWritten
                committedPackets = activeWriter.packetCount
                packetsWritten = committedPackets
                packetsSinceFlush = 0L
            } catch (failure: Throwable) {
                failLocked("PCAP flush failed during export", failure)
                throw IOException("PCAP capture was disabled because a complete export snapshot could not be committed", failure)
            }
        }
        val file = captureFile ?: File(context.applicationContext.filesDir, "captures/latest.pcap")
        if (!file.isFile) {
            PcapWriter.writeEmpty(destination)
            0L
        } else {
            // Do not copy any uncommitted tail, even if an earlier process crash left one behind.
            val safeLength = committedBytes.takeIf { it >= 24L } ?: 0L
            if (safeLength < 24L) {
                PcapWriter.writeEmpty(destination)
                return@synchronized 0L
            }
            file.inputStream().buffered().use { input ->
                var remaining = safeLength
                val buffer = ByteArray(32 * 1024)
                while (remaining > 0L) {
                    val requested = minOf(buffer.size.toLong(), remaining).toInt()
                    val read = input.read(buffer, 0, requested)
                    if (read < 0) throw IOException("PCAP file ended before its committed boundary")
                    destination.write(buffer, 0, read)
                    remaining -= read.toLong()
                }
            }
            destination.flush()
            committedPackets
        }
    }

    fun stop() = synchronized(lock) { closeLocked() }

    private fun closeLocked() {
        val activeWriter = writer
        val activeOutput = output
        if (activeWriter != null && activeOutput != null) {
            try {
                activeWriter.close()
                committedBytes = activeWriter.bytesWritten
                committedPackets = activeWriter.packetCount
                packetsWritten = committedPackets
            } catch (failure: Throwable) {
                failLocked("PCAP close/flush failed", failure)
            } finally {
                runCatching { activeOutput.close() }
            }
        }
        writer = null
        output = null
        packetsSinceFlush = 0L
    }

    private fun failLocked(context: String, failure: Throwable) {
        val file = captureFile
        val activeOutput = output
        val activeWriter = writer
        writer = null
        output = null
        captureError = "$context: ${failure.message ?: failure.javaClass.simpleName}"
        captureLimitReached = false
        packetsSinceFlush = 0L
        // Dispose buffers before truncating; truncation rolls back an interrupted record or batch.
        runCatching { activeOutput?.close() }
        if (file != null && committedBytes >= 24L) {
            runCatching {
                RandomAccessFile(file, "rw").use { raf -> raf.setLength(committedBytes) }
            }
        }
        packetsWritten = committedPackets
        if (activeWriter == null && committedBytes == 0L) captureError = "$context: no committed PCAP header"
    }
}
