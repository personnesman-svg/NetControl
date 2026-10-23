package com.netcontrol.app.capture

import java.io.Closeable
import java.io.OutputStream

/** Streaming classic PCAP writer (little-endian, DLT_RAW IPv4/IPv6 packets). */
class PcapWriter(private val output: OutputStream, private val snapLength: Int = 65_535) : Closeable {
    private var closed = false
    var bytesWritten: Long = 24
        private set
    var packetCount: Long = 0
        private set

    init {
        require(snapLength in 1..65_535)
        writeGlobalHeader(output, snapLength)
    }

    @Synchronized
    fun writePacket(timestampMillis: Long, packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset) {
        check(!closed) { "PCAP writer is closed" }
        require(offset >= 0 && length >= 0 && offset <= packet.size - length) { "Invalid packet slice" }
        require(length > 0) { "Empty packets cannot be stored" }
        val captured = minOf(length, snapLength)
        val seconds = (timestampMillis.coerceAtLeast(0L) / 1000L).coerceAtMost(0xffff_ffffL).toInt()
        val micros = ((timestampMillis.coerceAtLeast(0L) % 1000L) * 1000L).toInt()
        writeLe32(output, seconds)
        writeLe32(output, micros)
        writeLe32(output, captured)
        writeLe32(output, length)
        output.write(packet, offset, captured)
        bytesWritten += 16L + captured
        packetCount++
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            output.flush()
            output.close()
        }
    }

    companion object {
        /** Writes a valid empty classic PCAP file; no traffic is implied by this operation. */
        fun writeEmpty(output: OutputStream, snapLength: Int = 65_535) {
            require(snapLength in 1..65_535)
            writeGlobalHeader(output, snapLength)
            output.flush()
        }

        private fun writeGlobalHeader(output: OutputStream, snapLength: Int) {
            // Magic d4 c3 b2 a1, version 2.4, timezone/sigfigs 0, snaplen, DLT_RAW=101.
            output.write(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte()))
            writeLe16(output, 2)
            writeLe16(output, 4)
            writeLe32(output, 0)
            writeLe32(output, 0)
            writeLe32(output, snapLength)
            writeLe32(output, 101)
        }

        private fun writeLe16(out: OutputStream, value: Int) {
            out.write(value and 0xff)
            out.write((value ushr 8) and 0xff)
        }

        private fun writeLe32(out: OutputStream, value: Int) {
            out.write(value and 0xff)
            out.write((value ushr 8) and 0xff)
            out.write((value ushr 16) and 0xff)
            out.write((value ushr 24) and 0xff)
        }
    }
}
