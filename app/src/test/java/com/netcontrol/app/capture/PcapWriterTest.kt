package com.netcontrol.app.capture

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PcapWriterTest {
    @Test fun emptyPcapHasClassicHeaderAndNoRecords() {
        val out = ByteArrayOutputStream()
        PcapWriter.writeEmpty(out)
        val bytes = out.toByteArray()
        assertEquals(24, bytes.size)
        assertTrue(bytes.sliceArray(0..3).contentEquals(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte())))
        assertEquals(101, (bytes[20].toInt() and 0xff) or ((bytes[21].toInt() and 0xff) shl 8))
    }

    @Test fun packetRecordIsWrittenStreaming() {
        val out = ByteArrayOutputStream()
        val writer = PcapWriter(out, snapLength = 4)
        writer.writePacket(1_234L, byteArrayOf(1, 2, 3, 4, 5, 6))
        writer.close()
        val bytes = out.toByteArray()
        assertEquals(1L, writer.packetCount)
        assertEquals(24L + 16L + 4L, writer.bytesWritten)
        assertEquals(44, bytes.size)
        assertEquals(4, (bytes[32].toInt() and 0xff)) // captured length field starts at byte 32
        assertEquals(6, (bytes[36].toInt() and 0xff)) // original length
    }
}
