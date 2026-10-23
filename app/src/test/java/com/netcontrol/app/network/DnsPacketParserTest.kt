package com.netcontrol.app.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketParserTest {
    @Test fun extractsIpv4DnsQuestion() {
        assertEquals("www.example.com", DnsPacketParser.extractQueryName(dnsPacket(ipv6 = false)))
    }

    @Test fun extractsIpv6DnsQuestion() {
        assertEquals("www.example.com", DnsPacketParser.extractQueryName(dnsPacket(ipv6 = true)))
    }

    @Test fun ignoresResponsesAndNonDnsPackets() {
        val response = dnsPacket(ipv6 = false).also { it[30] = 0x81.toByte() }
        assertNull(DnsPacketParser.extractQueryName(response))
        val tcp = dnsPacket(ipv6 = false).also { it[9] = 6 }
        assertNull(DnsPacketParser.extractQueryName(tcp))
    }

    @Test fun rejectsTruncatedAndFragmentedPackets() {
        assertNull(DnsPacketParser.extractQueryName(byteArrayOf(0x45)))
        val fragmented = dnsPacket(ipv6 = false).also { it[6] = 0x20; it[7] = 0 }
        assertNull(DnsPacketParser.extractQueryName(fragmented))
    }

    private fun dnsPacket(ipv6: Boolean): ByteArray {
        val labels = listOf("www", "example", "com")
        val qname = labels.flatMap { label -> listOf(label.length.toByte()) + label.encodeToByteArray().toList() }
            .toByteArray() + byteArrayOf(0)
        val dns = ByteArray(12 + qname.size + 4)
        dns[0] = 0x12
        dns[1] = 0x34
        dns[2] = 0x01 // recursion desired; QR=0 query
        dns[5] = 0x01 // QDCOUNT=1
        qname.copyInto(dns, 12)
        val qtype = 12 + qname.size
        dns[qtype + 1] = 1 // QTYPE A
        dns[qtype + 3] = 1 // QCLASS IN

        val ipHeader = if (ipv6) 40 else 20
        val total = ipHeader + 8 + dns.size
        val packet = ByteArray(total)
        if (ipv6) {
            packet[0] = 0x60
            packet[4] = ((8 + dns.size) ushr 8).toByte()
            packet[5] = (8 + dns.size).toByte()
            packet[6] = 17
        } else {
            packet[0] = 0x45
            packet[2] = (total ushr 8).toByte()
            packet[3] = total.toByte()
            packet[9] = 17
        }
        packet[ipHeader] = 0x30
        packet[ipHeader + 1] = 0x39 // source port 12345
        packet[ipHeader + 2] = 0
        packet[ipHeader + 3] = 53
        packet[ipHeader + 4] = ((8 + dns.size) ushr 8).toByte()
        packet[ipHeader + 5] = (8 + dns.size).toByte()
        dns.copyInto(packet, ipHeader + 8)
        return packet
    }
}
