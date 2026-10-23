package com.netcontrol.app.network

/**
 * Small bounded observer for unencrypted DNS questions in raw IP packets.
 * This deliberately does not parse DNS-over-TLS/HTTPS or reassemble fragmented IP packets.
 */
object DnsPacketParser {
    private const val IPPROTO_UDP = 17
    private const val DNS_PORT = 53
    private const val DNS_HEADER_BYTES = 12
    private const val MAX_IPV6_EXTENSION_HEADERS = 8

    /** Returns the first queried name when [packet] is a complete, unfragmented DNS query. */
    fun extractQueryName(packet: ByteArray): String? {
        if (packet.isEmpty()) return null
        val version = u8(packet, 0) ushr 4
        val dnsOffset = when (version) {
            4 -> ipv4DnsOffset(packet)
            6 -> ipv6DnsOffset(packet)
            else -> null
        } ?: return null
        return parseDnsQuestion(packet, dnsOffset.first, dnsOffset.second)
    }

    private fun ipv4DnsOffset(packet: ByteArray): Pair<Int, Int>? {
        if (packet.size < 20) return null
        val headerLength = (u8(packet, 0) and 0x0f) * 4
        val totalLength = u16(packet, 2)
        if (headerLength < 20 || totalLength < headerLength + 8 || totalLength > packet.size) return null
        if (u8(packet, 9) != IPPROTO_UDP) return null
        val fragment = u16(packet, 6)
        // Skip packets with a fragment offset or MF set. Reassembly is intentionally out of scope.
        if ((fragment and 0x3fff) != 0) return null
        return udpDnsOffset(packet, headerLength, totalLength)
    }

    private fun ipv6DnsOffset(packet: ByteArray): Pair<Int, Int>? {
        if (packet.size < 40) return null
        val totalLength = 40 + u16(packet, 4)
        if (totalLength > packet.size) return null
        var nextHeader = u8(packet, 6)
        var offset = 40
        var extensions = 0
        while (nextHeader != IPPROTO_UDP) {
            if (++extensions > MAX_IPV6_EXTENSION_HEADERS) return null
            when (nextHeader) {
                0, 43, 60, 135, 139, 140 -> { // Hop-by-hop, Routing, Destination, Mobility, HIP, Shim6
                    if (offset + 2 > totalLength) return null
                    val following = u8(packet, offset)
                    val length = (u8(packet, offset + 1) + 1) * 8
                    if (length < 8 || offset + length > totalLength) return null
                    nextHeader = following
                    offset += length
                }
                44 -> { // Fragment header: only accept an atomic fragment.
                    if (offset + 8 > totalLength) return null
                    val following = u8(packet, offset)
                    val fragmentField = u16(packet, offset + 2)
                    if ((fragmentField and 0xfff9) != 0) return null
                    nextHeader = following
                    offset += 8
                }
                51 -> { // Authentication Header
                    if (offset + 2 > totalLength) return null
                    val following = u8(packet, offset)
                    val length = (u8(packet, offset + 1) + 2) * 4
                    if (length < 8 || offset + length > totalLength) return null
                    nextHeader = following
                    offset += length
                }
                else -> return null
            }
        }
        return udpDnsOffset(packet, offset, totalLength)
    }

    private fun udpDnsOffset(packet: ByteArray, offset: Int, ipPacketEnd: Int): Pair<Int, Int>? {
        if (offset < 0 || offset + 8 > ipPacketEnd || ipPacketEnd > packet.size) return null
        val destinationPort = u16(packet, offset + 2)
        if (destinationPort != DNS_PORT) return null
        val udpLength = u16(packet, offset + 4)
        if (udpLength < 8 || offset + udpLength > ipPacketEnd) return null
        val dnsOffset = offset + 8
        val dnsLength = udpLength - 8
        if (dnsLength < DNS_HEADER_BYTES) return null
        return dnsOffset to dnsLength
    }

    private fun parseDnsQuestion(packet: ByteArray, offset: Int, length: Int): String? {
        if (length < DNS_HEADER_BYTES || offset < 0 || offset + length > packet.size) return null
        val flags = u16(packet, offset + 2)
        val questionCount = u16(packet, offset + 4)
        if ((flags and 0x8000) != 0 || questionCount == 0) return null // QR=1 is a response.

        var cursor = offset + DNS_HEADER_BYTES
        val end = offset + length
        var textualLength = 0
        val labels = ArrayList<String>(8)
        while (cursor < end) {
            val labelLength = u8(packet, cursor++)
            if (labelLength == 0) break
            // Compression pointers are not legal in the question's QNAME and are not followed.
            if ((labelLength and 0xc0) != 0 || labelLength > 63 || cursor + labelLength > end) return null
            val labelBytes = packet.copyOfRange(cursor, cursor + labelLength)
            if (labelBytes.any { (it.toInt() and 0xff) !in 0x21..0x7e }) return null
            val label = labelBytes.toString(Charsets.US_ASCII)
            textualLength += label.length + if (labels.isEmpty()) 0 else 1
            if (textualLength > 253) return null
            labels += label
            cursor += labelLength
        }
        if (labels.isEmpty() || cursor + 4 > end) return null // QTYPE + QCLASS must be present.
        return labels.joinToString(".").lowercase()
    }

    private fun u8(bytes: ByteArray, offset: Int): Int = bytes[offset].toInt() and 0xff
    private fun u16(bytes: ByteArray, offset: Int): Int = (u8(bytes, offset) shl 8) or u8(bytes, offset + 1)
}
