package com.netcontrol.app.network

import com.netcontrol.app.service.EngineRuntime

/** Host integration: raw IP packets -> real JNI/native core -> actual Runtime StateFlow UI model. */
object NativeUiIntegration {
    @JvmStatic
    fun main(args: Array<String>) {
        check(NativeEngine.available) { "Native JNI library did not load" }
        NativeEngine.reset()
        EngineRuntime.resetSession()

        val syn = tcpPacket("10.0.0.2", "93.184.216.34", 51000, 443, 1000, 0x02, byteArrayOf())
        val hello = clientHello()
        val split = hello.size / 2
        // Deliver the second half first to verify that the production JNI bridge and UI model are
        // fed only after bounded sequence-aware reassembly fills the gap.
        val tail = tcpPacket("10.0.0.2", "93.184.216.34", 51000, 443, 1001 + split, 0x18, hello.copyOfRange(split, hello.size))
        val head = tcpPacket("10.0.0.2", "93.184.216.34", 51000, 443, 1001, 0x18, hello.copyOfRange(0, split))
        val tlsStats = process(listOf(
            syn to 1_800_000_000_000L,
            tail to 1_800_000_000_123L,
            head to 1_800_000_000_234L,
        ))
        check(tlsStats[0] == 3L) { "Expected three parsed TUN packets, got ${tlsStats[0]}" }
        val tlsEventCount = drainIntoUi()
        val tlsEvent = EngineRuntime.networkEvents.value.firstOrNull { it.type == "TLS_CLIENT_HELLO" }
        check(tlsEventCount >= 1) { "Native TLS event did not reach the UI state model" }
        check(tlsEvent != null) { "No TLS_CLIENT_HELLO event in EngineRuntime" }
        check(tlsEvent.hostname == "example.com") { "Unexpected SNI: ${tlsEvent.hostname}" }
        check(tlsEvent.alpn == "h2") { "Unexpected ALPN: ${tlsEvent.alpn}" }
        check(tlsEvent.source == "TLS_CLIENT_HELLO" && tlsEvent.flowId != null) { "Missing event provenance/flow ID" }
        check(tlsEvent.timestampMs == 1_800_000_000_234L) { "Per-packet capture timestamp was not preserved: ${tlsEvent.timestampMs}" }
        check(tlsEvent.sourceAddress == "10.0.0.2" && tlsEvent.destinationAddress == "93.184.216.34") {
            "Unexpected packet endpoints: ${tlsEvent.sourceAddress} -> ${tlsEvent.destinationAddress}"
        }

        val query = dnsQuery()
        val dnsPacket = udpPacket("10.0.0.2", "8.8.8.8", 53001, 53, query)
        val dnsStats = process(listOf(dnsPacket to 1_800_000_001_234L))
        check(dnsStats[0] == 4L) { "Expected cumulative count of four parsed packets, got ${dnsStats[0]}" }
        drainIntoUi()
        val dnsEvent = EngineRuntime.networkEvents.value.lastOrNull { it.type == "DNS" }
        check(dnsEvent != null) { "No live DNS event in EngineRuntime" }
        check(dnsEvent.hostname == "example.com") { "Unexpected DNS qname: ${dnsEvent.hostname}" }
        check(dnsEvent.source == "TUN_UDP_DNS" && dnsEvent.dnsResponse == false) { "DNS event provenance/type not preserved" }
        check(dnsEvent.timestampMs == 1_800_000_001_234L) { "DNS timestamp was not preserved" }

        println("PASS: TUN out-of-order TUN TCP segments -> sequence-aware native reassembly -> TLS SNI/ALPN -> EngineRuntime StateFlow")
        println("PASS: TUN UDP/53 packet -> native DNS event -> EngineRuntime StateFlow")
        println("PASS: packet timestamps, endpoints, event source and native stream ID preserved")
    }

    private fun process(items: List<Pair<ByteArray, Long>>): LongArray {
        val batch = java.io.ByteArrayOutputStream()
        for ((packet, _) in items) {
            batch.write((packet.size ushr 8) and 0xff)
            batch.write(packet.size and 0xff)
            batch.write(packet)
        }
        return NativeEngine.processBatch(batch.toByteArray(), items.map { it.second }.toLongArray(), items.last().second)
    }

    private fun drainIntoUi(): Int {
        val events = NativeEngine.drainEvents()
        EngineRuntime.appendNativeEvents(events)
        return events.size
    }

    private fun put16(b: ByteArray, at: Int, value: Int) {
        b[at] = (value ushr 8).toByte(); b[at + 1] = value.toByte()
    }

    private fun put32(b: ByteArray, at: Int, value: Int) {
        b[at] = (value ushr 24).toByte(); b[at + 1] = (value ushr 16).toByte()
        b[at + 2] = (value ushr 8).toByte(); b[at + 3] = value.toByte()
    }

    private fun ip4(address: String): ByteArray = address.split('.').map { it.toInt().toByte() }.toByteArray().also {
        require(it.size == 4)
    }

    private fun tcpPacket(src: String, dst: String, sport: Int, dport: Int, seq: Int, flags: Int, payload: ByteArray): ByteArray {
        val b = ByteArray(40 + payload.size)
        b[0] = 0x45
        put16(b, 2, b.size)
        b[8] = 64
        b[9] = 6
        ip4(src).copyInto(b, 12); ip4(dst).copyInto(b, 16)
        put16(b, 20, sport); put16(b, 22, dport); put32(b, 24, seq)
        b[32] = 0x50; b[33] = flags.toByte()
        payload.copyInto(b, 40)
        return b
    }

    private fun udpPacket(src: String, dst: String, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val b = ByteArray(28 + payload.size)
        b[0] = 0x45
        put16(b, 2, b.size)
        b[8] = 64; b[9] = 17
        ip4(src).copyInto(b, 12); ip4(dst).copyInto(b, 16)
        put16(b, 20, sport); put16(b, 22, dport); put16(b, 24, 8 + payload.size)
        payload.copyInto(b, 28)
        return b
    }

    private fun dnsQuery(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in listOf("example", "com")) {
            val bytes = label.toByteArray(Charsets.US_ASCII); out.write(bytes.size); out.write(bytes)
        }
        out.write(0); out.write(byteArrayOf(0, 1, 0, 1))
        return out.toByteArray()
    }

    private fun clientHello(): ByteArray {
        val ext = java.io.ByteArrayOutputStream()
        val sni = "example.com".toByteArray(Charsets.US_ASCII)
        val sniData = java.io.ByteArrayOutputStream().apply {
            write(byteArrayOf(0, (3 + sni.size).toByte(), 0)); write(byteArrayOf(0, sni.size.toByte())); write(sni)
        }.toByteArray()
        ext.write(byteArrayOf(0, 0)); ext.write(byteArrayOf((sniData.size ushr 8).toByte(), sniData.size.toByte())); ext.write(sniData)
        val alpnData = byteArrayOf(0, 3, 2, 'h'.code.toByte(), '2'.code.toByte())
        ext.write(byteArrayOf(0, 16, 0, alpnData.size.toByte())); ext.write(alpnData)
        val extensions = ext.toByteArray()
        val body = java.io.ByteArrayOutputStream().apply {
            write(byteArrayOf(3, 3)); write(ByteArray(32) { 0x42 }); write(0)
            write(byteArrayOf(0, 2, 0x13, 1, 1, 0)); write(byteArrayOf((extensions.size ushr 8).toByte(), extensions.size.toByte())); write(extensions)
        }.toByteArray()
        val handshake = byteArrayOf(1, (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(22, 3, 1, (handshake.size ushr 8).toByte(), handshake.size.toByte()) + handshake
    }
}
