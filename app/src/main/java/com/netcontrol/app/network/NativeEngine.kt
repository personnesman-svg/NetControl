package com.netcontrol.app.network

/** JNI accepts batches framed as repeated unsigned 16-bit big-endian length + packet bytes. */
object NativeEngine {
    val available: Boolean = runCatching {
        System.loadLibrary("netcontrol")
        true
    }.getOrDefault(false)

    /** Returns [processed, malformed, ipv4, ipv6, activeFlows, evictions, errors]. */
    external fun processBatch(framedPackets: ByteArray, packetTimestampsMillis: LongArray, fallbackTimestampMillis: Long): LongArray

    /** Drains bounded observations produced while processing real TUN-boundary IP packets. */
    external fun drainEvents(): Array<String>

    /** Clears native per-session counters, flow state, reassembly and queued observations. */
    external fun reset()
}
