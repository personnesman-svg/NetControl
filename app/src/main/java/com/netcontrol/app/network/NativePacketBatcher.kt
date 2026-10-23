package com.netcontrol.app.network

import com.netcontrol.app.service.EngineRuntime
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/** Batches captured raw IP packets before crossing JNI, avoiding one JNI call per packet. */
object NativePacketBatcher {
    private const val MAX_BATCH_PACKETS = 16
    private const val MAX_BATCH_BYTES = 48 * 1024

    private data class PendingPacket(val bytes: ByteArray, val timestampMillis: Long)

    private val lock = Any()
    private val pending = ArrayList<PendingPacket>(MAX_BATCH_PACKETS)
    private var pendingBytes = 0

    fun offer(packet: ByteArray) = offerOwned(packet.copyOf(), System.currentTimeMillis())

    /** Takes ownership of [packet], which the caller must not mutate after this call. */
    fun offerOwned(packet: ByteArray, timestampMillis: Long = System.currentTimeMillis()) = synchronized(lock) {
        if (packet.isEmpty() || packet.size > 65_535 || !NativeEngine.available) return@synchronized
        pending += PendingPacket(packet, timestampMillis.coerceAtLeast(0L))
        pendingBytes += packet.size + 2
        if (pending.size >= MAX_BATCH_PACKETS || pendingBytes >= MAX_BATCH_BYTES) flushLocked()
    }

    fun flush() = synchronized(lock) { flushLocked() }

    fun reset() = synchronized(lock) {
        pending.clear()
        pendingBytes = 0
        if (NativeEngine.available) runCatching { NativeEngine.reset() }
    }

    private fun flushLocked() {
        if (pending.isEmpty() || !NativeEngine.available) return
        val batch = pending.toList()
        val bytes = ByteArrayOutputStream(pendingBytes)
        DataOutputStream(bytes).use { out ->
            batch.forEach { packet ->
                out.writeShort(packet.bytes.size)
                out.write(packet.bytes)
            }
        }
        pending.clear()
        pendingBytes = 0
        runCatching {
            val timestamps = LongArray(batch.size) { batch[it].timestampMillis }
            EngineRuntime.updateNativeSnapshot(
                NativeEngine.processBatch(bytes.toByteArray(), timestamps, System.currentTimeMillis()),
            )
            EngineRuntime.appendNativeEvents(NativeEngine.drainEvents())
        }.onFailure {
            EngineRuntime.recordTransportError()
        }
    }
}
