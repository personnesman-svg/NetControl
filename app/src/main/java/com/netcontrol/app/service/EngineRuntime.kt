package com.netcontrol.app.service

import com.netcontrol.app.model.EnginePhase
import com.netcontrol.app.model.EngineStats
import com.netcontrol.app.model.EngineStatus
import com.netcontrol.app.model.FlowSnapshot
import com.netcontrol.app.model.NetworkEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Process-level state shared by the VPN service and the Compose UI. */
object EngineRuntime {
    private val mutableStatus = MutableStateFlow(EngineStatus())
    val status = mutableStatus.asStateFlow()

    private val mutableStats = MutableStateFlow(EngineStats())
    val stats = mutableStats.asStateFlow()

    private val mutableFlows = MutableStateFlow<List<FlowSnapshot>>(emptyList())
    val flows = mutableFlows.asStateFlow()

    private val mutableNetworkEvents = MutableStateFlow<List<NetworkEvent>>(emptyList())
    val networkEvents = mutableNetworkEvents.asStateFlow()

    fun update(phase: EnginePhase, detail: String) {
        mutableStatus.value = EngineStatus(
            phase = phase,
            detail = detail,
            sinceMs = if (phase == EnginePhase.STOPPED) null else System.currentTimeMillis(),
        )
    }

    @Synchronized fun resetSession() {
        nativeErrors = 0L
        proxyErrors = 0L
        transportErrors = 0L
        mutableStats.value = EngineStats()
        mutableFlows.value = emptyList()
        mutableNetworkEvents.value = emptyList()
        pendingFlowBytes.clear()
        lastFlowPublishAtMs = 0L
        nextNetworkEventId = 1L
    }

    /** Native packet-parser output is cumulative for the current process/session. */
    @Synchronized fun updateNativeSnapshot(values: LongArray) {
        if (values.size < 7) {
            recordTransportError()
            return
        }
        nativeErrors = values[6].coerceAtLeast(0L)
        mutableStats.value = mutableStats.value.copy(
            packetsProcessed = values[0].coerceAtLeast(0L),
            malformedPackets = values[1].coerceAtLeast(0L),
            nativeFlows = values[4].coerceIn(0L, Int.MAX_VALUE.toLong()).toInt(),
            evictions = values[5].coerceAtLeast(0L),
            errors = nativeErrors + proxyErrors + transportErrors,
        )
    }

    @Synchronized fun updateProxyStats(
        activeFlows: Int,
        bytesUploaded: Long,
        bytesDownloaded: Long,
        blockedFlows: Long,
        errors: Long,
    ) {
        applyPendingFlowByteUpdatesLocked(System.currentTimeMillis())
        proxyErrors = errors.coerceAtLeast(0L)
        mutableStats.value = mutableStats.value.copy(
            activeFlows = activeFlows.coerceAtLeast(0),
            bytesUploaded = bytesUploaded.coerceAtLeast(0L),
            bytesDownloaded = bytesDownloaded.coerceAtLeast(0L),
            blockedFlows = blockedFlows.coerceAtLeast(0L),
            errors = nativeErrors + proxyErrors + transportErrors,
        )
    }

    @Synchronized fun recordTransportError() {
        transportErrors += 1L
        mutableStats.value = mutableStats.value.copy(errors = nativeErrors + proxyErrors + transportErrors)
    }

    @Synchronized fun flowCreated(flow: FlowSnapshot) {
        val current = mutableFlows.value.filterNot { it.id == flow.id }
        mutableFlows.value = (current + flow).takeLast(MAX_FLOW_HISTORY)
    }

    @Synchronized fun flowBytes(id: Long, uploaded: Long, downloaded: Long) {
        if (uploaded <= 0L && downloaded <= 0L) return
        val pending = pendingFlowBytes.getOrPut(id) { LongArray(2) }
        pending[0] += uploaded.coerceAtLeast(0L)
        pending[1] += downloaded.coerceAtLeast(0L)
        val now = System.currentTimeMillis()
        if (now - lastFlowPublishAtMs >= FLOW_PUBLISH_INTERVAL_MS) applyPendingFlowByteUpdatesLocked(now)
    }

    @Synchronized fun flowEnded(id: Long, state: String) {
        applyPendingFlowByteUpdatesLocked(System.currentTimeMillis(), onlyFlowId = id)
        mutableFlows.value = mutableFlows.value.map { flow ->
            if (flow.id == id) flow.copy(active = false, state = state) else flow
        }
    }

    /** Converts native observer records into a bounded live UI model; no per-counter DB writes. */
    @Synchronized fun appendNativeEvents(encodedEvents: Array<String>) {
        if (encodedEvents.isEmpty()) return
        val parsed = ArrayList<NetworkEvent>(encodedEvents.size)
        for (encoded in encodedEvents) {
            val fields = encoded.split('\u001f')
            if (fields.size != 17) continue
            val type = fields[0]
            val timestamp = fields[1].toLongOrNull() ?: continue
            val flowIdValue = fields[2].toLongOrNull() ?: 0L
            val ipVersion = fields[3].toIntOrNull() ?: continue
            val protocol = fields[4]
            val sourcePort = fields[6].toIntOrNull()
            val destinationPort = fields[8].toIntOrNull()
            parsed += NetworkEvent(
                id = nextNetworkEventId++,
                timestampMs = timestamp,
                type = type,
                flowId = flowIdValue.takeIf { it > 0L },
                ipVersion = ipVersion,
                protocol = protocol,
                sourceAddress = fields[5].takeIf { it.isNotBlank() },
                sourcePort = sourcePort,
                destinationAddress = fields[7].takeIf { it.isNotBlank() },
                destinationPort = destinationPort,
                hostname = fields[9].takeIf { it.isNotBlank() },
                alpn = fields[10].takeIf { it.isNotBlank() },
                status = fields[11],
                source = fields[12],
                dnsType = fields[13].toIntOrNull(),
                dnsResponseCode = fields[14].toIntOrNull(),
                dnsTransactionId = fields[15].toIntOrNull(),
                dnsResponse = fields[16].toIntOrNull()?.let { it != 0 },
            )
        }
        if (parsed.isNotEmpty()) mutableNetworkEvents.value = (mutableNetworkEvents.value + parsed).takeLast(MAX_NETWORK_EVENT_HISTORY)
    }

    private fun applyPendingFlowByteUpdatesLocked(nowMs: Long, onlyFlowId: Long? = null) {
        if (pendingFlowBytes.isEmpty()) return
        val deltas = if (onlyFlowId == null) pendingFlowBytes.toMap() else pendingFlowBytes.filterKeys { it == onlyFlowId }
        if (deltas.isEmpty()) return
        deltas.keys.forEach(pendingFlowBytes::remove)
        mutableFlows.value = mutableFlows.value.map { flow ->
            val delta = deltas[flow.id]
            if (delta == null) flow else flow.copy(
                bytesUploaded = flow.bytesUploaded + delta[0],
                bytesDownloaded = flow.bytesDownloaded + delta[1],
            )
        }
        lastFlowPublishAtMs = nowMs
    }

    private val pendingFlowBytes = HashMap<Long, LongArray>()
    private var lastFlowPublishAtMs = 0L
    private var nextNetworkEventId = 1L
    private var nativeErrors: Long = 0L
    private var proxyErrors: Long = 0L
    private var transportErrors: Long = 0L
    private const val MAX_FLOW_HISTORY = 200
    private const val MAX_NETWORK_EVENT_HISTORY = 200
    private const val FLOW_PUBLISH_INTERVAL_MS = 250L
}
