package com.netcontrol.app.model

enum class EnginePhase { STOPPED, STARTING, RUNNING, DEGRADED, STOPPING }

data class EngineStatus(
    val phase: EnginePhase = EnginePhase.STOPPED,
    val detail: String = "Capture is stopped",
    val sinceMs: Long? = null,
) {
    val isActive: Boolean get() = phase == EnginePhase.RUNNING || phase == EnginePhase.DEGRADED
}

enum class CapabilityStatus(val label: String) {
    CONNECTED("Connected in code"),
    PARTIAL("Partial"),
    BACKEND_LIMITED("Backend limited"),
    NOT_IMPLEMENTED("Not implemented"),
    DEVICE_TEST_REQUIRED("Device test required"),
}

data class Capability(
    val key: String,
    /** True means a code path exists, not that real-device end-to-end behavior was verified. */
    val available: Boolean,
    val detail: String,
    val status: CapabilityStatus = if (available) CapabilityStatus.CONNECTED else CapabilityStatus.NOT_IMPLEMENTED,
)

data class NetworkSnapshot(
    val transport: String = "Unknown",
    val wifiEnabled: Boolean? = null,
    val connected: Boolean = false,
    val validatedInternet: Boolean = false,
    val interfaceName: String = "Unknown",
    val addresses: List<String> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val routes: List<String> = emptyList(),
    val interfaces: List<String> = emptyList(),
    val updatedAtMs: Long = System.currentTimeMillis(),
)

data class EngineStats(
    val packetsProcessed: Long = 0,
    val malformedPackets: Long = 0,
    val activeFlows: Int = 0,
    val evictions: Long = 0,
    val bufferBytes: Int = 0,
    val errors: Long = 0,
    val bytesUploaded: Long = 0,
    val bytesDownloaded: Long = 0,
    val blockedFlows: Long = 0,
    val nativeFlows: Int = 0,
)

data class FlowSnapshot(
    val id: Long,
    val protocol: String,
    val destination: String,
    val port: Int,
    val domain: String?,
    val action: String,
    val matchedRuleId: Long?,
    val startedAtMs: Long,
    val bytesUploaded: Long = 0,
    val bytesDownloaded: Long = 0,
    val active: Boolean = true,
    val state: String = "ACTIVE",
    val explanation: String = "",
)


/**
 * A packet-boundary observation from the native IP parser. flowId is the native TCP/TUN stream
 * identifier and is deliberately not the LocalSocks5Proxy flow id; the two layers cannot be
 * safely merged without a shared connection-identity contract.
 */
data class NetworkEvent(
    val id: Long,
    val timestampMs: Long,
    val type: String,
    val flowId: Long?,
    val ipVersion: Int,
    val protocol: String,
    val sourceAddress: String?,
    val sourcePort: Int?,
    val destinationAddress: String?,
    val destinationPort: Int?,
    val hostname: String?,
    val alpn: String?,
    val status: String,
    val source: String,
    val dnsType: Int?,
    val dnsResponseCode: Int?,
    val dnsTransactionId: Int?,
    val dnsResponse: Boolean?,
)
