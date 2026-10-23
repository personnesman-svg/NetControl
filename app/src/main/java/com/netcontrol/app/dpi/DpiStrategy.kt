package com.netcontrol.app.dpi

/** Stream-level extension contracts. The current app does not attach these to a live packet stream. */
interface DpiStrategy {
    val id: String
    fun inspect(input: DpiInput): DpiResult
}

data class DpiProfile(val id: String, val name: String, val enabledStrategyIds: Set<String>)
data class DpiCapabilities(
    val dnsParsing: Boolean,
    val tlsClientHelloParsing: Boolean,
    val streamMutation: Boolean,
    val udp443Handling: Boolean,
    val rawPacketControl: Boolean,
)
data class DpiInput(val protocol: String, val bytes: ByteArray, val source: String)
data class DpiResult(val strategyId: String, val status: Status, val detail: String, val domain: String? = null) {
    enum class Status { MATCH, NO_MATCH, NEED_MORE_DATA, UNAVAILABLE, MALFORMED }
}

object MetadataOnlyStrategy : DpiStrategy {
    override val id: String = "metadata-only"
    override fun inspect(input: DpiInput): DpiResult = DpiResult(
        strategyId = id,
        status = DpiResult.Status.UNAVAILABLE,
        detail = "No live stream source is connected in this build",
    )
}
