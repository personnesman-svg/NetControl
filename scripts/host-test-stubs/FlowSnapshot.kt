package com.netcontrol.app.model

data class FlowSnapshot(
    val id: Long,
    val protocol: String,
    val destination: String,
    val port: Int,
    val domain: String?,
    val action: String,
    val matchedRuleId: Long?,
    val startedAtMs: Long,
    val bytesUploaded: Long = 0L,
    val bytesDownloaded: Long = 0L,
    val active: Boolean = true,
    val state: String = "ACTIVE",
    val explanation: String = "",
)
