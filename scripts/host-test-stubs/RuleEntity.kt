package com.netcontrol.app.data

data class RuleEntity(
    val id: Long = 0L,
    val priority: Int = 100,
    val name: String = "",
    val enabled: Boolean = true,
    val action: String = "OBSERVE",
    val protocol: String = "ANY",
    val destinationIp: String = "",
    val port: Int? = null,
    val uid: Int? = null,
    val domain: String = "",
)
