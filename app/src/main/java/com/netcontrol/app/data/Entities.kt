package com.netcontrol.app.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "firewall_rules", indices = [Index("priority"), Index("enabled")])
data class RuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val priority: Int = 100,
    val name: String,
    val action: String = "OBSERVE",
    val protocol: String = "ANY",
    val destinationIp: String = "",
    val port: Int? = null,
    val uid: Int? = null,
    val domain: String = "",
    val enabled: Boolean = true,
    val createdAtMs: Long = System.currentTimeMillis(),
)

@Entity(tableName = "diagnostic_events", indices = [Index("timestampMs")])
data class DiagnosticEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val type: String,
    val detail: String,
    val timestampMs: Long = System.currentTimeMillis(),
)
