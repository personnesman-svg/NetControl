package com.netcontrol.app.network

import com.netcontrol.app.data.RuleEntity
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Locale

enum class RuleAction { ALLOW, BLOCK, OBSERVE }

data class FlowFacts(
    val protocol: String,
    val destinationIp: String,
    val destinationPort: Int?,
    val uid: Int?,
    val domain: String?,
)

data class RuleDecision(val action: RuleAction, val matchedRuleId: Long?, val explanation: String)

/** Deterministic pure matcher. The VPN data plane must apply BLOCK decisions before forwarding. */
object RuleEngine {
    fun evaluate(rules: List<RuleEntity>, flow: FlowFacts): RuleDecision {
        val match = rules.asSequence()
            .filter { it.enabled }
            .sortedWith(compareBy<RuleEntity> { it.priority }.thenBy { it.id })
            .firstOrNull { rule ->
                (rule.protocol == "ANY" || rule.protocol.equals(flow.protocol, ignoreCase = true)) &&
                    (rule.destinationIp.isBlank() || ipMatches(rule.destinationIp, flow.destinationIp)) &&
                    (rule.port == null || rule.port == flow.destinationPort) &&
                    (rule.uid == null || rule.uid == flow.uid) &&
                    (rule.domain.isBlank() || domainMatches(rule.domain, flow.domain))
            }
        val action = match?.action?.let { runCatching { RuleAction.valueOf(it) }.getOrNull() } ?: RuleAction.OBSERVE
        return RuleDecision(
            action = action,
            matchedRuleId = match?.id,
            explanation = if (match == null) "No matching rule; default Observe" else "Matched rule ${match.name}",
        )
    }

    private fun domainMatches(ruleDomain: String, flowDomain: String?): Boolean {
        if (flowDomain.isNullOrBlank()) return false
        val expected = ruleDomain.trim().trimEnd('.').lowercase(Locale.ROOT)
        val actual = flowDomain.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (expected.isBlank() || actual.isBlank()) return false
        return actual == expected || actual.endsWith(".$expected")
    }

    /** Compare IP literals by address bytes, so equivalent IPv6 spellings match. Never resolve names here. */
    private fun ipMatches(expectedValue: String, actualValue: String): Boolean {
        val expected = canonicalIp(expectedValue) ?: return false
        val actual = canonicalIp(actualValue) ?: return false
        return expected.contentEquals(actual)
    }

    private fun canonicalIp(raw: String): ByteArray? {
        val value = raw.trim().substringBefore('%')
        if (value.isEmpty()) return null
        return when {
            value.contains(':') -> {
                if (!value.matches(Regex("[0-9a-fA-F:.]+"))) return null
                runCatching { InetAddress.getByName(value) }
                    .getOrNull()?.takeIf { it is Inet6Address }?.address
            }
            value.contains('.') -> {
                val parts = value.split('.')
                if (parts.size != 4) return null
                val bytes = ByteArray(4)
                for (i in parts.indices) {
                    val octet = parts[i].toIntOrNull()?.takeIf { it in 0..255 } ?: return null
                    bytes[i] = octet.toByte()
                }
                bytes
            }
            else -> null
        }
    }
}
