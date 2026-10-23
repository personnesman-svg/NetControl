package com.netcontrol.app.root

/** Typed extension point only. No su process is started and no shell command is accepted. */
interface RootBackend {
    val isImplemented: Boolean

    suspend fun startCapture(): RootOperationResult
    suspend fun stopCapture(): RootOperationResult
    suspend fun applyRule(rule: ValidatedRootRule): RootOperationResult
}

class ValidatedRootRule private constructor(
    val destinationCidr: String?,
    val protocol: ProtocolFilter,
    val port: Int?,
    val block: Boolean,
) {
    companion object {
        /** Only literal IPv4/IPv6 CIDRs are accepted; hostnames and shell fragments are rejected. */
        fun create(destinationCidr: String?, protocol: ProtocolFilter, port: Int?, block: Boolean): ValidatedRootRule? {
            if (port != null && port !in 1..65535) return null
            if (destinationCidr != null && !isValidLiteralCidr(destinationCidr)) return null
            return ValidatedRootRule(destinationCidr, protocol, port, block)
        }

        private fun isValidLiteralCidr(value: String): Boolean {
            val pieces = value.split('/')
            if (pieces.size != 2 || pieces.any { it.isBlank() }) return false
            val prefix = pieces[1].toIntOrNull() ?: return false
            val host = pieces[0]
            if (host.contains(':')) {
                if (!host.matches(Regex("[0-9a-fA-F:]+")) || prefix !in 0..128) return false
                return runCatching { java.net.InetAddress.getByName(host) is java.net.Inet6Address }.getOrDefault(false)
            }
            val octets = host.split('.')
            if (octets.size != 4 || prefix !in 0..32) return false
            return octets.all { part ->
                val valuePart = part.toIntOrNull()
                part.isNotBlank() && valuePart != null && valuePart in 0..255
            }
        }
    }
}

enum class ProtocolFilter { ANY, TCP, UDP }

data class RootOperationResult(val successful: Boolean, val message: String)

object UnavailableRootBackend : RootBackend {
    override val isImplemented: Boolean = false
    override suspend fun startCapture() = unavailable()
    override suspend fun stopCapture() = unavailable()
    override suspend fun applyRule(rule: ValidatedRootRule) = unavailable()
    private fun unavailable() = RootOperationResult(false, "Root backend is not implemented")
}
