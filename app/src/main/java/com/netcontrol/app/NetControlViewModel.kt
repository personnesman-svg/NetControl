package com.netcontrol.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.netcontrol.app.data.DiagnosticEventEntity
import com.netcontrol.app.data.NetControlDatabase
import com.netcontrol.app.data.RuleEntity
import com.netcontrol.app.model.Capability
import com.netcontrol.app.model.CapabilityStatus
import com.netcontrol.app.network.NativeEngine
import com.netcontrol.app.root.RootCapabilityProbe
import com.netcontrol.app.network.NetworkRepository
import com.netcontrol.app.service.EngineRuntime
import com.netcontrol.app.service.NetworkVpnService
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class NetControlViewModel(application: Application) : AndroidViewModel(application) {
    private val database = NetControlDatabase.get(application)
    private val networkRepository = NetworkRepository(application)

    val network = networkRepository.snapshot
    val rules: StateFlow<List<RuleEntity>> = database.ruleDao().observeRules()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val events: StateFlow<List<DiagnosticEventEntity>> = database.eventDao().observeLatest()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val engineStatus = EngineRuntime.status
    val rootReport by lazy { RootCapabilityProbe.inspect() }

    val stats = EngineRuntime.stats
    val flows = EngineRuntime.flows
    val networkEvents = EngineRuntime.networkEvents

    val capabilities: List<Capability>
        get() = listOf(
            Capability(
                "Android VPN / TUN", true,
                "VpnService establishes IPv4/IPv6 routes after user consent. End-to-end Internet reachability has not been verified on a device.",
                CapabilityStatus.DEVICE_TEST_REQUIRED,
            ),
            Capability(
                "TCP policy proxy", true,
                "Local SOCKS5 CONNECT proxy applies protocol, IP, port and available domain rules. UID-based rules cannot currently match.",
                CapabilityStatus.PARTIAL,
            ),
            Capability(
                "UDP policy proxy", true,
                "Local SOCKS5 UDP relay applies protocol, IP, port and available domain rules. DoH/DoT are not decoded.",
                CapabilityStatus.PARTIAL,
            ),
            Capability(
                "Raw PCAP capture", true,
                "Classic PCAP DLT_RAW records are captured from both directions at the Android TUN boundary, up to 64 MiB per session. These are not physical-interface wire packets.",
                CapabilityStatus.DEVICE_TEST_REQUIRED,
            ),
            Capability(
                "Native packet counters", NativeEngine.available,
                if (NativeEngine.available) "JNI native parser accepts actual packets mirrored at the TUN boundary while VPN is active." else "JNI library failed to load; packet observation is unavailable.",
                if (NativeEngine.available) CapabilityStatus.DEVICE_TEST_REQUIRED else CapabilityStatus.NOT_IMPLEMENTED,
            ),
            Capability(
                "Plain DNS events", NativeEngine.available,
                "Complete, non-fragmented plaintext UDP/53 messages and TCP/53 framed messages can be observed at TUN. Encrypted DNS and hidden domains are not decoded.",
                if (NativeEngine.available) CapabilityStatus.PARTIAL else CapabilityStatus.NOT_IMPLEMENTED,
            ),
            Capability(
                "TLS ClientHello / SNI", NativeEngine.available,
                "Bounded, sequence-aware TCP reassembly emits SNI/ALPN only after a complete valid ClientHello. ECH, QUIC, non-ClientHello traffic and missing SNI remain unknown; HTTPS is not decrypted.",
                if (NativeEngine.available) CapabilityStatus.PARTIAL else CapabilityStatus.NOT_IMPLEMENTED,
            ),
            Capability(
                "App UID attribution", false,
                "The SOCKS5/TUN mapping does not provide a reliable originating Android UID. UID-specific rules cannot be enforced.",
                CapabilityStatus.BACKEND_LIMITED,
            ),
            Capability(
                "Per-app routing", false,
                "Per-app allow/disallow lists and split-routing configuration are not implemented in VpnService.Builder.",
                CapabilityStatus.NOT_IMPLEMENTED,
            ),
            Capability(
                "Root backend", false,
                "An extension point only; no su process or root-level interception is implemented.",
                CapabilityStatus.NOT_IMPLEMENTED,
            ),
            Capability(
                "QUIC inspection / HTTPS decryption", false,
                "QUIC payload analysis and TLS interception are not implemented. Encrypted content is not accessed.",
                CapabilityStatus.NOT_IMPLEMENTED,
            ),
        )

    fun startVpn() = NetworkVpnService.start(getApplication())
    fun stopVpn() = NetworkVpnService.stop(getApplication())

    // Compatibility aliases for UI code from the previous diagnostic-TUN iteration.
    fun startDiagnosticTun() = startVpn()
    fun stopDiagnosticTun() = stopVpn()

    fun consentDeclined() {
        EngineRuntime.update(com.netcontrol.app.model.EnginePhase.STOPPED, "VPN consent declined; VPN was not started")
        viewModelScope.launch { logEvent("vpn", "VPN consent declined") }
    }

    fun saveRule(rule: RuleEntity) {
        viewModelScope.launch {
            if (rule.id == 0L) database.ruleDao().insert(rule) else database.ruleDao().update(rule)
            logEvent("rule", "Saved rule '${rule.name}' (${rule.action}); TCP/UDP policy is applied when the local VPN is running. UID attribution is not currently available.")
        }
    }

    fun deleteRule(rule: RuleEntity) {
        viewModelScope.launch {
            database.ruleDao().delete(rule)
            logEvent("rule", "Deleted rule '${rule.name}'")
        }
    }

    fun setRuleEnabled(rule: RuleEntity, enabled: Boolean) {
        viewModelScope.launch { database.ruleDao().update(rule.copy(enabled = enabled)) }
    }

    fun clearDiagnosticEvents() {
        viewModelScope.launch { database.eventDao().clear() }
    }

    private suspend fun logEvent(type: String, detail: String) {
        database.eventDao().insert(DiagnosticEventEntity(type = type, detail = detail))
        database.eventDao().trimToLimit()
    }

    override fun onCleared() {
        networkRepository.close()
        super.onCleared()
    }
}
