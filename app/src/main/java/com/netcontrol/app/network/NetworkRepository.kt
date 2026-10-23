package com.netcontrol.app.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import com.netcontrol.app.model.NetworkSnapshot
import java.net.NetworkInterface
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class NetworkRepository(context: Context) : AutoCloseable {
    private val appContext = context.applicationContext
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
    private val wifiManager = appContext.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val mutableSnapshot = MutableStateFlow(readSnapshot())
    val snapshot: StateFlow<NetworkSnapshot> = mutableSnapshot.asStateFlow()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = publish()
        override fun onLost(network: Network) = publish()
        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) = publish()
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = publish()
    }

    init {
        try {
            connectivity.registerDefaultNetworkCallback(callback)
        } catch (_: RuntimeException) {
            // The initial snapshot still works on platforms where callbacks cannot be registered.
        }
        publish()
    }

    private fun publish() {
        mutableSnapshot.value = readSnapshot()
    }

    @Suppress("DEPRECATION")
    private fun readSnapshot(): NetworkSnapshot {
        val network = connectivity.activeNetwork
        val caps = if (network != null) connectivity.getNetworkCapabilities(network) else null
        val link = if (network != null) connectivity.getLinkProperties(network) else null
        val transport = when {
            caps == null -> "Unavailable"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "Bluetooth"
            else -> "Other"
        }
        val interfaces = runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp }
                .take(16)
                .map { networkInterface ->
                    val ips = networkInterface.interfaceAddresses.take(4).mapNotNull { it.address?.hostAddress }
                    "${networkInterface.name}: ${ips.joinToString().ifBlank { "no address" }}"
                }
        }.getOrDefault(emptyList())
        // WifiInfo is intentionally not used for SSID/BSSID: those fields have location/permission and
        // OEM restrictions. Transport and IP data come from public network APIs without those grants.
        return NetworkSnapshot(
            transport = transport,
            wifiEnabled = runCatching { wifiManager?.isWifiEnabled }.getOrNull(),
            connected = network != null && caps != null,
            validatedInternet = caps?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true,
            interfaceName = link?.interfaceName ?: "Unknown",
            addresses = link?.linkAddresses?.take(12)?.map { it.toString() }.orEmpty(),
            dnsServers = link?.dnsServers?.take(6)?.mapNotNull { it.hostAddress }.orEmpty(),
            routes = link?.routes?.take(16)?.map { route ->
                val gateway = route.gateway?.hostAddress ?: "direct"
                "${route.destination} via $gateway"
            }.orEmpty(),
            interfaces = interfaces,
            updatedAtMs = System.currentTimeMillis(),
        )
    }

    override fun close() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }
}
