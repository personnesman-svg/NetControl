package com.netcontrol.app

import android.Manifest
import android.app.Activity
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.netcontrol.app.capture.PacketCaptureStore
import com.netcontrol.app.data.DiagnosticEventEntity
import com.netcontrol.app.data.RuleEntity
import com.netcontrol.app.model.Capability
import com.netcontrol.app.model.EnginePhase
import com.netcontrol.app.model.EngineStatus
import com.netcontrol.app.model.EngineStats
import com.netcontrol.app.model.FlowSnapshot
import com.netcontrol.app.model.NetworkSnapshot
import com.netcontrol.app.model.NetworkEvent
import com.netcontrol.app.model.CapabilityStatus
import com.netcontrol.app.service.EngineRuntime
import com.netcontrol.app.service.NetworkVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Bg = Color(0xFF101312)
private val Surface = Color(0xFF171C19)
private val TextMain = Color(0xFFE3EAE6)
private val TextMuted = Color(0xFF9AA8A0)
private val Accent = Color(0xFF78D9BB)
private val Warning = Color(0xFFFFC078)

class MainActivity : ComponentActivity() {
    private val viewModel: NetControlViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Accent,
                    onPrimary = Bg,
                    background = Bg,
                    surface = Surface,
                    onSurface = TextMain,
                    onBackground = TextMain,
                    secondary = Accent,
                    outline = Color(0xFF354039),
                ),
            ) {
                NetControlScreen(viewModel)
            }
        }
    }
}

private enum class Screen(val title: String, val short: String) {
    FLOWS("Flows", "F"), DNS("DNS", "D"), RULES("Rules", "R"), DPI("DPI", "P"), NETWORK("Network", "N")
}

@Composable
private fun NetControlScreen(viewModel: NetControlViewModel) {
    val context = LocalContext.current
    var selectedScreen by remember { mutableStateOf(Screen.FLOWS) }
    val network by viewModel.network.collectAsState()
    val rules by viewModel.rules.collectAsState()
    val events by viewModel.events.collectAsState()
    val stats by viewModel.stats.collectAsState()
    val flows by viewModel.flows.collectAsState()
    val networkEvents by viewModel.networkEvents.collectAsState()
    val engineStatus by EngineRuntime.status.collectAsState()
    var editingRule by remember { mutableStateOf<RuleEntity?>(null) }
    var showRuleDialog by remember { mutableStateOf(false) }

    val vpnConsentLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) viewModel.startDiagnosticTun()
        else viewModel.consentDeclined()
    }
    val notificationPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        val intent = VpnService.prepare(context)
        if (intent != null) vpnConsentLauncher.launch(intent) else viewModel.startDiagnosticTun()
    }
    val createPcapLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")) { uri ->
        if (uri != null) {
            val outcome = runCatching {
                context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                    PacketCaptureStore.exportTo(context, output)
                } ?: error("Android did not provide an output stream")
            }
            Toast.makeText(
                context,
                outcome.fold(
                    onSuccess = { count -> "PCAP exported: $count packet(s)" },
                    onFailure = { failure -> "PCAP export failed: ${failure.message ?: failure.javaClass.simpleName}" },
                ),
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    fun startVpnPermissionFlow() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) vpnConsentLauncher.launch(prepareIntent) else viewModel.startDiagnosticTun()
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets.navigationBars,
        containerColor = Bg,
        bottomBar = {
            NavigationBar(containerColor = Bg, tonalElevation = 0.dp) {
                Screen.entries.forEach { screen ->
                    NavigationBarItem(
                        selected = selectedScreen == screen,
                        onClick = { selectedScreen = screen },
                        icon = {
                            Text(
                                screen.short,
                                fontWeight = if (selectedScreen == screen) FontWeight.Bold else FontWeight.Normal,
                                color = if (selectedScreen == screen) Accent else TextMuted,
                            )
                        },
                        label = { Text(screen.title, fontSize = 10.sp, maxLines = 1) },
                        alwaysShowLabel = true,
                    )
                }
            }
        },
    ) { innerPadding ->
        Column(Modifier.fillMaxSize().padding(innerPadding)) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("NetControl", fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = TextMain)
                    Text("Local network tools", fontSize = 12.sp, color = TextMuted)
                }
                PhaseLabel(engineStatus)
            }
            Divider(color = Color(0xFF2D3631), thickness = 1.dp)
            when (selectedScreen) {
                Screen.FLOWS -> FlowsPage(stats, flows)
                Screen.DNS -> DnsPage(events, networkEvents)
                Screen.RULES -> RulesPage(
                    rules = rules,
                    onAdd = { editingRule = null; showRuleDialog = true },
                    onEdit = { editingRule = it; showRuleDialog = true },
                    onToggle = viewModel::setRuleEnabled,
                    onDelete = viewModel::deleteRule,
                )
                Screen.DPI -> DpiPage(viewModel.capabilities, networkEvents, engineStatus, stats)
                Screen.NETWORK -> NetworkPage(
                    snapshot = network,
                    status = engineStatus,
                    capabilities = viewModel.capabilities,
                    events = events,
                    onStart = ::startVpnPermissionFlow,
                    onStop = viewModel::stopDiagnosticTun,
                    onExportPcap = { createPcapLauncher.launch("netcontrol-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.pcap") },
                    onClearEvents = viewModel::clearDiagnosticEvents,
                    rootDetail = viewModel.rootReport.detail + if (viewModel.rootReport.possibleIndicators.isEmpty()) "; no known indicators" else "; " + viewModel.rootReport.possibleIndicators.joinToString(),
                )
            }
        }
    }

    if (showRuleDialog) {
        RuleEditorDialog(
            initial = editingRule,
            onDismiss = { showRuleDialog = false },
            onSave = { rule -> viewModel.saveRule(rule); showRuleDialog = false },
        )
    }
}

@Composable
private fun PhaseLabel(status: EngineStatus) {
    val (label, color) = when (status.phase) {
        EnginePhase.STOPPED -> "Stopped" to TextMuted
        EnginePhase.STARTING -> "Starting" to Warning
        EnginePhase.RUNNING -> "VPN active" to Accent
        EnginePhase.DEGRADED -> "Degraded" to Warning
        EnginePhase.STOPPING -> "Stopping" to Warning
    }
    Text(label, color = color, fontSize = 12.sp, fontWeight = FontWeight.Medium)
}

@Composable
private fun PageTitle(title: String, subtitle: String? = null) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(title, fontSize = 21.sp, fontWeight = FontWeight.SemiBold, color = TextMain)
        if (subtitle != null) Text(subtitle, fontSize = 12.sp, color = TextMuted)
    }
}

@Composable
private fun FlowsPage(stats: com.netcontrol.app.model.EngineStats, flows: List<FlowSnapshot>) {
    var search by remember { mutableStateOf("") }
    val filtered = remember(flows, search) {
        val needle = search.trim().lowercase(Locale.ROOT)
        if (needle.isEmpty()) flows.asReversed() else flows.asReversed().filter { flow ->
            listOfNotNull(
                flow.destination, flow.domain, flow.protocol, flow.port.toString(),
                flow.action, flow.state, flow.explanation, flow.matchedRuleId?.toString(),
            ).any { it.lowercase(Locale.ROOT).contains(needle) }
        }
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { PageTitle("Flows", "Local proxy connection history · newest first") }
        item {
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Filter domain, IP, port or action") },
            )
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                Metric("Packets", stats.packetsProcessed.toString())
                Metric("Active", stats.activeFlows.toString())
                Metric("Blocked", stats.blockedFlows.toString())
            }
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                Metric("Upload", formatBytes(stats.bytesUploaded))
                Metric("Download", formatBytes(stats.bytesDownloaded))
                Metric("Errors", stats.errors.toString())
            }
        }
        item { Divider(color = Color(0xFF2D3631)) }
        if (filtered.isEmpty()) {
            item {
                Notice(
                    title = if (flows.isEmpty()) "No flows observed yet" else "No matching flows",
                    body = if (flows.isEmpty()) "Start VPN on the Network tab, then open an app or website to generate traffic. No sample flows are inserted." else "Try a different domain, IP address, port or action filter.",
                )
            }
        } else {
            items(filtered, key = { it.id }) { flow ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "${flow.protocol}  ${flow.domain ?: flow.destination}:${flow.port}",
                            modifier = Modifier.weight(1f),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium,
                            color = TextMain,
                        )
                        Text(flow.action, color = if (flow.action == "BLOCK") Warning else Accent, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                    }
                    Text(
                        "${flow.state} · ${SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(flow.startedAtMs))}" +
                            (flow.matchedRuleId?.let { " · rule #$it" } ?: ""),
                        color = TextMuted,
                        fontSize = 11.sp,
                    )
                    Text("↑ ${formatBytes(flow.bytesUploaded)}   ↓ ${formatBytes(flow.bytesDownloaded)}", color = TextMuted, fontSize = 11.sp)
                    if (flow.explanation.isNotBlank()) Text(flow.explanation, color = TextMuted, fontSize = 11.sp)
                    Divider(color = Color(0xFF252D28))
                }
            }
        }
    }
}

@Composable
private fun DnsPage(
    events: List<DiagnosticEventEntity>,
    liveEvents: List<NetworkEvent>,
) {
    var query by remember { mutableStateOf("") }
    val needle = query.trim().lowercase(Locale.ROOT)
    val dnsEvents = remember(events, needle) {
        events.asReversed().filter { it.type.equals("dns", ignoreCase = true) }
            .filter { needle.isEmpty() || it.detail.lowercase(Locale.ROOT).contains(needle) }
    }
    val liveDnsEvents = remember(liveEvents, needle) {
        liveEvents.asReversed().filter { it.type.startsWith("DNS") }
            .filter { event ->
                needle.isEmpty() || listOfNotNull(
                    event.hostname, event.sourceAddress, event.destinationAddress,
                    event.status, event.source, event.dnsType?.toString(),
                ).any { it.lowercase(Locale.ROOT).contains(needle) }
            }
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { PageTitle("DNS", "Live packets from TUN plus persistent proxy diagnostics") }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Search hostname, endpoint, type or status") },
            )
        }
        item { Text("Live TUN observations · ${liveDnsEvents.size}", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        if (liveDnsEvents.isEmpty()) {
            item {
                Notice(
                    title = "No matching live DNS packets",
                    body = "Live events require the native parser to be loaded and VPN traffic to cross the TUN. Only complete, non-fragmented plaintext UDP/53 and framed TCP/53 messages are decoded; DoH/DoT remain opaque.",
                )
            }
        } else {
            items(liveDnsEvents.take(200), key = { "live-dns-${it.id}" }) { event ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        "${SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(event.timestampMs))} · ${event.status}",
                        color = Accent, fontSize = 10.sp,
                    )
                    Text(event.hostname ?: "DNS message without a decoded question name", color = TextMain, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    Text(
                        "${event.protocol} IPv${event.ipVersion} · ${event.sourceAddress ?: "?"}:${event.sourcePort ?: 0} → ${event.destinationAddress ?: "?"}:${event.destinationPort ?: 0}",
                        color = TextMuted, fontSize = 11.sp,
                    )
                    val queryDirection = if (event.type == "DNS") {
                        when (event.dnsResponse) {
                            true -> " · response"
                            false -> " · query"
                            null -> " · direction unknown"
                        }
                    } else ""
                    Text(
                        "source=${event.source} · type=${event.dnsType ?: "?"} · id=${event.dnsTransactionId ?: "?"}$queryDirection",
                        color = TextMuted, fontSize = 10.sp,
                    )
                    Divider(color = Color(0xFF252D28))
                }
            }
        }
        item { Text("Persistent proxy diagnostics · ${dnsEvents.size}", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        if (dnsEvents.isEmpty()) {
            item { Text("No stored SOCKS DNS diagnostic events matching this search.", color = TextMuted, fontSize = 12.sp) }
        } else {
            items(dnsEvents.take(100), key = { "db-dns-${it.id}" }) { event ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(event.timestampMs)), color = Accent, fontSize = 10.sp)
                    Text(event.detail, color = TextMain, fontSize = 12.sp)
                    Divider(color = Color(0xFF252D28))
                }
            }
        }
    }
}

private fun formatBytes(value: Long): String {
    if (value < 1024L) return "$value B"
    if (value < 1024L * 1024L) return "%.1f KiB".format(Locale.ROOT, value / 1024.0)
    if (value < 1024L * 1024L * 1024L) return "%.1f MiB".format(Locale.ROOT, value / (1024.0 * 1024.0))
    return "%.1f GiB".format(Locale.ROOT, value / (1024.0 * 1024.0 * 1024.0))
}

@Composable
private fun RulesPage(
    rules: List<RuleEntity>,
    onAdd: () -> Unit,
    onEdit: (RuleEntity) -> Unit,
    onToggle: (RuleEntity, Boolean) -> Unit,
    onDelete: (RuleEntity) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) { PageTitle("Rules", "Local ordered rule set") }
                Button(onClick = onAdd, contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp)) { Text("Add rule") }
            }
        }
        item { Text("Order: priority ascending, then ID ascending. Lower priority values are evaluated first; new rules default to 100.", color = TextMuted, fontSize = 11.sp) }
        item {
            Notice(
                title = "Policy scope",
                body = "Rules apply to connections observed by NetControl's local TCP/UDP proxy while VPN is active. App UID rules cannot match yet because the proxy does not expose the originating Android UID. Unmatched connections default to OBSERVE.",
            )
        }
        if (rules.isEmpty()) {
            item { Text("No rules configured.", color = TextMuted, fontSize = 13.sp) }
        } else {
            items(rules, key = { it.id }) { rule ->
                Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(rule.name, fontWeight = FontWeight.Medium, color = TextMain)
                            Text(
                                buildString {
                                    append("${rule.action} · ${rule.protocol}")
                                    if (rule.destinationIp.isNotBlank()) append(" · ${rule.destinationIp}")
                                    if (rule.port != null) append(":${rule.port}")
                                    if (rule.uid != null) append(" · UID ${rule.uid}")
                                    if (rule.domain.isNotBlank()) append(" · ${rule.domain}")
                                },
                                fontSize = 11.sp,
                                color = TextMuted,
                            )
                        }
                        Switch(checked = rule.enabled, onCheckedChange = { onToggle(rule, it) })
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(onClick = { onEdit(rule) }) { Text("Edit") }
                        TextButton(onClick = { onDelete(rule) }) { Text("Delete", color = Warning) }
                    }
                    Divider(color = Color(0xFF2D3631))
                }
            }
        }
    }
}

@Composable
private fun RuleEditorDialog(initial: RuleEntity?, onDismiss: () -> Unit, onSave: (RuleEntity) -> Unit) {
    var name by remember(initial?.id) { mutableStateOf(initial?.name.orEmpty()) }
    var destinationIp by remember(initial?.id) { mutableStateOf(initial?.destinationIp.orEmpty()) }
    var port by remember(initial?.id) { mutableStateOf(initial?.port?.toString().orEmpty()) }
    var uid by remember(initial?.id) { mutableStateOf(initial?.uid?.toString().orEmpty()) }
    var domain by remember(initial?.id) { mutableStateOf(initial?.domain.orEmpty()) }
    var protocol by remember(initial?.id) { mutableStateOf(initial?.protocol ?: "ANY") }
    var action by remember(initial?.id) { mutableStateOf(initial?.action ?: "OBSERVE") }
    var enabled by remember(initial?.id) { mutableStateOf(initial?.enabled ?: true) }
    var error by remember(initial?.id) { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Surface,
        title = { Text(if (initial == null) "Add rule" else "Edit rule") },
        text = {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                item {
                    OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
                item { Text("Action", color = TextMuted, fontSize = 12.sp) }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        listOf("ALLOW", "BLOCK", "OBSERVE").forEach { option ->
                            FilterChip(selected = action == option, onClick = { action = option }, label = { Text(option.lowercase().replaceFirstChar(Char::uppercase)) })
                        }
                    }
                }
                item { Text("Protocol", color = TextMuted, fontSize = 12.sp) }
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        listOf("ANY", "TCP", "UDP").forEach { option ->
                            FilterChip(selected = protocol == option, onClick = { protocol = option }, label = { Text(option) })
                        }
                    }
                }
                item { OutlinedTextField(value = destinationIp, onValueChange = { destinationIp = it }, label = { Text("Destination IP (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth()) }
                item { OutlinedTextField(value = port, onValueChange = { port = it.filter(Char::isDigit).take(5) }, label = { Text("Port 1–65535 (optional)") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), singleLine = true, modifier = Modifier.fillMaxWidth()) }
                item { OutlinedTextField(value = uid, onValueChange = { uid = it.filter(Char::isDigit).take(10) }, label = { Text("UID (optional)") }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), singleLine = true, modifier = Modifier.fillMaxWidth()) }
                item { OutlinedTextField(value = domain, onValueChange = { domain = it.trim().take(253) }, label = { Text("Confirmed domain (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth()) }
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = enabled, onCheckedChange = { enabled = it })
                        Text("Enabled", color = TextMain)
                    }
                }
                if (error != null) item { Text(error!!, color = Warning, fontSize = 12.sp) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val normalizedName = name.trim()
                val parsedPort = port.toIntOrNull()
                val parsedUid = uid.toIntOrNull()
                error = when {
                    normalizedName.isBlank() -> "Name is required"
                    port.isNotBlank() && (parsedPort == null || parsedPort !in 1..65535) -> "Port must be between 1 and 65535"
                    uid.isNotBlank() && parsedUid == null -> "UID is invalid"
                    uid.isNotBlank() -> "UID filtering is not supported yet; clear UID to avoid a rule that cannot be enforced"
                    destinationIp.isNotBlank() && !isValidIpLiteral(destinationIp.trim()) -> "Destination must be an IP literal (not a hostname)"
                    else -> null
                }
                if (error == null) onSave(
                    RuleEntity(
                        id = initial?.id ?: 0L,
                        priority = initial?.priority ?: 100,
                        name = normalizedName,
                        action = action,
                        protocol = protocol,
                        destinationIp = destinationIp.trim(),
                        port = parsedPort,
                        uid = parsedUid,
                        domain = domain.trim().lowercase(Locale.ROOT),
                        enabled = enabled,
                        createdAtMs = initial?.createdAtMs ?: System.currentTimeMillis(),
                    ),
                )
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun isValidIpLiteral(value: String): Boolean {
    if (value.contains(":") && value.matches(Regex("[0-9a-fA-F:.%]+"))) return runCatching { java.net.InetAddress.getByName(value) is java.net.Inet6Address }.getOrDefault(false)
    val parts = value.split('.')
    return parts.size == 4 && parts.all { part ->
        val octet = part.toIntOrNull()
        part.isNotBlank() && octet != null && octet in 0..255
    }
}

@Composable
private fun DpiPage(
    capabilities: List<Capability>,
    events: List<NetworkEvent>,
    engineStatus: EngineStatus,
    stats: EngineStats,
) {
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("ALL") }
    val nativeAvailable = capabilities.firstOrNull { it.key == "Native packet counters" }?.available == true
    val parserStatus = when {
        !nativeAvailable -> "JNI unavailable"
        !engineStatus.isActive -> "VPN stopped"
        stats.packetsProcessed > 0L -> "Observing packets"
        else -> "Waiting for packets"
    }
    fun eventStatus(prefix: String): String = when {
        !nativeAvailable -> "JNI unavailable"
        !engineStatus.isActive -> "VPN stopped"
        events.any { it.type.startsWith(prefix) } -> "Events observed"
        stats.packetsProcessed > 0L -> "No matching event yet"
        else -> "Waiting for packets"
    }
    val filteredEvents = remember(events, query, filter) {
        val needle = query.trim().lowercase(Locale.ROOT)
        events.asReversed().filter { event ->
            (filter == "ALL" || (filter == "TLS" && event.type.startsWith("TLS")) || (filter == "DNS" && event.type.startsWith("DNS"))) &&
                (needle.isEmpty() || listOfNotNull(
                    event.hostname, event.alpn, event.sourceAddress, event.destinationAddress,
                    event.protocol, event.source, event.status, event.flowId?.toString(),
                ).any { it.lowercase(Locale.ROOT).contains(needle) })
        }
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { PageTitle("Inspection", "Live native TUN observations · bounded history") }
        item {
            StatusRow(
                "Raw IP parser",
                "Native parser receives the packets mirrored at the TUN boundary; a loaded JNI library alone does not prove traffic is flowing.",
                parserStatus,
                if (parserStatus == "Observing packets") Accent else Warning,
            )
            Divider(color = Color(0xFF2D3631))
            val dnsStatus = eventStatus("DNS")
            StatusRow(
                "DNS/UDP and DNS/TCP",
                "Only complete plaintext UDP/53 messages and length-framed TCP/53 messages can be decoded. DoH/DoT are not decoded.",
                dnsStatus,
                if (dnsStatus == "Events observed") Accent else Warning,
            )
            Divider(color = Color(0xFF2D3631))
            val tlsStatus = eventStatus("TLS")
            StatusRow(
                "TLS ClientHello / SNI",
                "Sequence-aware bounded TCP reassembly inspects client-to-server data and emits SNI/ALPN after a complete valid ClientHello. Some hostnames remain unavailable.",
                tlsStatus,
                if (tlsStatus == "Events observed") Accent else Warning,
            )
            Divider(color = Color(0xFF2D3631))
            StatusRow("UDP/443 / QUIC", "UDP connections can be policy-matched by available destination facts; QUIC payload and encrypted ClientHello are not inspected", "Not implemented", TextMuted)
            Divider(color = Color(0xFF2D3631))
            StatusRow("HTTPS decryption", "Not implemented. NetControl does not decrypt TLS application contents.", "Not implemented", TextMuted)
        }
        item { Text("ECH, QUIC, encrypted DNS, non-TLS protocols and midstream captures may not expose a hostname. The native stream ID is not the SOCKS proxy flow ID.", color = TextMuted, fontSize = 12.sp) }
        item { Text("Live events · ${filteredEvents.size}", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Search SNI, ALPN, IP, source or status") },
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("ALL", "TLS", "DNS").forEach { item ->
                    FilterChip(selected = filter == item, onClick = { filter = item }, label = { Text(item) })
                }
            }
        }
        if (filteredEvents.isEmpty()) {
            item {
                Notice(
                    title = "No matching live inspection events",
                    body = "This history only contains observations received from actual TUN packets. Start VPN and generate traffic. Event history is bounded to 200 items in the UI; native queue overflow can discard older events.",
                )
            }
        } else {
            items(filteredEvents.take(200), key = { "inspection-${it.id}" }) { event ->
                Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(event.type.replace('_', ' '), modifier = Modifier.weight(1f), color = Accent, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                        Text(event.status, color = if (event.status.startsWith("PARSED")) Accent else Warning, fontSize = 10.sp)
                    }
                    if (!event.hostname.isNullOrBlank()) Text(event.hostname, color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                    if (!event.alpn.isNullOrBlank()) Text("ALPN: ${event.alpn}", color = TextMain, fontSize = 12.sp)
                    Text(
                        "${SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(event.timestampMs))} · IPv${event.ipVersion} ${event.protocol}",
                        color = TextMuted, fontSize = 10.sp,
                    )
                    Text(
                        "${event.sourceAddress ?: "?"}:${event.sourcePort ?: 0} → ${event.destinationAddress ?: "?"}:${event.destinationPort ?: 0}",
                        color = TextMuted, fontSize = 11.sp,
                    )
                    Text("source=${event.source} · stream=${event.flowId?.toString() ?: "not assigned"}", color = TextMuted, fontSize = 10.sp)
                    Divider(color = Color(0xFF252D28))
                }
            }
        }
        item { Text("Capability status", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        items(capabilities, key = { it.key }) { CapabilityRow(it) }
    }
}

@Composable
private fun NetworkPage(
    snapshot: NetworkSnapshot,
    status: EngineStatus,
    capabilities: List<Capability>,
    events: List<DiagnosticEventEntity>,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onExportPcap: () -> Unit,
    onClearEvents: () -> Unit,
    rootDetail: String,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { PageTitle("Network", "Android connectivity and capture lifecycle") }
        item {
            StatusRow(
                "Connection",
                "${snapshot.transport} · ${if (snapshot.connected) "connected" else "disconnected"} · ${if (snapshot.validatedInternet) "internet validated" else "internet not validated"}",
                if (snapshot.connected) "Connected" else "Disconnected",
                if (snapshot.connected) Accent else Warning,
            )
        }
        item { FieldLine("Interface", snapshot.interfaceName) }
        item { FieldLine("Wi-Fi enabled", snapshot.wifiEnabled?.toString() ?: "Unavailable") }
        item { FieldLine("Addresses", snapshot.addresses.ifEmpty { listOf("Unavailable") }.joinToString("\n")) }
        item { FieldLine("DNS servers", snapshot.dnsServers.ifEmpty { listOf("Unavailable") }.joinToString("\n")) }
        item { FieldLine("Routes", snapshot.routes.ifEmpty { listOf("Unavailable") }.joinToString("\n")) }
        item { FieldLine("Interfaces", snapshot.interfaces.ifEmpty { listOf("Unavailable") }.joinToString("\n")) }
        item { Divider(color = Color(0xFF2D3631)) }
        item { Text("Capture", fontSize = 15.sp, fontWeight = FontWeight.SemiBold) }
        item { Text(status.detail, color = TextMuted, fontSize = 12.sp) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (status.isActive) {
                    Button(onClick = onStop, modifier = Modifier.weight(1f)) { Text("Stop VPN") }
                } else {
                    Button(onClick = onStart, modifier = Modifier.weight(1f)) { Text("Start VPN") }
                }
                OutlinedButton(onClick = onExportPcap, modifier = Modifier.weight(1f)) { Text("Export PCAP") }
            }
        }
        item {
            Notice(
                title = "Local VPN / no external proxy",
                body = "NetControl establishes IPv4/IPv6 TUN routes through the embedded tun2socks engine and a loopback-only policy proxy. Outgoing sockets are protected from VPN recursion and bound to Android's selected underlying network. Native packet/DNS/TLS events are derived from packets at the TUN boundary. End-to-end reachability still requires device testing; UID attribution, per-app routing, QUIC inspection and HTTPS decryption are not implemented. PCAP is limited to 64 MiB per session.",
            )
        }
        item { Divider(color = Color(0xFF2D3631)) }
        item { Text("Capabilities", fontSize = 15.sp, fontWeight = FontWeight.SemiBold) }
        items(capabilities, key = { it.key }) { CapabilityRow(it) }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Recent diagnostics", modifier = Modifier.weight(1f), fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                TextButton(onClick = onClearEvents, enabled = events.isNotEmpty()) { Text("Clear") }
            }
        }
        if (events.isEmpty()) {
            item { Text("No diagnostic events recorded.", color = TextMuted, fontSize = 12.sp) }
        } else {
            items(events.take(100), key = { it.id }) { event ->
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("${event.type.uppercase(Locale.ROOT)} · ${SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(event.timestampMs))}", color = Accent, fontSize = 10.sp, fontWeight = FontWeight.Medium)
                    Text(event.detail, color = TextMain, fontSize = 12.sp)
                    Divider(color = Color(0xFF252D28))
                }
            }
        }
        item {
            Text("Root: $rootDetail", color = TextMuted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(value, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = TextMain)
        Text(label, fontSize = 11.sp, color = TextMuted)
    }
}

@Composable
private fun Notice(title: String, body: String) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Text(title, color = Warning, fontWeight = FontWeight.Medium, fontSize = 14.sp)
        Text(body, color = TextMuted, fontSize = 12.sp, lineHeight = 17.sp)
    }
}

@Composable
private fun FieldLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, color = TextMuted, fontSize = 11.sp)
        Text(value, color = TextMain, fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 17.sp)
    }
}

@Composable
private fun StatusRow(title: String, detail: String, status: String, statusColor: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.Top) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(title, color = TextMain, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Text(detail, color = TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
        }
        Text(status, color = statusColor, fontSize = 10.sp, maxLines = 2)
    }
}

@Composable
private fun CapabilityRow(capability: Capability) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.Top) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(capability.key, fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextMain)
            Text(capability.detail, fontSize = 11.sp, color = TextMuted, lineHeight = 15.sp)
        }
        Text(
            capability.status.label,
            color = when (capability.status) {
                CapabilityStatus.CONNECTED -> Accent
                CapabilityStatus.PARTIAL,
                CapabilityStatus.BACKEND_LIMITED,
                CapabilityStatus.DEVICE_TEST_REQUIRED -> Warning
                CapabilityStatus.NOT_IMPLEMENTED -> TextMuted
            },
            fontSize = 10.sp,
            maxLines = 2,
        )
    }
    Divider(color = Color(0xFF252D28))
}
