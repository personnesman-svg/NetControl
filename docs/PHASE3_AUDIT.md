# NetControl Phase 3 — datapath and observation audit

Audit snapshot: 2026-10-21. This document describes code paths present in the source, not proof of a successful Android build, VPN session, or device-level Internet connectivity.

## Datapath and descriptor ownership

```text
Android apps
  -> Android VpnService TUN fd (owned by NetworkVpnService)
  -> TunPacketBridge thread reads TUN and writes socketpair endpoint B
  -> socketpair endpoint A, duplicated as engineTun, is passed by integer fd to hev
  -> hev resolves TCP/UDP flows through 127.0.0.1:1080
  -> LocalSocks5Proxy matches rules and opens protected/bound upstream sockets
  -> underlying Android Network

Responses traverse the same path in reverse. The bridge is the only reader of the real TUN fd;
NativePacketBatcher and PacketCaptureStore receive mirrors and never read TUN independently.
```

| Resource | Created by | Ownership / normal close path | Failure considerations |
|---|---|---|---|
| Real Android TUN `ParcelFileDescriptor` | `VpnService.Builder.establish()` in `NetworkVpnService` | Service-owned; bridge polls it, service closes it during stop after requesting bridge shutdown | Startup failure removes the descriptor/routes; VPN revoke routes through `stopVpn` |
| `socketpair` endpoint A | `Os.socketpair(AF_UNIX, SOCK_DGRAM)` | Original FD is closed in `finally` after `ParcelFileDescriptor.dup`; the duplicated `engineTun` is retained through native stop and then closed by service | Right endpoint remains in `bridgeSocketForCleanup` until `TunPacketBridge` takes ownership |
| `socketpair` endpoint B | `Os.socketpair` | Transferred to `TunPacketBridge`, which closes it idempotently during stop | Poll timeouts and bounded joins prevent the bridge relying solely on Java thread interruption |
| `hev-socks5-tunnel` native worker | `TProxyService.TProxyStartService(config, engineTun.fd)` | Service tracks both `tunnelStartAttempted` and `tunnelStarted`; `TProxyStopService()` is attempted for partial startup too; duplicated PFD closes afterwards | `TProxyIsRunning()` only verifies the native worker state, not DNS or Internet reachability |
| Local SOCKS TCP/UDP upstream sockets | `LocalSocks5Proxy` | Proxy tracks and closes sockets; `protect()` is called before binding to the current underlying `Network` | TCP/UDP relay worker counts and diagnostics are not evidence that every app protocol works |
| PCAP output | `PacketCaptureStore.start()` | Store is synchronized, commits global header first, checkpoints after flush and at close, and exports only committed bytes | Capture failure disables further writes and reports an error without intentionally interrupting packet forwarding |
| Native observer buffers | `NativePacketBatcher` / C++ `PacketEngine` | One batcher lock guards pending packets and native JNI entrypoints; each packet carries its TUN-boundary timestamp | Batches/history are bounded; a native observer error is counted separately and does not itself change VPN forwarding |

### Startup and stop sequence

Startup checks the VPN permission, selects the active underlying network, starts a bounded local SOCKS server, creates PCAP, establishes IPv4/IPv6 routes, associates the selected underlay, creates the packet socketpair, starts hev, then starts the polling bridge and checks for early bridge/native failure. Status text explicitly says end-to-end reachability is unverified.

Stop is idempotent at the service lifecycle boundary. It transitions to `STOPPING`, cancels/joins an in-progress start, stops bridge readers, closes the real TUN to remove routes and release an outstanding TUN poll, waits once more for bridge threads, flushes the native packet batch, stops the attempted native tunnel, closes any still-owned socketpair/duplicated descriptor, stops the SOCKS proxy, detaches underlying networks, and closes PCAP. A lost underlying network enters `DEGRADED`; a 2.5-second handover grace allows a replacement network only after Android accepts `setUnderlyingNetworks`. The health/statistics loop continues while degraded. If no usable underlay attaches, the service stops to avoid leaving routes on a dead datapath. Existing TCP sessions may fail; the proxy does not transparently recreate an app session. Existing TCP sessions are not promised to survive a network switch.

These paths have been source-reviewed and host/native tested where possible; Android system callbacks, actual native FD ownership in a packaged AAR, and cancellation behavior must still be verified on an Android device. The official hev README documents the Android `TProxyService` API and the native tunnel entrypoint; the code keeps the duplicate descriptor open until native stop. It does not infer data-plane health from `TProxyIsRunning()` alone. The pinned upstream release is 2.19.1, the latest upstream release listed on 2026-10-21 (released 2026-10-19). Upstream: <https://github.com/heiher/hev-socks5-tunnel>.

## Counter and flow identity semantics

NetControl intentionally exposes two layers of flow model rather than merging IDs whose identity cannot be proven.

| Metric/model | Source | Exact meaning / limitation |
|---|---|---|
| `packetsProcessed` | Native `PacketEngine` | Number of TUN-mirrored raw IP packets successfully parsed as supported IPv4/IPv6 packets; both directions count |
| `malformedPackets` | Native `PacketEngine` | Packets rejected by the parser, including unsupported IP layouts as well as malformed headers; not a count of only corrupt traffic |
| `nativeFlows` | Native `FlowTable` | Current bounded IP-level tuple count after timeout/FIN/RST handling; independent of SOCKS flow IDs |
| Native `bytesForward/bytesReverse` | Native `FlowEntry` | IP `totalLength` bytes grouped by direction relative to the first observed packet; first packet may be either direction, so labels are not guaranteed app upload/download |
| `activeFlows` | `LocalSocks5Proxy` | Active TCP CONNECT streams plus active UDP destination-flow entries; not the native IP flow-table size |
| `bytesUploaded/bytesDownloaded` | SOCKS relay | Payload bytes copied/relayed at the SOCKS layer; excludes outer IP/TCP/UDP headers and SOCKS negotiation/UDP encapsulation |
| `blockedFlows` | SOCKS rule decisions | Blocked TCP CONNECT attempts and first blocked UDP destination key within its suppression/idle window; not blocked IP packets |
| `evictions` | Native observer | Sum of native IP-flow table evictions and TCP reassembly-state evictions; it is not a lost-packet counter |
| DNS `flowId = null` | TUN UDP/53 event | UDP DNS has no stable native TCP stream ID in this model; transaction ID and endpoints are reported instead |
| TLS/DNS TCP `flowId` | Native TCP reassembly state | A native observer stream ID; never equated with the SOCKS proxy's `FlowSnapshot.id` |

Pending SOCKS byte deltas are coalesced and published to Compose at most every 250 ms (or when a flow ends), while proxy aggregate stats are refreshed once a second. UI history is limited to 200 flows and 200 inspection events; the native inspection event queue is limited to 256 and drops its oldest event if full. No SQLite row is written for every packet or byte-counter change.

UDP reply bytes are attributed to an individual proxy flow only when the remote endpoint is unambiguous among active flows. If different requested domains share a remote IP/port, aggregate proxy totals still increment, but per-flow download bytes are not falsely assigned to one hostname.

## DNS and domain-rule truth

- Native DNS events only come from packet payloads actually mirrored at TUN: complete plaintext UDP/53 questions/responses and length-framed TCP/53 messages. First-fragment UDP DNS is reported as `FRAGMENTED_DNS_NOT_REASSEMBLED`; later fragments are not reassembled by this observer.
- The configured hev `mapdns` pool is `100.64.0.0/10`, with mapped DNS endpoint `198.18.0.2`. The upstream tunnel implementation can map a DNS-returned synthetic address back to its requested host for SOCKS routing; whether the Android resolver and every app use this path still requires device testing. The local proxy evaluates hostname rules only when a hostname is present in the SOCKS request or DNS question; IP-only requests cannot match domain-only rules.
- `RuleEngine` normalizes domain case with `Locale.ROOT`; exact and subdomain matches are allowed (`a.example.com` matches `example.com`, while `example.com.attacker.test` does not). IP literals are compared by address bytes. Unknown domain or UID values do not satisfy a rule that requires those fields. UID is currently unavailable through this SOCKS/TUN contract, so UID-specific rules are not advertised as enforceable.
- DoH/DoT inspection, QUIC hostname inspection, HTTPS decryption, per-app routing and root interception are not implemented. ECH is not decrypted; when the visible ClientHello contains the ECH extension, the parser suppresses the outer/cover SNI and emits `ECH_EXTENSION_PRESENT_SNI_SUPPRESSED`, while retaining ALPN if it parsed successfully. This is conservative: absence of the extension in observed bytes is not proof that the true hostname is available. SNI/ALPN are best-effort metadata from a structurally valid ClientHello visible in the client-to-server direction; they are not universal hostname detection.

## Bounds and parse behavior

- Native IP-flow table: 256 active entries; TCP idle expiry 300 s, UDP/non-TCP idle expiry 60 s, TCP tuple reuse detected by initial SYN sequence where available.
- Native TCP reassembly: state is allocated only for TCP/53 or TLS candidates (known TLS ports, or a client-to-server payload beginning with a TLS handshake record), not every ordinary TCP SYN. Up to 128 candidate streams, 16 KiB per direction, 120 s idle expiry; sequence-aware byte placement accepts identical retransmissions, while conflicting overlaps/out-of-window data taint that stream and stop further inspection for it. This is best-effort passive reconstruction, not a full TCP stack.
- Native DNS/TCP frame accumulator: 4 KiB per direction. TLS parser/handshake buffers are bounded at 16 KiB; exceeding limits yields a parse status, not arbitrary buffer growth.
- Native inspection events: 256. Kotlin live event history: 200. PCAP: classic little-endian PCAP, `DLT_RAW` (101), 65,535 snap length, both packet directions at TUN boundary, 64 MiB maximum per session.
- Packet timestamps are taken in the bridge immediately after each read and passed as a per-packet `LongArray` through JNI; stats use Java `Long` counters to avoid early 32-bit overflow.

## Verification matrix

| Capability | Source status | Current proof available | Remaining gate |
|---|---|---|---|
| TUN ↔ socketpair ↔ hev ↔ local SOCKS code | Connected in source | Lifecycle review; native/JNI source compile checks | Android build and device packet forwarding |
| TCP/UDP rule matching | Partial; policy point connected | JVM tests for ordered rules, domains, IP literals, unknown fields | Android integration tests, mapdns behavior, IPv6 and app protocol compatibility |
| TUN-boundary raw PCAP | Connected in source | Writer format/rotation tests and independent structural parser validation | Device-generated capture validated by tcpdump/Wireshark |
| UDP/53 and TCP/53 live events | Connected partially | Host-generated packet tests, source/status checks | Device resolver path and mapdns results |
| TLS ClientHello SNI/ALPN | Connected partially | Native reassembly tests, including ECH cover-name suppression | Device-generated ClientHello and fragmented real traffic behavior |
| UID per app / root backend / QUIC inspection / HTTPS decryption | Not implemented / backend limited | Capability records describe absence | Requires separate design; not claimed for Phase 3 |
| Full end-to-end firewall behavior | Not yet proven | Code paths and native tests only | Android Gradle build, device tests, external connectivity / leak tests |


## Phase 3 delta — UDP association and ECH safety

- `LocalSocks5Proxy` now uses separate sockets for the SOCKS UDP loopback endpoint and the protected/bound upstream UDP socket. Only the upstream socket is passed through `VpnService.protect()` and bound to the selected Android `Network`. The SOCKS endpoint remains bound to `127.0.0.1`. This avoids relying on one network-bound datagram socket to receive both loopback and upstream packets. The upstream reader accepts responses only from an endpoint seen in an active request mapping; unsolicited endpoints are dropped.
- UDP flow/reply attribution remains conservative when multiple domain flows share an IP:port. The integration test exercises a real host-loopback SOCKS5 UDP ASSOCIATE exchange through the production `LocalSocks5Proxy` code and a UDP echo endpoint; it does not validate Android `Network.bindSocket`, Hev, or device forwarding.
- Native TLS parsing records visible ECH extension presence and suppresses the outer/cover SNI before a live event is emitted. This prevents a visible cover name from being falsely represented as the origin site; ECH itself is not decrypted or otherwise inspected.
- Reproducible host test: `bash scripts/test_socks5_udp_host.sh`.
