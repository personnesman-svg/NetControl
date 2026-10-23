# NetControl — local Android VPN firewall

NetControl is an Android/Kotlin/Jetpack Compose project with Room persistence, a C++17/JNI packet parser, and a local `VpnService` data path. This is an extension of the existing project, not a new application.

## Current implementation

- Android `VpnService` owns the TUN lifecycle and installs IPv4/IPv6 default routes only after user consent.
- The embedded **hev-socks5-tunnel** engine moves IP packets between the Android TUN and a local SOCKS5 endpoint. No remote SOCKS5/VPN server is configured.
- `LocalSocks5Proxy` implements SOCKS5 TCP CONNECT and UDP ASSOCIATE locally. Outbound sockets are protected with `VpnService.protect()` so they use the underlying network rather than loop back into the VPN.
- `RuleEngine` evaluates ordered `ALLOW`, `BLOCK`, and `OBSERVE` rules for TCP/UDP protocol, destination IP, port, and domain when the domain is available to the proxy.
- `TunPacketBridge` is the only reader for Android's TUN fd. It uses a packet-oriented Unix socketpair toward `hev-socks5-tunnel`, polls with bounded timeouts, and mirrors both observed directions before forwarding. Shutdown closes the producer path and waits for bridge threads within bounded deadlines.
- `EngineRuntime` exposes bounded live DNS/TLS events and a throttled Compose view of proxy-flow counters. SOCKS proxy flow IDs and native IP/TCP observer IDs are intentionally separate because there is no safe common connection identity.
- `PcapWriter` writes classic PCAP with `DLT_RAW` (101) and Unix-millisecond timestamps. The synchronized `PacketCaptureStore` exports a flushed record-boundary snapshot and caps each session at 64 MiB; records that were not committed successfully are not exported.
- The C++ observer receives real raw IPv4/IPv6 packets mirrored at the TUN boundary. It maintains a bounded, idle-expiring IP-flow table; decodes complete plaintext UDP/53 and length-framed TCP/53 DNS messages; and performs per-direction, sequence-aware bounded TCP reassembly for valid TLS ClientHello SNI/ALPN events. Events include timestamp, native stream ID, endpoints, source and parse status.

## Important limitations (not a production firewall yet)

- Android build, emulator testing, and real-device testing have **not** been executed in this environment. The network data plane is integrated in source, but must be validated on a device before relying on it.
- UID-based rules are not enforceable because the local SOCKS5 protocol does not expose the originating app UID. The UI marks UID attribution as unavailable.
- Live SNI is best-effort: it requires a complete, valid ClientHello to be visible at the TUN boundary. If the ECH extension is visible, NetControl suppresses the outer/cover SNI rather than presenting it as the origin hostname. QUIC, missing/late first segments, malformed traffic, nonstandard framing, and ClientHello without SNI can still leave the hostname unknown. HTTPS application payloads are never decrypted.
- Plain DNS is decoded only when a complete, non-fragmented UDP/53 packet or a fully framed TCP/53 message is visible. Fragmented UDP DNS is reported as not reassembled. DoH, DoT and other encrypted DNS are not decoded.
- SOCKS5 UDP fragmentation and the BIND command are not implemented by the local proxy. Some applications/protocols may require additional compatibility work.
- ICMP is not proxied as an ordinary SOCKS stream; the tunnel is configured for local echo replies, but full ICMP forwarding is not promised.
- IPv6, network changes, captive portals, long-lived TCP sessions, QUIC/HTTP3, DNS mapping, battery/background restrictions, and OEM VPN behavior must be tested on actual Android versions. If the tunnel core exits, the service attempts to stop the VPN to avoid leaving routes pointed at a dead packet path.
- Native packet counters and PCAP capture observe raw IP packets at the TUN boundary, both directions. They are not physical-interface wire captures. Native IP-flow byte counts use IP total-length bytes and a first-observed direction; SOCKS-flow byte counts use relayed application payload bytes (not IP/TCP/UDP overhead). These layers are not merged. The proxy cannot reliably attribute a UDP response to one hostname if multiple SOCKS domain flows share the same remote IP/port endpoint.
- Native reassembly is bounded to 128 TCP flow states and 16 KiB per direction; DNS/TCP framing is capped at 4 KiB per direction. TLS event history is bounded in native code and again in the UI. Queue overflow drops oldest native inspection events. The local SOCKS UDP maps have per-association capacity and a 60-second idle expiry; hostname resolution cache is bounded.

## Build requirements

Use JDK 17, Android SDK Platform 35, Android NDK `27.2.12479018`, and CMake `3.22.1`. The project uses Android Gradle Plugin 8.7.3 / Gradle 8.9, Kotlin 2.0.21, KSP 2.0.21-1.0.28, Room 2.6.1, and Compose BOM 2024.12.01.

The first Android build downloads the official self-contained `hev-socks5-tunnel` Android AAR (version 2.19.1, released 2026-10-19) into `app/libs/`. A working internet connection is required for this one-time download. The downloaded AAR is checked for `classes.jar` and native libraries for the configured ABIs. The upstream project documents the `hev.htproxy.TProxyService` API and distributes the AAR under the MIT license: <https://github.com/heiher/hev-socks5-tunnel>.

Open the root `NetControl` directory in Android Studio, install the required SDK/NDK/CMake components, let Gradle sync, then run:

```powershell
.\gradlew.bat :app:assembleDebug
.\gradlew.bat :app:testDebugUnitTest
.\gradlew.bat :app:lintDebug
```

The debug APK is expected at `app/build/outputs/apk/debug/app-debug.apk`. The first build needs internet to obtain the AAR and normal Maven dependencies.

The repository contains custom `gradlew` / `gradlew.bat` bootstrap scripts rather than the binary Gradle wrapper JAR; they fetch Gradle 8.9 and verify its checksum when it is not cached.

## Phase 3 audit notes

See [`docs/PHASE3_AUDIT.md`](docs/PHASE3_AUDIT.md) for descriptor ownership, startup/stop sequence, counter definitions, event provenance, parser bounds, DNS mapping assumptions and the current capability matrix.

## Native tests

The host-side native test suite can be run without Android Studio:

```bash
cmake -S native -B /tmp/netcontrol-native-build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/netcontrol-native-build
ctest --test-dir /tmp/netcontrol-native-build --output-on-failure
```

Native parser/flow-table/PCAP tests were run in the available environment. That is not a substitute for Android Gradle/NDK compilation or real-device VPN tests.

## Safe device test procedure

Use a physical device first if possible. Keep a second route to disable the VPN available in Android Settings. Start the VPN, confirm ordinary HTTPS browsing, check that Flows/byte counters update, add a narrow test rule (for example, block a single test domain), and verify expected block/pass behavior. Then stop the VPN and confirm connectivity returns. If the VPN starts but browsing fails, stop it immediately in the app or Android Settings and share the complete Gradle output plus Android Logcat filtered to `NetControl` / `hev`.

PCAP files and DNS history may contain sensitive data. Captures remain local and are exported only through the Android document picker.

## Phase 3 host integration checks

The following checks do not require Android SDK and complement native CTest. They require a desktop JDK, `kotlinc`, and a C++ compiler; they do not validate Android `Os.poll`, VpnService lifecycle, the packaged hev AAR, or real-device forwarding.

```bash
./scripts/test_jni_ui_integration.sh
./scripts/test_pcap_independent.sh
./scripts/test_kotlin_policy_host.sh
./scripts/test_socks5_udp_host.sh
```

The first passes out-of-order synthetic TCP segments through the real host-built JNI/native parser and the same Kotlin `EngineRuntime` StateFlow used by the UI, asserting live SNI/ALPN and DNS metadata. The second writes PCAP with the production `PcapWriter` then validates the file with an independent standard-library parser. The third executes deterministic tests against the real `RuleEngine` and compiles `LocalSocks5Proxy` on the host JVM, using only stubs for Android-side data models. The fourth performs a real host-loopback SOCKS5 UDP ASSOCIATE + UDP echo exchange through the actual proxy implementation; it still does not validate Android network binding or Hev integration.
