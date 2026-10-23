# Verification status

Checked in the available build environment on 2026-10-21.

## Executed successfully

- Host CMake configure/build of `native/` using GCC 14.2.
- Native CTest: 1/1 test executable passed, covering IPv4/IPv6, IP/TCP bounds, DNS query/response parsing, malformed and fragmented DNS status, TCP DNS framing, fragmented/out-of-order/retransmitted/conflicting TLS ClientHello segments, per-flow/per-direction isolation, sequence wrap/zero cases, stream timeout/capacity eviction, ordinary HTTP not consuming TLS reassembly capacity, per-packet timestamps, false TLS-event suppression for HTTP, and native PCAP headers/rotation.
- Host CMake build and CTest with AddressSanitizer and UndefinedBehaviorSanitizer, leak detection enabled: 1/1 test executable passed.
- JNI bridge syntax compilation against desktop JDK JNI headers. This is not an Android NDK ABI build.
- XML parse of `AndroidManifest.xml` and theme resources.
- Standalone Kotlin smoke test of the bounded DNS packet parser: IPv4 query, IPv6 query, DNS response rejection, and IPv4 fragmentation rejection.
- Host JNI-to-UI integration harness (`scripts/test_jni_ui_integration.sh`): synthetic raw IPv4 TCP SYN and out-of-order ClientHello segments pass through the actual compiled C++ core/JNI bridge, then the actual `NativeEngine` and `EngineRuntime` StateFlow model; it asserts SNI `example.com`, ALPN `h2`, endpoints, native stream ID, and per-packet timestamp. It also passes a raw UDP/53 query through the same chain and asserts the DNS event/source/time.
- Independent standard-library PCAP validation (`scripts/test_pcap_independent.sh`): writes IPv4/IPv6 records with the actual Kotlin `PcapWriter` and parses the generated file with a separate Python parser, checking global header, DLT_RAW, record boundaries, timestamp fractions, IP versions, captured lengths, and original lengths.
- Executable host JVM/Kotlin checks (`scripts/test_kotlin_policy_host.sh`) against the real `RuleEngine`: ordered/disabled rules, exact and subdomain matching, lookalike domains, unknown domain/UID, canonical IPv6 and malformed IP handling. It also compiles `LocalSocks5Proxy` with Android-facing model stubs; this does not exercise Android socket binding.
- SOCKS5 UDP loopback integration (`scripts/test_socks5_udp_host.sh`): the actual `LocalSocks5Proxy` code negotiated UDP ASSOCIATE, sent an encapsulated datagram to a real host loopback UDP echo socket through the separate upstream socket, received the encapsulated response on the advertised loopback relay, and updated payload counters. This is a host socket integration test, not a test of Android `Network.bindSocket` or the embedded Hev datapath.
- Native ECH regression: a synthetically valid ClientHello containing the ECH extension produces `ECH_EXTENSION_PRESENT_SNI_SUPPRESSED`, with an empty hostname and parsed ALPN retained; the outer/cover SNI is not emitted as the website hostname.
- POSIX shell syntax check for the Gradle bootstrap and the two host test scripts.

## Not verified in this environment

- Android Gradle tasks `:app:testDebugUnitTest` and `:app:assembleDebug`: both were attempted on 2026-10-21 but the custom wrapper failed before starting Gradle because `curl` could not resolve `services.gradle.org` (`curl: (6) Could not resolve host`). The Android app itself has not been compiled here. `:app:lintDebug` was not attempted.
- Android NDK link for arm64-v8a / armeabi-v7a / x86_64.
- First-build download/validation of the pinned upstream 2.19.1 AAR on a connected Windows developer machine. Official release metadata and the documented Java/Kotlin `TProxyService` contract were checked, but the exact AAR download and Gradle task were not run here.
- APK install, VPN permission, embedded native tunnel startup, real TCP/UDP forwarding, IPv6 and DNS mapping on an emulator or physical device.
- Network handover, captive portals, memory/CPU profile, OEM-specific VPN behavior or release/obfuscation behavior.

This execution environment has no configured `ANDROID_HOME`/`ANDROID_SDK_ROOT`, Android SDK/NDK or cached Gradle 8.9 distribution, and cannot resolve external hosts from the container. The two Gradle tasks therefore failed during wrapper bootstrap and did not reach project configuration or compilation. It is not honest to label this snapshot `BUILDABLE`, a verified APK, or a production-ready firewall. Android build and real-device tests are the next required gate.
