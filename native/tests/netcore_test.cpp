#include "netcore.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace netcontrol;

namespace {
int failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << " : " << #condition << "\n"; ++failures; \
} } while (false)

void put16(std::vector<std::uint8_t>& bytes, std::size_t at, std::uint16_t value) {
    bytes[at] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[at + 1U] = static_cast<std::uint8_t>(value & 0xffU);
}

std::vector<std::uint8_t> ipv4Udp(std::uint16_t sourcePort, const char* source = "10.0.0.1") {
    std::vector<std::uint8_t> bytes(28U, 0U);
    bytes[0] = 0x45U;
    put16(bytes, 2U, static_cast<std::uint16_t>(bytes.size()));
    bytes[8] = 64U;
    bytes[9] = 17U;
    unsigned octets[4]{10U, 0U, 0U, 1U};
    std::sscanf(source, "%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], &octets[3]);
    for (std::size_t i = 0; i < 4U; ++i) bytes[12U + i] = static_cast<std::uint8_t>(octets[i]);
    bytes[16] = 8U; bytes[17] = 8U; bytes[18] = 8U; bytes[19] = 8U;
    put16(bytes, 20U, sourcePort);
    put16(bytes, 22U, 53U);
    put16(bytes, 24U, 8U);
    return bytes;
}

std::vector<std::uint8_t> ipv6Udp() {
    std::vector<std::uint8_t> bytes(48U, 0U);
    bytes[0] = 0x60U;
    put16(bytes, 4U, 8U);
    bytes[6] = 17U;
    bytes[7] = 64U;
    bytes[8] = 0x20U; bytes[9] = 0x01U; bytes[10] = 0x0dU; bytes[11] = 0xb8U;
    bytes[23] = 1U;
    bytes[24] = 0x20U; bytes[25] = 0x01U; bytes[26] = 0x0dU; bytes[27] = 0xb8U;
    bytes[39] = 2U;
    put16(bytes, 40U, 44444U);
    put16(bytes, 42U, 443U);
    put16(bytes, 44U, 8U);
    return bytes;
}

std::vector<std::uint8_t> ipv4Tcp(const char* source, const char* destination,
                                    std::uint16_t sourcePort, std::uint16_t destinationPort,
                                    std::uint32_t sequence, std::uint8_t flags,
                                    const std::vector<std::uint8_t>& payload = {}) {
    const std::size_t total = 40U + payload.size();
    std::vector<std::uint8_t> packet(total, 0U);
    packet[0] = 0x45U;
    put16(packet, 2U, static_cast<std::uint16_t>(total));
    packet[8] = 64U;
    packet[9] = 6U;
    unsigned src[4]{0U, 0U, 0U, 0U};
    unsigned dst[4]{0U, 0U, 0U, 0U};
    std::sscanf(source, "%u.%u.%u.%u", &src[0], &src[1], &src[2], &src[3]);
    std::sscanf(destination, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]);
    for (std::size_t i = 0; i < 4U; ++i) {
        packet[12U + i] = static_cast<std::uint8_t>(src[i]);
        packet[16U + i] = static_cast<std::uint8_t>(dst[i]);
    }
    put16(packet, 20U, sourcePort);
    put16(packet, 22U, destinationPort);
    packet[24] = static_cast<std::uint8_t>((sequence >> 24U) & 0xffU);
    packet[25] = static_cast<std::uint8_t>((sequence >> 16U) & 0xffU);
    packet[26] = static_cast<std::uint8_t>((sequence >> 8U) & 0xffU);
    packet[27] = static_cast<std::uint8_t>(sequence & 0xffU);
    packet[32] = 0x50U;
    packet[33] = flags;
    if (!payload.empty()) std::copy(payload.begin(), payload.end(), packet.begin() + 40);
    return packet;
}

void addPacket(std::vector<std::uint8_t>& batch, const std::vector<std::uint8_t>& packet) {
    batch.push_back(static_cast<std::uint8_t>((packet.size() >> 8U) & 0xffU));
    batch.push_back(static_cast<std::uint8_t>(packet.size() & 0xffU));
    batch.insert(batch.end(), packet.begin(), packet.end());
}

std::vector<std::uint8_t> dnsQuery() {
    std::vector<std::uint8_t> b(12U, 0U);
    b[0] = 0x12U; b[1] = 0x34U; b[2] = 0x01U; b[5] = 0x01U;
    for (const char* label : {"example", "com"}) {
        const auto len = static_cast<std::uint8_t>(std::strlen(label));
        b.push_back(len);
        for (std::size_t i = 0; i < len; ++i) b.push_back(static_cast<std::uint8_t>(label[i]));
    }
    b.push_back(0U);
    b.insert(b.end(), {0U, 1U, 0U, 1U});
    return b;
}

std::vector<std::uint8_t> clientHello(bool includeEch = false) {
    const std::string sni = "example.com";
    const std::string alpn = "h2";
    std::vector<std::uint8_t> extensions;
    // SNI extension: list length (2), name type (1), name length (2), name.
    const std::size_t sniDataLength = 2U + 1U + 2U + sni.size();
    extensions.insert(extensions.end(), {0U, 0U});
    extensions.push_back(static_cast<std::uint8_t>((sniDataLength >> 8U) & 0xffU));
    extensions.push_back(static_cast<std::uint8_t>(sniDataLength & 0xffU));
    const std::size_t listLength = 1U + 2U + sni.size();
    extensions.push_back(static_cast<std::uint8_t>((listLength >> 8U) & 0xffU));
    extensions.push_back(static_cast<std::uint8_t>(listLength & 0xffU));
    extensions.push_back(0U);
    extensions.push_back(0U);
    extensions.push_back(static_cast<std::uint8_t>(sni.size()));
    extensions.insert(extensions.end(), sni.begin(), sni.end());
    // ALPN extension.
    const std::size_t alpnDataLength = 2U + 1U + alpn.size();
    extensions.insert(extensions.end(), {0U, 16U,
        static_cast<std::uint8_t>((alpnDataLength >> 8U) & 0xffU), static_cast<std::uint8_t>(alpnDataLength & 0xffU),
        0U, static_cast<std::uint8_t>(alpnDataLength - 2U), static_cast<std::uint8_t>(alpn.size())});
    extensions.insert(extensions.end(), alpn.begin(), alpn.end());
    // ECH extension body is opaque to this observer. Its presence is sufficient to suppress
    // the visible SNI because the value may be only the configured public cover name.
    if (includeEch) extensions.insert(extensions.end(), {0xfeU, 0x0dU, 0U, 1U, 0U});

    std::vector<std::uint8_t> body{3U, 3U};
    body.insert(body.end(), 32U, 0x42U);  // Random.
    body.push_back(0U);                  // Session ID length.
    body.insert(body.end(), {0U, 2U, 0x13U, 0x01U});  // One cipher suite.
    body.insert(body.end(), {1U, 0U});  // Compression methods.
    body.push_back(static_cast<std::uint8_t>((extensions.size() >> 8U) & 0xffU));
    body.push_back(static_cast<std::uint8_t>(extensions.size() & 0xffU));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake{1U,
        static_cast<std::uint8_t>((body.size() >> 16U) & 0xffU),
        static_cast<std::uint8_t>((body.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(body.size() & 0xffU)};
    handshake.insert(handshake.end(), body.begin(), body.end());
    std::vector<std::uint8_t> record{22U, 3U, 1U,
        static_cast<std::uint8_t>((handshake.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(handshake.size() & 0xffU)};
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

void testIpv4UdpAndTruncation() {
    auto packet = ipv4Udp(12345U);
    PacketInfo info{};
    CHECK(parseIpPacket(packet.data(), packet.size(), info) == ParseStatus::Ok);
    CHECK(info.ipVersion == 4U);
    CHECK(info.protocol == 17U);
    CHECK(std::string(info.source) == "10.0.0.1");
    CHECK(std::string(info.destination) == "8.8.8.8");
    CHECK(info.sourcePort == 12345U && info.destinationPort == 53U);
    CHECK(info.hasPorts);
    CHECK(info.payloadLength == 0U);
    CHECK(parseIpPacket(packet.data(), 17U, info) == ParseStatus::Malformed);
    packet[0] = 0x4fU;
    CHECK(parseIpPacket(packet.data(), packet.size(), info) == ParseStatus::Malformed);
}

void testIpv6Udp() {
    auto packet = ipv6Udp();
    PacketInfo info{};
    CHECK(parseIpPacket(packet.data(), packet.size(), info) == ParseStatus::Ok);
    CHECK(info.ipVersion == 6U);
    CHECK(info.protocol == 17U);
    CHECK(info.sourcePort == 44444U && info.destinationPort == 443U);
    CHECK(std::string(info.source).find("2001:db8") == 0U);
    CHECK(parseIpPacket(packet.data(), 39U, info) == ParseStatus::Malformed);
}


void testTcpHeaderValidation() {
    std::vector<std::uint8_t> packet(40U, 0U);
    packet[0] = 0x45U;
    put16(packet, 2U, static_cast<std::uint16_t>(packet.size()));
    packet[8] = 64U;
    packet[9] = 6U;
    packet[12] = 192U; packet[13] = 0U; packet[14] = 2U; packet[15] = 1U;
    packet[16] = 198U; packet[17] = 51U; packet[18] = 100U; packet[19] = 9U;
    put16(packet, 20U, 49152U); put16(packet, 22U, 443U);
    packet[32] = 0x50U; // TCP data offset: 20-byte header.
    PacketInfo info{};
    CHECK(parseIpPacket(packet.data(), packet.size(), info) == ParseStatus::Ok);
    CHECK(info.protocol == 6U && info.hasPorts);
    CHECK(info.sourcePort == 49152U && info.destinationPort == 443U);
    packet[32] = 0x40U; // Data offset shorter than a TCP header.
    CHECK(parseIpPacket(packet.data(), packet.size(), info) == ParseStatus::Malformed);
}

void testDns() {
    auto packet = dnsQuery();
    DnsInfo info{};
    CHECK(parseDnsMessage(packet.data(), packet.size(), info) == ParseStatus::Ok);
    CHECK(std::string(info.name) == "example.com");
    CHECK(info.recordType == 1U);
    CHECK(!info.isResponse);
    CHECK(info.responseCode == 0U);
    CHECK(parseDnsMessage(packet.data(), 9U, info) == ParseStatus::Malformed);
    packet[12] = 0xffU;
    CHECK(parseDnsMessage(packet.data(), packet.size(), info) == ParseStatus::Malformed);
}

void testTlsFragmentedClientHello() {
    const auto bytes = clientHello();
    TlsClientHelloParser parser;
    TlsClientHelloInfo info{};
    const std::size_t split = bytes.size() / 2U;
    CHECK(parser.feed(bytes.data(), split, info) == TlsStatus::NeedMore);
    CHECK(parser.feed(bytes.data() + split, bytes.size() - split, info) == TlsStatus::ClientHello);
    CHECK(std::string(info.sni) == "example.com");
    CHECK(std::string(info.alpn) == "h2");
    CHECK(info.legacyVersion == 0x0303U);
    CHECK(!info.echPresent);

    parser.reset();
    const auto echBytes = clientHello(true);
    CHECK(parser.feed(echBytes.data(), echBytes.size(), info) == TlsStatus::ClientHello);
    CHECK(info.echPresent);
    CHECK(info.sni[0] == '\0'); // Never expose the visible cover SNI as the real hostname.
    CHECK(std::string(info.alpn) == "h2");

    parser.reset();
    const std::uint8_t invalid[]{22U, 3U, 3U, 0xffU, 0xffU};
    CHECK(parser.feed(invalid, sizeof(invalid), info) == TlsStatus::Malformed);
}

void testBoundedFlowTableAndBatch() {
    FlowTable table;
    for (std::uint32_t i = 0; i < kFlowCapacity + 1U; ++i) {
        PacketInfo info{};
        info.protocol = 17U;
        std::snprintf(info.source, sizeof(info.source), "10.0.%u.%u", (i / 255U), (i % 255U) + 1U);
        std::snprintf(info.destination, sizeof(info.destination), "8.8.8.8");
        info.sourcePort = static_cast<std::uint16_t>(1000U + i);
        info.destinationPort = 53U;
        info.hasPorts = true;
        info.totalLength = 28U;
        table.observe(info, 1000U + i);
    }
    CHECK(table.size() == kFlowCapacity);
    CHECK(table.evictions() == 1U);

    PacketEngine engine;
    const auto packet = ipv4Udp(12345U);
    std::vector<std::uint8_t> batch;
    batch.push_back(0U);
    batch.push_back(static_cast<std::uint8_t>(packet.size()));
    batch.insert(batch.end(), packet.begin(), packet.end());
    const auto stats = engine.processBatch(batch.data(), batch.size(), 1234U);
    CHECK(stats.processed == 1U);
    CHECK(stats.ipv4 == 1U);
    CHECK(engine.flows().size() == 1U);
    const std::uint8_t broken[]{0U};
    CHECK(engine.processBatch(broken, sizeof(broken), 1U).malformed == 1U);
}

void testLiveDnsObservationFromUdpPackets() {
    const auto dns = dnsQuery();
    std::vector<std::uint8_t> packet(20U + 8U + dns.size(), 0U);
    packet[0] = 0x45U;
    put16(packet, 2U, static_cast<std::uint16_t>(packet.size()));
    packet[8] = 64U;
    packet[9] = 17U;
    packet[12] = 10U; packet[15] = 2U;
    packet[16] = 8U; packet[17] = 8U; packet[18] = 8U; packet[19] = 8U;
    put16(packet, 20U, 53000U); put16(packet, 22U, 53U);
    put16(packet, 24U, static_cast<std::uint16_t>(8U + dns.size()));
    std::copy(dns.begin(), dns.end(), packet.begin() + 28);
    std::vector<std::uint8_t> batch;
    addPacket(batch, packet);
    PacketEngine engine;
    engine.processBatch(batch.data(), batch.size(), 42'000U);
    const auto events = engine.takeEvents();
    CHECK(events.size() == 1U);
    if (!events.empty()) {
        CHECK(events[0].kind == InspectionEventKind::Dns);
        CHECK(events[0].source == "TUN_UDP_DNS");
        CHECK(events[0].hostname == "example.com");
        CHECK(events[0].sourcePort == 53000U && events[0].destinationPort == 53U);
        CHECK(events[0].timestampMs == 42'000U);
        CHECK(events[0].dnsTransactionId == 0x1234U);
    }
}

void testTcpReassemblyOutOfOrderOverlapAndRetransmission() {
    const auto hello = clientHello();
    const std::size_t split = hello.size() / 2U;
    const std::uint32_t clientBase = 1001U; // SYN sequence 1000 consumes one sequence number.
    PacketEngine engine;
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 50000U, 443U, 1000U, 0x02U));
    // Out-of-order tail first, including an overlap with the future prefix (the overlap bytes agree).
    std::vector<std::uint8_t> tail(hello.begin() + static_cast<std::ptrdiff_t>(split), hello.end());
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 50000U, 443U,
                             clientBase + static_cast<std::uint32_t>(split), 0x18U, tail));
    // Identical retransmission must not duplicate data or events.
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 50000U, 443U,
                             clientBase + static_cast<std::uint32_t>(split), 0x18U, tail));
    // Prefix overlaps the tail by four bytes; the overlap is byte-identical.
    const std::size_t prefixLength = split + 4U;
    std::vector<std::uint8_t> prefix(hello.begin(), hello.begin() + static_cast<std::ptrdiff_t>(prefixLength));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 50000U, 443U, clientBase, 0x18U, prefix));
    engine.processBatch(batch.data(), batch.size(), 50'000U);
    const auto events = engine.takeEvents();
    const auto found = std::count_if(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    });
    CHECK(found == 1);
    const auto tls = std::find_if(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    });
    if (tls != events.end()) {
        CHECK(tls->source == "TLS_CLIENT_HELLO");
        CHECK(tls->hostname == "example.com");
        CHECK(tls->alpn == "h2");
        CHECK(tls->flowId != 0U);
        CHECK(tls->timestampMs == 50'000U);
        CHECK(tls->sourceAddress == "10.0.0.2");
        CHECK(tls->destinationAddress == "203.0.113.20");
    }
}

void testTcpReassemblyDoesNotMixFlowsOrDirections() {
    const auto hello = clientHello();
    const std::size_t split = hello.size() / 2U;
    const std::vector<std::uint8_t> prefix(hello.begin(), hello.begin() + static_cast<std::ptrdiff_t>(split));
    const std::vector<std::uint8_t> tail(hello.begin() + static_cast<std::ptrdiff_t>(split), hello.end());
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 51000U, 443U, 2000U, 0x02U));
    addPacket(batch, ipv4Tcp("10.0.0.3", "203.0.113.20", 51001U, 443U, 3000U, 0x02U));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 51000U, 443U, 2001U, 0x18U, prefix));
    addPacket(batch, ipv4Tcp("10.0.0.3", "203.0.113.20", 51001U, 443U,
                             3001U + static_cast<std::uint32_t>(split), 0x18U, tail));
    PacketEngine engine;
    engine.processBatch(batch.data(), batch.size(), 60'000U);
    const auto partialEvents = engine.takeEvents();
    CHECK(std::count_if(partialEvents.begin(), partialEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    }) == 0);
    std::vector<std::uint8_t> completion;
    addPacket(completion, ipv4Tcp("10.0.0.2", "203.0.113.20", 51000U, 443U,
                                  2001U + static_cast<std::uint32_t>(split), 0x18U, tail));
    engine.processBatch(completion.data(), completion.size(), 60'001U);
    const auto events = engine.takeEvents();
    CHECK(std::count_if(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello && event.sourcePort == 51000U;
    }) == 1);
    CHECK(std::none_of(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello && event.sourcePort == 51001U;
    }));
}

void testTcpReassemblyConflictingOverlapAndWindowLimit() {
    const auto hello = clientHello();
    const std::size_t split = hello.size() / 2U;
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 52000U, 443U, 4000U, 0x02U));
    const std::vector<std::uint8_t> first(hello.begin(), hello.begin() + static_cast<std::ptrdiff_t>(split));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 52000U, 443U, 4001U, 0x18U, first));
    std::vector<std::uint8_t> conflict(hello.begin() + 4, hello.begin() + static_cast<std::ptrdiff_t>(split + 8U));
    conflict[0] ^= 0x7fU; // same sequence range, conflicting byte: inspection must stop for this flow
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 52000U, 443U, 4005U, 0x18U, conflict));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", 52000U, 443U,
                             4001U + static_cast<std::uint32_t>(split), 0x18U,
                             std::vector<std::uint8_t>(hello.begin() + static_cast<std::ptrdiff_t>(split), hello.end())));
    PacketEngine engine;
    engine.processBatch(batch.data(), batch.size(), 70'000U);
    const auto events = engine.takeEvents();
    CHECK(std::none_of(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    }));
    CHECK(std::any_of(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.status == "REASSEMBLY_OVERLAP_OR_LIMIT";
    }));

    std::vector<std::uint8_t> overrun;
    addPacket(overrun, ipv4Tcp("10.0.0.2", "203.0.113.20", 52001U, 443U, 9000U, 0x02U));
    addPacket(overrun, ipv4Tcp("10.0.0.2", "203.0.113.20", 52001U, 443U,
                               9001U + static_cast<std::uint32_t>(kMaxTcpReassemblyBytes), 0x18U, {0x16U}));
    engine.processBatch(overrun.data(), overrun.size(), 70'001U);
    const auto limitEvents = engine.takeEvents();
    CHECK(std::any_of(limitEvents.begin(), limitEvents.end(), [](const InspectionEvent& event) {
        return event.status == "REASSEMBLY_OVERLAP_OR_LIMIT";
    }));
}

void testTcpDnsFramingAndMalformedClientHello() {
    const auto dns = dnsQuery();
    std::vector<std::uint8_t> frame{static_cast<std::uint8_t>((dns.size() >> 8U) & 0xffU),
                                    static_cast<std::uint8_t>(dns.size() & 0xffU)};
    frame.insert(frame.end(), dns.begin(), dns.end());
    const std::size_t split = 6U;
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 53001U, 53U, 7000U, 0x02U));
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 53001U, 53U, 7001U, 0x18U,
                             std::vector<std::uint8_t>(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(split))));
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 53001U, 53U,
                             7001U + static_cast<std::uint32_t>(split), 0x18U,
                             std::vector<std::uint8_t>(frame.begin() + static_cast<std::ptrdiff_t>(split), frame.end())));
    PacketEngine engine;
    engine.processBatch(batch.data(), batch.size(), 80'000U);
    const auto events = engine.takeEvents();
    CHECK(std::any_of(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::Dns && event.source == "TUN_TCP_DNS" && event.hostname == "example.com";
    }));

    auto malformed = clientHello();
    malformed[3] = 0xffU; malformed[4] = 0xffU; // declared record exceeds parser window
    std::vector<std::uint8_t> malformedBatch;
    addPacket(malformedBatch, ipv4Tcp("10.0.0.4", "203.0.113.21", 53002U, 443U, 900U, 0x02U));
    addPacket(malformedBatch, ipv4Tcp("10.0.0.4", "203.0.113.21", 53002U, 443U, 901U, 0x18U, malformed));
    engine.processBatch(malformedBatch.data(), malformedBatch.size(), 80'001U);
    const auto badEvents = engine.takeEvents();
    CHECK(std::none_of(badEvents.begin(), badEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    }));
    CHECK(std::any_of(badEvents.begin(), badEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsParseStatus && event.status == "MALFORMED_OR_LIMIT_EXCEEDED";
    }));
}

void testTcpReassemblyTimeoutAndTableBound() {
    PacketEngine engine;
    const auto hello = clientHello();
    std::vector<std::uint8_t> first;
    addPacket(first, ipv4Tcp("10.0.0.2", "203.0.113.20", 54000U, 443U, 12000U, 0x02U));
    addPacket(first, ipv4Tcp("10.0.0.2", "203.0.113.20", 54000U, 443U, 12001U, 0x18U,
                             std::vector<std::uint8_t>(hello.begin(), hello.begin() + 10)));
    engine.processBatch(first.data(), first.size(), 100'000U);
    const std::vector<std::uint8_t> tail(hello.begin() + 10, hello.end());
    std::vector<std::uint8_t> afterTimeout;
    addPacket(afterTimeout, ipv4Tcp("10.0.0.2", "203.0.113.20", 54000U, 443U, 12011U, 0x18U, tail));
    engine.processBatch(afterTimeout.data(), afterTimeout.size(), 221'000U);
    const auto timedOutEvents = engine.takeEvents();
    CHECK(std::none_of(timedOutEvents.begin(), timedOutEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    }));

    std::vector<std::uint8_t> batch;
    for (std::uint32_t i = 0; i < kTcpFlowCapacity + 1U; ++i) {
        const auto port = static_cast<std::uint16_t>(20000U + i);
        addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.20", port, 443U, 30000U + i, 0x02U));
    }
    const auto stats = engine.processBatch(batch.data(), batch.size(), 222'000U);
    CHECK(engine.reassemblyEvictions() >= 1U);
    CHECK(stats.evictions >= 1U);
}

void testOrdinaryTcpDoesNotConsumeInspectionReassemblyCapacity() {
    PacketEngine engine;
    std::vector<std::uint8_t> batch;
    for (std::uint32_t i = 0; i < kTcpFlowCapacity + 1U; ++i) {
        const auto clientPort = static_cast<std::uint16_t>(20000U + i);
        addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.80", clientPort, 80U,
                                 1000U + i, 0x02U));
    }
    engine.processBatch(batch.data(), batch.size(), 90'000U);
    CHECK(engine.reassemblyEvictions() == 0U);

    // A normal HTTP payload remains in the IP-flow table but is not sent to TLS reassembly.
    std::vector<std::uint8_t> http;
    const std::vector<std::uint8_t> request{'G','E','T',' ','/',' ','H','T','T','P','/','1','.','1','\r','\n'};
    addPacket(http, ipv4Tcp("10.0.0.2", "203.0.113.80", 20'500U, 80U, 5000U, 0x18U, request));
    engine.processBatch(http.data(), http.size(), 90'001U);
    CHECK(engine.reassemblyEvictions() == 0U);
    CHECK(engine.takeEvents().empty());
}

void testHttpTcpDoesNotGenerateTlsEventsAndPacketTimestampsArePreserved() {
    PacketEngine engine;
    std::vector<std::uint8_t> batch;
    const std::vector<std::uint8_t> http{'G','E','T',' ','/',' ','H','T','T','P','/','1','.','1','\r','\n'};
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.30", 55000U, 80U, 0U, 0x02U));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.30", 55000U, 80U, 1U, 0x18U, http));
    const std::uint64_t timestamps[]{101U, 125U};
    engine.processBatch(batch.data(), batch.size(), 999U, timestamps, 2U);
    const auto ordinaryEvents = engine.takeEvents();
    CHECK(std::none_of(ordinaryEvents.begin(), ordinaryEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello || event.kind == InspectionEventKind::TlsParseStatus;
    }));

    const auto dns = dnsQuery();
    std::vector<std::uint8_t> packet(20U + 8U + dns.size(), 0U);
    packet[0] = 0x45U;
    put16(packet, 2U, static_cast<std::uint16_t>(packet.size()));
    packet[8] = 64U;
    packet[9] = 17U;
    packet[12] = 10U; packet[15] = 2U;
    packet[16] = 8U; packet[17] = 8U; packet[18] = 8U; packet[19] = 8U;
    put16(packet, 20U, 53001U); put16(packet, 22U, 53U);
    put16(packet, 24U, static_cast<std::uint16_t>(8U + dns.size()));
    std::copy(dns.begin(), dns.end(), packet.begin() + 28);
    std::vector<std::uint8_t> dnsBatch;
    addPacket(dnsBatch, packet);
    const std::uint64_t dnsTimestamp[]{3456U};
    engine.processBatch(dnsBatch.data(), dnsBatch.size(), 7777U, dnsTimestamp, 1U);
    const auto dnsEvents = engine.takeEvents();
    CHECK(dnsEvents.size() == 1U);
    if (!dnsEvents.empty()) CHECK(dnsEvents[0].timestampMs == 3456U);
}

void testTcpInitialSequenceZeroAndDnsParseStatus() {
    const auto hello = clientHello();
    PacketEngine engine;
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.31", 56000U, 443U, 0U, 0x02U));
    addPacket(batch, ipv4Tcp("10.0.0.2", "203.0.113.31", 56000U, 443U, 1U, 0x18U,
                             std::vector<std::uint8_t>(hello.begin(), hello.end())));
    engine.processBatch(batch.data(), batch.size(), 2000U);
    const auto events = engine.takeEvents();
    CHECK(std::count_if(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello && event.hostname == "example.com";
    }) == 1);

    // Even if an ECH outer ClientHello includes a cover name in server_name, live events must not
    // publish it as the origin hostname.
    PacketEngine echEngine;
    const auto echHello = clientHello(true);
    std::vector<std::uint8_t> echBatch;
    addPacket(echBatch, ipv4Tcp("10.0.0.2", "203.0.113.31", 56001U, 443U, 0U, 0x02U));
    addPacket(echBatch, ipv4Tcp("10.0.0.2", "203.0.113.31", 56001U, 443U, 1U, 0x18U,
                                std::vector<std::uint8_t>(echHello.begin(), echHello.end())));
    echEngine.processBatch(echBatch.data(), echBatch.size(), 2001U);
    const auto echEvents = echEngine.takeEvents();
    const auto echEvent = std::find_if(echEvents.begin(), echEvents.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::TlsClientHello;
    });
    CHECK(echEvent != echEvents.end());
    if (echEvent != echEvents.end()) {
        CHECK(echEvent->hostname.empty());
        CHECK(echEvent->status == "ECH_EXTENSION_PRESENT_SNI_SUPPRESSED");
        CHECK(echEvent->alpn == "h2");
    }
}

void testUdpDnsMalformedAndFragmentEvents() {
    auto dns = dnsQuery();
    dns[4] = 0U;
    dns[5] = 0U; // Deliberately invalid for this query parser: no question section.
    auto makeDnsPacket = [&dns](bool fragmented) {
        std::vector<std::uint8_t> packet(28U + dns.size(), 0U);
        packet[0] = 0x45U;
        put16(packet, 2U, static_cast<std::uint16_t>(packet.size()));
        if (fragmented) put16(packet, 6U, 0x2000U); // Initial IPv4 fragment, MF set.
        packet[8] = 64U;
        packet[9] = 17U;
        packet[12] = 10U; packet[15] = 2U;
        packet[16] = 8U; packet[17] = 8U; packet[18] = 8U; packet[19] = 8U;
        put16(packet, 20U, 54000U); put16(packet, 22U, 53U);
        put16(packet, 24U, static_cast<std::uint16_t>(8U + dns.size()));
        std::copy(dns.begin(), dns.end(), packet.begin() + 28);
        return packet;
    };
    PacketEngine engine;
    std::vector<std::uint8_t> malformedBatch;
    addPacket(malformedBatch, makeDnsPacket(false));
    engine.processBatch(malformedBatch.data(), malformedBatch.size(), 3000U);
    auto events = engine.takeEvents();
    CHECK(events.size() == 1U);
    if (!events.empty()) {
        CHECK(events[0].kind == InspectionEventKind::DnsParseStatus);
        CHECK(events[0].status == "MALFORMED_OR_TRUNCATED_DNS");
        CHECK(events[0].source == "TUN_UDP_DNS");
    }

    std::vector<std::uint8_t> fragmentedBatch;
    addPacket(fragmentedBatch, makeDnsPacket(true));
    engine.processBatch(fragmentedBatch.data(), fragmentedBatch.size(), 3001U);
    events = engine.takeEvents();
    CHECK(events.size() == 1U);
    if (!events.empty()) {
        CHECK(events[0].kind == InspectionEventKind::DnsParseStatus);
        CHECK(events[0].status == "FRAGMENTED_DNS_NOT_REASSEMBLED");
    }
}

void testTcpDnsReassemblyErrorIsDnsStatus() {
    const auto dns = dnsQuery();
    std::vector<std::uint8_t> frame{static_cast<std::uint8_t>((dns.size() >> 8U) & 0xffU),
                                    static_cast<std::uint8_t>(dns.size() & 0xffU)};
    frame.insert(frame.end(), dns.begin(), dns.end());
    std::vector<std::uint8_t> batch;
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 54001U, 53U, 100U, 0x02U));
    const std::vector<std::uint8_t> prefix(frame.begin(), frame.begin() + 8);
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 54001U, 53U, 101U, 0x18U, prefix));
    auto conflicting = prefix;
    conflicting[4] ^= 0x7fU;
    addPacket(batch, ipv4Tcp("10.0.0.2", "198.51.100.53", 54001U, 53U, 101U, 0x18U, conflicting));
    PacketEngine engine;
    engine.processBatch(batch.data(), batch.size(), 4000U);
    const auto events = engine.takeEvents();
    CHECK(std::any_of(events.begin(), events.end(), [](const InspectionEvent& event) {
        return event.kind == InspectionEventKind::DnsParseStatus &&
               event.status == "REASSEMBLY_OVERLAP_OR_LIMIT" && event.source == "TUN_TCP_DNS";
    }));
}

void testPcapFormatAndRotation() {
    const std::string base = "/tmp/netcontrol-pcap-test";
    std::remove((base + ".000.pcap").c_str());
    std::remove((base + ".001.pcap").c_str());
    const auto packet = ipv4Udp(12345U);
    RotatingPcapWriter writer(base, 24U + 16U + packet.size(), 2U);
    CHECK(writer.open());
    CHECK(writer.bytesWritten() == 24U);
    CHECK(writer.writePacket(1'234'567U, packet.data(), packet.size(), packet.size()));
    CHECK(writer.bytesWritten() == 24U + 16U + packet.size());
    CHECK(writer.writePacket(2'234'567U, packet.data(), packet.size(), packet.size()));
    CHECK(writer.currentIndex() == 1U);
    CHECK(writer.writePacket(3'234'567U, packet.data(), packet.size(), packet.size()));
    CHECK(writer.currentIndex() == 0U);
    writer.close();

    std::ifstream input(base + ".000.pcap", std::ios::binary);
    std::vector<std::uint8_t> file((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    CHECK(file.size() == 24U + 16U + packet.size());
    CHECK(file.size() >= 24U);
    if (file.size() >= 24U) {
        CHECK(file[0] == 0xd4U && file[1] == 0xc3U && file[2] == 0xb2U && file[3] == 0xa1U);
        CHECK(file[4] == 2U && file[5] == 0U && file[6] == 4U && file[7] == 0U);
        CHECK(file[20] == 0x65U && file[21] == 0U && file[22] == 0U && file[23] == 0U); // DLT_RAW
    }
    std::remove((base + ".000.pcap").c_str());
    std::remove((base + ".001.pcap").c_str());
}

}  // namespace

int main() {
    testIpv4UdpAndTruncation();
    testIpv6Udp();
    testTcpHeaderValidation();
    testDns();
    testTlsFragmentedClientHello();
    testBoundedFlowTableAndBatch();
    testLiveDnsObservationFromUdpPackets();
    testTcpReassemblyOutOfOrderOverlapAndRetransmission();
    testTcpReassemblyDoesNotMixFlowsOrDirections();
    testTcpReassemblyConflictingOverlapAndWindowLimit();
    testTcpDnsFramingAndMalformedClientHello();
    testTcpReassemblyTimeoutAndTableBound();
    testOrdinaryTcpDoesNotConsumeInspectionReassemblyCapacity();
    testHttpTcpDoesNotGenerateTlsEventsAndPacketTimestampsArePreserved();
    testTcpInitialSequenceZeroAndDnsParseStatus();
    testUdpDnsMalformedAndFragmentEvents();
    testTcpDnsReassemblyErrorIsDnsStatus();
    testPcapFormatAndRotation();
    if (failures != 0) {
        std::cerr << failures << " test assertion(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "All native NetControl tests passed\n";
    return EXIT_SUCCESS;
}
