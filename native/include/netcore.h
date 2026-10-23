#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <bitset>
#include <deque>
#include <vector>
#include <memory>

namespace netcontrol {

constexpr std::size_t kFlowCapacity = 256;
constexpr std::size_t kAddressSize = 46;
constexpr std::size_t kMaxTlsRecordBuffer = 16 * 1024;
constexpr std::size_t kMaxTcpReassemblyBytes = 16 * 1024;
constexpr std::size_t kTcpFlowCapacity = 128;
constexpr std::size_t kMaxInspectionEvents = 256;
constexpr std::size_t kMaxDnsTcpMessageBytes = 4096;

enum class ParseStatus : std::uint8_t { Ok, Malformed, Unsupported };

struct PacketInfo {
    std::uint8_t ipVersion{0};
    std::uint8_t protocol{0};
    char source[kAddressSize]{};
    char destination[kAddressSize]{};
    std::uint16_t sourcePort{0};
    std::uint16_t destinationPort{0};
    std::size_t payloadOffset{0};
    std::size_t payloadLength{0};
    std::size_t totalLength{0};
    bool hasPorts{false};
    bool fragmented{false};
    std::uint32_t tcpSequence{0};
    std::uint32_t tcpAcknowledgement{0};
    std::uint8_t tcpFlags{0};
};

ParseStatus parseIpPacket(const std::uint8_t* data, std::size_t length, PacketInfo& out) noexcept;

struct DnsInfo {
    char name[254]{};
    std::uint16_t recordType{0};
    std::uint8_t responseCode{0};
    bool isResponse{false};
    std::uint16_t transactionId{0};
};

ParseStatus parseDnsMessage(const std::uint8_t* data, std::size_t length, DnsInfo& out) noexcept;

enum class TlsStatus : std::uint8_t { NeedMore, ClientHello, NotClientHello, Malformed };

struct TlsClientHelloInfo {
    char sni[254]{};
    char alpn[128]{};
    std::uint16_t legacyVersion{0};
    // If the ECH extension is present, the server_name extension may only contain an outer
    // cover name. Do not expose that value as an authoritative hostname.
    bool echPresent{false};
};

class TlsClientHelloParser {
public:
    TlsStatus feed(const std::uint8_t* data, std::size_t length, TlsClientHelloInfo& out) noexcept;
    void reset() noexcept;

private:
    TlsStatus consumeRecords(TlsClientHelloInfo& out) noexcept;
    TlsStatus parseClientHello(const std::uint8_t* body, std::size_t length, TlsClientHelloInfo& out) noexcept;
    std::array<std::uint8_t, kMaxTlsRecordBuffer> input_{};
    std::size_t inputLength_{0};
    std::array<std::uint8_t, kMaxTlsRecordBuffer> handshake_{};
    std::size_t handshakeLength_{0};
    bool finished_{false};
};

struct FlowEntry {
    bool valid{false};
    std::uint8_t ipVersion{0};
    std::uint8_t protocol{0};
    char source[kAddressSize]{};
    char destination[kAddressSize]{};
    std::uint16_t sourcePort{0};
    std::uint16_t destinationPort{0};
    bool hasPorts{false};
    std::uint64_t firstSeenMs{0};
    std::uint64_t lastSeenMs{0};
    // IP total-length bytes relative to the direction of the first observed packet. These are
    // neither proxy payload bytes nor guaranteed app-upload/download counters.
    std::uint64_t bytesForward{0};
    std::uint64_t bytesReverse{0};
    std::uint64_t packets{0};
    std::uint64_t generation{0};
    std::uint32_t initialTcpSequence{0};
    bool initialTcpSequenceKnown{false};
    std::uint8_t lastTcpFlags{0};
    std::uint8_t tcpFinMask{0};
};


enum class InspectionEventKind : std::uint8_t { Dns, DnsParseStatus, TlsClientHello, TlsParseStatus };

/** A bounded observation produced from the raw IP packets captured at the TUN boundary. */
struct InspectionEvent {
    InspectionEventKind kind{InspectionEventKind::Dns};
    std::uint64_t timestampMs{0};
    std::uint64_t flowId{0}; // Native IP/TCP ID; deliberately not a SOCKS proxy flow ID.
    std::uint8_t ipVersion{0};
    std::uint8_t protocol{0};
    std::string sourceAddress;
    std::string destinationAddress;
    std::uint16_t sourcePort{0};
    std::uint16_t destinationPort{0};
    std::string hostname;
    std::string alpn;
    std::string status;
    std::string source;
    std::uint16_t dnsType{0};
    std::uint8_t dnsResponseCode{0};
    std::uint16_t dnsTransactionId{0};
    bool dnsResponse{false};
};

class FlowTable {
public:
    void observe(const PacketInfo& packet, std::uint64_t timestampMs) noexcept;
    std::size_t size() const noexcept { return size_; }
    std::uint64_t evictions() const noexcept { return evictions_; }
    const std::array<FlowEntry, kFlowCapacity>& entries() const noexcept { return entries_; }
    void clear() noexcept;

private:
    std::array<FlowEntry, kFlowCapacity> entries_{};
    std::size_t size_{0};
    std::uint64_t sequence_{0};
    std::uint64_t evictions_{0};
};

struct EngineStats {
    std::uint64_t processed{0};
    std::uint64_t malformed{0};
    std::uint64_t ipv4{0};
    std::uint64_t ipv6{0};
    std::uint64_t evictions{0};
    std::uint64_t errors{0};
};

class PacketEngine {
public:
    PacketEngine();
    PacketEngine(const PacketEngine&) = delete;
    PacketEngine& operator=(const PacketEngine&) = delete;
    // Framing is repeated [uint16 big-endian packet length][packet bytes]. The simple overload
    // assigns one timestamp to the batch; the timestamped overload preserves each observed packet's
    // TUN arrival time when available.
    EngineStats processBatch(const std::uint8_t* data, std::size_t length, std::uint64_t timestampMs);
    EngineStats processBatch(const std::uint8_t* data, std::size_t length, std::uint64_t fallbackTimestampMs,
                             const std::uint64_t* packetTimestampsMs, std::size_t timestampCount);
    const FlowTable& flows() const noexcept { return flows_; }
    std::vector<InspectionEvent> takeEvents();
    std::uint64_t reassemblyEvictions() const noexcept { return reassemblyEvictions_; }
    void reset() noexcept;

private:
    struct DirectionBuffer {
        bool initialized{false};
        std::uint32_t baseSequence{0};
        std::size_t contiguous{0};
        std::size_t delivered{0};
        std::array<std::uint8_t, kMaxTcpReassemblyBytes> bytes{};
        std::bitset<kMaxTcpReassemblyBytes> present{};

        void initialize(std::uint32_t sequence) noexcept;
        // Returns false on an ambiguous overlap or a bounded-window violation.
        bool insert(std::uint32_t sequence, const std::uint8_t* data, std::size_t length,
                    std::size_t& newOffset, std::size_t& newLength) noexcept;
    };

    struct TcpFlowState {
        bool valid{false};
        bool clientKnown{false};
        bool clientSequenceKnown{false};
        bool tlsExpected{false};
        bool tlsCandidate{false};
        bool tlsComplete{false};
        bool tlsAttempted{false};
        bool reassemblyTainted{false};
        std::uint8_t ipVersion{0};
        std::uint8_t protocol{6};
        std::string clientAddress;
        std::string serverAddress;
        std::uint16_t clientPort{0};
        std::uint16_t serverPort{0};
        std::uint32_t initialClientSequence{0};
        std::uint64_t id{0};
        std::uint64_t firstSeenMs{0};
        std::uint64_t lastSeenMs{0};
        DirectionBuffer clientToServer;
        DirectionBuffer serverToClient;
        TlsClientHelloParser tlsParser;
        std::array<std::uint8_t, kMaxDnsTcpMessageBytes> clientDnsBuffer{};
        std::size_t clientDnsBufferLength{0};
        std::array<std::uint8_t, kMaxDnsTcpMessageBytes> serverDnsBuffer{};
        std::size_t serverDnsBufferLength{0};
        bool dnsTcp{false};
    };

    void observePacket(const std::uint8_t* data, std::size_t length,
                       const PacketInfo& packet, std::uint64_t timestampMs);
    TcpFlowState* getTcpFlow(const PacketInfo& packet, const std::uint8_t* data,
                             std::uint64_t timestampMs, bool& fromClient);
    void processTcpStream(TcpFlowState& flow, bool fromClient, const std::uint8_t* data,
                          std::size_t length, std::uint64_t timestampMs);
    void processDnsTcpBytes(TcpFlowState& flow, bool fromClient, const std::uint8_t* data,
                            std::size_t length, std::uint64_t timestampMs);
    void emitDns(const PacketInfo& packet, const DnsInfo& dns, std::uint64_t timestampMs,
                 std::uint64_t flowId, const char* source);
    void emitEvent(InspectionEvent event);
    void expireTcpFlows(std::uint64_t timestampMs) noexcept;

    FlowTable flows_{};
    EngineStats stats_{};
    std::unique_ptr<TcpFlowState[]> tcpFlows_;
    std::deque<InspectionEvent> events_{};
    std::uint64_t nextInspectionFlowId_{1};
    std::uint64_t reassemblyEvictions_{0};
};

class RotatingPcapWriter {
public:
    RotatingPcapWriter(std::string basePath, std::uint64_t maxFileBytes, std::size_t maxFiles,
                       std::uint32_t snapLength = 65535U, std::uint32_t linkType = 101U);
    ~RotatingPcapWriter();
    RotatingPcapWriter(const RotatingPcapWriter&) = delete;
    RotatingPcapWriter& operator=(const RotatingPcapWriter&) = delete;

    bool open() noexcept;
    bool writePacket(std::uint64_t timestampMicros, const std::uint8_t* packet,
                     std::size_t capturedLength, std::size_t originalLength) noexcept;
    void close() noexcept;
    std::uint64_t bytesWritten() const noexcept { return bytesWritten_; }
    std::uint64_t packetsWritten() const noexcept { return packetsWritten_; }
    std::size_t currentIndex() const noexcept { return fileIndex_; }
    const std::string& currentPath() const noexcept { return currentPath_; }

private:
    bool openIndex(std::size_t index) noexcept;
    bool writeGlobalHeader() noexcept;
    bool writeLittleEndian(std::uint32_t value) noexcept;
    bool writeLittleEndian16(std::uint16_t value) noexcept;
    std::string pathFor(std::size_t index) const;

    std::string basePath_;
    std::string currentPath_;
    std::uint64_t maxFileBytes_;
    std::size_t maxFiles_;
    std::uint32_t snapLength_;
    std::uint32_t linkType_;
    std::size_t fileIndex_{0};
    std::uint64_t bytesWritten_{0};
    std::uint64_t packetsWritten_{0};
    std::ofstream output_;
    bool open_{false};
};

}  // namespace netcontrol
