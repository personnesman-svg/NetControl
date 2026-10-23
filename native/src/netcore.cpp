#include "netcore.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <utility>
#include <cstdint>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace netcontrol {
namespace {

std::uint16_t be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
}

std::uint32_t be24(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 16U) |
           (static_cast<std::uint32_t>(p[1]) << 8U) | static_cast<std::uint32_t>(p[2]);
}

bool copyAddress(int family, const void* bytes, char* destination, std::size_t destinationSize) noexcept {
    destination[0] = '\0';
    return inet_ntop(family, bytes, destination, static_cast<socklen_t>(destinationSize)) != nullptr;
}

bool parseTransport(const std::uint8_t* data, std::size_t length, PacketInfo& out,
                    std::size_t transportOffset, bool fragmentHasOffset) noexcept {
    out.payloadOffset = transportOffset;
    if (fragmentHasOffset) {
        out.payloadLength = length - transportOffset;
        return true;
    }
    if (out.protocol == 6U) {
        if (length - transportOffset < 20U) return false;
        const std::size_t tcpHeaderLength = static_cast<std::size_t>(data[transportOffset + 12U] >> 4U) * 4U;
        if (tcpHeaderLength < 20U || tcpHeaderLength > length - transportOffset) return false;
        out.sourcePort = be16(data + transportOffset);
        out.destinationPort = be16(data + transportOffset + 2U);
        out.tcpSequence = (static_cast<std::uint32_t>(data[transportOffset + 4U]) << 24U) |
                          (static_cast<std::uint32_t>(data[transportOffset + 5U]) << 16U) |
                          (static_cast<std::uint32_t>(data[transportOffset + 6U]) << 8U) |
                           static_cast<std::uint32_t>(data[transportOffset + 7U]);
        out.tcpAcknowledgement = (static_cast<std::uint32_t>(data[transportOffset + 8U]) << 24U) |
                                 (static_cast<std::uint32_t>(data[transportOffset + 9U]) << 16U) |
                                 (static_cast<std::uint32_t>(data[transportOffset + 10U]) << 8U) |
                                  static_cast<std::uint32_t>(data[transportOffset + 11U]);
        out.tcpFlags = data[transportOffset + 13U];
        out.hasPorts = true;
        out.payloadOffset = transportOffset + tcpHeaderLength;
    } else if (out.protocol == 17U) {
        if (length - transportOffset < 8U) return false;
        const std::size_t udpLength = be16(data + transportOffset + 4U);
        if (udpLength < 8U || (!out.fragmented && udpLength > length - transportOffset)) return false;
        out.sourcePort = be16(data + transportOffset);
        out.destinationPort = be16(data + transportOffset + 2U);
        out.hasPorts = true;
        out.payloadOffset = transportOffset + 8U;
        out.payloadLength = std::min(udpLength, length - transportOffset) - 8U;
        return true;
    }
    out.payloadLength = length - out.payloadOffset;
    return true;
}

bool isDnsLabelCharacter(std::uint8_t c) noexcept {
    return c >= 0x21U && c <= 0x7eU && c != '.';
}

bool decodeDnsName(const std::uint8_t* data, std::size_t length, std::size_t start,
                   char* out, std::size_t outSize, std::size_t& consumed) noexcept {
    out[0] = '\0';
    consumed = 0;
    if (start >= length || outSize < 2U) return false;
    std::size_t pos = start;
    std::size_t outputLength = 0;
    std::size_t steps = 0;
    bool jumped = false;
    while (pos < length && ++steps <= 128U) {
        const std::uint8_t labelLength = data[pos];
        if ((labelLength & 0xc0U) == 0xc0U) {
            if (pos + 1U >= length) return false;
            const std::size_t pointer = static_cast<std::size_t>(((labelLength & 0x3fU) << 8U) | data[pos + 1U]);
            if (pointer >= length || pointer == pos) return false;
            if (!jumped) consumed += 2U;
            pos = pointer;
            jumped = true;
            continue;
        }
        if ((labelLength & 0xc0U) != 0U) return false;
        ++pos;
        if (!jumped) ++consumed;
        if (labelLength == 0U) {
            if (outputLength == 0U) {
                if (outSize < 2U) return false;
                out[outputLength++] = '.';
            }
            out[outputLength] = '\0';
            return true;
        }
        if (labelLength > 63U || pos + labelLength > length) return false;
        if (outputLength != 0U) {
            if (outputLength + 1U >= outSize) return false;
            out[outputLength++] = '.';
        }
        if (outputLength + labelLength >= outSize) return false;
        for (std::size_t i = 0; i < labelLength; ++i) {
            const auto c = data[pos + i];
            if (!isDnsLabelCharacter(c)) return false;
            out[outputLength++] = static_cast<char>(c);
        }
        pos += labelLength;
        if (!jumped) consumed += labelLength;
    }
    return false;
}

bool parseSniAlpn(const std::uint8_t* extensions, std::size_t extensionsLength,
                  TlsClientHelloInfo& out) noexcept {
    std::size_t pos = 0;
    while (pos < extensionsLength) {
        if (extensionsLength - pos < 4U) return false;
        const std::uint16_t extensionType = be16(extensions + pos);
        const std::size_t extensionLength = be16(extensions + pos + 2U);
        pos += 4U;
        if (extensionLength > extensionsLength - pos) return false;
        const auto* value = extensions + pos;
        if (extensionType == 0U) {  // server_name
            if (extensionLength < 5U) return false;
            const std::size_t listLength = be16(value);
            if (listLength != extensionLength - 2U) return false;
            std::size_t at = 2U;
            const std::size_t end = extensionLength;
            while (at < end) {
                if (end - at < 3U) return false;
                const std::uint8_t nameType = value[at];
                const std::size_t nameLength = be16(value + at + 1U);
                at += 3U;
                if (nameLength == 0U || nameLength > end - at) return false;
                if (nameType == 0U && nameLength < sizeof(out.sni)) {
                    bool valid = true;
                    for (std::size_t i = 0; i < nameLength; ++i) {
                        const auto c = value[at + i];
                        if (!(std::isalnum(c) || c == '-' || c == '.' || c == '_')) valid = false;
                    }
                    if (valid && out.sni[0] == '\0') {
                        std::memcpy(out.sni, value + at, nameLength);
                        out.sni[nameLength] = '\0';
                    }
                }
                at += nameLength;
            }
        } else if (extensionType == 0xfe0dU) {
            // Encrypted ClientHello (ECH). The visible SNI may be only the public cover name;
            // suppress it conservatively rather than presenting it as the true destination.
            out.echPresent = true;
        } else if (extensionType == 16U) {  // ALPN ProtocolNameList
            if (extensionLength < 3U) return false;
            const std::size_t listLength = be16(value);
            if (listLength != extensionLength - 2U || listLength < 1U) return false;
            std::size_t at = 2U;
            while (at < extensionLength) {
                const std::size_t nameLength = value[at++];
                if (nameLength == 0U || nameLength > extensionLength - at) return false;
                const std::size_t used = std::strlen(out.alpn);
                const std::size_t delimiterLength = used == 0U ? 0U : 1U;
                if (delimiterLength + nameLength >= sizeof(out.alpn) - used) return false;
                if (delimiterLength != 0U) out.alpn[used] = ',';
                const std::size_t destination = used + delimiterLength;
                for (std::size_t i = 0; i < nameLength; ++i) {
                    const auto c = value[at + i];
                    out.alpn[destination + i] = (c >= 0x21U && c <= 0x7eU && c != ',')
                        ? static_cast<char>(c) : '?';
                }
                out.alpn[destination + nameLength] = '\0';
                at += nameLength;
            }
        }
        pos += extensionLength;
    }
    return true;
}

}  // namespace

ParseStatus parseIpPacket(const std::uint8_t* data, std::size_t length, PacketInfo& out) noexcept {
    out = PacketInfo{};
    if (data == nullptr || length < 1U) return ParseStatus::Malformed;
    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4U);
    if (version == 4U) {
        if (length < 20U) return ParseStatus::Malformed;
        const std::size_t headerLength = static_cast<std::size_t>(data[0] & 0x0fU) * 4U;
        const std::size_t totalLength = be16(data + 2U);
        if (headerLength < 20U || headerLength > length || totalLength < headerLength || totalLength > length) return ParseStatus::Malformed;
        out.ipVersion = 4U;
        out.protocol = data[9];
        out.totalLength = totalLength;
        if (!copyAddress(AF_INET, data + 12U, out.source, sizeof(out.source)) ||
            !copyAddress(AF_INET, data + 16U, out.destination, sizeof(out.destination))) return ParseStatus::Malformed;
        const std::uint16_t fragment = be16(data + 6U);
        const bool offsetNonZero = (fragment & 0x1fffU) != 0U;
        out.fragmented = offsetNonZero || ((fragment & 0x2000U) != 0U);
        if (!parseTransport(data, totalLength, out, headerLength, offsetNonZero)) return ParseStatus::Malformed;
        return ParseStatus::Ok;
    }
    if (version == 6U) {
        if (length < 40U) return ParseStatus::Malformed;
        const std::size_t payloadLength = be16(data + 4U);
        const std::size_t totalLength = 40U + payloadLength;
        if (totalLength > length || payloadLength == 0U) return ParseStatus::Malformed;  // jumbograms not supported
        out.ipVersion = 6U;
        out.totalLength = totalLength;
        if (!copyAddress(AF_INET6, data + 8U, out.source, sizeof(out.source)) ||
            !copyAddress(AF_INET6, data + 24U, out.destination, sizeof(out.destination))) return ParseStatus::Malformed;
        std::uint8_t nextHeader = data[6];
        std::size_t offset = 40U;
        bool nonInitialFragment = false;
        unsigned extensionCount = 0;
        while (nextHeader == 0U || nextHeader == 43U || nextHeader == 44U || nextHeader == 51U || nextHeader == 60U) {
            if (++extensionCount > 8U || offset + 2U > totalLength) return ParseStatus::Malformed;
            const std::uint8_t current = nextHeader;
            nextHeader = data[offset];
            std::size_t extensionLength = 0;
            if (current == 44U) {
                extensionLength = 8U;
                if (offset + extensionLength > totalLength) return ParseStatus::Malformed;
                const std::uint16_t fragmentBits = be16(data + offset + 2U);
                nonInitialFragment = (fragmentBits & 0xfff8U) != 0U;
                out.fragmented = nonInitialFragment || ((fragmentBits & 1U) != 0U);
            } else if (current == 51U) {
                extensionLength = (static_cast<std::size_t>(data[offset + 1U]) + 2U) * 4U;
            } else {
                extensionLength = (static_cast<std::size_t>(data[offset + 1U]) + 1U) * 8U;
            }
            if (extensionLength < 8U || extensionLength > totalLength - offset) return ParseStatus::Malformed;
            offset += extensionLength;
            if (current == 44U && nonInitialFragment) break;
        }
        out.protocol = nextHeader;
        if (!parseTransport(data, totalLength, out, offset, nonInitialFragment)) return ParseStatus::Malformed;
        return ParseStatus::Ok;
    }
    return ParseStatus::Unsupported;
}

ParseStatus parseDnsMessage(const std::uint8_t* data, std::size_t length, DnsInfo& out) noexcept {
    out = DnsInfo{};
    if (data == nullptr || length < 12U) return ParseStatus::Malformed;
    const std::uint16_t flags = be16(data + 2U);
    const std::uint16_t questions = be16(data + 4U);
    if (questions == 0U) return ParseStatus::Malformed;
    std::size_t consumed = 0;
    if (!decodeDnsName(data, length, 12U, out.name, sizeof(out.name), consumed)) return ParseStatus::Malformed;
    if (consumed > length - 12U) return ParseStatus::Malformed;
    const std::size_t questionTail = 12U + consumed;
    if (questionTail > length || length - questionTail < 4U) return ParseStatus::Malformed;
    out.transactionId = be16(data);
    out.recordType = be16(data + questionTail);
    out.responseCode = static_cast<std::uint8_t>(flags & 0x0fU);
    out.isResponse = (flags & 0x8000U) != 0U;
    return ParseStatus::Ok;
}

TlsStatus TlsClientHelloParser::feed(const std::uint8_t* data, std::size_t length, TlsClientHelloInfo& out) noexcept {
    if (finished_) return TlsStatus::NotClientHello;
    if (data == nullptr && length != 0U) return TlsStatus::Malformed;
    if (length > input_.size() - inputLength_) return TlsStatus::Malformed;
    if (length != 0U) {
        std::memcpy(input_.data() + inputLength_, data, length);
        inputLength_ += length;
    }
    return consumeRecords(out);
}

TlsStatus TlsClientHelloParser::consumeRecords(TlsClientHelloInfo& out) noexcept {
    while (inputLength_ >= 5U) {
        const std::uint8_t contentType = input_[0];
        const std::size_t recordLength = be16(input_.data() + 3U);
        if (recordLength > input_.size() - 5U) return TlsStatus::Malformed;
        const std::size_t fullRecordLength = 5U + recordLength;
        if (inputLength_ < fullRecordLength) return TlsStatus::NeedMore;
        if (contentType != 22U) {
            finished_ = true;
            return TlsStatus::NotClientHello;
        }
        if (recordLength > handshake_.size() - handshakeLength_) return TlsStatus::Malformed;
        std::memcpy(handshake_.data() + handshakeLength_, input_.data() + 5U, recordLength);
        handshakeLength_ += recordLength;
        inputLength_ -= fullRecordLength;
        if (inputLength_ > 0U) std::memmove(input_.data(), input_.data() + fullRecordLength, inputLength_);
        if (handshakeLength_ >= 1U && handshake_[0] != 1U) {
            finished_ = true;
            return TlsStatus::NotClientHello;
        }
        if (handshakeLength_ >= 4U) {
            const std::size_t bodyLength = be24(handshake_.data() + 1U);
            if (bodyLength > handshake_.size() - 4U) return TlsStatus::Malformed;
            if (handshakeLength_ >= bodyLength + 4U) {
                const auto result = parseClientHello(handshake_.data() + 4U, bodyLength, out);
                finished_ = true;
                return result == TlsStatus::ClientHello ? result : TlsStatus::Malformed;
            }
        }
    }
    return TlsStatus::NeedMore;
}

TlsStatus TlsClientHelloParser::parseClientHello(const std::uint8_t* body, std::size_t length, TlsClientHelloInfo& out) noexcept {
    out = TlsClientHelloInfo{};
    if (body == nullptr || length < 34U) return TlsStatus::Malformed;
    out.legacyVersion = be16(body);
    std::size_t pos = 34U;  // legacy_version + random
    if (pos >= length) return TlsStatus::Malformed;
    const std::size_t sessionLength = body[pos++];
    if (sessionLength > length - pos) return TlsStatus::Malformed;
    pos += sessionLength;
    if (length - pos < 2U) return TlsStatus::Malformed;
    const std::size_t cipherLength = be16(body + pos);
    pos += 2U;
    if (cipherLength == 0U || (cipherLength % 2U) != 0U || cipherLength > length - pos) return TlsStatus::Malformed;
    pos += cipherLength;
    if (pos >= length) return TlsStatus::Malformed;
    const std::size_t compressionLength = body[pos++];
    if (compressionLength == 0U || compressionLength > length - pos) return TlsStatus::Malformed;
    pos += compressionLength;
    if (pos == length) return TlsStatus::ClientHello;  // legal ClientHello without extensions
    if (length - pos < 2U) return TlsStatus::Malformed;
    const std::size_t extensionsLength = be16(body + pos);
    pos += 2U;
    if (extensionsLength != length - pos) return TlsStatus::Malformed;
    if (!parseSniAlpn(body + pos, extensionsLength, out)) return TlsStatus::Malformed;
    if (out.echPresent) out.sni[0] = '\0';
    return TlsStatus::ClientHello;
}

void TlsClientHelloParser::reset() noexcept {
    inputLength_ = 0;
    handshakeLength_ = 0;
    finished_ = false;
    input_.fill(0);
    handshake_.fill(0);
}

void FlowTable::observe(const PacketInfo& packet, std::uint64_t timestampMs) noexcept {
    ++sequence_;

    // Expire stale tuples before looking them up. The table is an IP-packet observation table,
    // not the SOCKS proxy's connection list; idle expiration prevents old tuples being treated
    // as live connections forever and limits incorrect reuse of source ports.
    for (auto& entry : entries_) {
        if (!entry.valid || timestampMs < entry.lastSeenMs) continue;
        const std::uint64_t idleLimit = entry.protocol == 6U ? 300'000U : 60'000U;
        if (timestampMs - entry.lastSeenMs > idleLimit) {
            entry.valid = false;
            if (size_ > 0U) --size_;
        }
    }

    FlowEntry* selected = nullptr;
    bool reversed = false;
    for (auto& entry : entries_) {
        if (!entry.valid || entry.ipVersion != packet.ipVersion || entry.protocol != packet.protocol || entry.hasPorts != packet.hasPorts) continue;
        const bool sameForward = entry.sourcePort == packet.sourcePort && entry.destinationPort == packet.destinationPort &&
            std::strncmp(entry.source, packet.source, kAddressSize) == 0 &&
            std::strncmp(entry.destination, packet.destination, kAddressSize) == 0;
        const bool sameReverse = entry.sourcePort == packet.destinationPort && entry.destinationPort == packet.sourcePort &&
            std::strncmp(entry.source, packet.destination, kAddressSize) == 0 &&
            std::strncmp(entry.destination, packet.source, kAddressSize) == 0;
        if (sameForward || sameReverse) {
            selected = &entry;
            reversed = !sameForward && sameReverse;
            // A new SYN with a different initial sequence on the same client tuple is a new TCP
            // connection (source-port reuse), not another packet in the old flow.
            if (packet.protocol == 6U && sameForward && (packet.tcpFlags & 0x02U) != 0U &&
                (packet.tcpFlags & 0x10U) == 0U && entry.initialTcpSequenceKnown &&
                entry.initialTcpSequence != packet.tcpSequence) {
                *selected = FlowEntry{};
                selected = nullptr;
                if (size_ > 0U) --size_;
            }
            break;
        }
    }
    if (selected == nullptr) {
        for (auto& entry : entries_) {
            if (!entry.valid) {
                selected = &entry;
                ++size_;
                break;
            }
        }
    }
    if (selected == nullptr) {
        selected = &*std::min_element(entries_.begin(), entries_.end(), [](const FlowEntry& a, const FlowEntry& b) {
            if (a.valid != b.valid) return !a.valid;
            return a.generation < b.generation;
        });
        ++evictions_;
        if (!selected->valid && size_ < kFlowCapacity) ++size_;
    }

    if (!selected->valid) {
        *selected = FlowEntry{};
        selected->valid = true;
        selected->ipVersion = packet.ipVersion;
        selected->protocol = packet.protocol;
        std::snprintf(selected->source, sizeof(selected->source), "%s", packet.source);
        std::snprintf(selected->destination, sizeof(selected->destination), "%s", packet.destination);
        selected->sourcePort = packet.sourcePort;
        selected->destinationPort = packet.destinationPort;
        selected->hasPorts = packet.hasPorts;
        selected->firstSeenMs = timestampMs;
        if (packet.protocol == 6U && (packet.tcpFlags & 0x02U) != 0U && (packet.tcpFlags & 0x10U) == 0U) {
            selected->initialTcpSequence = packet.tcpSequence;
            selected->initialTcpSequenceKnown = true;
        }
    }
    selected->lastSeenMs = timestampMs;
    selected->generation = sequence_;
    selected->lastTcpFlags = packet.tcpFlags;
    selected->packets++;
    if (reversed) selected->bytesReverse += packet.totalLength;
    else selected->bytesForward += packet.totalLength;

    // TCP FIN/RST ends the observed conversation. The final packet remains counted, but the
    // tuple won't be kept as active state waiting for a response that may never arrive.
    if (packet.protocol == 6U && (packet.tcpFlags & 0x04U) != 0U) {
        selected->valid = false;
        if (size_ > 0U) --size_;
    } else if (packet.protocol == 6U && (packet.tcpFlags & 0x01U) != 0U) {
        selected->tcpFinMask = static_cast<std::uint8_t>(selected->tcpFinMask | (reversed ? 0x02U : 0x01U));
        if (selected->tcpFinMask == 0x03U) {
            selected->valid = false;
            if (size_ > 0U) --size_;
        }
    }
}

void FlowTable::clear() noexcept {
    entries_.fill(FlowEntry{});
    size_ = 0;
    sequence_ = 0;
    evictions_ = 0;
}

void PacketEngine::DirectionBuffer::initialize(std::uint32_t sequence) noexcept {
    initialized = true;
    baseSequence = sequence;
    contiguous = 0;
    delivered = 0;
    bytes.fill(0U);
    present.reset();
}

bool PacketEngine::DirectionBuffer::insert(std::uint32_t sequence, const std::uint8_t* data,
                                           std::size_t length, std::size_t& newOffset,
                                           std::size_t& newLength) noexcept {
    newOffset = 0;
    newLength = 0;
    if (length == 0U) return true;
    if (data == nullptr) return false;
    if (!initialized) initialize(sequence);

    const std::int32_t relative = static_cast<std::int32_t>(sequence - baseSequence);
    if (relative < 0) {
        const std::size_t distance = static_cast<std::size_t>(-static_cast<std::int64_t>(relative));
        if (delivered != 0U) {
            // Bytes before the current base arrived after the stream had already advanced.
            // Do not rewind a TLS parser; trim the already-late prefix or discard it entirely.
            if (distance >= length) return true;
            data += distance;
            length -= distance;
            sequence = baseSequence;
        } else {
            if (distance >= kMaxTcpReassemblyBytes || length > kMaxTcpReassemblyBytes - distance) return false;
            std::move_backward(bytes.begin(), bytes.end() - static_cast<std::ptrdiff_t>(distance), bytes.end());
            present <<= distance;
            std::fill(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(distance), 0U);
            for (std::size_t i = 0; i < distance; ++i) present.reset(i);
            baseSequence = sequence;
            contiguous = 0U;
        }
    }

    const std::uint32_t unsignedOffset = sequence - baseSequence;
    if (unsignedOffset >= kMaxTcpReassemblyBytes) return false;
    const std::size_t offset = static_cast<std::size_t>(unsignedOffset);
    if (length > kMaxTcpReassemblyBytes - offset) return false;
    for (std::size_t i = 0; i < length; ++i) {
        const std::size_t at = offset + i;
        if (present.test(at)) {
            if (bytes[at] != data[i]) return false; // conflicting overlap: stop inspection of this stream
            continue; // exact retransmission/overlap is harmless
        }
        bytes[at] = data[i];
        present.set(at);
    }
    while (contiguous < kMaxTcpReassemblyBytes && present.test(contiguous)) ++contiguous;
    if (contiguous > delivered) {
        newOffset = delivered;
        newLength = contiguous - delivered;
        delivered = contiguous;
    }
    return true;
}

namespace {
bool endpointMatches(const std::string& address, std::uint16_t port, const char* otherAddress,
                     std::uint16_t otherPort) {
    return port == otherPort && address == otherAddress;
}

bool likelyTlsPort(std::uint16_t port) {
    return port == 443U || port == 8443U || port == 9443U || port == 4433U || port == 993U || port == 995U;
}

std::string dnsResponseStatus(const DnsInfo& dns) {
    if (!dns.isResponse) return "QUERY";
    switch (dns.responseCode) {
        case 0U: return "RESPONSE_NOERROR";
        case 1U: return "RESPONSE_FORMERR";
        case 2U: return "RESPONSE_SERVFAIL";
        case 3U: return "RESPONSE_NXDOMAIN";
        case 4U: return "RESPONSE_NOTIMP";
        case 5U: return "RESPONSE_REFUSED";
        default: return "RESPONSE_RCODE_" + std::to_string(dns.responseCode);
    }
}
} // namespace

PacketEngine::PacketEngine() : tcpFlows_(std::make_unique<TcpFlowState[]>(kTcpFlowCapacity)) {}

PacketEngine::TcpFlowState* PacketEngine::getTcpFlow(const PacketInfo& packet, const std::uint8_t* data,
                                                      std::uint64_t timestampMs, bool& fromClient) {
    const bool syn = (packet.tcpFlags & 0x02U) != 0U;
    const bool ack = (packet.tcpFlags & 0x10U) != 0U;
    const bool synWithoutAck = syn && !ack;
    const bool synAck = syn && ack;
    const bool hasPayload = packet.payloadLength > 0U && packet.payloadOffset <= packet.totalLength && !packet.fragmented;
    const std::uint8_t* payload = hasPayload ? data + packet.payloadOffset : nullptr;
    const bool tlsDestination = likelyTlsPort(packet.destinationPort);
    const bool tlsSource = likelyTlsPort(packet.sourcePort);
    const bool isDnsTcp = packet.sourcePort == 53U || packet.destinationPort == 53U;

    TcpFlowState* matched = nullptr;
    bool matchedFromClient = false;
    for (std::size_t flowIndex = 0; flowIndex < kTcpFlowCapacity; ++flowIndex) {
        auto& flow = tcpFlows_[flowIndex];
        if (!flow.valid || flow.ipVersion != packet.ipVersion) continue;
        const bool forward = endpointMatches(flow.clientAddress, flow.clientPort, packet.source, packet.sourcePort) &&
                             endpointMatches(flow.serverAddress, flow.serverPort, packet.destination, packet.destinationPort);
        const bool reverse = endpointMatches(flow.serverAddress, flow.serverPort, packet.source, packet.sourcePort) &&
                             endpointMatches(flow.clientAddress, flow.clientPort, packet.destination, packet.destinationPort);
        if (forward || reverse) {
            matched = &flow;
            matchedFromClient = forward;
            break;
        }
    }

    if (synWithoutAck && matched != nullptr && matchedFromClient && matched->initialClientSequence != packet.tcpSequence) {
        // Same 4-tuple, new SYN sequence: release old reconstruction buffers before source-port reuse.
        *matched = TcpFlowState{};
        matched = nullptr;
    }

    if (matched == nullptr) {
        // Keep reassembly state only for DNS/TCP or TLS-like streams. Tracking every ordinary
        // TCP SYN would allow routine HTTP traffic to evict the bounded ClientHello states.
        // Unknown-port TLS is discovered when a client-to-server TLS record header is observed.
        const bool candidate = isDnsTcp ||
            (synWithoutAck && tlsDestination) ||
            (synAck && tlsSource) ||
            (hasPayload && tlsDestination) ||
            (hasPayload && payload[0] == 22U && !tlsSource);
        if (!candidate) return nullptr;

        TcpFlowState* selected = nullptr;
        for (std::size_t flowIndex = 0; flowIndex < kTcpFlowCapacity; ++flowIndex) {
            auto& flow = tcpFlows_[flowIndex];
            if (!flow.valid) { selected = &flow; break; }
        }
        if (selected == nullptr) {
            selected = &*std::min_element(tcpFlows_.get(), tcpFlows_.get() + kTcpFlowCapacity, [](const TcpFlowState& left, const TcpFlowState& right) {
                return left.lastSeenMs < right.lastSeenMs;
            });
            ++reassemblyEvictions_;
        }
        *selected = TcpFlowState{};
        selected->valid = true;
        selected->ipVersion = packet.ipVersion;
        selected->protocol = 6U;
        selected->dnsTcp = isDnsTcp;
        selected->id = nextInspectionFlowId_++;
        selected->firstSeenMs = timestampMs;
        selected->lastSeenMs = timestampMs;

        if (synAck || (hasPayload && likelyTlsPort(packet.sourcePort) && !likelyTlsPort(packet.destinationPort) &&
                       packet.destinationPort != 53U)) {
            // Response-first capture: orient endpoints using a known server port so server bytes
            // can never be passed to the client-to-server ClientHello parser.
            selected->clientAddress = packet.destination;
            selected->clientPort = packet.destinationPort;
            selected->serverAddress = packet.source;
            selected->serverPort = packet.sourcePort;
            selected->clientKnown = false;
            selected->serverToClient.initialize(packet.tcpSequence + (syn ? 1U : 0U));
        } else if (packet.destinationPort == 53U || synWithoutAck ||
                   likelyTlsPort(packet.destinationPort) || (hasPayload && payload[0] == 22U)) {
            selected->clientAddress = packet.source;
            selected->clientPort = packet.sourcePort;
            selected->serverAddress = packet.destination;
            selected->serverPort = packet.destinationPort;
            selected->clientKnown = true;
            if (synWithoutAck) {
                selected->initialClientSequence = packet.tcpSequence;
                selected->clientSequenceKnown = true;
                selected->clientToServer.initialize(packet.tcpSequence + 1U);
            }
        } else {
            // Midstream packets without enough direction evidence are not eligible for SNI until
            // a structurally valid client-to-server ClientHello is found.
            selected->clientAddress = packet.destination;
            selected->clientPort = packet.destinationPort;
            selected->serverAddress = packet.source;
            selected->serverPort = packet.sourcePort;
            selected->clientKnown = false;
        }
        selected->tlsExpected = likelyTlsPort(selected->serverPort);
        selected->tlsCandidate = selected->tlsExpected ||
            (hasPayload && payload[0] == 22U && selected->clientKnown);
        matched = selected;
        matchedFromClient = endpointMatches(matched->clientAddress, matched->clientPort, packet.source, packet.sourcePort);
    }

    matched->lastSeenMs = timestampMs;
    if (synWithoutAck && matchedFromClient && !matched->clientSequenceKnown) {
        matched->initialClientSequence = packet.tcpSequence;
        matched->clientSequenceKnown = true;
        matched->clientKnown = true;
        matched->tlsExpected = likelyTlsPort(matched->serverPort);
        matched->tlsCandidate = matched->tlsExpected;
        matched->clientToServer.initialize(packet.tcpSequence + 1U);
    }
    if (hasPayload && matchedFromClient && payload != nullptr && payload[0] == 22U) {
        matched->tlsCandidate = true;
    }
    fromClient = matchedFromClient;
    return matched;
}

void PacketEngine::emitEvent(InspectionEvent event) {
    if (events_.size() >= kMaxInspectionEvents) events_.pop_front();
    events_.push_back(std::move(event));
}

void PacketEngine::emitDns(const PacketInfo& packet, const DnsInfo& dns, std::uint64_t timestampMs,
                           std::uint64_t flowId, const char* source) {
    InspectionEvent event{};
    event.kind = InspectionEventKind::Dns;
    event.timestampMs = timestampMs;
    event.flowId = flowId;
    event.ipVersion = packet.ipVersion;
    event.protocol = packet.protocol;
    event.sourceAddress = packet.source;
    event.destinationAddress = packet.destination;
    event.sourcePort = packet.sourcePort;
    event.destinationPort = packet.destinationPort;
    event.hostname = dns.name;
    event.status = dnsResponseStatus(dns);
    event.source = source;
    event.dnsType = dns.recordType;
    event.dnsResponseCode = dns.responseCode;
    event.dnsTransactionId = dns.transactionId;
    event.dnsResponse = dns.isResponse;
    emitEvent(std::move(event));
}

void PacketEngine::processDnsTcpBytes(TcpFlowState& flow, bool fromClient, const std::uint8_t* data,
                                      std::size_t length, std::uint64_t timestampMs) {
    auto& buffer = fromClient ? flow.clientDnsBuffer : flow.serverDnsBuffer;
    auto& used = fromClient ? flow.clientDnsBufferLength : flow.serverDnsBufferLength;
    if (length > buffer.size() - used) {
        used = 0U;
        InspectionEvent failure{};
        failure.kind = InspectionEventKind::DnsParseStatus;
        failure.timestampMs = timestampMs;
        failure.flowId = flow.id;
        failure.ipVersion = flow.ipVersion;
        failure.protocol = 6U;
        failure.sourceAddress = fromClient ? flow.clientAddress : flow.serverAddress;
        failure.destinationAddress = fromClient ? flow.serverAddress : flow.clientAddress;
        failure.sourcePort = fromClient ? flow.clientPort : flow.serverPort;
        failure.destinationPort = fromClient ? flow.serverPort : flow.clientPort;
        failure.status = "DNS_TCP_BUFFER_LIMIT";
        failure.source = "TUN_TCP_DNS";
        emitEvent(std::move(failure));
        return;
    }
    std::memcpy(buffer.data() + used, data, length);
    used += length;
    while (used >= 2U) {
        const std::size_t messageLength = be16(buffer.data());
        if (messageLength < 12U || messageLength > buffer.size() - 2U) {
            used = 0U;
            InspectionEvent failure{};
            failure.kind = InspectionEventKind::DnsParseStatus;
            failure.timestampMs = timestampMs;
            failure.flowId = flow.id;
            failure.ipVersion = flow.ipVersion;
            failure.protocol = 6U;
            failure.sourceAddress = fromClient ? flow.clientAddress : flow.serverAddress;
            failure.destinationAddress = fromClient ? flow.serverAddress : flow.clientAddress;
            failure.sourcePort = fromClient ? flow.clientPort : flow.serverPort;
            failure.destinationPort = fromClient ? flow.serverPort : flow.clientPort;
            failure.status = "DNS_TCP_INVALID_FRAME_LENGTH";
            failure.source = "TUN_TCP_DNS";
            emitEvent(std::move(failure));
            return;
        }
        if (used < messageLength + 2U) return;
        DnsInfo dns{};
        const ParseStatus parsed = parseDnsMessage(buffer.data() + 2U, messageLength, dns);
        if (parsed == ParseStatus::Ok) {
            PacketInfo packet{};
            packet.ipVersion = flow.ipVersion;
            packet.protocol = 6U;
            std::snprintf(packet.source, sizeof(packet.source), "%s", fromClient ? flow.clientAddress.c_str() : flow.serverAddress.c_str());
            std::snprintf(packet.destination, sizeof(packet.destination), "%s", fromClient ? flow.serverAddress.c_str() : flow.clientAddress.c_str());
            packet.sourcePort = fromClient ? flow.clientPort : flow.serverPort;
            packet.destinationPort = fromClient ? flow.serverPort : flow.clientPort;
            emitDns(packet, dns, timestampMs, flow.id, "TUN_TCP_DNS");
        } else {
            InspectionEvent failure{};
            failure.kind = InspectionEventKind::DnsParseStatus;
            failure.timestampMs = timestampMs;
            failure.flowId = flow.id;
            failure.ipVersion = flow.ipVersion;
            failure.protocol = 6U;
            failure.sourceAddress = fromClient ? flow.clientAddress : flow.serverAddress;
            failure.destinationAddress = fromClient ? flow.serverAddress : flow.clientAddress;
            failure.sourcePort = fromClient ? flow.clientPort : flow.serverPort;
            failure.destinationPort = fromClient ? flow.serverPort : flow.clientPort;
            failure.status = "DNS_TCP_MALFORMED_MESSAGE";
            failure.source = "TUN_TCP_DNS";
            emitEvent(std::move(failure));
        }
        const std::size_t remaining = used - (messageLength + 2U);
        if (remaining > 0U) std::memmove(buffer.data(), buffer.data() + messageLength + 2U, remaining);
        used = remaining;
    }
}

void PacketEngine::processTcpStream(TcpFlowState& flow, bool fromClient, const std::uint8_t* data,
                                    std::size_t length, std::uint64_t timestampMs) {
    if (flow.dnsTcp) processDnsTcpBytes(flow, fromClient, data, length, timestampMs);
    if (!fromClient || flow.tlsComplete || flow.tlsAttempted || flow.reassemblyTainted || flow.dnsTcp) return;
    if (!flow.tlsCandidate && length > 0U && data[0] == 22U) flow.tlsCandidate = true;
    if (!flow.tlsCandidate) return; // Do not emit false TLS parse events for ordinary HTTP/TCP flows.

    // Parse TLS only for a stream whose destination looks TLS-like. The TLS parser itself is
    // deliberately bounded and only emits SNI/ALPN after a complete, structurally valid ClientHello.
    TlsClientHelloInfo hello{};
    const TlsStatus status = flow.tlsParser.feed(data, length, hello);
    if (status == TlsStatus::NeedMore) return;
    flow.tlsAttempted = true;
    if (status == TlsStatus::ClientHello) {
        flow.tlsComplete = true;
        InspectionEvent event{};
        event.kind = InspectionEventKind::TlsClientHello;
        event.timestampMs = timestampMs;
        event.flowId = flow.id;
        event.ipVersion = flow.ipVersion;
        event.protocol = 6U;
        event.sourceAddress = flow.clientAddress;
        event.destinationAddress = flow.serverAddress;
        event.sourcePort = flow.clientPort;
        event.destinationPort = flow.serverPort;
        // TlsClientHelloParser clears the outer/cover SNI whenever it sees the ECH extension.
        // This event therefore never labels an ECH cover name as the origin hostname.
        event.hostname = hello.sni;
        event.alpn = hello.alpn;
        event.status = hello.echPresent ? "ECH_EXTENSION_PRESENT_SNI_SUPPRESSED" :
            (event.hostname.empty() ? "PARSED_NO_SNI" : "PARSED");
        event.source = "TLS_CLIENT_HELLO";
        emitEvent(std::move(event));
    } else {
        if (status == TlsStatus::NotClientHello && !flow.tlsExpected) return;
        InspectionEvent event{};
        event.kind = InspectionEventKind::TlsParseStatus;
        event.timestampMs = timestampMs;
        event.flowId = flow.id;
        event.ipVersion = flow.ipVersion;
        event.protocol = 6U;
        event.sourceAddress = flow.clientAddress;
        event.destinationAddress = flow.serverAddress;
        event.sourcePort = flow.clientPort;
        event.destinationPort = flow.serverPort;
        event.status = status == TlsStatus::Malformed ? "MALFORMED_OR_LIMIT_EXCEEDED" : "NOT_CLIENT_HELLO";
        event.source = "TCP_REASSEMBLY";
        emitEvent(std::move(event));
    }
}

void PacketEngine::expireTcpFlows(std::uint64_t timestampMs) noexcept {
    for (std::size_t flowIndex = 0; flowIndex < kTcpFlowCapacity; ++flowIndex) {
        auto& flow = tcpFlows_[flowIndex];
        if (!flow.valid || timestampMs < flow.lastSeenMs) continue;
        if (timestampMs - flow.lastSeenMs > 120'000U) flow = TcpFlowState{};
    }
}

void PacketEngine::observePacket(const std::uint8_t* data, std::size_t length,
                                 const PacketInfo& packet, std::uint64_t timestampMs) {
    flows_.observe(packet, timestampMs);
    // Fragment reassembly is intentionally not attempted here. Report that limitation only when
    // the initial fragment exposes UDP/53, instead of parsing a truncated DNS message as complete.
    if (packet.fragmented) {
        if (packet.protocol == 17U && packet.hasPorts &&
            (packet.sourcePort == 53U || packet.destinationPort == 53U)) {
            InspectionEvent failure{};
            failure.kind = InspectionEventKind::DnsParseStatus;
            failure.timestampMs = timestampMs;
            failure.protocol = 17U;
            failure.ipVersion = packet.ipVersion;
            failure.sourceAddress = packet.source;
            failure.destinationAddress = packet.destination;
            failure.sourcePort = packet.sourcePort;
            failure.destinationPort = packet.destinationPort;
            failure.status = "FRAGMENTED_DNS_NOT_REASSEMBLED";
            failure.source = "TUN_UDP_DNS";
            emitEvent(std::move(failure));
        }
        return;
    }
    if (!packet.hasPorts || packet.payloadOffset > length ||
        packet.payloadLength > length - packet.payloadOffset) return;

    if (packet.protocol == 17U && (packet.sourcePort == 53U || packet.destinationPort == 53U)) {
        DnsInfo dns{};
        if (parseDnsMessage(data + packet.payloadOffset, packet.payloadLength, dns) == ParseStatus::Ok) {
            emitDns(packet, dns, timestampMs, 0U, "TUN_UDP_DNS");
        } else {
            InspectionEvent failure{};
            failure.kind = InspectionEventKind::DnsParseStatus;
            failure.timestampMs = timestampMs;
            failure.protocol = 17U;
            failure.ipVersion = packet.ipVersion;
            failure.sourceAddress = packet.source;
            failure.destinationAddress = packet.destination;
            failure.sourcePort = packet.sourcePort;
            failure.destinationPort = packet.destinationPort;
            failure.status = "MALFORMED_OR_TRUNCATED_DNS";
            failure.source = "TUN_UDP_DNS";
            emitEvent(std::move(failure));
        }
        return;
    }

    if (packet.protocol != 6U) return;
    bool fromClient = false;
    TcpFlowState* flow = getTcpFlow(packet, data, timestampMs, fromClient);
    if (flow == nullptr) return;
    const bool isSyn = (packet.tcpFlags & 0x02U) != 0U;
    const bool isFinOrRst = (packet.tcpFlags & (0x01U | 0x04U)) != 0U;
    if (isSyn && packet.payloadLength == 0U) {
        if (isFinOrRst) flow->valid = false;
        return;
    }
    if (packet.payloadLength > 0U && !packet.fragmented && packet.payloadOffset <= length &&
        packet.payloadLength <= length - packet.payloadOffset && !flow->reassemblyTainted) {
        auto& direction = fromClient ? flow->clientToServer : flow->serverToClient;
        const std::uint32_t payloadSequence = packet.tcpSequence + ((packet.tcpFlags & 0x02U) != 0U ? 1U : 0U);
        std::size_t newOffset = 0U;
        std::size_t newLength = 0U;
        if (!direction.insert(payloadSequence, data + packet.payloadOffset, packet.payloadLength, newOffset, newLength)) {
            flow->reassemblyTainted = true;
            InspectionEvent event{};
            event.kind = flow->dnsTcp ? InspectionEventKind::DnsParseStatus : InspectionEventKind::TlsParseStatus;
            event.timestampMs = timestampMs;
            event.flowId = flow->id;
            event.ipVersion = flow->ipVersion;
            event.protocol = 6U;
            event.sourceAddress = fromClient ? flow->clientAddress : flow->serverAddress;
            event.destinationAddress = fromClient ? flow->serverAddress : flow->clientAddress;
            event.sourcePort = fromClient ? flow->clientPort : flow->serverPort;
            event.destinationPort = fromClient ? flow->serverPort : flow->clientPort;
            event.status = "REASSEMBLY_OVERLAP_OR_LIMIT";
            event.source = flow->dnsTcp ? "TUN_TCP_DNS" : "TCP_REASSEMBLY";
            emitEvent(std::move(event));
        } else if (newLength > 0U) {
            processTcpStream(*flow, fromClient, direction.bytes.data() + newOffset, newLength, timestampMs);
        }
    }
    if (isFinOrRst) *flow = TcpFlowState{};
}

std::vector<InspectionEvent> PacketEngine::takeEvents() {
    std::vector<InspectionEvent> result;
    result.reserve(events_.size());
    while (!events_.empty()) {
        result.push_back(std::move(events_.front()));
        events_.pop_front();
    }
    return result;
}

EngineStats PacketEngine::processBatch(const std::uint8_t* data, std::size_t length, std::uint64_t timestampMs) {
    return processBatch(data, length, timestampMs, nullptr, 0U);
}

EngineStats PacketEngine::processBatch(const std::uint8_t* data, std::size_t length,
                                       std::uint64_t fallbackTimestampMs,
                                       const std::uint64_t* packetTimestampsMs,
                                       std::size_t timestampCount) {
    if (data == nullptr && length != 0U) {
        stats_.errors++;
        return stats_;
    }
    std::size_t offset = 0U;
    std::size_t packetIndex = 0U;
    while (offset < length) {
        if (length - offset < 2U) {
            stats_.malformed++;
            break;
        }
        const std::size_t packetLength = be16(data + offset);
        offset += 2U;
        if (packetLength == 0U || packetLength > length - offset) {
            stats_.malformed++;
            break;
        }
        std::uint64_t packetTimestampMs = fallbackTimestampMs;
        if (packetTimestampsMs != nullptr && packetIndex < timestampCount) {
            packetTimestampMs = packetTimestampsMs[packetIndex];
        }
        expireTcpFlows(packetTimestampMs);
        PacketInfo packet{};
        const ParseStatus result = parseIpPacket(data + offset, packetLength, packet);
        if (result != ParseStatus::Ok) {
            stats_.malformed++;
            offset += packetLength;
            ++packetIndex;
            continue;
        }
        stats_.processed++;
        if (packet.ipVersion == 4U) stats_.ipv4++;
        else if (packet.ipVersion == 6U) stats_.ipv6++;
        observePacket(data + offset, packetLength, packet, packetTimestampMs);
        offset += packetLength;
        ++packetIndex;
    }
    stats_.evictions = flows_.evictions() + reassemblyEvictions_;
    return stats_;
}

void PacketEngine::reset() noexcept {
    flows_.clear();
    stats_ = EngineStats{};
    for (std::size_t flowIndex = 0; flowIndex < kTcpFlowCapacity; ++flowIndex) tcpFlows_[flowIndex] = TcpFlowState{};
    events_.clear();
    nextInspectionFlowId_ = 1U;
    reassemblyEvictions_ = 0U;
}

RotatingPcapWriter::RotatingPcapWriter(std::string basePath, std::uint64_t maxFileBytes,
                                       std::size_t maxFiles, std::uint32_t snapLength,
                                       std::uint32_t linkType)
    : basePath_(std::move(basePath)), maxFileBytes_(maxFileBytes), maxFiles_(maxFiles),
      snapLength_(snapLength), linkType_(linkType) {}

RotatingPcapWriter::~RotatingPcapWriter() { close(); }

std::string RotatingPcapWriter::pathFor(std::size_t index) const {
    char suffix[24]{};
    std::snprintf(suffix, sizeof(suffix), ".%03zu.pcap", index);
    return basePath_ + suffix;
}

bool RotatingPcapWriter::open() noexcept {
    if (basePath_.empty() || maxFiles_ == 0U || maxFileBytes_ < 24U || snapLength_ == 0U || snapLength_ > 65535U) return false;
    fileIndex_ = 0;
    packetsWritten_ = 0;
    return openIndex(fileIndex_);
}

bool RotatingPcapWriter::openIndex(std::size_t index) noexcept {
    if (output_.is_open()) output_.close();
    currentPath_ = pathFor(index);
    std::remove(currentPath_.c_str());
    output_.open(currentPath_, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output_.is_open()) {
        open_ = false;
        return false;
    }
    fileIndex_ = index;
    bytesWritten_ = 0;
    open_ = writeGlobalHeader();
    return open_;
}

bool RotatingPcapWriter::writeGlobalHeader() noexcept {
    const std::uint8_t magic[4]{0xd4U, 0xc3U, 0xb2U, 0xa1U};
    output_.write(reinterpret_cast<const char*>(magic), sizeof(magic));
    if (!output_) return false;
    const bool ok = writeLittleEndian16(2U) && writeLittleEndian16(4U) && writeLittleEndian(0U) &&
                    writeLittleEndian(0U) && writeLittleEndian(snapLength_) && writeLittleEndian(linkType_);
    if (ok) bytesWritten_ = 24U;
    return ok;
}

bool RotatingPcapWriter::writeLittleEndian(std::uint32_t value) noexcept {
    const char bytes[4]{static_cast<char>(value & 0xffU), static_cast<char>((value >> 8U) & 0xffU),
                        static_cast<char>((value >> 16U) & 0xffU), static_cast<char>((value >> 24U) & 0xffU)};
    output_.write(bytes, sizeof(bytes));
    return static_cast<bool>(output_);
}

bool RotatingPcapWriter::writeLittleEndian16(std::uint16_t value) noexcept {
    const char bytes[2]{static_cast<char>(value & 0xffU), static_cast<char>((value >> 8U) & 0xffU)};
    output_.write(bytes, sizeof(bytes));
    return static_cast<bool>(output_);
}

bool RotatingPcapWriter::writePacket(std::uint64_t timestampMicros, const std::uint8_t* packet,
                                     std::size_t capturedLength, std::size_t originalLength) noexcept {
    if (!open_ || packet == nullptr || capturedLength == 0U || originalLength < capturedLength) return false;
    if (capturedLength > snapLength_) capturedLength = snapLength_;
    const std::uint64_t recordBytes = 16U + capturedLength;
    if (bytesWritten_ + recordBytes > maxFileBytes_) {
        const std::size_t next = (fileIndex_ + 1U) % maxFiles_;
        if (!openIndex(next)) return false;
        if (bytesWritten_ + recordBytes > maxFileBytes_) return false;
    }
    const std::uint64_t seconds64 = timestampMicros / 1'000'000U;
    const std::uint32_t seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(seconds64, 0xffffffffULL));
    const std::uint32_t micros = static_cast<std::uint32_t>(timestampMicros % 1'000'000U);
    if (!writeLittleEndian(seconds) || !writeLittleEndian(micros) ||
        !writeLittleEndian(static_cast<std::uint32_t>(capturedLength)) ||
        !writeLittleEndian(static_cast<std::uint32_t>(std::min<std::size_t>(originalLength, 0xffffffffULL)))) return false;
    output_.write(reinterpret_cast<const char*>(packet), static_cast<std::streamsize>(capturedLength));
    if (!output_) return false;
    bytesWritten_ += recordBytes;
    ++packetsWritten_;
    return true;
}

void RotatingPcapWriter::close() noexcept {
    if (output_.is_open()) {
        output_.flush();
        output_.close();
    }
    open_ = false;
}

}  // namespace netcontrol
