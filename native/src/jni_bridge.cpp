#include "netcore.h"

#include <jni.h>
#include <cstdint>
#include <mutex>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {
netcontrol::PacketEngine g_engine;
std::mutex g_engine_mutex;
constexpr char kFieldSeparator = '\x1f';

std::string safeField(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char raw : value) {
        const auto c = static_cast<unsigned char>(raw);
        // The compact JNI wire format uses ASCII control separators. Never allow data such as
        // an opaque ALPN identifier to forge additional fields in the Kotlin observer.
        // JNI NewStringUTF expects modified UTF-8; source fields and SNI are ASCII, while ALPN is
        // an opaque byte identifier. Keep the wire format printable instead of forwarding bytes
        // that may be invalid UTF-8 or contain the record delimiter.
        result.push_back(c < 0x20U || c > 0x7eU || c == static_cast<unsigned char>(kFieldSeparator)
            ? '?' : static_cast<char>(c));
    }
    return result;
}

std::string encodeEvent(const netcontrol::InspectionEvent& event) {
    const char* kind = "DNS";
    switch (event.kind) {
        case netcontrol::InspectionEventKind::Dns: kind = "DNS"; break;
        case netcontrol::InspectionEventKind::DnsParseStatus: kind = "DNS_PARSE_STATUS"; break;
        case netcontrol::InspectionEventKind::TlsClientHello: kind = "TLS_CLIENT_HELLO"; break;
        case netcontrol::InspectionEventKind::TlsParseStatus: kind = "TLS_PARSE_STATUS"; break;
    }
    const char* protocol = event.protocol == 6U ? "TCP" : (event.protocol == 17U ? "UDP" : "IP");
    const std::string fields[] = {
        kind,
        std::to_string(event.timestampMs),
        std::to_string(event.flowId),
        std::to_string(event.ipVersion),
        protocol,
        safeField(event.sourceAddress),
        std::to_string(event.sourcePort),
        safeField(event.destinationAddress),
        std::to_string(event.destinationPort),
        safeField(event.hostname),
        safeField(event.alpn),
        safeField(event.status),
        safeField(event.source),
        std::to_string(event.dnsType),
        std::to_string(event.dnsResponseCode),
        std::to_string(event.dnsTransactionId),
        event.dnsResponse ? "1" : "0",
    };
    std::string encoded;
    std::size_t total = 0U;
    for (const auto& field : fields) total += field.size() + 1U;
    encoded.reserve(total);
    for (std::size_t i = 0; i < (sizeof(fields) / sizeof(fields[0])); ++i) {
        if (i != 0U) encoded.push_back(kFieldSeparator);
        encoded += fields[i];
    }
    return encoded;
}

jlong toJavaLong(std::uint64_t value) {
    return value > static_cast<std::uint64_t>(std::numeric_limits<jlong>::max())
        ? std::numeric_limits<jlong>::max() : static_cast<jlong>(value);
}

jlongArray makeStats(JNIEnv* env, const netcontrol::EngineStats& stats) {
    // Counters are cumulative uint64 values. Use Java Long and saturate rather than truncating at INT_MAX.
    const jlong values[7]{
        toJavaLong(stats.processed),
        toJavaLong(stats.malformed),
        toJavaLong(stats.ipv4),
        toJavaLong(stats.ipv6),
        static_cast<jlong>(g_engine.flows().size()),
        toJavaLong(stats.evictions),
        toJavaLong(stats.errors),
    };
    jlongArray result = env->NewLongArray(7);
    if (result != nullptr) env->SetLongArrayRegion(result, 0, 7, values);
    return result;
}
} // namespace

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_netcontrol_app_network_NativeEngine_processBatch(JNIEnv* env, jobject /*thiz*/, jbyteArray input,
                                                           jlongArray packetTimestampArray,
                                                           jlong fallbackTimestampMillis) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    if (input == nullptr) {
        netcontrol::EngineStats stats{};
        stats.errors = 1U;
        return makeStats(env, stats);
    }
    const jsize length = env->GetArrayLength(input);
    jbyte* bytes = env->GetByteArrayElements(input, nullptr);
    if (bytes == nullptr) {
        netcontrol::EngineStats stats{};
        stats.errors = 1U;
        return makeStats(env, stats);
    }

    jlong* rawTimestamps = nullptr;
    if (packetTimestampArray != nullptr) {
        rawTimestamps = env->GetLongArrayElements(packetTimestampArray, nullptr);
        if (rawTimestamps == nullptr) {
            env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);
            netcontrol::EngineStats stats{};
            stats.errors = 1U;
            return makeStats(env, stats);
        }
    }
    bool bytesReleased = false;
    bool timestampsReleased = false;
    try {
        std::vector<std::uint64_t> packetTimestamps;
        if (rawTimestamps != nullptr) {
            const jsize timestampCount = env->GetArrayLength(packetTimestampArray);
            packetTimestamps.reserve(static_cast<std::size_t>(timestampCount));
            for (jsize i = 0; i < timestampCount; ++i) {
                const jlong value = rawTimestamps[i];
                packetTimestamps.push_back(value < 0 ? 0U : static_cast<std::uint64_t>(value));
            }
        }
        const auto stats = g_engine.processBatch(
            reinterpret_cast<const std::uint8_t*>(bytes), static_cast<std::size_t>(length),
            fallbackTimestampMillis < 0 ? 0U : static_cast<std::uint64_t>(fallbackTimestampMillis),
            packetTimestamps.empty() ? nullptr : packetTimestamps.data(), packetTimestamps.size());
        env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);
        bytesReleased = true;
        if (rawTimestamps != nullptr) {
            env->ReleaseLongArrayElements(packetTimestampArray, rawTimestamps, JNI_ABORT);
            timestampsReleased = true;
        }
        return makeStats(env, stats);
    } catch (...) {
        if (!bytesReleased) env->ReleaseByteArrayElements(input, bytes, JNI_ABORT);
        if (rawTimestamps != nullptr && !timestampsReleased) {
            env->ReleaseLongArrayElements(packetTimestampArray, rawTimestamps, JNI_ABORT);
        }
        netcontrol::EngineStats stats{};
        stats.errors = 1U;
        return makeStats(env, stats);
    }
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netcontrol_app_network_NativeEngine_drainEvents(JNIEnv* env, jobject /*thiz*/) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    std::vector<netcontrol::InspectionEvent> events;
    try {
        events = g_engine.takeEvents();
    } catch (...) {
        events.clear();
    }
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(events.size()), stringClass, nullptr);
    if (result == nullptr) return nullptr;
    for (std::size_t i = 0; i < events.size(); ++i) {
        try {
            const std::string encoded = encodeEvent(events[i]);
            jstring item = env->NewStringUTF(encoded.c_str());
            if (item == nullptr) return result;
            env->SetObjectArrayElement(result, static_cast<jsize>(i), item);
            env->DeleteLocalRef(item);
        } catch (...) {
            // A malformed observation is dropped rather than letting a C++ exception cross JNI.
        }
    }
    return result;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netcontrol_app_network_NativeEngine_reset(JNIEnv* /*env*/, jobject /*thiz*/) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    g_engine.reset();
}
