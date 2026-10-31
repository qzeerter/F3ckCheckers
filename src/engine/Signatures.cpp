#include "Signatures.hpp"
#include "../core/Platform.hpp"
#include <nmmintrin.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace trace::engine {

static uint32_t CalcSoftwareCRC32C(std::string_view sv) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : sv) {
        crc ^= b;
        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return ~crc;
}

uint32_t CalcCRC32C(std::string_view sv, bool hasSse42) noexcept {
    if (!hasSse42) {
        return CalcSoftwareCRC32C(sv);
    }
    uint64_t crc = 0xFFFFFFFFULL;
    size_t i = 0;
#if defined(_M_X64) || defined(__x86_64__)
    for (; i + 8 <= sv.size(); i += 8) {
        uint64_t chunk = 0;
        std::memcpy(&chunk, sv.data() + i, sizeof(uint64_t));
        crc = _mm_crc32_u64(crc, chunk);
    }
#endif
    for (; i < sv.size(); ++i) {
        crc = _mm_crc32_u8(static_cast<uint32_t>(crc), static_cast<uint8_t>(sv[i]));
    }
    return static_cast<uint32_t>(~crc);
}

uint32_t CalcFNV1a32(std::string_view sv) noexcept {
    uint32_t hash = 0x811C9DC5u;
    for (uint8_t c : sv) {
        hash ^= c;
        hash *= 0x01000193u;
    }
    return hash;
}

uint64_t CalcFNV1a64(std::string_view sv) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (uint8_t c : sv) {
        hash ^= c;
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

std::string ApplyRot13(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>('a' + (c - 'a' + 13) % 26);
        } else if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>('A' + (c - 'A' + 13) % 26);
        }
    }
    return out;
}

static std::string EncodeBase64Raw(std::string_view input) {
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    return out;
}

SearchSignatures BuildSignatures(std::string_view queryUtf8, bool enableHeuristics, bool hasSse42) {
    SearchSignatures sig;
    sig.rawOriginal = std::string(queryUtf8);
    sig.rawLower = ToLowerASCII(queryUtf8);
    sig.enableHeuristics = enableHeuristics;

    sig.reversedLower = sig.rawLower;
    std::reverse(sig.reversedLower.begin(), sig.reversedLower.end());

    sig.rot13Lower = ApplyRot13(sig.rawLower);

    sig.nibbleSwappedLower.resize(sig.rawLower.size());
    for (size_t i = 0; i < sig.rawLower.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(sig.rawLower[i]);
        sig.nibbleSwappedLower[i] = static_cast<char>((b << 4) | (b >> 4));
    }

    if (sig.rawLower.size() >= 4) {
        std::memcpy(&sig.packedFirst4LE, sig.rawLower.data(), sizeof(uint32_t));
        uint64_t maskLE = 0;
        uint64_t maskBE = 0;
        for (size_t k = 0; k < 4; ++k) {
            char c = sig.rawLower[k];
            if (c >= 'a' && c <= 'z') {
                maskLE |= (0x20ULL << (k * 16));
                maskBE |= (0x20ULL << (k * 16 + 8));
            }
        }
        sig.pextAlphaMaskLE = maskLE;
        sig.pextAlphaMaskBE = maskBE;
    }

    for (size_t pad = 0; pad < 3; ++pad) {
        std::string padded(pad, 'A');
        padded.append(queryUtf8);
        std::string b64 = EncodeBase64Raw(padded);

        size_t startCut = (pad == 0) ? 0 : (pad + 1);
        size_t endCut = b64.size() > 1 ? b64.size() - 1 : b64.size();
        if (endCut > startCut && (endCut - startCut) >= 4) {
            std::string core = ToLowerASCII(b64.substr(startCut, endCut - startCut));
            if (std::find(sig.base64Variants.begin(), sig.base64Variants.end(), core) == sig.base64Variants.end()) {
                sig.base64Variants.push_back(std::move(core));
            }
        }
    }

    if (sig.rawLower.size() >= 2) {
        size_t dLen = sig.rawLower.size() - 1;
        sig.xorDiff1.resize(dLen);
        sig.subDiff.resize(dLen);
        for (size_t i = 0; i < dLen; ++i) {
            uint8_t c0 = static_cast<uint8_t>(sig.rawLower[i]);
            uint8_t c1 = static_cast<uint8_t>(sig.rawLower[i + 1]);
            sig.xorDiff1[i] = c0 ^ c1;
            sig.subDiff[i] = static_cast<uint8_t>(c1 - c0);
        }
    }

    if (sig.rawLower.size() >= 3) {
        size_t dLen2 = sig.rawLower.size() - 2;
        sig.xorDiff2.resize(dLen2);
        for (size_t i = 0; i < dLen2; ++i) {
            uint8_t c0 = static_cast<uint8_t>(sig.rawLower[i]);
            uint8_t c2 = static_cast<uint8_t>(sig.rawLower[i + 2]);
            sig.xorDiff2[i] = c0 ^ c2;
        }
    }

    sig.crc32cOrig  = CalcCRC32C(sig.rawOriginal, hasSse42);
    sig.crc32cLower = CalcCRC32C(sig.rawLower, hasSse42);
    sig.fnv1a32Orig  = CalcFNV1a32(sig.rawOriginal);
    sig.fnv1a32Lower = CalcFNV1a32(sig.rawLower);
    sig.fnv1a64Orig  = CalcFNV1a64(sig.rawOriginal);
    sig.fnv1a64Lower = CalcFNV1a64(sig.rawLower);

    return sig;
}

std::wstring FormatHitDescription(const RawHit& hit, size_t queryLen) {
    std::wostringstream oss;
    switch (hit.kind) {
        case HitKind::PlainAscii:    return L"ASCII";
        case HitKind::Utf16LE:       return L"UTF-16LE";
        case HitKind::Utf16BE:       return L"UTF-16BE";
        case HitKind::Base64:        return L"Base64";
        case HitKind::Reversed:      return L"Rev";
        case HitKind::Rot13:         return L"ROT13";
        case HitKind::NibbleSwapped: return L"Swap";
        case HitKind::Xor8Encrypted:
            oss << L"XOR-8 (0x" << std::hex << std::uppercase
                << std::setw(2) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::Xor16Encrypted:
            oss << L"XOR-16 (0x" << std::hex << std::uppercase
                << std::setw(4) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::RollingXor:
            oss << L"XOR-R (0x" << std::hex << std::uppercase
                << std::setw(2) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::AddRotEncrypted:
            oss << L"ADD (+0x" << std::hex << std::uppercase
                << std::setw(2) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::FuzzyPopcnt:
            oss << L"Fuzzy (" << std::dec << hit.extraKey << L"/" << queryLen << L")";
            return oss.str();
        case HitKind::HashCRC32C:
            oss << L"CRC32 (0x" << std::hex << std::uppercase
                << std::setw(8) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::HashFNV1a32:
            oss << L"FNV32 (0x" << std::hex << std::uppercase
                << std::setw(8) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        case HitKind::HashFNV1a64:
            oss << L"FNV64 (0x" << std::hex << std::uppercase
                << std::setw(16) << std::setfill(L'0') << hit.extraKey << L")";
            return oss.str();
        default:
            return L"data";
    }
}

}