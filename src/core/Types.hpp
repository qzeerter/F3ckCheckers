#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <atomic>

namespace trace {

enum class SimdPath {
    Sse2,
    Avx2Pure,
    Avx2FastBmi2,
    Avx512BW
};

struct CpuCapabilities {
    std::wstring vendor;
    std::wstring brand;
    int family = 0;
    int model = 0;
    uint32_t logicalCores = 1;

    bool hasSse42 = false;
    bool hasPopcnt = false;
    bool hasAvx2 = false;
    bool hasBmi1 = false;
    bool hasBmi2 = false;
    bool hasFastBmi2 = false;
    bool hasAvx512BW = false;

    SimdPath activePath = SimdPath::Sse2;
};

struct OsVersionInfo {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    uint32_t ubr = 0;
    std::wstring displayName;
    bool isWin11 = false;
    bool hasPcaDatabase = false;
    bool hasBamService = false;
    bool hasFeatureUsage = false;
    bool isElevated = false;
};

enum class MatchType {
    FileOrDirName,
    FileContentPlain,
    FileContentEncoded,
    RegistryKey,
    RegistryValue
};

enum class HitKind : int {
    None = 0,
    PlainAscii,
    Utf16LE,
    Utf16BE,
    Base64,
    Reversed,
    Rot13,
    NibbleSwapped,
    Xor8Encrypted,
    Xor16Encrypted,
    RollingXor,
    AddRotEncrypted,
    FuzzyPopcnt,
    HashCRC32C,
    HashFNV1a32,
    HashFNV1a64
};

struct RawHit {
    HitKind kind = HitKind::None;
    size_t offset = 0;
    uint64_t extraKey = 0;
};

struct ArtifactMatch {
    MatchType type;
    std::wstring location;
    std::wstring subLocation;
    std::wstring details;
    HKEY rootKey = nullptr;
    std::wstring subKeyPath;
};

struct SearchSignatures {
    std::string rawOriginal;
    std::string rawLower;
    std::string reversedLower;
    std::string rot13Lower;
    std::string nibbleSwappedLower;
    std::vector<std::string> base64Variants;

    std::vector<uint8_t> xorDiff1;
    std::vector<uint8_t> xorDiff2;
    std::vector<uint8_t> subDiff;

    uint32_t packedFirst4LE = 0;
    uint64_t pextAlphaMaskLE = 0;
    uint64_t pextAlphaMaskBE = 0;

    uint32_t crc32cOrig = 0;
    uint32_t crc32cLower = 0;
    uint32_t fnv1a32Orig = 0;
    uint32_t fnv1a32Lower = 0;
    uint64_t fnv1a64Orig = 0;
    uint64_t fnv1a64Lower = 0;

    bool enableHeuristics = true;
};

struct ScanStats {
    std::atomic<uint64_t> filesScanned{ 0 };
    std::atomic<uint64_t> bytesScanned{ 0 };
    std::atomic<uint64_t> regKeysScanned{ 0 };
    std::atomic<uint64_t> prefetchUnpacked{ 0 };
};

}