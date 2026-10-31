#include "SimdScanner.hpp"
#include "../core/Platform.hpp"

#include <immintrin.h>
#include <nmmintrin.h>
#include <emmintrin.h>
#include <intrin.h>
#include <bit>
#include <algorithm>
#include <cstring>

#if defined(_MSC_VER)
#define TRACE_FORCEINLINE __forceinline
#define TRACE_NOINLINE __declspec(noinline)
#else
#define TRACE_FORCEINLINE inline __attribute__((always_inline))
#define TRACE_NOINLINE __attribute__((noinline))
#endif

namespace trace::engine {

TRACE_FORCEINLINE bool VerifyXor8Candidate(const uint8_t* cand, const char* rawLower, size_t nLen, uint8_t keyCandidate) noexcept {
    if (keyCandidate == 0x00 || keyCandidate == 0x20) return false;
    for (size_t k = 0; k < nLen; ++k) {
        char dec = ExactCharToLower(static_cast<char>(cand[k] ^ keyCandidate));
        if (dec != rawLower[k]) return false;
    }
    return true;
}

TRACE_FORCEINLINE bool VerifyXor16Candidate(const uint8_t* cand, const char* rawLower, size_t nLen, uint8_t keyLo, uint8_t keyHi) noexcept {
    if ((keyLo == 0 && keyHi == 0) || keyLo == keyHi) return false;
    for (size_t k = 0; k < nLen; ++k) {
        uint8_t kb = (k & 1) ? keyHi : keyLo;
        char dec = ExactCharToLower(static_cast<char>(cand[k] ^ kb));
        if (dec != rawLower[k]) return false;
    }
    return true;
}

TRACE_FORCEINLINE bool VerifyRollingXorCandidate(const uint8_t* cand, const char* rawLower, size_t nLen, uint8_t baseKey) noexcept {
    for (size_t k = 0; k < nLen; ++k) {
        uint8_t kByte = static_cast<uint8_t>(baseKey + k);
        char dec = ExactCharToLower(static_cast<char>(cand[k] ^ kByte));
        if (dec != rawLower[k]) return false;
    }
    return true;
}

TRACE_FORCEINLINE bool HasValidCmpImm32Prefix(const uint8_t* baseData, size_t candidateOffset) noexcept {
    if (candidateOffset < 2) return false;
    uint8_t prev1 = baseData[candidateOffset - 1];
    uint8_t prev2 = baseData[candidateOffset - 2];

    if (prev1 == 0x3D) return true;
    if (prev2 == 0x81 && prev1 >= 0xF8 && prev1 <= 0xFF) return true;

    return false;
}

static bool ScalarScanAscii(const uint8_t* data, size_t size, const char* needleLower, size_t nLen, size_t& hitOffset) noexcept {
    if (nLen == 0 || size < nLen) return false;
    const size_t limit = size - nLen;
    const char first = needleLower[0];
    const char last  = needleLower[nLen - 1];

    for (size_t i = 0; i <= limit; ++i) {
        if (ExactCharToLower(static_cast<char>(data[i])) == first &&
            ExactCharToLower(static_cast<char>(data[i + nLen - 1])) == last) {
            bool ok = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (ExactCharToLower(static_cast<char>(data[i + k])) != needleLower[k]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hitOffset = i;
                return true;
            }
        }
    }
    return false;
}

TRACE_FORCEINLINE bool Sse2ScanCaseInsensitive(const uint8_t* data, size_t size, const char* needleLower, size_t nLen, size_t& hitOffset) noexcept {
    if (nLen == 0 || size < nLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m128i vFirst = _mm_set1_epi8(cFirst);
    const __m128i vLast  = _mm_set1_epi8(cLast);
    const __m128i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm_set1_epi8(0x20) : _mm_setzero_si128();
    const __m128i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm_set1_epi8(0x20) : _mm_setzero_si128();

    const size_t limit = size - nLen;
    size_t i = 0;

    for (; i + 16 <= limit; i += 16) {
        __m128i blockFirst = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i));
        __m128i blockLast  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i + nLen - 1));

        __m128i eqFirst = _mm_cmpeq_epi8(_mm_or_si128(blockFirst, vMaskFirst), vFirst);
        __m128i eqLast  = _mm_cmpeq_epi8(_mm_or_si128(blockLast, vMaskLast), vLast);

        uint32_t mask = static_cast<uint32_t>(_mm_movemask_epi8(_mm_and_si128(eqFirst, eqLast)));

        while (mask != 0) {
            unsigned long bitPos = 0;
            _BitScanForward(&bitPos, mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            bool fullMatch = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (ExactCharToLower(static_cast<char>(data[candidate + k])) != needleLower[k]) {
                    fullMatch = false;
                    break;
                }
            }
            if (fullMatch) {
                hitOffset = candidate;
                return true;
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanAscii(data + i, size - i, needleLower, nLen, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

static bool ScalarScanUtf16LE(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const char* needleLower = sig.rawLower.data();
    const size_t nLen = sig.rawLower.size();
    const size_t byteLen = nLen * 2;
    if (nLen < 4 || size < byteLen) return false;

    const size_t lastOff = (nLen - 1) * 2;
    const size_t limit = size - byteLen;

    for (size_t i = 0; i <= limit; ++i) {
        if (data[i + 1] == 0 && data[i + lastOff + 1] == 0 &&
            ExactCharToLower(static_cast<char>(data[i])) == needleLower[0] &&
            ExactCharToLower(static_cast<char>(data[i + lastOff])) == needleLower[nLen - 1]) {
            bool ok = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (data[i + k * 2 + 1] != 0 ||
                    ExactCharToLower(static_cast<char>(data[i + k * 2])) != needleLower[k]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hitOffset = i;
                return true;
            }
        }
    }
    return false;
}

TRACE_FORCEINLINE bool Sse2ScanUtf16LE(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const char* needleLower = sig.rawLower.data();
    const size_t nLen = sig.rawLower.size();
    const size_t byteLen = nLen * 2;
    if (nLen < 4 || size < byteLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m128i vFirst = _mm_set1_epi8(cFirst);
    const __m128i vLast  = _mm_set1_epi8(cLast);
    const __m128i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm_set1_epi8(0x20) : _mm_setzero_si128();
    const __m128i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm_set1_epi8(0x20) : _mm_setzero_si128();
    const __m128i vZero  = _mm_setzero_si128();

    const size_t lastOff = (nLen - 1) * 2;
    const size_t limit = size - byteLen;
    size_t i = 0;

    for (; i + 16 <= limit; i += 16) {
        __m128i bFirst = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i));
        __m128i bNull  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i + 1));
        __m128i bLast  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i + lastOff));

        __m128i eqFirst = _mm_cmpeq_epi8(_mm_or_si128(bFirst, vMaskFirst), vFirst);
        __m128i eqLast  = _mm_cmpeq_epi8(_mm_or_si128(bLast, vMaskLast), vLast);
        __m128i eqNull  = _mm_cmpeq_epi8(bNull, vZero);

        uint32_t mask = static_cast<uint32_t>(_mm_movemask_epi8(_mm_and_si128(_mm_and_si128(eqFirst, eqLast), eqNull)));

        while (mask != 0) {
            unsigned long bitPos = 0;
            _BitScanForward(&bitPos, mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            if (data[candidate + lastOff + 1] == 0) {
                bool ok = true;
                for (size_t k = 1; k + 1 < nLen; ++k) {
                    if (data[candidate + k * 2 + 1] != 0 ||
                        ExactCharToLower(static_cast<char>(data[candidate + k * 2])) != needleLower[k]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    hitOffset = candidate;
                    return true;
                }
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanUtf16LE(data + i, size - i, sig, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

static bool ScalarScanUtf16BE(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const char* needleLower = sig.rawLower.data();
    const size_t nLen = sig.rawLower.size();
    const size_t byteLen = nLen * 2;
    if (nLen < 4 || size < byteLen) return false;

    const size_t lastOff = (nLen - 1) * 2;
    const size_t limit = size - byteLen;

    for (size_t i = 0; i <= limit; ++i) {
        if (data[i] == 0 && data[i + lastOff] == 0 &&
            ExactCharToLower(static_cast<char>(data[i + 1])) == needleLower[0] &&
            ExactCharToLower(static_cast<char>(data[i + lastOff + 1])) == needleLower[nLen - 1]) {
            bool ok = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (data[i + k * 2] != 0 ||
                    ExactCharToLower(static_cast<char>(data[i + k * 2 + 1])) != needleLower[k]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hitOffset = i;
                return true;
            }
        }
    }
    return false;
}

static bool ScalarScanNibbleSwapped(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const size_t nLen = sig.rawLower.size();
    if (nLen < 4 || size < nLen) return false;
    const size_t limit = size - nLen;

    for (size_t i = 0; i <= limit; ++i) {
        uint8_t b0 = data[i];
        uint8_t u0 = static_cast<uint8_t>((b0 << 4) | (b0 >> 4));
        if (ExactCharToLower(static_cast<char>(u0)) == sig.rawLower[0]) {
            bool ok = true;
            for (size_t k = 1; k < nLen; ++k) {
                uint8_t bk = data[i + k];
                uint8_t uk = static_cast<uint8_t>((bk << 4) | (bk >> 4));
                if (ExactCharToLower(static_cast<char>(uk)) != sig.rawLower[k]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hitOffset = i;
                return true;
            }
        }
    }
    return false;
}

static HitKind ScalarScanObfuscated(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset, uint64_t& outKey) noexcept {
    const size_t rawLen = sig.rawLower.size();
    if (rawLen < 5 || size < rawLen) return HitKind::None;
    const char* rawPtr = sig.rawLower.data();
    const size_t limit = size - rawLen;

    for (size_t i = 0; i <= limit; ++i) {
        const uint8_t* cand = data + i;

        if (((cand[0] ^ cand[1]) & ~0x20) == (sig.xorDiff1[0] & ~0x20) &&
            ((cand[1] ^ cand[2]) & ~0x20) == (sig.xorDiff1[1] & ~0x20)) {
            uint8_t kLower = cand[0] ^ static_cast<uint8_t>(rawPtr[0]);
            if (VerifyXor8Candidate(cand, rawPtr, rawLen, kLower)) {
                hitOffset = i;
                outKey = kLower;
                return HitKind::Xor8Encrypted;
            }
            uint8_t kUpper = kLower ^ 0x20;
            if (VerifyXor8Candidate(cand, rawPtr, rawLen, kUpper)) {
                hitOffset = i;
                outKey = kUpper;
                return HitKind::Xor8Encrypted;
            }
        }

        if (((cand[0] ^ cand[2]) & ~0x20) == (sig.xorDiff2[0] & ~0x20) &&
            ((cand[1] ^ cand[3]) & ~0x20) == (sig.xorDiff2[1] & ~0x20)) {
            uint8_t kLo = cand[0] ^ static_cast<uint8_t>(rawPtr[0]);
            uint8_t kHi = cand[1] ^ static_cast<uint8_t>(rawPtr[1]);
            for (int mask = 0; mask < 4; ++mask) {
                uint8_t tryLo = (mask & 1) ? (kLo ^ 0x20) : kLo;
                uint8_t tryHi = (mask & 2) ? (kHi ^ 0x20) : kHi;
                if (VerifyXor16Candidate(cand, rawPtr, rawLen, tryLo, tryHi)) {
                    hitOffset = i;
                    outKey = (static_cast<uint16_t>(tryHi) << 8) | tryLo;
                    return HitKind::Xor16Encrypted;
                }
            }
        }

        uint8_t rk0 = (cand[0] ^ static_cast<uint8_t>(rawPtr[0])) & ~0x20;
        uint8_t rk1 = (cand[1] ^ static_cast<uint8_t>(rawPtr[1])) & ~0x20;
        uint8_t rk2 = (cand[2] ^ static_cast<uint8_t>(rawPtr[2])) & ~0x20;
        if (static_cast<uint8_t>((rk1 - rk0) & ~0x20) == 1 &&
            static_cast<uint8_t>((rk2 - rk1) & ~0x20) == 1) {
            uint8_t baseK = cand[0] ^ static_cast<uint8_t>(rawPtr[0]);
            if (VerifyRollingXorCandidate(cand, rawPtr, rawLen, baseK)) {
                hitOffset = i;
                outKey = baseK;
                return HitKind::RollingXor;
            }
            if (VerifyRollingXorCandidate(cand, rawPtr, rawLen, baseK ^ 0x20)) {
                hitOffset = i;
                outKey = baseK ^ 0x20;
                return HitKind::RollingXor;
            }
        }

        if (static_cast<uint8_t>(cand[1] - cand[0]) == sig.subDiff[0] &&
            static_cast<uint8_t>(cand[2] - cand[1]) == sig.subDiff[1]) {
            uint8_t key = static_cast<uint8_t>(cand[0] - static_cast<uint8_t>(rawPtr[0]));
            if (key != 0) {
                bool ok = true;
                for (size_t k = 1; k < rawLen; ++k) {
                    char dec = ExactCharToLower(static_cast<char>(cand[k] - key));
                    if (dec != rawPtr[k]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    hitOffset = i;
                    outKey = key;
                    return HitKind::AddRotEncrypted;
                }
            }
        }
    }
    return HitKind::None;
}

static HitKind ScalarScanHashes(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset, uint64_t& outHash) noexcept {
    if (!sig.enableHeuristics || size < 8) return HitKind::None;
    const size_t limit = size - 8;

    for (size_t i = 0; i <= limit; ++i) {
        uint64_t v64 = 0;
        std::memcpy(&v64, data + i, sizeof(uint64_t));
        if (v64 == sig.fnv1a64Orig || v64 == sig.fnv1a64Lower) {
            hitOffset = i;
            outHash = v64;
            return HitKind::HashFNV1a64;
        }

        if (HasValidCmpImm32Prefix(data, i)) {
            uint32_t v32 = 0;
            std::memcpy(&v32, data + i, sizeof(uint32_t));
            if (v32 == sig.crc32cOrig || v32 == sig.crc32cLower) {
                hitOffset = i;
                outHash = v32;
                return HitKind::HashCRC32C;
            }
            if (v32 == sig.fnv1a32Orig || v32 == sig.fnv1a32Lower) {
                hitOffset = i;
                outHash = v32;
                return HitKind::HashFNV1a32;
            }
        }
    }
    return HitKind::None;
}

TRACE_FORCEINLINE bool Avx512ScanCaseInsensitive(const uint8_t* data, size_t size, const char* needleLower, size_t nLen, size_t& hitOffset) noexcept {
    if (nLen == 0 || size < nLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m512i vFirst = _mm512_set1_epi8(cFirst);
    const __m512i vLast  = _mm512_set1_epi8(cLast);
    const __m512i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm512_set1_epi8(0x20) : _mm512_setzero_si512();
    const __m512i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm512_set1_epi8(0x20) : _mm512_setzero_si512();

    const size_t limit = size - nLen;
    size_t i = 0;

    for (; i + 64 <= limit; i += 64) {
        __m512i blockFirst = _mm512_loadu_si512(reinterpret_cast<const void*>(data + i));
        __m512i blockLast  = _mm512_loadu_si512(reinterpret_cast<const void*>(data + i + nLen - 1));

        uint64_t mFirst = _mm512_cmpeq_epi8_mask(_mm512_or_si512(blockFirst, vMaskFirst), vFirst);
        uint64_t mLast  = _mm512_cmpeq_epi8_mask(_mm512_or_si512(blockLast, vMaskLast), vLast);
        uint64_t mask   = mFirst & mLast;

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            bool fullMatch = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (ExactCharToLower(static_cast<char>(data[candidate + k])) != needleLower[k]) {
                    fullMatch = false;
                    break;
                }
            }
            if (fullMatch) {
                hitOffset = candidate;
                return true;
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanAscii(data + i, size - i, needleLower, nLen, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

TRACE_FORCEINLINE __m256i Avx2ExactToLower(__m256i block) noexcept {
    const __m256i vUpperShift = _mm256_set1_epi8(static_cast<char>('A' + 128));
    const __m256i vUpperBound = _mm256_set1_epi8(static_cast<char>(-128 + 26));
    const __m256i vCaseBit    = _mm256_set1_epi8(0x20);

    __m256i rot     = _mm256_sub_epi8(block, vUpperShift);
    __m256i isUpper = _mm256_cmpgt_epi8(vUpperBound, rot);
    return _mm256_add_epi8(block, _mm256_and_si256(isUpper, vCaseBit));
}

TRACE_FORCEINLINE bool Avx2ScanCaseInsensitive(const uint8_t* data, size_t size, const char* needleLower, size_t nLen, size_t& hitOffset) noexcept {
    if (nLen == 0 || size < nLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m256i vFirst = _mm256_set1_epi8(cFirst);
    const __m256i vLast  = _mm256_set1_epi8(cLast);
    const __m256i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();
    const __m256i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();

    const size_t limit = size - nLen;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i blockFirst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i blockLast  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + nLen - 1));

        __m256i eqFirst = _mm256_cmpeq_epi8(_mm256_or_si256(blockFirst, vMaskFirst), vFirst);
        __m256i eqLast  = _mm256_cmpeq_epi8(_mm256_or_si256(blockLast, vMaskLast), vLast);

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(eqFirst, eqLast)));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            bool fullMatch = true;
            for (size_t k = 1; k + 1 < nLen; ++k) {
                if (ExactCharToLower(static_cast<char>(data[candidate + k])) != needleLower[k]) {
                    fullMatch = false;
                    break;
                }
            }
            if (fullMatch) {
                hitOffset = candidate;
                return true;
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanAscii(data + i, size - i, needleLower, nLen, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

template <bool UseHardwarePext>
TRACE_FORCEINLINE bool Avx2ScanUtf16LE(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const char* needleLower = sig.rawLower.data();
    const size_t nLen = sig.rawLower.size();
    const size_t byteLen = nLen * 2;
    if (nLen < 4 || size < byteLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m256i vFirst = _mm256_set1_epi8(cFirst);
    const __m256i vLast  = _mm256_set1_epi8(cLast);
    const __m256i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();
    const __m256i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();
    const __m256i vZero  = _mm256_setzero_si256();

    const size_t lastCharByteOffset = (nLen - 1) * 2;
    const size_t limit = size - byteLen;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i bFirst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i bNull  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 1));
        __m256i bLast  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + lastCharByteOffset));

        __m256i eqFirst = _mm256_cmpeq_epi8(_mm256_or_si256(bFirst, vMaskFirst), vFirst);
        __m256i eqLast  = _mm256_cmpeq_epi8(_mm256_or_si256(bLast, vMaskLast), vLast);
        __m256i eqNull  = _mm256_cmpeq_epi8(bNull, vZero);

        __m256i combined = _mm256_and_si256(_mm256_and_si256(eqFirst, eqLast), eqNull);
        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(combined));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            if constexpr (UseHardwarePext) {
                uint64_t rawUtf16 = 0;
                std::memcpy(&rawUtf16, data + candidate, sizeof(uint64_t));
                if ((rawUtf16 & 0xFF00FF00FF00FF00ULL) == 0 && data[candidate + lastCharByteOffset + 1] == 0) {
                    uint32_t packed4 = static_cast<uint32_t>(_pext_u64(rawUtf16 | sig.pextAlphaMaskLE, 0x00FF00FF00FF00FFULL));
                    if (packed4 == sig.packedFirst4LE) {
                        bool fullMatch = true;
                        for (size_t k = 4; k + 1 < nLen; ++k) {
                            if (data[candidate + k * 2 + 1] != 0 ||
                                ExactCharToLower(static_cast<char>(data[candidate + k * 2])) != needleLower[k]) {
                                fullMatch = false;
                                break;
                            }
                        }
                        if (fullMatch) {
                            hitOffset = candidate;
                            return true;
                        }
                    }
                }
            } else {
                if (data[candidate + lastCharByteOffset + 1] == 0) {
                    bool fullMatch = true;
                    for (size_t k = 1; k + 1 < nLen; ++k) {
                        if (data[candidate + k * 2 + 1] != 0 ||
                            ExactCharToLower(static_cast<char>(data[candidate + k * 2])) != needleLower[k]) {
                            fullMatch = false;
                            break;
                        }
                    }
                    if (fullMatch) {
                        hitOffset = candidate;
                        return true;
                    }
                }
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanUtf16LE(data + i, size - i, sig, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

template <bool UseHardwarePext>
TRACE_FORCEINLINE bool Avx2ScanUtf16BE(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const char* needleLower = sig.rawLower.data();
    const size_t nLen = sig.rawLower.size();
    const size_t byteLen = nLen * 2;
    if (nLen < 4 || size < byteLen) return false;

    const char cFirst = needleLower[0];
    const char cLast  = needleLower[nLen - 1];

    const __m256i vZero  = _mm256_setzero_si256();
    const __m256i vFirst = _mm256_set1_epi8(cFirst);
    const __m256i vLast  = _mm256_set1_epi8(cLast);
    const __m256i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();
    const __m256i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();

    const size_t lastCharByteOffset = (nLen - 1) * 2;
    const size_t limit = size - byteLen;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i bNull  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i bFirst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 1));
        __m256i bLast  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + lastCharByteOffset + 1));

        __m256i eqNull  = _mm256_cmpeq_epi8(bNull, vZero);
        __m256i eqFirst = _mm256_cmpeq_epi8(_mm256_or_si256(bFirst, vMaskFirst), vFirst);
        __m256i eqLast  = _mm256_cmpeq_epi8(_mm256_or_si256(bLast, vMaskLast), vLast);

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(_mm256_and_si256(eqFirst, eqLast), eqNull)));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            if constexpr (UseHardwarePext) {
                uint64_t rawUtf16BE = 0;
                std::memcpy(&rawUtf16BE, data + candidate, sizeof(uint64_t));
                if ((rawUtf16BE & 0x00FF00FF00FF00FFULL) == 0 && data[candidate + lastCharByteOffset] == 0) {
                    uint32_t packed4 = static_cast<uint32_t>(_pext_u64(rawUtf16BE | sig.pextAlphaMaskBE, 0xFF00FF00FF00FF00ULL));
                    if (packed4 == sig.packedFirst4LE) {
                        bool fullMatch = true;
                        for (size_t k = 4; k + 1 < nLen; ++k) {
                            if (data[candidate + k * 2] != 0 ||
                                ExactCharToLower(static_cast<char>(data[candidate + k * 2 + 1])) != needleLower[k]) {
                                fullMatch = false;
                                break;
                            }
                        }
                        if (fullMatch) {
                            hitOffset = candidate;
                            return true;
                        }
                    }
                }
            } else {
                if (data[candidate + lastCharByteOffset] == 0) {
                    bool fullMatch = true;
                    for (size_t k = 1; k + 1 < nLen; ++k) {
                        if (data[candidate + k * 2] != 0 ||
                            ExactCharToLower(static_cast<char>(data[candidate + k * 2 + 1])) != needleLower[k]) {
                            fullMatch = false;
                            break;
                        }
                    }
                    if (fullMatch) {
                        hitOffset = candidate;
                        return true;
                    }
                }
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanUtf16BE(data + i, size - i, sig, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

TRACE_FORCEINLINE bool Avx2ScanNibbleSwapped(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset) noexcept {
    const size_t nLen = sig.nibbleSwappedLower.size();
    if (nLen < 4 || size < nLen) return false;

    const char* target = sig.nibbleSwappedLower.data();
    const __m256i vFirst = _mm256_set1_epi8(target[0]);
    const __m256i vLast  = _mm256_set1_epi8(target[nLen - 1]);
    const __m256i vSwappedCaseMask = _mm256_set1_epi8(0x02);

    const size_t limit = size - nLen;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i bFirst = _mm256_or_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i)), vSwappedCaseMask);
        __m256i bLast  = _mm256_or_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + nLen - 1)), vSwappedCaseMask);

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(
            _mm256_and_si256(_mm256_cmpeq_epi8(bFirst, vFirst), _mm256_cmpeq_epi8(bLast, vLast))
        ));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            bool fullMatch = true;
            for (size_t k = 0; k < nLen; ++k) {
                uint8_t b = data[candidate + k];
                uint8_t unswapped = static_cast<uint8_t>((b << 4) | (b >> 4));
                if (ExactCharToLower(static_cast<char>(unswapped)) != sig.rawLower[k]) {
                    fullMatch = false;
                    break;
                }
            }
            if (fullMatch) {
                hitOffset = candidate;
                return true;
            }
            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        if (ScalarScanNibbleSwapped(data + i, size - i, sig, tailHit)) {
            hitOffset = i + tailHit;
            return true;
        }
    }
    return false;
}

TRACE_FORCEINLINE HitKind Avx2ScanObfuscated(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset, uint64_t& outKey) noexcept {
    const size_t rawLen = sig.rawLower.size();
    if (rawLen < 5 || size < rawLen + 4) return HitKind::None;

    const uint8_t* xorPtr1 = sig.xorDiff1.data();
    const uint8_t* xorPtr2 = sig.xorDiff2.data();
    const uint8_t* subPtr  = sig.subDiff.data();
    const char* rawPtr     = sig.rawLower.data();

    const __m256i vCaseClear = _mm256_set1_epi8(static_cast<char>(~0x20));

    const __m256i vXor0 = _mm256_set1_epi8(static_cast<char>(xorPtr1[0] & ~0x20));
    const __m256i vXor1 = _mm256_set1_epi8(static_cast<char>(xorPtr1[1] & ~0x20));
    const __m256i vXor2 = _mm256_set1_epi8(static_cast<char>(xorPtr1[2] & ~0x20));

    const __m256i vXor16_0 = _mm256_set1_epi8(static_cast<char>(xorPtr2[0] & ~0x20));
    const __m256i vXor16_1 = _mm256_set1_epi8(static_cast<char>(xorPtr2[1] & ~0x20));
    const __m256i vXor16_2 = _mm256_set1_epi8(static_cast<char>(xorPtr2[2] & ~0x20));

    const __m256i vPlain0 = _mm256_set1_epi8(rawPtr[0]);
    const __m256i vPlain1 = _mm256_set1_epi8(rawPtr[1]);
    const __m256i vPlain2 = _mm256_set1_epi8(rawPtr[2]);
    const __m256i vOne    = _mm256_set1_epi8(1);

    const __m256i vSub0 = _mm256_set1_epi8(static_cast<char>(subPtr[0]));
    const __m256i vSub1 = _mm256_set1_epi8(static_cast<char>(subPtr[1]));
    const __m256i vSub2 = _mm256_set1_epi8(static_cast<char>(subPtr[2]));

    const size_t limit = size - rawLen;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i b0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i b1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 1));
        __m256i b2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 2));
        __m256i b3 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 3));
        __m256i b4 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 4));

        __m256i x0 = _mm256_and_si256(_mm256_xor_si256(b0, b1), vCaseClear);
        __m256i x1 = _mm256_and_si256(_mm256_xor_si256(b1, b2), vCaseClear);
        __m256i x2 = _mm256_and_si256(_mm256_xor_si256(b2, b3), vCaseClear);

        uint32_t xorMask8 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(
            _mm256_and_si256(_mm256_cmpeq_epi8(x0, vXor0), _mm256_cmpeq_epi8(x1, vXor1)),
            _mm256_cmpeq_epi8(x2, vXor2)
        )));

        while (xorMask8 != 0) {
            int bitPos = std::countr_zero(xorMask8);
            size_t candidate = i + static_cast<size_t>(bitPos);
            const uint8_t* candPtr = data + candidate;

            uint8_t kLower = candPtr[0] ^ static_cast<uint8_t>(rawPtr[0]);
            if (VerifyXor8Candidate(candPtr, rawPtr, rawLen, kLower)) {
                hitOffset = candidate;
                outKey = kLower;
                return HitKind::Xor8Encrypted;
            }
            uint8_t kUpper = kLower ^ 0x20;
            if (VerifyXor8Candidate(candPtr, rawPtr, rawLen, kUpper)) {
                hitOffset = candidate;
                outKey = kUpper;
                return HitKind::Xor8Encrypted;
            }
            xorMask8 &= (xorMask8 - 1);
        }

        __m256i x16_0 = _mm256_and_si256(_mm256_xor_si256(b0, b2), vCaseClear);
        __m256i x16_1 = _mm256_and_si256(_mm256_xor_si256(b1, b3), vCaseClear);
        __m256i x16_2 = _mm256_and_si256(_mm256_xor_si256(b2, b4), vCaseClear);

        uint32_t xorMask16 = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(
            _mm256_and_si256(_mm256_cmpeq_epi8(x16_0, vXor16_0), _mm256_cmpeq_epi8(x16_1, vXor16_1)),
            _mm256_cmpeq_epi8(x16_2, vXor16_2)
        )));

        while (xorMask16 != 0) {
            int bitPos = std::countr_zero(xorMask16);
            size_t candidate = i + static_cast<size_t>(bitPos);
            const uint8_t* candPtr = data + candidate;

            uint8_t kLo = candPtr[0] ^ static_cast<uint8_t>(rawPtr[0]);
            uint8_t kHi = candPtr[1] ^ static_cast<uint8_t>(rawPtr[1]);
            for (int m = 0; m < 4; ++m) {
                uint8_t tryLo = (m & 1) ? (kLo ^ 0x20) : kLo;
                uint8_t tryHi = (m & 2) ? (kHi ^ 0x20) : kHi;
                if (VerifyXor16Candidate(candPtr, rawPtr, rawLen, tryLo, tryHi)) {
                    hitOffset = candidate;
                    outKey = (static_cast<uint16_t>(tryHi) << 8) | tryLo;
                    return HitKind::Xor16Encrypted;
                }
            }
            xorMask16 &= (xorMask16 - 1);
        }

        __m256i rk0 = _mm256_and_si256(_mm256_xor_si256(b0, vPlain0), vCaseClear);
        __m256i rk1 = _mm256_and_si256(_mm256_xor_si256(b1, vPlain1), vCaseClear);
        __m256i rk2 = _mm256_and_si256(_mm256_xor_si256(b2, vPlain2), vCaseClear);

        __m256i rd0 = _mm256_and_si256(_mm256_sub_epi8(rk1, rk0), vCaseClear);
        __m256i rd1 = _mm256_and_si256(_mm256_sub_epi8(rk2, rk1), vCaseClear);

        uint32_t rollMask = static_cast<uint32_t>(_mm256_movemask_epi8(
            _mm256_and_si256(_mm256_cmpeq_epi8(rd0, vOne), _mm256_cmpeq_epi8(rd1, vOne))
        ));

        while (rollMask != 0) {
            int bitPos = std::countr_zero(rollMask);
            size_t candidate = i + static_cast<size_t>(bitPos);
            const uint8_t* candPtr = data + candidate;

            uint8_t baseK = candPtr[0] ^ static_cast<uint8_t>(rawPtr[0]);
            if (VerifyRollingXorCandidate(candPtr, rawPtr, rawLen, baseK)) {
                hitOffset = candidate;
                outKey = baseK;
                return HitKind::RollingXor;
            }
            if (VerifyRollingXorCandidate(candPtr, rawPtr, rawLen, baseK ^ 0x20)) {
                hitOffset = candidate;
                outKey = baseK ^ 0x20;
                return HitKind::RollingXor;
            }
            rollMask &= (rollMask - 1);
        }

        __m256i s0 = _mm256_sub_epi8(b1, b0);
        __m256i s1 = _mm256_sub_epi8(b2, b1);
        __m256i s2 = _mm256_sub_epi8(b3, b2);

        uint32_t subMask = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_and_si256(
            _mm256_and_si256(_mm256_cmpeq_epi8(s0, vSub0), _mm256_cmpeq_epi8(s1, vSub1)),
            _mm256_cmpeq_epi8(s2, vSub2)
        )));

        while (subMask != 0) {
            int bitPos = std::countr_zero(subMask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            uint8_t key = static_cast<uint8_t>(data[candidate] - static_cast<uint8_t>(rawPtr[0]));
            if (key != 0x00) {
                bool match = true;
                for (size_t k = 1; k < rawLen; ++k) {
                    char dec = ExactCharToLower(static_cast<char>(data[candidate + k] - key));
                    if (dec != rawPtr[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    hitOffset = candidate;
                    outKey = key;
                    return HitKind::AddRotEncrypted;
                }
            }
            subMask &= (subMask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        HitKind hk = ScalarScanObfuscated(data + i, size - i, sig, tailHit, outKey);
        if (hk != HitKind::None) {
            hitOffset = i + tailHit;
            return hk;
        }
    }
    return HitKind::None;
}

TRACE_FORCEINLINE bool Avx2ScanFuzzyPopcnt(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset, uint64_t& outMatchedChars) noexcept {
    const size_t nLen = sig.rawLower.size();
    if (!sig.enableHeuristics || nLen < 6 || nLen > 32 || size < nLen + 32) return false;

    const uint32_t maxTypos = (nLen >= 10) ? 2u : 1u;
    const uint32_t minMatches = static_cast<uint32_t>(nLen) - maxTypos;
    const uint32_t lenMask = (nLen == 32) ? 0xFFFFFFFFu : ((1u << nLen) - 1u);

    alignas(32) char paddedNeedle[32]{};
    std::memcpy(paddedNeedle, sig.rawLower.data(), nLen);
    const __m256i vNeedle = _mm256_load_si256(reinterpret_cast<const __m256i*>(paddedNeedle));

    const char cFirst = sig.rawLower[0];
    const char cLast  = sig.rawLower[nLen - 1];
    const __m256i vFirst = _mm256_set1_epi8(cFirst);
    const __m256i vLast  = _mm256_set1_epi8(cLast);
    const __m256i vMaskFirst = (cFirst >= 'a' && cFirst <= 'z') ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();
    const __m256i vMaskLast  = (cLast >= 'a' && cLast <= 'z')   ? _mm256_set1_epi8(0x20) : _mm256_setzero_si256();

    const size_t limit = size - 32;
    for (size_t i = 0; i + 32 <= limit; i += 32) {
        __m256i bFirst = _mm256_or_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i)), vMaskFirst);
        __m256i bLast  = _mm256_or_si256(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + nLen - 1)), vMaskLast);

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(
            _mm256_and_si256(_mm256_cmpeq_epi8(bFirst, vFirst), _mm256_cmpeq_epi8(bLast, vLast))
        ));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            __m256i candVec = Avx2ExactToLower(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + candidate)));
            uint32_t eqMask = static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(candVec, vNeedle))) & lenMask;
            uint32_t matched = static_cast<uint32_t>(std::popcount(eqMask));

            if (matched >= minMatches && matched < nLen) {
                bool allPrintable = true;
                for (size_t k = 0; k < nLen; ++k) {
                    uint8_t c = data[candidate + k];
                    if (c < 0x20 || c > 0x7E) {
                        allPrintable = false;
                        break;
                    }
                }
                if (allPrintable) {
                    hitOffset = candidate;
                    outMatchedChars = matched;
                    return true;
                }
            }
            mask &= (mask - 1);
        }
    }
    return false;
}

TRACE_FORCEINLINE HitKind Avx2ScanCompiledHashes(const uint8_t* data, size_t size, const SearchSignatures& sig, size_t& hitOffset, uint64_t& outHash) noexcept {
    if (!sig.enableHeuristics || size < 40) return HitKind::None;

    const __m256i vCrcOrig0    = _mm256_set1_epi8(static_cast<char>(sig.crc32cOrig & 0xFF));
    const __m256i vCrcLower0   = _mm256_set1_epi8(static_cast<char>(sig.crc32cLower & 0xFF));
    const __m256i vFnv32Orig0  = _mm256_set1_epi8(static_cast<char>(sig.fnv1a32Orig & 0xFF));
    const __m256i vFnv32Lower0 = _mm256_set1_epi8(static_cast<char>(sig.fnv1a32Lower & 0xFF));
    const __m256i vFnv64Orig0  = _mm256_set1_epi8(static_cast<char>(sig.fnv1a64Orig & 0xFF));
    const __m256i vFnv64Lower0 = _mm256_set1_epi8(static_cast<char>(sig.fnv1a64Lower & 0xFF));

    const size_t limit = size - 8;
    size_t i = 0;

    for (; i + 32 <= limit; i += 32) {
        __m256i b0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));

        __m256i mCrc   = _mm256_or_si256(_mm256_cmpeq_epi8(b0, vCrcOrig0), _mm256_cmpeq_epi8(b0, vCrcLower0));
        __m256i mFnv32 = _mm256_or_si256(_mm256_cmpeq_epi8(b0, vFnv32Orig0), _mm256_cmpeq_epi8(b0, vFnv32Lower0));
        __m256i mFnv64 = _mm256_or_si256(_mm256_cmpeq_epi8(b0, vFnv64Orig0), _mm256_cmpeq_epi8(b0, vFnv64Lower0));

        uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(
            _mm256_or_si256(_mm256_or_si256(mCrc, mFnv32), mFnv64)
        ));

        while (mask != 0) {
            int bitPos = std::countr_zero(mask);
            size_t candidate = i + static_cast<size_t>(bitPos);

            uint64_t val64 = 0;
            std::memcpy(&val64, data + candidate, sizeof(uint64_t));
            if (val64 == sig.fnv1a64Orig || val64 == sig.fnv1a64Lower) {
                hitOffset = candidate;
                outHash = val64;
                return HitKind::HashFNV1a64;
            }

            if (HasValidCmpImm32Prefix(data, candidate)) {
                uint32_t val32 = 0;
                std::memcpy(&val32, data + candidate, sizeof(uint32_t));
                if (val32 == sig.crc32cOrig || val32 == sig.crc32cLower) {
                    hitOffset = candidate;
                    outHash = val32;
                    return HitKind::HashCRC32C;
                }
                if (val32 == sig.fnv1a32Orig || val32 == sig.fnv1a32Lower) {
                    hitOffset = candidate;
                    outHash = val32;
                    return HitKind::HashFNV1a32;
                }
            }

            mask &= (mask - 1);
        }
    }

    if (i <= limit) {
        size_t tailHit = 0;
        HitKind hk = ScalarScanHashes(data + i, size - i, sig, tailHit, outHash);
        if (hk != HitKind::None) {
            hitOffset = i + tailHit;
            return hk;
        }
    }
    return HitKind::None;
}

TRACE_NOINLINE RawHit ScanMemoryBuffer(
    const uint8_t* data,
    size_t size,
    const SearchSignatures& sig,
    SimdPath simdPath,
    bool isPeBinary
) noexcept {
    constexpr size_t kBlockSize = 64 * 1024;
    const size_t overlap = sig.rawLower.size() * 2 + 64;

    for (size_t blockStart = 0; blockStart < size; blockStart += kBlockSize) {
        size_t chunkLen = (std::min)(kBlockSize + overlap, size - blockStart);
        const uint8_t* chunkPtr = data + blockStart;
        size_t localOffset = 0;

        if (simdPath == SimdPath::Sse2) {
            if (Sse2ScanCaseInsensitive(chunkPtr, chunkLen, sig.rawLower.data(), sig.rawLower.size(), localOffset)) {
                return { HitKind::PlainAscii, blockStart + localOffset, 0 };
            }
            if (Sse2ScanUtf16LE(chunkPtr, chunkLen, sig, localOffset)) {
                return { HitKind::Utf16LE, blockStart + localOffset, 0 };
            }
            if (ScalarScanUtf16BE(chunkPtr, chunkLen, sig, localOffset)) {
                return { HitKind::Utf16BE, blockStart + localOffset, 0 };
            }
            for (const auto& b64 : sig.base64Variants) {
                if (Sse2ScanCaseInsensitive(chunkPtr, chunkLen, b64.data(), b64.size(), localOffset)) {
                    return { HitKind::Base64, blockStart + localOffset, 0 };
                }
            }
            if (sig.reversedLower.size() >= 4 && Sse2ScanCaseInsensitive(chunkPtr, chunkLen, sig.reversedLower.data(), sig.reversedLower.size(), localOffset)) {
                return { HitKind::Reversed, blockStart + localOffset, 0 };
            }
            if (sig.rot13Lower != sig.rawLower && Sse2ScanCaseInsensitive(chunkPtr, chunkLen, sig.rot13Lower.data(), sig.rot13Lower.size(), localOffset)) {
                return { HitKind::Rot13, blockStart + localOffset, 0 };
            }
            if (ScalarScanNibbleSwapped(chunkPtr, chunkLen, sig, localOffset)) {
                return { HitKind::NibbleSwapped, blockStart + localOffset, 0 };
            }
            uint64_t obfKey = 0;
            HitKind obfKind = ScalarScanObfuscated(chunkPtr, chunkLen, sig, localOffset, obfKey);
            if (obfKind != HitKind::None) {
                return { obfKind, blockStart + localOffset, obfKey };
            }
            if (isPeBinary) {
                uint64_t hashVal = 0;
                HitKind hk = ScalarScanHashes(chunkPtr, chunkLen, sig, localOffset, hashVal);
                if (hk != HitKind::None) {
                    return { hk, blockStart + localOffset, hashVal };
                }
            }
        } else {
            if (simdPath == SimdPath::Avx512BW) {
                if (Avx512ScanCaseInsensitive(chunkPtr, chunkLen, sig.rawLower.data(), sig.rawLower.size(), localOffset)) {
                    return { HitKind::PlainAscii, blockStart + localOffset, 0 };
                }
            } else {
                if (Avx2ScanCaseInsensitive(chunkPtr, chunkLen, sig.rawLower.data(), sig.rawLower.size(), localOffset)) {
                    return { HitKind::PlainAscii, blockStart + localOffset, 0 };
                }
            }

            if (simdPath == SimdPath::Avx2FastBmi2 || simdPath == SimdPath::Avx512BW) {
                if (Avx2ScanUtf16LE<true>(chunkPtr, chunkLen, sig, localOffset)) {
                    return { HitKind::Utf16LE, blockStart + localOffset, 0 };
                }
                if (Avx2ScanUtf16BE<true>(chunkPtr, chunkLen, sig, localOffset)) {
                    return { HitKind::Utf16BE, blockStart + localOffset, 0 };
                }
            } else {
                if (Avx2ScanUtf16LE<false>(chunkPtr, chunkLen, sig, localOffset)) {
                    return { HitKind::Utf16LE, blockStart + localOffset, 0 };
                }
                if (Avx2ScanUtf16BE<false>(chunkPtr, chunkLen, sig, localOffset)) {
                    return { HitKind::Utf16BE, blockStart + localOffset, 0 };
                }
            }

            for (const auto& b64 : sig.base64Variants) {
                if (simdPath == SimdPath::Avx512BW) {
                    if (Avx512ScanCaseInsensitive(chunkPtr, chunkLen, b64.data(), b64.size(), localOffset)) {
                        return { HitKind::Base64, blockStart + localOffset, 0 };
                    }
                } else {
                    if (Avx2ScanCaseInsensitive(chunkPtr, chunkLen, b64.data(), b64.size(), localOffset)) {
                        return { HitKind::Base64, blockStart + localOffset, 0 };
                    }
                }
            }
            if (sig.reversedLower.size() >= 4 && Avx2ScanCaseInsensitive(chunkPtr, chunkLen, sig.reversedLower.data(), sig.reversedLower.size(), localOffset)) {
                return { HitKind::Reversed, blockStart + localOffset, 0 };
            }
            if (sig.rot13Lower != sig.rawLower && Avx2ScanCaseInsensitive(chunkPtr, chunkLen, sig.rot13Lower.data(), sig.rot13Lower.size(), localOffset)) {
                return { HitKind::Rot13, blockStart + localOffset, 0 };
            }
            if (Avx2ScanNibbleSwapped(chunkPtr, chunkLen, sig, localOffset)) {
                return { HitKind::NibbleSwapped, blockStart + localOffset, 0 };
            }

            uint64_t obfKey = 0;
            HitKind obfKind = Avx2ScanObfuscated(chunkPtr, chunkLen, sig, localOffset, obfKey);
            if (obfKind != HitKind::None) {
                return { obfKind, blockStart + localOffset, obfKey };
            }

            uint64_t matchedChars = 0;
            if (Avx2ScanFuzzyPopcnt(chunkPtr, chunkLen, sig, localOffset, matchedChars)) {
                return { HitKind::FuzzyPopcnt, blockStart + localOffset, matchedChars };
            }

            if (isPeBinary) {
                uint64_t hashVal = 0;
                HitKind hashKind = Avx2ScanCompiledHashes(chunkPtr, chunkLen, sig, localOffset, hashVal);
                if (hashKind != HitKind::None) {
                    return { hashKind, blockStart + localOffset, hashVal };
                }
            }
        }
    }

    return { HitKind::None, 0, 0 };
}

RawHit SafeScanMappedMemory(
    const uint8_t* data,
    size_t size,
    const SearchSignatures& sig,
    SimdPath simdPath,
    bool isPeBinary
) noexcept {
    RawHit hit{ HitKind::None, 0, 0 };
#if defined(_MSC_VER)
    __try {
        hit = ScanMemoryBuffer(data, size, sig, simdPath, isPeBinary);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hit.kind = HitKind::None;
    }
#else
    hit = ScanMemoryBuffer(data, size, sig, simdPath, isPeBinary);
#endif
    return hit;
}

}