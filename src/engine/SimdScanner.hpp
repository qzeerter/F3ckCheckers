#pragma once

#include "../core/Types.hpp"

namespace trace::engine {

RawHit ScanMemoryBuffer(
    const uint8_t* data,
    size_t size,
    const SearchSignatures& sig,
    SimdPath simdPath,
    bool isPeBinary = false
) noexcept;

RawHit SafeScanMappedMemory(
    const uint8_t* data,
    size_t size,
    const SearchSignatures& sig,
    SimdPath simdPath,
    bool isPeBinary = false
) noexcept;

}