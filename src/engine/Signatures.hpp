#pragma once

#include "../core/Types.hpp"
#include <string_view>

namespace trace::engine {

uint32_t CalcCRC32C(std::string_view sv, bool hasSse42) noexcept;
uint32_t CalcFNV1a32(std::string_view sv) noexcept;
uint64_t CalcFNV1a64(std::string_view sv) noexcept;

std::string ApplyRot13(std::string_view sv);
SearchSignatures BuildSignatures(std::string_view queryUtf8, bool enableHeuristics, bool hasSse42);
std::wstring FormatHitDescription(const RawHit& hit, size_t queryLen);

}