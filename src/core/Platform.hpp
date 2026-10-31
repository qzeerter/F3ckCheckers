#pragma once

#include "Types.hpp"
#include <filesystem>

namespace trace {

CpuCapabilities DetectCpuCapabilities();
OsVersionInfo DetectOsVersion();
bool EnableSystemPrivileges();

std::string WideToUtf8(std::wstring_view wv);
std::wstring Utf8ToWide(std::string_view sv);

constexpr char ExactCharToLower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 0x20) : c;
}

std::string ToLowerASCII(std::string_view sv);
std::wstring ToLowerWide(std::wstring_view wv);

std::filesystem::path GetDesktopDirectory();
std::filesystem::path GetSelfExecutablePath();

}