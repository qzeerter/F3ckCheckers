#pragma once

#include "../core/Types.hpp"
#include "FileScanner.hpp"

namespace trace::scanners {

void EnqueueRegistryTasks(
    ThreadPool& pool,
    const OsVersionInfo& os,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    MatchCallback onMatch
);

void EnqueueFastSelfCleanTasks(
    ThreadPool& pool,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    MatchCallback onMatch
);

}