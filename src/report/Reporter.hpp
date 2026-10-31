#pragma once

#include "../core/Types.hpp"
#include <filesystem>
#include <vector>

namespace trace::report {

std::filesystem::path WriteDesktopReport(
    const std::wstring& queryWide,
    const CpuCapabilities& cpu,
    const OsVersionInfo& os,
    const SearchSignatures& sig,
    const ScanStats& stats,
    const std::vector<ArtifactMatch>& matches,
    double elapsedSec
);

void PrintMatchesPreview(const std::vector<ArtifactMatch>& matches, size_t maxItems = 100);
void RemoveArtifactsInteractive(const std::vector<ArtifactMatch>& matches, bool askForContentMatches);
void CleanAppLaunchCaches(const std::filesystem::path& targetExePath, SimdPath simdPath, bool hasSse42);
void SpawnPostExitCleaner(const std::filesystem::path& selfExePath);

}