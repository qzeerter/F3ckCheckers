#include "FileScanner.hpp"
#include "Prefetch.hpp"
#include "../core/Platform.hpp"
#include "../engine/Signatures.hpp"
#include "../engine/SimdScanner.hpp"
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace trace::scanners {

ThreadPool::ThreadPool(size_t numThreads) : m_stop(false) {
    m_workers.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        m_workers.emplace_back([this]() {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);
                    m_cv.wait(lock, [this]() { return m_stop || !m_tasks.empty(); });
                    if (m_stop && m_tasks.empty()) return;
                    task = std::move(m_tasks.front());
                    m_tasks.pop();
                }
                task();
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    WaitAll();
}

void ThreadPool::Enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_tasks.push(std::move(task));
    }
    m_cv.notify_one();
}

void ThreadPool::WaitAll() {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_stop) return;
        m_stop = true;
    }
    m_cv.notify_all();
    m_workers.clear();
}

static bool IsPeBinaryExtension(std::wstring_view extLower) {
    return (extLower == L".exe" || extLower == L".dll" || extLower == L".sys" || extLower == L".asi");
}

static bool ShouldInspectFileContent(const fs::path& p, std::wstring& outExtLower) {
    static const std::vector<std::wstring_view> targetExts = {
        L".exe", L".dll", L".sys", L".asi", L".pf", L".dat", L".bin",
        L".cfg", L".ini", L".json", L".xml", L".log", L".txt",
        L".bat", L".cmd", L".ps1", L".vbs", L".jar", L".class", L".tmp",
        L".lnk", L".automaticdestinations-ms", L".customdestinations-ms",
        L".wer", L".dmp", L".mdmp", L".db", L".sqlite"
    };
    outExtLower = ToLowerWide(p.extension().wstring());
    for (auto t : targetExts) {
        if (outExtLower == t) return true;
    }
    return false;
}

static bool ShouldSkipSystemSdkDir(std::wstring_view fullDirPathLower) {
    static const std::vector<std::wstring_view> skipPatterns = {
        L"\\windows\\winsxs",
        L"\\windows\\servicing",
        L"\\windows\\microsoft.net",
        L"\\program files\\dotnet",
        L"\\program files (x86)\\dotnet",
        L"\\program files\\microsoft visual studio",
        L"\\program files (x86)\\microsoft visual studio",
        L"\\program files (x86)\\windows kits",
        L"\\appdata\\local\\microsoft\\visualstudio",
        L"\\.nuget\\packages",
        L"\\.vscode\\extensions"
    };
    for (auto pat : skipPatterns) {
        if (fullDirPathLower.find(pat) != std::wstring_view::npos) {
            return true;
        }
    }
    return false;
}

static fs::path FindSelfProjectRoot(const fs::path& selfExePath) {
    std::error_code ec;
    fs::path cur = selfExePath.parent_path();
    for (int i = 0; i < 4 && !cur.empty(); ++i) {
        if (fs::exists(cur / L"src", ec) || fs::exists(cur / L"TraceScanner.sln", ec) || fs::exists(cur / L"TraceScanner.vcxproj", ec)) {
            return cur;
        }
        cur = cur.parent_path();
    }
    return selfExePath.parent_path();
}

static void ScanFileContentMapped(
    const fs::path& filePath,
    std::wstring_view extLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    const MatchCallback& onMatch
) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize) ||
        fileSize.QuadPart < static_cast<LONGLONG>(sig.rawLower.size()) ||
        fileSize.QuadPart > (256LL * 1024 * 1024)) {
        CloseHandle(hFile);
        return;
    }

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        CloseHandle(hFile);
        return;
    }

    const auto* mappedData = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (mappedData) {
        size_t sz = static_cast<size_t>(fileSize.QuadPart);
        RawHit hit{ HitKind::None, 0, 0 };
        bool isPe = IsPeBinaryExtension(extLower);

        std::vector<uint8_t> decompressedPrefetch;
        if (extLower == L".pf" && TryDecompressPrefetch(mappedData, sz, decompressedPrefetch)) {
            stats.prefetchUnpacked.fetch_add(1, std::memory_order_relaxed);
            stats.bytesScanned.fetch_add(decompressedPrefetch.size(), std::memory_order_relaxed);
            hit = engine::ScanMemoryBuffer(decompressedPrefetch.data(), decompressedPrefetch.size(), sig, simdPath, false);
        } else {
            stats.bytesScanned.fetch_add(sz, std::memory_order_relaxed);
            hit = engine::SafeScanMappedMemory(mappedData, sz, sig, simdPath, isPe);
        }

        if (hit.kind != HitKind::None) {
            std::wostringstream oss;
            oss << engine::FormatHitDescription(hit, sig.rawLower.size())
                << L" (0x" << std::hex << std::uppercase << hit.offset << L")";

            MatchType mType = (hit.kind == HitKind::PlainAscii || hit.kind == HitKind::Utf16LE || hit.kind == HitKind::Utf16BE)
                ? MatchType::FileContentPlain
                : MatchType::FileContentEncoded;

            onMatch({
                mType,
                filePath.wstring(),
                L"",
                oss.str()
            });
        }
        UnmapViewOfFile(mappedData);
    }

    CloseHandle(hMap);
    CloseHandle(hFile);
}

std::vector<fs::path> BuildTargetDirectories(bool fullDiskScan, const OsVersionInfo& os) {
    std::vector<fs::path> dirs;
    if (fullDiskScan) {
        DWORD drivesMask = GetLogicalDrives();
        for (wchar_t d = L'A'; d <= L'Z'; ++d) {
            if (drivesMask & (1u << (d - L'A'))) {
                std::wstring root = std::wstring(1, d) + L":\\";
                if (GetDriveTypeW(root.c_str()) == DRIVE_FIXED) {
                    dirs.emplace_back(root);
                }
            }
        }
    } else {
        wchar_t buf[MAX_PATH]{};
        if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH)) {
            dirs.emplace_back(buf);
        }
        if (GetEnvironmentVariableW(L"WINDIR", buf, MAX_PATH)) {
            fs::path winDir(buf);
            dirs.emplace_back(winDir / L"Prefetch");
            dirs.emplace_back(winDir / L"Temp");
            dirs.emplace_back(winDir / L"Minidump");
            if (os.hasPcaDatabase) {
                dirs.emplace_back(winDir / L"appcompat" / L"pca");
            }
            dirs.emplace_back(winDir / L"appcompat" / L"Programs");
        }
        if (GetEnvironmentVariableW(L"PROGRAMDATA", buf, MAX_PATH)) {
            dirs.emplace_back(buf);
        }
    }
    return dirs;
}

void CrawlDirectory(
    const fs::path& rootPath,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ThreadPool& pool,
    const fs::path& selfExePath,
    ScanStats& stats,
    MatchCallback onMatch
) {
    std::error_code ec;
    if (!fs::exists(rootPath, ec)) return;

    const std::wstring selfRootLower = ToLowerWide(FindSelfProjectRoot(selfExePath).wstring());

    fs::directory_options opts = fs::directory_options::skip_permission_denied;
    for (auto it = fs::recursive_directory_iterator(rootPath, opts, ec);
         it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        const fs::path currentPath = it->path();
        if (currentPath == selfExePath) continue;

        std::wstring fullPathLower = ToLowerWide(currentPath.wstring());

        if (!selfRootLower.empty() && fullPathLower.starts_with(selfRootLower)) {
            if (it->is_directory(ec)) {
                it.disable_recursion_pending();
            }
            continue;
        }

        bool isDir = it->is_directory(ec);
        if (isDir && ShouldSkipSystemSdkDir(fullPathLower)) {
            it.disable_recursion_pending();
            continue;
        }

        std::wstring filenameLower = ToLowerWide(currentPath.filename().wstring());
        if (filenameLower.find(queryWideLower) != std::wstring::npos) {
            onMatch({
                MatchType::FileOrDirName,
                currentPath.wstring(),
                L"",
                isDir ? L"dir" : L"file"
            });
            continue;
        }

        if (it->is_regular_file(ec)) {
            stats.filesScanned.fetch_add(1, std::memory_order_relaxed);
            std::wstring extLower;
            if (ShouldInspectFileContent(currentPath, extLower)) {
                pool.Enqueue([currentPath, extLower, &sig, simdPath, &stats, onMatch]() {
                    ScanFileContentMapped(currentPath, extLower, sig, simdPath, stats, onMatch);
                });
            }
        }
    }
}

}