#pragma once

#include "../core/Types.hpp"
#include <filesystem>
#include <vector>
#include <functional>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace trace::scanners {

class ThreadPool {
public:
    explicit ThreadPool(size_t numThreads);
    ~ThreadPool();

    void Enqueue(std::function<void()> task);
    void WaitAll();

private:
    std::vector<std::jthread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_queueMutex;
    std::condition_variable m_cv;
    bool m_stop = false;
};

using MatchCallback = std::function<void(ArtifactMatch)>;

std::vector<std::filesystem::path> BuildTargetDirectories(bool fullDiskScan, const OsVersionInfo& os);

void CrawlDirectory(
    const std::filesystem::path& rootPath,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ThreadPool& pool,
    const std::filesystem::path& selfExePath,
    ScanStats& stats,
    MatchCallback onMatch
);

}