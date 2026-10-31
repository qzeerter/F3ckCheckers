#include "core/Types.hpp"
#include "core/Platform.hpp"
#include "ui/Console.hpp"
#include "engine/Signatures.hpp"
#include "scanners/FileScanner.hpp"
#include "scanners/RegistryScanner.hpp"
#include "report/Reporter.hpp"

#include <mutex>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>

static std::filesystem::path g_selfPath;

static BOOL WINAPI ConsoleCloseHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        if (!g_selfPath.empty()) {
            trace::report::SpawnPostExitCleaner(g_selfPath);
        }
        ExitProcess(0);
    }
    return TRUE;
}

static bool QuickDeleteCompatStoreAllUsers(const std::filesystem::path& exePath) {
    bool deletedAny = false;
    const std::wstring exeStr = exePath.wstring();
    const std::wstring exeStemLower = trace::ToLowerWide(exePath.stem().wstring());
    const wchar_t* storeRelPath = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store";

    auto cleanStoreKey = [&](HKEY hRoot, const std::wstring& subPath) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(hRoot, subPath.c_str(), 0, KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
            return;
        }
        if (RegDeleteValueW(hKey, exeStr.c_str()) == ERROR_SUCCESS) {
            deletedAny = true;
        }

        wchar_t valName[2048]{};
        DWORD idx = 0;
        std::vector<std::wstring> toDel;
        for (;;) {
            DWORD len = 2048;
            if (RegEnumValueW(hKey, idx++, valName, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                break;
            }
            std::wstring v(valName, len);
            if (trace::ToLowerWide(v).find(exeStemLower) != std::wstring::npos) {
                toDel.push_back(std::move(v));
            }
        }
        for (const auto& v : toDel) {
            if (RegDeleteValueW(hKey, v.c_str()) == ERROR_SUCCESS) {
                deletedAny = true;
            }
        }
        RegCloseKey(hKey);
    };

    cleanStoreKey(HKEY_CURRENT_USER, storeRelPath);

    HKEY hUsers = nullptr;
    if (RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_READ | KEY_WOW64_64KEY, &hUsers) == ERROR_SUCCESS) {
        wchar_t sidBuf[256]{};
        DWORD idx = 0;
        for (;;) {
            DWORD sidLen = 256;
            if (RegEnumKeyExW(hUsers, idx++, sidBuf, &sidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                break;
            }
            std::wstring sid(sidBuf, sidLen);
            if (sid.starts_with(L"S-1-5-21-") && !sid.ends_with(L"_Classes")) {
                cleanStoreKey(HKEY_USERS, sid + L"\\" + storeRelPath);
            }
        }
        RegCloseKey(hUsers);
    }

    return deletedAny;
}

int main(int argc, char* argv[]) {
    using namespace trace;

    EnableSystemPrivileges();
    CpuCapabilities cpu = DetectCpuCapabilities();
    g_selfPath = GetSelfExecutablePath();

    if (argc >= 3 && std::string_view(argv[1]) == "--postclean") {
        DWORD parentPid = static_cast<DWORD>(std::strtoul(argv[2], nullptr, 10));
        if (parentPid != 0) {
            HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
            if (hParent != nullptr) {
                WaitForSingleObject(hParent, 5000);
                CloseHandle(hParent);
            }
        }

        Sleep(100);
        report::CleanAppLaunchCaches(g_selfPath, cpu.activePath, cpu.hasSse42);

        for (int i = 0; i < 60; ++i) {
            if (QuickDeleteCompatStoreAllUsers(g_selfPath) && i >= 4) {
                Sleep(150);
                QuickDeleteCompatStoreAllUsers(g_selfPath);
                break;
            }
            Sleep(50);
        }
        report::CleanAppLaunchCaches(g_selfPath, cpu.activePath, cpu.hasSse42);
        return 0;
    }

    ui::InitConsole();
    OsVersionInfo os = DetectOsVersion();
    SetConsoleCtrlHandler(ConsoleCloseHandler, TRUE);

    ui::PrintHeader(cpu, os);

    std::wstring queryWide = ui::ReadLine(L"\r\nЗапрос (от 4 симв.): ");
    if (queryWide.size() < 4) {
        ui::ClearScreen();
        report::SpawnPostExitCleaner(g_selfPath);
        return 0;
    }

    std::wstring modeStr = ui::ReadLine(L"Режим (1 - быстрый, 2 - все диски) [1]: ");
    bool fullDiskScan = (modeStr == L"2");

    std::wstring heurStr = ui::ReadLine(L"Хэши и опечатки? (y/n) [y]: ");
    bool enableHeuristics = (heurStr.empty() || heurStr == L"y" || heurStr == L"Y" || heurStr == L"д" || heurStr == L"Д");

    std::wstring queryWideLower = ToLowerWide(queryWide);
    SearchSignatures sig = engine::BuildSignatures(WideToUtf8(queryWide), enableHeuristics, cpu.hasSse42);

    std::mutex resultsMutex;
    std::vector<ArtifactMatch> matches;
    ScanStats stats;

    auto addMatch = [&](ArtifactMatch m) {
        std::lock_guard<std::mutex> lock(resultsMutex);
        for (const auto& existing : matches) {
            if (existing.type == m.type &&
                existing.location == m.location &&
                existing.subLocation == m.subLocation) {
                return;
            }
        }
        matches.push_back(std::move(m));
    };

    auto startTime = std::chrono::high_resolution_clock::now();

    uint32_t workerCount = std::max(4u, cpu.logicalCores);
    ui::PrintLn(L"Поиск (" + std::to_wstring(workerCount) + L" пот.)...", ui::Color::Accent);

    {
        scanners::ThreadPool pool(workerCount);

        scanners::EnqueueRegistryTasks(pool, os, queryWideLower, sig, cpu.activePath, stats, addMatch);

        auto targetDirs = scanners::BuildTargetDirectories(fullDiskScan, os);
        for (const auto& dir : targetDirs) {
            scanners::CrawlDirectory(dir, queryWideLower, sig, cpu.activePath, pool, g_selfPath, stats, addMatch);
        }

        pool.WaitAll();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    double elapsedSec = std::chrono::duration<double>(endTime - startTime).count();

    std::wostringstream summary;
    summary << L"\r\nВремя: " << std::fixed << std::setprecision(2) << elapsedSec << L" с | "
            << L"Файлов: " << stats.filesScanned.load()
            << L" (" << (stats.bytesScanned.load() / (1024 * 1024)) << L" МБ) | "
            << L"Реестр: " << stats.regKeysScanned.load() << L" | "
            << L"Найдено: " << matches.size();
    ui::PrintLn(summary.str(), matches.empty() ? ui::Color::Success : ui::Color::Warning);

    if (!matches.empty()) {
        report::PrintMatchesPreview(matches, 200);
    }

    for (;;) {
        ui::PrintLn(L"\r\n1 - выход, 2 - удалить (реестр + имена), 3 - удалить (с запросом по контенту), 4 - сохранить out.txt", ui::Color::Muted);
        std::wstring action = ui::ReadLine(L"Выбор [1]: ");

        if (action == L"4") {
            auto p = report::WriteDesktopReport(queryWide, cpu, os, sig, stats, matches, elapsedSec);
            ui::PrintLn(L"Сохранено: " + p.wstring(), ui::Color::Accent);
            continue;
        }

        if (action == L"2" || action == L"3") {
            std::wstring confirm = ui::ReadLine(L"Подтвердить? (y/n): ");
            if (confirm == L"y" || confirm == L"Y" || confirm == L"д" || confirm == L"Д") {
                report::RemoveArtifactsInteractive(matches, action == L"3");
            }
        }
        break;
    }

    ui::ClearScreen();
    report::SpawnPostExitCleaner(g_selfPath);
    return 0;
}