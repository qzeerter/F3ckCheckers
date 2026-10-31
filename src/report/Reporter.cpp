#include "Reporter.hpp"
#include "../core/Platform.hpp"
#include "../ui/Console.hpp"
#include "../engine/Signatures.hpp"
#include "../scanners/RegistryScanner.hpp"
#include <aclapi.h>
#include <tlhelp32.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>

namespace fs = std::filesystem;

namespace trace::report {

static std::wstring CategoryToTag(MatchType t) {
    switch (t) {
        case MatchType::FileOrDirName:      return L"[файл]";
        case MatchType::FileContentPlain:   return L"[текст]";
        case MatchType::FileContentEncoded: return L"[шифр]";
        case MatchType::RegistryKey:        return L"[реестр]";
        case MatchType::RegistryValue:      return L"[реестр]";
    }
    return L"[?]";
}

static bool UnlockRegistryKeyPermissions(HKEY hRoot, const std::wstring& subKey) {
    PSID pAdminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
        return false;
    }

    HKEY hKeyOwner = nullptr;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, WRITE_OWNER | KEY_WOW64_64KEY, &hKeyOwner) == ERROR_SUCCESS) {
        SetSecurityInfo(hKeyOwner, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, pAdminSid, nullptr, nullptr, nullptr);
        RegCloseKey(hKeyOwner);
    }

    bool success = false;
    HKEY hKeyDacl = nullptr;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, READ_CONTROL | WRITE_DAC | KEY_WOW64_64KEY, &hKeyDacl) == ERROR_SUCCESS) {
        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (GetSecurityInfo(hKeyDacl, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, &pOldDacl, nullptr, &pSD) == ERROR_SUCCESS) {
            EXPLICIT_ACCESSW ea{};
            ea.grfAccessPermissions = KEY_ALL_ACCESS;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea.Trustee.ptstrName = static_cast<LPWSTR>(pAdminSid);

            PACL pNewDacl = nullptr;
            if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
                if (SetSecurityInfo(hKeyDacl, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                                    nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS) {
                    success = true;
                }
                LocalFree(pNewDacl);
            }
            if (pSD) LocalFree(pSD);
        }
        RegCloseKey(hKeyDacl);
    }

    FreeSid(pAdminSid);
    return success;
}

static bool DeleteRegistryValueForce(HKEY rootKey, const std::wstring& subKeyPath, const std::wstring& valueName) {
    HKEY hKey = nullptr;
    LSTATUS st = RegOpenKeyExW(rootKey, subKeyPath.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    if (st == ERROR_ACCESS_DENIED) {
        UnlockRegistryKeyPermissions(rootKey, subKeyPath);
        st = RegOpenKeyExW(rootKey, subKeyPath.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    }
    if (st == ERROR_SUCCESS && hKey != nullptr) {
        bool ok = (RegDeleteValueW(hKey, valueName.c_str()) == ERROR_SUCCESS);
        RegCloseKey(hKey);
        return ok;
    }
    return false;
}

static bool DeleteRegistryTreeForce(HKEY rootKey, const std::wstring& subKeyPath) {
    if (RegDeleteTreeW(rootKey, subKeyPath.c_str()) == ERROR_SUCCESS) {
        return true;
    }
    UnlockRegistryKeyPermissions(rootKey, subKeyPath);
    return (RegDeleteTreeW(rootKey, subKeyPath.c_str()) == ERROR_SUCCESS);
}

fs::path WriteDesktopReport(
    const std::wstring& queryWide,
    const CpuCapabilities& cpu,
    const OsVersionInfo& os,
    const SearchSignatures& sig,
    const ScanStats& stats,
    const std::vector<ArtifactMatch>& matches,
    double elapsedSec
) {
    (void)queryWide;
    (void)cpu;
    (void)os;
    (void)sig;
    (void)stats;
    (void)elapsedSec;

    fs::path reportPath = GetDesktopDirectory() / L"out.txt";
    std::ofstream out(reportPath, std::ios::binary);

    const uint8_t bom[] = { 0xEF, 0xBB, 0xBF };
    out.write(reinterpret_cast<const char*>(bom), sizeof(bom));

    std::wostringstream woss;
    size_t idx = 1;
    for (const auto& m : matches) {
        woss << idx++ << L". " << CategoryToTag(m.type) << L" " << m.location;
        if (m.type == MatchType::RegistryValue && !m.subLocation.empty()) {
            woss << L" -> " << m.subLocation;
        }
        woss << L" (" << m.details << L")\r\n";
    }

    std::string utf8Data = WideToUtf8(woss.str());
    out.write(utf8Data.data(), static_cast<std::streamsize>(utf8Data.size()));
    return reportPath;
}

void PrintMatchesPreview(const std::vector<ArtifactMatch>& matches, size_t maxItems) {
    if (matches.empty()) return;

    ui::PrintLn();
    size_t count = std::min(matches.size(), maxItems);
    for (size_t i = 0; i < count; ++i) {
        const auto& m = matches[i];
        ui::Color tagColor = ui::Color::Default;
        if (m.type == MatchType::FileOrDirName) tagColor = ui::Color::Success;
        else if (m.type == MatchType::FileContentEncoded) tagColor = ui::Color::Warning;
        else if (m.type == MatchType::RegistryKey || m.type == MatchType::RegistryValue) tagColor = ui::Color::Accent;

        ui::Print(L"  " + std::to_wstring(i + 1) + L". ", ui::Color::Muted);
        ui::Print(CategoryToTag(m.type) + L" ", tagColor);

        if (m.type == MatchType::RegistryValue && !m.subLocation.empty()) {
            ui::Print(m.location + L" -> " + m.subLocation);
        } else {
            ui::Print(m.location);
        }
        ui::PrintLn(L" (" + m.details + L")", ui::Color::Muted);
    }

    if (matches.size() > maxItems) {
        ui::PrintLn(L"  ... еще " + std::to_wstring(matches.size() - maxItems), ui::Color::Warning);
    }
}

static bool IsProtectedSystemFile(const fs::path& p) {
    std::wstring lower = ToLowerWide(p.wstring());
    std::wstring extLower = ToLowerWide(p.extension().wstring());

    if (lower.find(L"\\$recycle.bin\\") == std::wstring::npos) {
        if (extLower == L".cpp" || extLower == L".hpp" || extLower == L".h" ||
            extLower == L".c" || extLower == L".rc" || extLower == L".sln" ||
            extLower == L".vcxproj" || extLower == L".filters") {
            return true;
        }
    }

    if (lower.find(L"\\windows\\prefetch\\") != std::wstring::npos ||
        lower.find(L"\\windows\\temp\\") != std::wstring::npos ||
        lower.find(L"\\$recycle.bin\\") != std::wstring::npos) {
        return false;
    }

    if (lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
        lower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
        lower.find(L"\\windows\\winsxs\\") != std::wstring::npos ||
        lower.find(L"\\windows\\appcompat\\") != std::wstring::npos ||
        lower.find(L"\\programdata\\microsoft\\search\\") != std::wstring::npos ||
        lower.find(L"\\programdata\\microsoft\\windows defender\\") != std::wstring::npos ||
        lower.find(L"\\appdata\\local\\microsoft\\visualstudio\\") != std::wstring::npos ||
        lower.find(L"\\windows\\webcache\\") != std::wstring::npos ||
        lower.find(L"ntuser.dat") != std::wstring::npos ||
        lower.find(L"usrclass.dat") != std::wstring::npos ||
        lower.find(L"activitiescache.db") != std::wstring::npos) {
        return true;
    }
    return false;
}

void RemoveArtifactsInteractive(const std::vector<ArtifactMatch>& matches, bool askForContentMatches) {
    size_t deletedFiles = 0;
    size_t deletedReg = 0;
    size_t skippedFiles = 0;

    for (const auto& m : matches) {
        std::error_code ec;

        if (m.type == MatchType::FileOrDirName ||
            m.type == MatchType::FileContentPlain ||
            m.type == MatchType::FileContentEncoded) {
            fs::path p(m.location);
            if (!fs::exists(p, ec)) continue;

            if (IsProtectedSystemFile(p)) {
                ui::PrintLn(L"  [пропущено] " + m.location, ui::Color::Warning);
                ++skippedFiles;
                continue;
            }

            std::wstring pathLower = ToLowerWide(p.wstring());
            bool isRecycleBinItem = (pathLower.find(L"\\$recycle.bin\\") != std::wstring::npos);

            if ((m.type == MatchType::FileContentPlain || m.type == MatchType::FileContentEncoded) && !isRecycleBinItem) {
                if (!askForContentMatches) {
                    ++skippedFiles;
                    continue;
                } else {
                    ui::PrintLn(L"\r\n  " + m.location + L" (" + m.details + L")", ui::Color::Warning);
                    std::wstring ans = ui::ReadLine(L"  Удалить? (y/n): ");
                    if (ans != L"y" && ans != L"Y") {
                        ++skippedFiles;
                        continue;
                    }
                }
            }

            SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (fs::remove_all(p, ec) > 0) {
                ++deletedFiles;
                ui::PrintLn(L"  [удалено] " + m.location, ui::Color::Success);

                if (isRecycleBinItem) {
                    std::wstring fn = p.filename().wstring();
                    if (fn.size() > 2 && fn[0] == L'$' && (fn[1] == L'R' || fn[1] == L'r')) {
                        fn[1] = L'I';
                        fs::path metaFile = p.parent_path() / fn;
                        if (fs::exists(metaFile, ec)) {
                            SetFileAttributesW(metaFile.c_str(), FILE_ATTRIBUTE_NORMAL);
                            fs::remove_all(metaFile, ec);
                        }
                    }
                }
            }
        } else if (m.type == MatchType::RegistryValue && m.rootKey != nullptr) {
            if (m.subLocation.empty() && ToLowerWide(m.subKeyPath).find(L"\\propertystore\\") != std::wstring::npos) {
                if (DeleteRegistryTreeForce(m.rootKey, m.subKeyPath)) {
                    ++deletedReg;
                    ui::PrintLn(L"  [удалено] " + m.location, ui::Color::Success);
                }
                continue;
            }

            if (DeleteRegistryValueForce(m.rootKey, m.subKeyPath, m.subLocation)) {
                ++deletedReg;
                ui::PrintLn(L"  [удалено] " + m.location + L" -> " + m.subLocation, ui::Color::Success);
            }
        } else if (m.type == MatchType::RegistryKey && m.rootKey != nullptr) {
            if (DeleteRegistryTreeForce(m.rootKey, m.subKeyPath)) {
                ++deletedReg;
                ui::PrintLn(L"  [удалено] " + m.location, ui::Color::Success);
            }
        }
    }

    std::error_code ec;
    fs::path tempReport = GetDesktopDirectory() / L"out.txt";
    if (fs::exists(tempReport, ec)) {
        fs::remove(tempReport, ec);
    }

    ui::PrintLn(L"\r\nУдалено файлов: " + std::to_wstring(deletedFiles) +
                L" | реестр: " + std::to_wstring(deletedReg) +
                L" | пропущено: " + std::to_wstring(skippedFiles), ui::Color::Success);
}

void CleanAppLaunchCaches(const fs::path& targetExePath, SimdPath simdPath, bool hasSse42) {
    std::wstring exeStemLower = ToLowerWide(targetExePath.stem().wstring());
    if (exeStemLower.size() < 3) return;

    SearchSignatures selfSig = engine::BuildSignatures(WideToUtf8(exeStemLower), false, hasSse42);
    ScanStats dummyStats;

    std::mutex mtx;
    std::vector<ArtifactMatch> selfMatches;

    auto onSelfMatch = [&](ArtifactMatch m) {
        std::lock_guard<std::mutex> lock(mtx);
        selfMatches.push_back(std::move(m));
    };

    {
        scanners::ThreadPool pool(6);
        scanners::EnqueueFastSelfCleanTasks(pool, exeStemLower, selfSig, simdPath, dummyStats, onSelfMatch);
        pool.WaitAll();
    }

    for (const auto& m : selfMatches) {
        if (m.type == MatchType::RegistryValue && m.rootKey != nullptr) {
            DeleteRegistryValueForce(m.rootKey, m.subKeyPath, m.subLocation);
        } else if (m.type == MatchType::RegistryKey && m.rootKey != nullptr) {
            DeleteRegistryTreeForce(m.rootKey, m.subKeyPath);
        }
    }

    wchar_t winBuf[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"WINDIR", winBuf, MAX_PATH)) {
        fs::path pfDir = fs::path(winBuf) / L"Prefetch";
        std::error_code ec;
        if (fs::exists(pfDir, ec)) {
            for (const auto& entry : fs::directory_iterator(pfDir, ec)) {
                std::wstring fn = ToLowerWide(entry.path().filename().wstring());
                if (fn.starts_with(exeStemLower) && fn.ends_with(L".pf")) {
                    fs::remove(entry.path(), ec);
                }
            }
        }
    }
}

static bool TrySpawnWithParent(HANDLE hParent, const fs::path& selfExePath, const std::wstring& cmdLine) {
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    if (attrSize == 0) return false;

    std::vector<uint8_t> attrBuf(attrSize);
    auto pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize)) {
        return false;
    }

    bool spawned = false;
    if (UpdateProcThreadAttribute(
            pAttrList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent,
            sizeof(HANDLE),
            nullptr,
            nullptr)) {
        std::wstring mutableCmd = cmdLine;
        STARTUPINFOEXW siEx{};
        siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
        siEx.lpAttributeList = pAttrList;
        PROCESS_INFORMATION pi{};

        if (CreateProcessW(
                selfExePath.c_str(),
                mutableCmd.data(),
                nullptr,
                nullptr,
                FALSE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &siEx.StartupInfo,
                &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            spawned = true;
        }
    }

    DeleteProcThreadAttributeList(pAttrList);
    return spawned;
}

void SpawnPostExitCleaner(const fs::path& selfExePath) {
    DWORD selfPid = GetCurrentProcessId();
    std::wstring cmdLine = L"\"" + selfExePath.wstring() + L"\" --postclean " + std::to_wstring(selfPid);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID != selfPid && ToLowerWide(pe.szExeFile) == L"winlogon.exe") {
                    HANDLE hProc = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProc != nullptr) {
                        bool ok = TrySpawnWithParent(hProc, selfExePath, cmdLine);
                        CloseHandle(hProc);
                        if (ok) {
                            CloseHandle(hSnap);
                            return;
                        }
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }

        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID <= 4 || pe.th32ProcessID == selfPid) continue;
                HANDLE hProc = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc != nullptr) {
                    BOOL inJob = TRUE;
                    if (IsProcessInJob(hProc, nullptr, &inJob) && !inJob) {
                        bool ok = TrySpawnWithParent(hProc, selfExePath, cmdLine);
                        CloseHandle(hProc);
                        if (ok) {
                            CloseHandle(hSnap);
                            return;
                        }
                    } else {
                        CloseHandle(hProc);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);
    }

    std::wstring fallbackCmd = cmdLine;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(
            selfExePath.c_str(),
            fallbackCmd.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

}