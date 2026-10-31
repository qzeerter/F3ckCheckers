#include "RegistryScanner.hpp"
#include "../core/Platform.hpp"
#include "../engine/Signatures.hpp"
#include "../engine/SimdScanner.hpp"
#include <vector>

namespace trace::scanners {

static std::wstring RootKeyToString(HKEY root) {
    if (root == HKEY_CURRENT_USER)  return L"HKCU";
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_USERS)         return L"HKU";
    if (root == HKEY_CLASSES_ROOT)  return L"HKCR";
    return L"HKEY";
}

static std::wstring ApplyWideRot13(std::wstring_view wv) {
    std::wstring out(wv);
    for (wchar_t& c : out) {
        if (c >= L'a' && c <= L'z') {
            c = static_cast<wchar_t>(L'a' + (c - L'a' + 13) % 26);
        } else if (c >= L'A' && c <= L'Z') {
            c = static_cast<wchar_t>(L'A' + (c - L'A' + 13) % 26);
        }
    }
    return out;
}

static void ScanRegistryRecursive(
    HKEY hRoot,
    const std::wstring& subKey,
    const std::wstring& queryWideLower,
    const std::wstring& queryRot13Lower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    const MatchCallback& onMatch,
    int depth = 0
) {
    if (depth > 28) return;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        return;
    }

    stats.regKeysScanned.fetch_add(1, std::memory_order_relaxed);
    std::wstring fullKeyDisplay = RootKeyToString(hRoot) + L"\\" + subKey;

    DWORD maxValueNameLen = 16384;
    DWORD maxValueDataLen = 256 * 1024;
    RegQueryInfoKeyW(
        hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr
    );

    std::vector<wchar_t> valNameBuf(std::max<DWORD>(maxValueNameLen + 2, 16384));
    std::vector<uint8_t> valDataBuf(std::max<DWORD>(maxValueDataLen + 16, 256 * 1024));

    DWORD index = 0;
    for (;;) {
        DWORD nameLen = static_cast<DWORD>(valNameBuf.size());
        DWORD dataLen = static_cast<DWORD>(valDataBuf.size());
        DWORD type = 0;

        LSTATUS status = RegEnumValueW(
            hKey, index++, valNameBuf.data(), &nameLen,
            nullptr, &type, valDataBuf.data(), &dataLen
        );

        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status == ERROR_MORE_DATA) {
            if (dataLen > valDataBuf.size() && dataLen <= 16 * 1024 * 1024) {
                valDataBuf.resize(dataLen + 64);
                nameLen = static_cast<DWORD>(valNameBuf.size());
                status = RegEnumValueW(
                    hKey, index - 1, valNameBuf.data(), &nameLen,
                    nullptr, &type, valDataBuf.data(), &dataLen
                );
            }
        }
        if (status != ERROR_SUCCESS) continue;

        std::wstring valName(valNameBuf.data(), nameLen);
        std::wstring valNameLower = ToLowerWide(valName);

        if (valNameLower.find(queryWideLower) != std::wstring::npos) {
            onMatch({
                MatchType::RegistryValue,
                fullKeyDisplay,
                valName,
                L"name",
                hRoot,
                subKey
            });
            continue;
        }

        if (!queryRot13Lower.empty() && queryRot13Lower != queryWideLower &&
            valNameLower.find(queryRot13Lower) != std::wstring::npos) {
            onMatch({
                MatchType::RegistryValue,
                fullKeyDisplay,
                valName,
                L"ROT13: " + ApplyWideRot13(valName),
                hRoot,
                subKey
            });
            continue;
        }

        if (dataLen > 0) {
            if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
                std::wstring strData(reinterpret_cast<const wchar_t*>(valDataBuf.data()), dataLen / sizeof(wchar_t));
                if (ToLowerWide(strData).find(queryWideLower) != std::wstring::npos) {
                    onMatch({
                        MatchType::RegistryValue,
                        fullKeyDisplay,
                        valName,
                        L"str",
                        hRoot,
                        subKey
                    });
                }
            } else {
                RawHit hit = engine::ScanMemoryBuffer(valDataBuf.data(), dataLen, sig, simdPath, false);
                if (hit.kind != HitKind::None) {
                    onMatch({
                        MatchType::RegistryValue,
                        fullKeyDisplay,
                        valName,
                        L"bin (" + engine::FormatHitDescription(hit, sig.rawLower.size()) + L")",
                        hRoot,
                        subKey
                    });
                }
            }
        }
    }

    index = 0;
    std::vector<wchar_t> keyNameBuf(1024);
    std::vector<std::wstring> childKeys;

    for (;;) {
        DWORD keyNameLen = static_cast<DWORD>(keyNameBuf.size());
        LSTATUS status = RegEnumKeyExW(
            hKey, index++, keyNameBuf.data(), &keyNameLen,
            nullptr, nullptr, nullptr, nullptr
        );
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        std::wstring childName(keyNameBuf.data(), keyNameLen);
        std::wstring childPath = subKey.empty() ? childName : (subKey + L"\\" + childName);
        std::wstring childLower = ToLowerWide(childName);

        if (childLower.find(queryWideLower) != std::wstring::npos) {
            onMatch({
                MatchType::RegistryKey,
                RootKeyToString(hRoot) + L"\\" + childPath,
                L"",
                L"key",
                hRoot,
                childPath
            });
        }
        childKeys.push_back(std::move(childPath));
    }

    RegCloseKey(hKey);

    for (const auto& child : childKeys) {
        ScanRegistryRecursive(hRoot, child, queryWideLower, queryRot13Lower, sig, simdPath, stats, onMatch, depth + 1);
    }
}

void EnqueueRegistryTasks(
    ThreadPool& pool,
    const OsVersionInfo& os,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    MatchCallback onMatch
) {
    (void)os;
    std::wstring queryRot13Lower = ApplyWideRot13(queryWideLower);

    static const std::vector<std::pair<HKEY, std::wstring>> roots = {
        { HKEY_CURRENT_USER,  L"Software" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" }
    };

    for (const auto& [rootKey, subPath] : roots) {
        pool.Enqueue([rootKey, subPath, queryWideLower, queryRot13Lower, &sig, simdPath, &stats, onMatch]() {
            ScanRegistryRecursive(rootKey, subPath, queryWideLower, queryRot13Lower, sig, simdPath, stats, onMatch, 0);
        });
    }
}

void EnqueueFastSelfCleanTasks(
    ThreadPool& pool,
    const std::wstring& queryWideLower,
    const SearchSignatures& sig,
    SimdPath simdPath,
    ScanStats& stats,
    MatchCallback onMatch
) {
    std::wstring queryRot13Lower = ApplyWideRot13(queryWideLower);

    std::vector<std::pair<HKEY, std::wstring>> fastRoots = {
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags" },
        { HKEY_CURRENT_USER,  L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" },
        { HKEY_CURRENT_USER,  L"Software\\Hex-Rays" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\bam\\UserSettings" }
    };

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
                fastRoots.emplace_back(HKEY_USERS, sid + L"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags");
                fastRoots.emplace_back(HKEY_USERS, sid + L"\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell");
                fastRoots.emplace_back(HKEY_USERS, sid + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer");
                fastRoots.emplace_back(HKEY_USERS, sid + L"\\Software\\Hex-Rays");
            }
        }
        RegCloseKey(hUsers);
    }

    for (const auto& [rootKey, subPath] : fastRoots) {
        pool.Enqueue([rootKey, subPath, queryWideLower, queryRot13Lower, &sig, simdPath, &stats, onMatch]() {
            ScanRegistryRecursive(rootKey, subPath, queryWideLower, queryRot13Lower, sig, simdPath, stats, onMatch, 0);
        });
    }
}

}