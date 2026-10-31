#include "Platform.hpp"
#include <shlobj.h>
#include <intrin.h>
#include <thread>
#include <algorithm>
#include <cwctype>
#include <cstring>
#include <sstream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

namespace trace {

using RtlGetVersion_t = LONG(NTAPI*)(PRTL_OSVERSIONINFOW);

std::string ToLowerASCII(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) {
        c = ExactCharToLower(c);
    }
    return out;
}

std::wstring ToLowerWide(std::wstring_view wv) {
    std::wstring out(wv);
    for (wchar_t& c : out) {
        if (c >= L'A' && c <= L'Z') {
            c += 0x20;
        } else {
            c = static_cast<wchar_t>(std::towlower(c));
        }
    }
    return out;
}

std::string WideToUtf8(std::wstring_view wv) {
    if (wv.empty()) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wv.data(), static_cast<int>(wv.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string out(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wv.data(), static_cast<int>(wv.size()), out.data(), sizeNeeded, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(std::string_view sv) {
    if (sv.empty()) return {};
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, sv.data(), static_cast<int>(sv.size()), nullptr, 0);
    if (sizeNeeded <= 0) return {};
    std::wstring out(sizeNeeded, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, sv.data(), static_cast<int>(sv.size()), out.data(), sizeNeeded);
    return out;
}

CpuCapabilities DetectCpuCapabilities() {
    CpuCapabilities cap;
    cap.logicalCores = std::max(1u, std::thread::hardware_concurrency());

    int cpuInfo0[4]{ 0, 0, 0, 0 };
    __cpuid(cpuInfo0, 0);
    int maxLeaf = cpuInfo0[0];

    char vendorBuf[13]{};
    std::memcpy(vendorBuf + 0, &cpuInfo0[1], 4);
    std::memcpy(vendorBuf + 4, &cpuInfo0[3], 4);
    std::memcpy(vendorBuf + 8, &cpuInfo0[2], 4);
    cap.vendor = Utf8ToWide(vendorBuf);

    if (maxLeaf >= 1) {
        int cpuInfo1[4]{ 0, 0, 0, 0 };
        __cpuid(cpuInfo1, 1);

        int baseModel  = (cpuInfo1[0] >> 4) & 0xF;
        int baseFamily = (cpuInfo1[0] >> 8) & 0xF;
        int extModel   = (cpuInfo1[0] >> 16) & 0xF;
        int extFamily  = (cpuInfo1[0] >> 20) & 0xFF;

        cap.family = (baseFamily == 0xF) ? (baseFamily + extFamily) : baseFamily;
        cap.model  = (baseFamily == 0x6 || baseFamily == 0xF) ? ((extModel << 4) | baseModel) : baseModel;

        cap.hasSse42  = (cpuInfo1[2] & (1 << 20)) != 0;
        cap.hasPopcnt = (cpuInfo1[2] & (1 << 23)) != 0;

        bool osUsesXSave = (cpuInfo1[2] & (1 << 27)) != 0;
        bool cpuAvx      = (cpuInfo1[2] & (1 << 28)) != 0;
        bool ymmStateEnabled = false;
        bool zmmStateEnabled = false;
        if (osUsesXSave && cpuAvx) {
            unsigned long long xcr0 = _xgetbv(0);
            ymmStateEnabled = ((xcr0 & 0x6) == 0x6);
            zmmStateEnabled = ((xcr0 & 0xE6) == 0xE6);
        }

        if (maxLeaf >= 7 && ymmStateEnabled) {
            int cpuInfo7[4]{ 0, 0, 0, 0 };
            __cpuidex(cpuInfo7, 7, 0);
            cap.hasBmi1 = (cpuInfo7[1] & (1 << 3)) != 0;
            cap.hasAvx2 = (cpuInfo7[1] & (1 << 5)) != 0;
            cap.hasBmi2 = (cpuInfo7[1] & (1 << 8)) != 0;

            bool avx512f  = (cpuInfo7[1] & (1 << 16)) != 0;
            bool avx512bw = (cpuInfo7[1] & (1 << 30)) != 0;
            if (zmmStateEnabled && avx512f && avx512bw) {
                cap.hasAvx512BW = true;
            }
        }
    }

    int extInfo0[4]{ 0, 0, 0, 0 };
    __cpuid(extInfo0, 0x80000000);
    if (static_cast<uint32_t>(extInfo0[0]) >= 0x80000004u) {
        char brandBuf[49]{};
        int brandRegs[4]{};
        __cpuid(brandRegs, 0x80000002);
        std::memcpy(brandBuf + 0, brandRegs, 16);
        __cpuid(brandRegs, 0x80000003);
        std::memcpy(brandBuf + 16, brandRegs, 16);
        __cpuid(brandRegs, 0x80000004);
        std::memcpy(brandBuf + 32, brandRegs, 16);

        std::string brandStr(brandBuf);
        auto first = brandStr.find_first_not_of(" \t\r\n");
        auto last  = brandStr.find_last_not_of(" \t\r\n");
        if (first != std::string::npos && last != std::string::npos) {
            brandStr = brandStr.substr(first, last - first + 1);
        }
        cap.brand = Utf8ToWide(brandStr);
    } else {
        cap.brand = cap.vendor;
    }

    if (cap.hasBmi2) {
        if (cap.vendor == L"AuthenticAMD" && cap.family <= 0x17) {
            cap.hasFastBmi2 = false;
        } else {
            cap.hasFastBmi2 = true;
        }
    }

    if (cap.hasAvx512BW && cap.hasAvx2 && cap.hasBmi1 && cap.hasPopcnt) {
        cap.activePath = SimdPath::Avx512BW;
    } else if (cap.hasAvx2 && cap.hasBmi1 && cap.hasPopcnt) {
        cap.activePath = cap.hasFastBmi2 ? SimdPath::Avx2FastBmi2 : SimdPath::Avx2Pure;
    } else {
        cap.activePath = SimdPath::Sse2;
    }

    return cap;
}

static bool CheckIsElevated() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

static std::wstring ReadRegString(HKEY hKey, const wchar_t* name) {
    wchar_t buf[256]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && size >= sizeof(wchar_t)) {
        return std::wstring(buf);
    }
    return {};
}

static uint32_t ReadRegDword(HKEY hKey, const wchar_t* name) {
    DWORD val = 0;
    DWORD size = sizeof(val);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, name, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS &&
        type == REG_DWORD) {
        return val;
    }
    return 0;
}

static std::wstring MapEditionId(std::wstring_view editionId) {
    if (editionId == L"Professional")            return L"Pro";
    if (editionId == L"ProfessionalWorkstation") return L"Pro for Workstations";
    if (editionId == L"ProfessionalEducation")   return L"Pro Education";
    if (editionId == L"Core")                    return L"Home";
    if (editionId == L"CoreSingleLanguage")      return L"Home Single Language";
    if (editionId == L"Enterprise")              return L"Enterprise";
    if (editionId == L"EnterpriseS")             return L"Enterprise LTSC";
    if (editionId == L"IoTEnterprise")           return L"IoT Enterprise";
    if (editionId == L"IoTEnterpriseS")          return L"IoT Enterprise LTSC";
    if (editionId == L"Education")               return L"Education";
    return std::wstring(editionId);
}

static std::wstring ReleaseByBuild(uint32_t major, uint32_t build) {
    if (major == 10 && build >= 22000) {
        if (build >= 26300) return L"26H1";
        if (build >= 26200) return L"25H2";
        if (build >= 26100) return L"24H2";
        if (build >= 22631) return L"23H2";
        if (build >= 22621) return L"22H2";
        return L"21H2";
    }
    if (major == 10) {
        if (build >= 19045) return L"22H2";
        if (build >= 19044) return L"21H2";
        if (build >= 19043) return L"21H1";
        if (build >= 19042) return L"20H2";
        if (build >= 19041) return L"2004";
        if (build >= 18363) return L"1909";
        if (build >= 18362) return L"1903";
        if (build >= 17763) return L"1809";
        if (build >= 17134) return L"1803";
        if (build >= 16299) return L"1709";
        if (build >= 15063) return L"1703";
        if (build >= 14393) return L"1607";
        if (build >= 10586) return L"1511";
        if (build >= 10240) return L"1507";
    }
    return {};
}

OsVersionInfo DetectOsVersion() {
    OsVersionInfo info;
    info.isElevated = CheckIsElevated();

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pRtlGetVersion = reinterpret_cast<RtlGetVersion_t>(GetProcAddress(hNtdll, "RtlGetVersion"));
        if (pRtlGetVersion) {
            RTL_OSVERSIONINFOW osvi{};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (pRtlGetVersion(&osvi) == 0) {
                info.major = osvi.dwMajorVersion;
                info.minor = osvi.dwMinorVersion;
                info.build = osvi.dwBuildNumber;
            }
        }
    }

    std::wstring regDisplayVersion;
    std::wstring edition;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        regDisplayVersion = ReadRegString(hKey, L"DisplayVersion");
        if (regDisplayVersion.empty()) {
            regDisplayVersion = ReadRegString(hKey, L"ReleaseId");
        }
        std::wstring rawEdition = ReadRegString(hKey, L"EditionID");
        if (!rawEdition.empty()) {
            edition = MapEditionId(rawEdition);
        }
        info.ubr = ReadRegDword(hKey, L"UBR");
        RegCloseKey(hKey);
    }

    std::wstring exactVer = ReleaseByBuild(info.major, info.build);
    std::wstring finalVer = !exactVer.empty() ? exactVer : regDisplayVersion;

    std::wostringstream oss;
    if (info.major == 10 && info.build >= 22000) {
        info.isWin11 = true;
        oss << L"Windows 11";
        if (!edition.empty()) oss << L" " << edition;
        if (!finalVer.empty()) oss << L" " << finalVer;
    } else if (info.major == 10) {
        oss << L"Windows 10";
        if (!edition.empty()) oss << L" " << edition;
        if (!finalVer.empty()) oss << L" " << finalVer;
    } else if (info.major == 6 && info.minor == 3) {
        oss << L"Windows 8.1";
        if (!edition.empty()) oss << L" " << edition;
    } else if (info.major == 6 && info.minor == 2) {
        oss << L"Windows 8";
        if (!edition.empty()) oss << L" " << edition;
    } else if (info.major == 6 && info.minor == 1) {
        oss << L"Windows 7";
        if (!edition.empty()) oss << L" " << edition;
    } else {
        oss << L"Windows NT " << info.major << L"." << info.minor;
    }

    oss << L" (" << info.build;
    if (info.ubr > 0) {
        oss << L"." << info.ubr;
    }
    oss << L")";

    info.displayName     = oss.str();
    info.hasPcaDatabase  = (info.build >= 22621);
    info.hasBamService   = (info.build >= 16299);
    info.hasFeatureUsage = (info.build >= 18362);
    return info;
}

static bool SetPrivilege(HANDLE hToken, LPCWSTR privName) {
    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privName, &luid)) return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    return (GetLastError() == ERROR_SUCCESS);
}

bool EnableSystemPrivileges() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    bool ok1 = SetPrivilege(hToken, SE_BACKUP_NAME);
    bool ok2 = SetPrivilege(hToken, SE_RESTORE_NAME);
    bool ok3 = SetPrivilege(hToken, SE_DEBUG_NAME);
    bool ok4 = SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME);
    CloseHandle(hToken);
    return ok1 || ok2 || ok3 || ok4;
}

std::filesystem::path GetDesktopDirectory() {
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &path))) {
        std::filesystem::path desktop(path);
        CoTaskMemFree(path);
        return desktop;
    }
    return std::filesystem::current_path();
}

std::filesystem::path GetSelfExecutablePath() {
    wchar_t selfBuf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfBuf, MAX_PATH);
    return std::filesystem::path(selfBuf);
}

}