#include "Console.hpp"
#include "../core/Platform.hpp"
#include <iostream>
#include <sstream>
#include <mutex>

namespace trace::ui {

static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static HANDLE g_hIn  = INVALID_HANDLE_VALUE;
static bool g_isConsoleOut = false;
static bool g_isConsoleIn  = false;
static WORD g_defaultAttrs = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static std::mutex g_conMutex;

void InitConsole() {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hIn  = GetStdHandle(STD_INPUT_HANDLE);

    DWORD modeOut = 0;
    if (g_hOut != INVALID_HANDLE_VALUE && GetConsoleMode(g_hOut, &modeOut)) {
        g_isConsoleOut = true;
        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        if (GetConsoleScreenBufferInfo(g_hOut, &csbi)) {
            g_defaultAttrs = csbi.wAttributes;
        }
    }

    DWORD modeIn = 0;
    if (g_hIn != INVALID_HANDLE_VALUE && GetConsoleMode(g_hIn, &modeIn)) {
        g_isConsoleIn = true;
    }

    SetConsoleTitleW(L"Runtime Broker");
}

void ClearScreen() {
    if (!g_isConsoleOut) return;
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (!GetConsoleScreenBufferInfo(g_hOut, &csbi)) return;

    DWORD cellCount = static_cast<DWORD>(csbi.dwSize.X) * static_cast<DWORD>(csbi.dwSize.Y);
    DWORD count = 0;
    COORD homeCoords = { 0, 0 };

    FillConsoleOutputCharacterW(g_hOut, L' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(g_hOut, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(g_hOut, homeCoords);
}

static WORD ColorToAttr(Color c) {
    switch (c) {
        case Color::Muted:   return FOREGROUND_INTENSITY;
        case Color::Accent:  return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case Color::Success: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Warning: return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case Color::Error:   return FOREGROUND_RED | FOREGROUND_INTENSITY;
        default:             return g_defaultAttrs;
    }
}

void Print(std::wstring_view text, Color color) {
    if (text.empty()) return;
    std::lock_guard<std::mutex> lock(g_conMutex);

    if (g_isConsoleOut) {
        if (color != Color::Default) {
            SetConsoleTextAttribute(g_hOut, ColorToAttr(color));
        }
        DWORD written = 0;
        WriteConsoleW(g_hOut, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        if (color != Color::Default) {
            SetConsoleTextAttribute(g_hOut, g_defaultAttrs);
        }
    } else {
        std::string utf8 = WideToUtf8(text);
        std::cout << utf8 << std::flush;
    }
}

void PrintLn(std::wstring_view text, Color color) {
    std::wstring line(text);
    line.append(L"\r\n");
    Print(line, color);
}

void PrintHeader(const CpuCapabilities& cpu, const OsVersionInfo& os) {
    std::wstring simdName;
    switch (cpu.activePath) {
        case SimdPath::Avx512BW:     simdName = L"AVX-512BW"; break;
        case SimdPath::Avx2FastBmi2: simdName = L"AVX2+BMI2"; break;
        case SimdPath::Avx2Pure:     simdName = L"AVX2"; break;
        case SimdPath::Sse2:         simdName = L"SSE2"; break;
    }

    Print(L"ОС : ", Color::Muted);
    Print(os.displayName);
    if (os.isElevated) {
        PrintLn(L" (админ)", Color::Success);
    } else {
        PrintLn(L" (обычный)", Color::Warning);
    }

    Print(L"CPU: ", Color::Muted);
    PrintLn(cpu.brand + L" (" + std::to_wstring(cpu.logicalCores) + L" пот., " + simdName + L")");
}

std::wstring ReadLine(std::wstring_view prompt) {
    Print(prompt, Color::Default);

    if (g_isConsoleIn) {
        wchar_t buf[1024]{};
        DWORD charsRead = 0;
        if (ReadConsoleW(g_hIn, buf, 1023, &charsRead, nullptr) && charsRead > 0) {
            std::wstring res(buf, charsRead);
            while (!res.empty() && (res.back() == L'\r' || res.back() == L'\n' || res.back() == L' ')) {
                res.pop_back();
            }
            while (!res.empty() && res.front() == L' ') {
                res.erase(res.begin());
            }
            return res;
        }
        return {};
    } else {
        std::string line;
        std::getline(std::cin, line);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        return Utf8ToWide(line);
    }
}

void WaitForEnter(std::wstring_view prompt) {
    ReadLine(prompt);
}

}