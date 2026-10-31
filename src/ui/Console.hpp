#pragma once

#include "../core/Types.hpp"
#include <string>
#include <string_view>

namespace trace::ui {

enum class Color {
    Default,
    Muted,
    Accent,
    Success,
    Warning,
    Error
};

void InitConsole();
void ClearScreen();
void Print(std::wstring_view text, Color color = Color::Default);
void PrintLn(std::wstring_view text = L"", Color color = Color::Default);
void PrintHeader(const CpuCapabilities& cpu, const OsVersionInfo& os);

std::wstring ReadLine(std::wstring_view prompt);
void WaitForEnter(std::wstring_view prompt = L"Нажмите Enter для выхода...");

}