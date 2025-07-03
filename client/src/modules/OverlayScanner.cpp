#include "pch.h"
#include "../include/OverlayScanner.h"
#include "../include/Utils.h"
#include <iostream>
#include <algorithm>

// deklarasi helper logging
extern void LogToServer(const std::string& msg);
extern std::string Narrow(const std::wstring& ws);

using namespace GarudaHS;

std::vector<WindowInfo> OverlayScanner::knownWindows;

static const std::vector<std::wstring> cheatWindowIdentifiers = {
    L"cheatengine",
    L"openkore",
    L"wpe",
    L"rpe",
    L"trainer"
};

void OverlayScanner::Initialize() {
    knownWindows = EnumerateWindows();
    LogToServer("[Overlay] Initialized: " +
        std::to_string(knownWindows.size()) + "\n");
}

void OverlayScanner::Tick() {
    auto current = EnumerateWindows();
    for (auto& wi : current) {
        bool found = false;
        for (auto& old : knownWindows) {
            if (old.hWnd == wi.hWnd) { found = true; break; }
        }
        if (!found) OnNewOverlay(wi);
    }
    knownWindows = std::move(current);
}

BOOL CALLBACK EnumWndProc(HWND hWnd, LPARAM lParam) {
    auto* list = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
    wchar_t cls[256] = { 0 }, title[256] = { 0 };
    GetClassNameW(hWnd, cls, _countof(cls));
    GetWindowTextW(hWnd, title, _countof(title));
    if (IsWindowVisible(hWnd) && (wcslen(title) || wcslen(cls))) {
        list->push_back({ hWnd, cls, title });
    }
    return TRUE;
}

std::vector<WindowInfo> OverlayScanner::EnumerateWindows() {
    std::vector<WindowInfo> list;
    EnumWindows(EnumWndProc, reinterpret_cast<LPARAM>(&list));
    return list;
}

void OverlayScanner::OnNewOverlay(const WindowInfo& wi) {
    for (const auto& cheat : cheatWindowIdentifiers) {
        if (ContainsIgnoreCase(wi.windowTitle, cheat) ||
            ContainsIgnoreCase(wi.className, cheat)) {

            LogToServer("[Overlay] Detected cheat window: [" +
                Narrow(wi.className) + "] \"" +
                Narrow(wi.windowTitle) + "\"\n");

            // Destroy overlay window
            if (DestroyWindow(wi.hWnd)) {
                LogToServer("[Overlay] Destroyed overlay window: " +
                    Narrow(wi.windowTitle) + "\n");
            }
            else {
                LogToServer("[Overlay] Failed to destroy overlay window: " +
                    Narrow(wi.windowTitle) + "\n");
            }
            break;
        }
    }
}