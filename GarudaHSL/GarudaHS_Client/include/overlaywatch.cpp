#include "overlaywatch.h"
#include "whitelist.h"
#include <windows.h>
#include <string>
#include <vector>
#include <psapi.h>
#include <set>
#include <algorithm>
#include <tlhelp32.h>
#include <iostream>

// Daftar aplikasi yang diizinkan (whitelist)
static const std::set<std::wstring> ALLOWED_PROCESSES = {
    L"discord.exe",
    L"steam.exe",
    L"nvidia.exe",
    L"obs64.exe",
    L"obs32.exe",
    L"streamlabs obs.exe",
    L"bandicam.exe",
    L"fraps.exe",
    L"msiafterburner.exe",
    L"rivatuner.exe",
    L"teamspeak3.exe",
    L"spotify.exe",
    L"chrome.exe",
    L"firefox.exe",
    L"edge.exe",
    L"explorer.exe",
    L"dwm.exe",
    L"winlogon.exe",
    L"csrss.exe"
};

// Daftar nama window yang diizinkan
static const std::set<std::wstring> ALLOWED_WINDOW_NAMES = {
    L"Discord",
    L"Steam",
    L"NVIDIA GeForce Experience",
    L"OBS",
    L"Streamlabs OBS",
    L"MSI Afterburner",
    L"RivaTuner Statistics Server",
    L"TeamSpeak 3",
    L"Spotify",
    L"Task Manager",
    L"Volume Control",
    L"Notification Area",
    L"System Tray"
};

// Fungsi untuk mendapatkan nama proses dari HWND
std::wstring GetProcessNameFromHWND(HWND hwnd) {
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return L"";

    wchar_t processName[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
        std::wstring fullPath(processName);
        size_t pos = fullPath.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            CloseHandle(hProcess);
            return fullPath.substr(pos + 1);
        }
    }

    CloseHandle(hProcess);
    return L"";
}

// Fungsi untuk mengecek apakah window adalah bagian dari sistem Windows
bool IsSystemWindow(HWND hwnd) {
    wchar_t className[256];
    GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t));

    std::wstring classNameStr(className);

    // Daftar class name sistem Windows yang umum
    std::set<std::wstring> systemClasses = {
        L"Shell_TrayWnd",
        L"DV2ControlHost",
        L"MsgrIMEWindowClass",
        L"SysShadow",
        L"Button",
        L"Progman",
        L"WorkerW",
        L"Desktop",
        L"#32770", // Dialog box
        L"tooltips_class32",
        L"CiceroUIWndFrame"
    };

    return systemClasses.find(classNameStr) != systemClasses.end();
}

// Enhanced overlay detection with better heuristics
bool IsSuspiciousOverlay(HWND hwnd) {
    RECT rect;
    GetWindowRect(hwnd, &rect);

    // Ukuran window
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    // Skip window yang terlalu kecil (tooltip, cursor, notification)
    if (width < 100 || height < 50) return false;

    // Skip window yang terlalu besar (aplikasi normal, fullscreen)
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (width > screenWidth * 0.9 || height > screenHeight * 0.9) return false;

    // Check for legitimate overlay positions
    // Top-right corner (system notifications, antivirus, etc.)
    if (rect.left > screenWidth * 0.7 && rect.top < screenHeight * 0.3) {
        return false;
    }

    // Bottom-right corner (system tray notifications)
    if (rect.left > screenWidth * 0.7 && rect.top > screenHeight * 0.7) {
        return false;
    }

    // Top-left corner (some legitimate overlays)
    if (rect.left < screenWidth * 0.3 && rect.top < screenHeight * 0.3) {
        return false;
    }

    // Check window class for known legitimate overlays
    wchar_t className[256];
    if (GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t))) {
        std::wstring classStr(className);
        std::transform(classStr.begin(), classStr.end(), classStr.begin(), ::tolower);

        // Known legitimate overlay classes
        if (classStr.find(L"tooltip") != std::wstring::npos ||
            classStr.find(L"notification") != std::wstring::npos ||
            classStr.find(L"popup") != std::wstring::npos ||
            classStr.find(L"menu") != std::wstring::npos ||
            classStr.find(L"dropdown") != std::wstring::npos) {
            return false;
        }
    }

    // Check for suspicious characteristics
    // Very small but not tiny (common cheat overlay size)
    if (width >= 100 && width <= 400 && height >= 50 && height <= 300) {
        // Check if positioned suspiciously (center or game area)
        int centerX = screenWidth / 2;
        int centerY = screenHeight / 2;
        int windowCenterX = rect.left + width / 2;
        int windowCenterY = rect.top + height / 2;

        // If near center of screen, more suspicious
        int distanceFromCenter = abs(windowCenterX - centerX) + abs(windowCenterY - centerY);
        if (distanceFromCenter < screenWidth * 0.3) {
            return true;
        }
    }

    return false; // Default to not suspicious to reduce false positives
}

// Overlay detection state
static DWORD last_overlay_scan = 0;
static int overlay_scan_count = 0;

BOOL CALLBACK EnumWindowsOverlayProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    // Skip window sistem
    if (IsSystemWindow(hwnd)) return TRUE;

    // Dapatkan atribut window
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

    // More relaxed overlay detection - require at least 2 of 3 characteristics
    bool noBorder = !(style & WS_CAPTION);
    bool isTopMost = (exStyle & WS_EX_TOPMOST);
    bool isLayered = (exStyle & WS_EX_LAYERED);

    int overlay_characteristics = (noBorder ? 1 : 0) + (isTopMost ? 1 : 0) + (isLayered ? 1 : 0);

    // Require at least 2 characteristics to reduce false positives
    if (overlay_characteristics >= 2) {
        // Dapatkan nama proses
        std::wstring processName = GetProcessNameFromHWND(hwnd);
        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

        // Use intelligent whitelist system
        if (IntelligentWhitelist::IsProcessWhitelisted(processName)) {
            return TRUE;
        }

        // Additional check for window legitimacy
        if (IntelligentWhitelist::IsWindowLegitimate(hwnd)) {
            return TRUE;
        }

        // Dapatkan judul window
        wchar_t title[256];
        GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));
        std::wstring judul(title);

        // Enhanced window title checking
        for (const auto& allowedName : ALLOWED_WINDOW_NAMES) {
            if (judul.find(allowedName) != std::wstring::npos) {
                return TRUE;
            }
        }

        // Additional legitimate window title patterns
        if (judul.find(L"notification") != std::wstring::npos ||
            judul.find(L"tooltip") != std::wstring::npos ||
            judul.find(L"popup") != std::wstring::npos ||
            judul.find(L"menu") != std::wstring::npos) {
            return TRUE;
        }

        // Enhanced suspicious overlay detection
        if (IsSuspiciousOverlay(hwnd)) {
            // Check layered window attributes if available
            BYTE alpha = 255;
            COLORREF crKey;
            DWORD flags = 0;

            if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
                // More strict alpha threshold
                if ((flags & LWA_ALPHA) && alpha < 180) {
                    if (judul.empty()) judul = L"(Tidak Berjudul / Overlay)";

                    // Log detection for analysis
                    std::wcout << L"[OVERLAY] Suspicious overlay detected: " << judul
                               << L" (Process: " << processName << L", Alpha: " << alpha << L")" << std::endl;

                    // Ask for user confirmation to reduce false positives
                    std::wstring debugInfo = L"Deteksi Overlay Mencurigakan:\n";
                    debugInfo += L"Judul: " + judul + L"\n";
                    debugInfo += L"Proses: " + processName + L"\n";
                    debugInfo += L"Alpha: " + std::to_wstring(alpha) + L"\n";
                    debugInfo += L"Karakteristik: " + std::to_wstring(overlay_characteristics) + L"/3\n";
                    debugInfo += L"Apakah Anda yakin ini adalah cheat?";

                    int result = MessageBoxW(NULL, debugInfo.c_str(), L"GarudaHS - Konfirmasi",
                        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2); // Default to NO

                    if (result == IDYES) {
                        std::wcout << L"[ACTION] User confirmed cheat overlay, terminating game" << std::endl;
                        system("taskkill /IM RRO.exe /F");
                        return FALSE;
                    } else {
                        std::wcout << L"[INFO] User denied cheat overlay, continuing" << std::endl;
                    }
                }
            }
        }
    }

    return TRUE;
}

void cek_overlay_cheat() {
    EnumWindows(EnumWindowsOverlayProc, 0);
}