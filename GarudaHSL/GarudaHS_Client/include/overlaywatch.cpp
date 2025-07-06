#include "overlaywatch.h"
#include <windows.h>
#include <string>
#include <vector>
#include <psapi.h>
#include <set>
#include <algorithm>
#include <tlhelp32.h>

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

// Fungsi untuk mengecek apakah window adalah overlay yang mencurigakan
bool IsSuspiciousOverlay(HWND hwnd) {
    RECT rect;
    GetWindowRect(hwnd, &rect);

    // Ukuran window
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    // Skip window yang terlalu kecil (kemungkinan tooltip, cursor, dll)
    if (width < 50 || height < 50) return false;

    // Skip window yang terlalu besar (kemungkinan aplikasi normal)
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (width > screenWidth * 0.8 || height > screenHeight * 0.8) return false;

    // Cek posisi - overlay cheat biasanya di tengah atau sudut tertentu
    int centerX = screenWidth / 2;
    int centerY = screenHeight / 2;
    int windowCenterX = rect.left + width / 2;
    int windowCenterY = rect.top + height / 2;

    // Jika window berada di pojok kanan atas (kemungkinan legitimate overlay)
    if (rect.left > screenWidth * 0.7 && rect.top < screenHeight * 0.3) {
        return false;
    }

    return true;
}

BOOL CALLBACK EnumWindowsOverlayProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    // Skip window sistem
    if (IsSystemWindow(hwnd)) return TRUE;

    // Dapatkan atribut window
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

    // Cek apakah window memiliki karakteristik overlay
    bool noBorder = !(style & WS_CAPTION);
    bool isTopMost = (exStyle & WS_EX_TOPMOST);
    bool isLayered = (exStyle & WS_EX_LAYERED);

    // Hanya proses window yang memiliki semua karakteristik overlay
    if (noBorder && isTopMost && isLayered) {
        // Dapatkan nama proses
        std::wstring processName = GetProcessNameFromHWND(hwnd);

        // Konversi ke lowercase untuk perbandingan case-insensitive
        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

        // Cek whitelist proses
        if (ALLOWED_PROCESSES.find(processName) != ALLOWED_PROCESSES.end()) {
            return TRUE; // Skip proses yang diizinkan
        }

        // Dapatkan judul window
        wchar_t title[256];
        GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));
        std::wstring judul(title);

        // Cek whitelist nama window
        for (const auto& allowedName : ALLOWED_WINDOW_NAMES) {
            if (judul.find(allowedName) != std::wstring::npos) {
                return TRUE; // Skip window yang diizinkan
            }
        }

        // Cek atribut layered window
        BYTE alpha = 255;
        COLORREF crKey;
        DWORD flags = 0;

        if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
            // Cek transparansi dengan threshold yang lebih ketat
            if ((flags & LWA_ALPHA) && alpha < 200) {
                // Lakukan pemeriksaan tambahan untuk mengurangi false positive
                if (!IsSuspiciousOverlay(hwnd)) {
                    return TRUE; // Skip jika tidak mencurigakan
                }

                // Jika semua pemeriksaan menunjukkan overlay mencurigakan
                if (judul.empty()) judul = L"(Tidak Berjudul / Overlay)";

                // Tambahkan informasi debug
                std::wstring debugInfo = L"Deteksi Overlay Mencurigakan:\n";
                debugInfo += L"Judul: " + judul + L"\n";
                debugInfo += L"Proses: " + processName + L"\n";
                debugInfo += L"Alpha: " + std::to_wstring(alpha) + L"\n";
                debugInfo += L"Apakah Anda yakin ini adalah cheat?";

                int result = MessageBoxW(NULL, debugInfo.c_str(), L"GarudaHS - Konfirmasi",
                    MB_YESNO | MB_ICONQUESTION);

                if (result == IDYES) {
                    // Hanya kill RRO.exe jika user mengkonfirmasi
                    system("taskkill /IM RRO.exe /F");
                    return FALSE; // stop scan
                }
            }
        }
    }

    return TRUE;
}

void cek_overlay_cheat() {
    EnumWindows(EnumWindowsOverlayProc, 0);
}