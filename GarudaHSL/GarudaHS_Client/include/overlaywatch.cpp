#include "overlaywatch.h"
#include <windows.h>
#include <string>
#include <vector>
#include <psapi.h>

BOOL CALLBACK EnumWindowsOverlayProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    // Dapatkan atribut window
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

    // Hanya scan window tanpa border DAN topmost AND layered
    bool noBorder = !(style & WS_CAPTION);
    bool isTopMost = (exStyle & WS_EX_TOPMOST);
    bool isLayered = (exStyle & WS_EX_LAYERED);

    if (noBorder && isTopMost && isLayered) {
        BYTE alpha = 255;
        COLORREF crKey;
        DWORD flags = 0;

        if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
            // Deteksi hanya jika alpha < 220 (lebih ketat)
            if ((flags & LWA_ALPHA) && alpha < 220) {
                wchar_t title[256];
                GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));

                std::wstring judul(title);
                if (judul.empty()) judul = L"(Tidak Berjudul / Overlay)";

                MessageBoxW(NULL, (L"Deteksi Overlay: " + judul).c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
                system("taskkill /IM RRO.exe /F");
                return FALSE; // stop scan
            }
        }
    }

    return TRUE;
}

void cek_overlay_cheat() {
    EnumWindows(EnumWindowsOverlayProc, 0);
}