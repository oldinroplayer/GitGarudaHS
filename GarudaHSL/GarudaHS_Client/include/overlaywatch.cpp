#include "overlaywatch.h"
#include <windows.h>
#include <string>
#include <vector>
#include <psapi.h>

BOOL CALLBACK EnumWindowsOverlayProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;

    LONG style = GetWindowLong(hwnd, GWL_EXSTYLE);
    LONG regular = GetWindowLong(hwnd, GWL_STYLE);

    // Jika window transparan atau overlay (layered, topmost, tanpa border)
    bool isLayered = (style & WS_EX_LAYERED);
    bool isTopMost = (style & WS_EX_TOPMOST);
    bool noBorder = !(regular & WS_CAPTION);

    if (isLayered && isTopMost && noBorder) {
        // Ambil opacity (transparansi)
        BYTE alpha = 255;
        COLORREF crKey;
        DWORD flags;

        if (GetLayeredWindowAttributes(hwnd, &crKey, &alpha, &flags)) {
            if (alpha < 245) {
                wchar_t title[256];
                GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));

                std::wstring judul(title);
                if (judul.empty()) judul = L"(Tidak Berjudul / Overlay)";
                MessageBoxW(NULL, (L"Deteksi Overlay: " + judul).c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
                system("taskkill /IM RRO.exe /F");
                return FALSE;
            }
        }
    }

    return TRUE;
}

void cek_overlay_cheat() {
    EnumWindows(EnumWindowsOverlayProc, 0);
}