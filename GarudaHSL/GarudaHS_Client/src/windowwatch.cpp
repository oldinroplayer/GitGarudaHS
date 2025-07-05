#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include "windowwatch.h"

std::vector<std::wstring> window_keywords = {
    L"cheat engine",
    L"wpe",
    L"rpe",
    L"speedhack",
    L"openkore",
    L"packet editor",
    L"injector"
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    wchar_t title[256];
    GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));

    std::wstring judul(title);
    std::transform(judul.begin(), judul.end(), judul.begin(), ::towlower);

    for (const auto& keyword : window_keywords) {
        if (judul.find(keyword) != std::wstring::npos) {
            MessageBoxW(NULL, (L"Deteksi Window: " + judul).c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
            system("taskkill /IM RRO.exe /F");
            break;
        }
    }

    return TRUE;
}

void cek_jendela_cheat() {
    EnumWindows(EnumWindowsProc, 0);
}
