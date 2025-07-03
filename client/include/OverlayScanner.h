#pragma once

#include <windows.h>
#include <vector>
#include <string>

namespace GarudaHS {

    struct WindowInfo {
        HWND   hWnd;
        std::wstring className;
        std::wstring windowTitle;
    };

    class OverlayScanner {
    public:
        // Inisialisasi module
        static void Initialize();

        // Panggil periodik untuk scan window baru
        static void Tick();

    private:
        static std::vector<WindowInfo> knownWindows;

        static std::vector<WindowInfo> EnumerateWindows();
        static void OnNewOverlay(const WindowInfo& wi);
    };

}
