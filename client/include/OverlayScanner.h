#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <atomic>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi window
    struct WindowInfo
    {
        HWND hwnd;
        std::string title;
        std::string className;
        DWORD processId;
        std::string processName;
        RECT rect;
        bool isVisible;
        bool isOverlapping;
    };

    // Kelas untuk mendeteksi overlay/ESP cheat
    class OverlayScanner : public IAntiCheatModule
    {
    public:
        OverlayScanner();
        ~OverlayScanner();

        // Implementasi dari IAntiCheatModule
        bool Initialize() override;
        bool Scan() override;
        void Shutdown() override;
        const char* GetName() const override;

        // Fungsi untuk mendapatkan daftar window yang aktif
        std::vector<WindowInfo> GetActiveWindows();

        // Fungsi untuk memeriksa apakah ada overlay cheat
        bool HasOverlayCheat();

    private:
        // Daftar nama window cheat yang dikenal
        std::unordered_set<std::string> m_knownCheatWindows;
        
        // Daftar nama class window cheat yang dikenal
        std::unordered_set<std::string> m_knownCheatClasses;

        // Thread untuk memantau window secara periodik
        std::thread m_scannerThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_mutex;

        // Handle window game
        HWND m_gameWindow;

        // Fungsi yang dijalankan oleh thread scanner
        void ScannerThreadFunc();

        // Fungsi untuk memeriksa apakah window adalah cheat
        bool IsCheatWindow(const WindowInfo& window);

        // Fungsi untuk memeriksa apakah window overlap dengan game window
        bool IsWindowOverlapping(const RECT& windowRect, const RECT& gameRect);

        // Fungsi untuk mendapatkan nama proses dari process ID
        std::string GetProcessName(DWORD processId);

        // Callback untuk EnumWindows
        static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
    };
}