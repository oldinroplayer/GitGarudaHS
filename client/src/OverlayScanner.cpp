#include "../include/OverlayScanner.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <TlHelp32.h>
#include <Psapi.h>

namespace GarudaHS
{
    // Struktur untuk menyimpan data yang akan digunakan dalam callback EnumWindows
    struct EnumWindowsData
    {
        std::vector<WindowInfo>* windows;
        DWORD gameProcessId;
        HWND gameWindow;
    };

    OverlayScanner::OverlayScanner()
        : m_isRunning(false), m_gameWindow(NULL)
    {
        // Inisialisasi daftar nama window cheat yang dikenal
        // Nama-nama window ini case-insensitive
        m_knownCheatWindows = {
            "cheat engine",
            "ce",
            "trainer",
            "hack",
            "esp",
            "aimbot",
            "wallhack",
            "memory editor",
            "memory scanner",
            "memory viewer",
            "memory modifier",
            "memory hacker",
            "process hacker",
            "ollydbg",
            "x64dbg",
            "x32dbg",
            "ida",
            "ida pro",
            "ghidra",
            "dnspy",
            "wireshark",
            "fiddler",
            "charles",
            "burp",
            "burp suite",
            "packet editor",
            "packet sniffer",
            "artmoney",
            "gamehacker",
            "game guardian",
            "frida",
            "openkore",
            "wpe",
            "wpe pro",
            "rpe"
        };

        // Inisialisasi daftar nama class window cheat yang dikenal
        m_knownCheatClasses = {
            "cheatengine",
            "ollydbg",
            "x64dbg",
            "x32dbg",
            "ida",
            "idapro",
            "ghidra",
            "dnspy",
            "wireshark",
            "fiddler",
            "charles",
            "burp",
            "burpsuite",
            "artmoney",
            "gamehacker",
            "gameguardian",
            "frida",
            "openkore",
            "wpe",
            "wpepro",
            "rpe"
        };
    }

    OverlayScanner::~OverlayScanner()
    {
        Shutdown();
    }

    bool OverlayScanner::Initialize()
    {
        std::cout << "Menginisialisasi Overlay Scanner..." << std::endl;
        
        // Dapatkan handle window game
        m_gameWindow = GetForegroundWindow();
        if (m_gameWindow == NULL)
        {
            std::cerr << "Gagal mendapatkan handle window game." << std::endl;
            return false;
        }
        
        // Mulai thread scanner jika belum berjalan
        if (!m_isRunning)
        {
            m_isRunning = true;
            m_scannerThread = std::thread(&OverlayScanner::ScannerThreadFunc, this);
        }
        
        return true;
    }

    bool OverlayScanner::Scan()
    {
        // Periksa apakah ada overlay cheat
        if (HasOverlayCheat())
        {
            return false; // Terdeteksi cheat
        }
        
        return true; // Tidak ada cheat yang terdeteksi
    }

    void OverlayScanner::Shutdown()
    {
        // Hentikan thread scanner jika sedang berjalan
        if (m_isRunning)
        {
            m_isRunning = false;
            if (m_scannerThread.joinable())
            {
                m_scannerThread.join();
            }
        }
    }

    const char* OverlayScanner::GetName() const
    {
        return "Overlay Scanner";
    }

    std::vector<WindowInfo> OverlayScanner::GetActiveWindows()
    {
        std::vector<WindowInfo> windows;
        
        // Dapatkan process ID dari window game
        DWORD gameProcessId = 0;
        GetWindowThreadProcessId(m_gameWindow, &gameProcessId);
        
        // Siapkan data untuk callback EnumWindows
        EnumWindowsData data;
        data.windows = &windows;
        data.gameProcessId = gameProcessId;
        data.gameWindow = m_gameWindow;
        
        // Enumerate semua window
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));
        
        return windows;
    }

    bool OverlayScanner::HasOverlayCheat()
    {
        // Dapatkan daftar window yang aktif
        std::vector<WindowInfo> windows = GetActiveWindows();
        
        // Periksa setiap window
        for (const auto& window : windows)
        {
            // Jika window adalah cheat dan overlap dengan game window
            if (IsCheatWindow(window) && window.isOverlapping)
            {
                // Buat laporan deteksi
                CheatDetection detection;
                detection.type = CheatType::OVERLAY_DETECTED;
                detection.details = "Terdeteksi overlay cheat: " + window.title + " (" + window.className + ")";
                detection.processId = window.processId;
                detection.processName = window.processName;
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                return true;
            }
        }
        
        return false;
    }

    void OverlayScanner::ScannerThreadFunc()
    {
        while (m_isRunning)
        {
            // Periksa window setiap 2 detik
            Scan();
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    bool OverlayScanner::IsCheatWindow(const WindowInfo& window)
    {
        // Jika window tidak visible, bukan cheat
        if (!window.isVisible)
        {
            return false;
        }
        
        // Konversi title dan className ke lowercase untuk perbandingan case-insensitive
        std::string lowerTitle = window.title;
        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        std::string lowerClassName = window.className;
        std::transform(lowerClassName.begin(), lowerClassName.end(), lowerClassName.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        // Periksa apakah title mengandung nama cheat yang dikenal
        for (const auto& cheatWindow : m_knownCheatWindows)
        {
            if (lowerTitle.find(cheatWindow) != std::string::npos)
            {
                return true;
            }
        }
        
        // Periksa apakah className mengandung nama class cheat yang dikenal
        for (const auto& cheatClass : m_knownCheatClasses)
        {
            if (lowerClassName.find(cheatClass) != std::string::npos)
            {
                return true;
            }
        }
        
        return false;
    }

    bool OverlayScanner::IsWindowOverlapping(const RECT& windowRect, const RECT& gameRect)
    {
        // Periksa apakah window overlap dengan game window
        return (windowRect.left < gameRect.right &&
                windowRect.right > gameRect.left &&
                windowRect.top < gameRect.bottom &&
                windowRect.bottom > gameRect.top);
    }

    std::string OverlayScanner::GetProcessName(DWORD processId)
    {
        std::string name;
        
        // Buka handle ke proses
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess != NULL)
        {
            CHAR szProcessName[MAX_PATH];
            DWORD dwSize = MAX_PATH;
            
            if (GetModuleBaseNameA(hProcess, NULL, szProcessName, dwSize))
            {
                name = szProcessName;
            }
            
            CloseHandle(hProcess);
        }
        
        return name;
    }

    BOOL CALLBACK OverlayScanner::EnumWindowsProc(HWND hwnd, LPARAM lParam)
    {
        EnumWindowsData* data = reinterpret_cast<EnumWindowsData*>(lParam);
        
        // Dapatkan process ID dari window
        DWORD processId = 0;
        GetWindowThreadProcessId(hwnd, &processId);
        
        // Jika window adalah milik game, skip
        if (processId == data->gameProcessId || hwnd == data->gameWindow)
        {
            return TRUE;
        }
        
        // Dapatkan informasi window
        WindowInfo windowInfo;
        windowInfo.hwnd = hwnd;
        
        // Dapatkan title window
        char title[256];
        GetWindowTextA(hwnd, title, sizeof(title));
        windowInfo.title = title;
        
        // Dapatkan class name
        char className[256];
        GetClassNameA(hwnd, className, sizeof(className));
        windowInfo.className = className;
        
        // Dapatkan process ID dan nama proses
        windowInfo.processId = processId;
        windowInfo.processName = OverlayScanner().GetProcessName(processId);
        
        // Dapatkan posisi dan ukuran window
        GetWindowRect(hwnd, &windowInfo.rect);
        
        // Periksa apakah window visible
        windowInfo.isVisible = IsWindowVisible(hwnd);
        
        // Dapatkan posisi dan ukuran game window
        RECT gameRect;
        GetWindowRect(data->gameWindow, &gameRect);
        
        // Periksa apakah window overlap dengan game window
        windowInfo.isOverlapping = OverlayScanner().IsWindowOverlapping(windowInfo.rect, gameRect);
        
        // Tambahkan window ke daftar
        data->windows->push_back(windowInfo);
        
        return TRUE;
    }
}