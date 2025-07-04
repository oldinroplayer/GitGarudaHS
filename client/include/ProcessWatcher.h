#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi proses
    struct ProcessInfo
    {
        DWORD processId;
        std::string processName;
        std::string executablePath;
    };

    // Struktur untuk menyimpan informasi thread
    struct ThreadInfo
    {
        DWORD threadId;
        DWORD processId;
        DWORD basePriority;
        bool isSuspended;
    };

    // Kelas untuk memantau proses dan thread
    class ProcessWatcher : public IAntiCheatModule
    {
    public:
        ProcessWatcher();
        ~ProcessWatcher();

        // Implementasi dari IAntiCheatModule
        bool Initialize() override;
        bool Scan() override;
        void Shutdown() override;
        const char* GetName() const override;

        // Fungsi untuk mendapatkan daftar proses yang berjalan
        std::vector<ProcessInfo> GetRunningProcesses();

        // Fungsi untuk mendapatkan daftar thread dari suatu proses
        std::vector<ThreadInfo> GetProcessThreads(DWORD processId);

        // Fungsi untuk memeriksa apakah ada proses cheat yang berjalan
        bool IsCheatProcessRunning();

        // Fungsi untuk memeriksa apakah ada thread yang di-suspend
        bool HasSuspendedThreads(DWORD processId);

    private:
        // Daftar nama proses cheat yang dikenal
        std::unordered_set<std::string> m_knownCheatProcesses;

        // Thread untuk memantau proses secara periodik
        std::thread m_watcherThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_mutex;

        // Fungsi yang dijalankan oleh thread watcher
        void WatcherThreadFunc();

        // Fungsi untuk memeriksa apakah nama proses cocok dengan daftar cheat
        bool IsCheatProcess(const std::string& processName);

        // Fungsi untuk mendapatkan path executable dari proses
        std::string GetProcessPath(DWORD processId);

        // Fungsi untuk mendapatkan nama proses dari process ID
        std::string GetProcessName(DWORD processId);
    };
}