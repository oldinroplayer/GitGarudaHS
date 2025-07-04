#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi thread
    struct ThreadMonitorInfo
    {
        DWORD threadId;
        DWORD suspendCount;
        DWORD lastCheckTime;
        bool wasRunning;
    };

    // Kelas untuk mendeteksi dan mencegah suspend thread
    class AntiSuspendThread : public IAntiCheatModule
    {
    public:
        AntiSuspendThread();
        ~AntiSuspendThread();

        // Implementasi dari IAntiCheatModule
        bool Initialize() override;
        bool Scan() override;
        void Shutdown() override;
        const char* GetName() const override;

        // Fungsi untuk mendapatkan daftar thread dari proses saat ini
        std::vector<DWORD> GetProcessThreads();

        // Fungsi untuk memeriksa apakah thread di-suspend
        bool IsThreadSuspended(DWORD threadId);

        // Fungsi untuk mendapatkan suspend count dari thread
        DWORD GetThreadSuspendCount(DWORD threadId);

        // Fungsi untuk resume thread yang di-suspend
        bool ResumeThread(DWORD threadId);

        // Fungsi untuk memproteksi thread dari suspend
        bool ProtectThreadFromSuspend(DWORD threadId);

    private:
        // Thread untuk memantau suspend thread secara periodik
        std::thread m_monitorThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_mutex;

        // Map untuk menyimpan informasi thread yang dipantau
        std::unordered_map<DWORD, ThreadMonitorInfo> m_monitoredThreads;

        // Fungsi yang dijalankan oleh thread monitor
        void MonitorThreadFunc();

        // Fungsi untuk memperbarui informasi thread yang dipantau
        void UpdateThreadInfo();

        // Fungsi untuk memeriksa apakah ada thread yang di-suspend
        bool CheckSuspendedThreads();

        // Fungsi untuk mendeteksi perubahan suspend count
        bool DetectSuspendCountChange(DWORD threadId, DWORD currentSuspendCount);

        // Fungsi untuk hook API SuspendThread dan NtSuspendThread
        bool HookSuspendThreadAPI();

        // Fungsi untuk unhook API SuspendThread dan NtSuspendThread
        void UnhookSuspendThreadAPI();

        // Fungsi untuk mendapatkan nama thread
        std::string GetThreadName(DWORD threadId);
    };
}