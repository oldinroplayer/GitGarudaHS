#include "../include/AntiSuspendThread.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <Psapi.h>

// Definisi untuk hook API
#include <detours/detours.h>
#pragma comment(lib, "detours.lib")

namespace GarudaHS
{
    // Tipe fungsi untuk SuspendThread dan NtSuspendThread
    typedef DWORD (WINAPI* pfnSuspendThread)(HANDLE hThread);
    typedef NTSTATUS (NTAPI* pfnNtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    // Pointer ke fungsi asli
    pfnSuspendThread g_originalSuspendThread = nullptr;
    pfnNtSuspendThread g_originalNtSuspendThread = nullptr;

    // Fungsi hook untuk SuspendThread
    DWORD WINAPI HookedSuspendThread(HANDLE hThread)
    {
        // Dapatkan thread ID dari handle
        DWORD threadId = GetThreadId(hThread);
        
        // Dapatkan process ID dari thread
        DWORD processId = GetProcessIdOfThread(hThread);
        
        // Jika thread adalah milik game, tolak suspend
        if (processId == GetCurrentProcessId())
        {
            std::cout << "Upaya suspend thread terdeteksi! Thread ID: " << threadId << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::SUSPENDED_THREAD;
            detection.details = "Upaya suspend thread terdeteksi! Thread ID: " + std::to_string(threadId);
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return error
            SetLastError(ERROR_ACCESS_DENIED);
            return (DWORD)-1;
        }
        
        // Jika bukan thread game, lanjutkan ke fungsi asli
        return g_originalSuspendThread(hThread);
    }

    // Fungsi hook untuk NtSuspendThread
    NTSTATUS NTAPI HookedNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
    {
        // Dapatkan thread ID dari handle
        DWORD threadId = GetThreadId(ThreadHandle);
        
        // Dapatkan process ID dari thread
        DWORD processId = GetProcessIdOfThread(ThreadHandle);
        
        // Jika thread adalah milik game, tolak suspend
        if (processId == GetCurrentProcessId())
        {
            std::cout << "Upaya suspend thread (NtSuspendThread) terdeteksi! Thread ID: " << threadId << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::SUSPENDED_THREAD;
            detection.details = "Upaya suspend thread (NtSuspendThread) terdeteksi! Thread ID: " + std::to_string(threadId);
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return error
            return STATUS_ACCESS_DENIED;
        }
        
        // Jika bukan thread game, lanjutkan ke fungsi asli
        return g_originalNtSuspendThread(ThreadHandle, PreviousSuspendCount);
    }

    AntiSuspendThread::AntiSuspendThread()
        : m_isRunning(false)
    {
    }

    AntiSuspendThread::~AntiSuspendThread()
    {
        Shutdown();
    }

    bool AntiSuspendThread::Initialize()
    {
        std::cout << "Menginisialisasi Anti-Suspend Thread..." << std::endl;
        
        // Hook API SuspendThread dan NtSuspendThread
        if (!HookSuspendThreadAPI())
        {
            std::cerr << "Gagal hook API SuspendThread dan NtSuspendThread." << std::endl;
            return false;
        }
        
        // Dapatkan daftar thread dari proses saat ini
        std::vector<DWORD> threads = GetProcessThreads();
        
        // Inisialisasi informasi thread yang dipantau
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (DWORD threadId : threads)
            {
                ThreadMonitorInfo info;
                info.threadId = threadId;
                info.suspendCount = GetThreadSuspendCount(threadId);
                info.lastCheckTime = GetTickCount();
                info.wasRunning = (info.suspendCount == 0);
                
                m_monitoredThreads[threadId] = info;
            }
        }
        
        // Mulai thread monitor jika belum berjalan
        if (!m_isRunning)
        {
            m_isRunning = true;
            m_monitorThread = std::thread(&AntiSuspendThread::MonitorThreadFunc, this);
        }
        
        return true;
    }

    bool AntiSuspendThread::Scan()
    {
        // Perbarui informasi thread yang dipantau
        UpdateThreadInfo();
        
        // Periksa apakah ada thread yang di-suspend
        if (CheckSuspendedThreads())
        {
            return false; // Terdeteksi thread yang di-suspend
        }
        
        return true; // Tidak ada thread yang di-suspend
    }

    void AntiSuspendThread::Shutdown()
    {
        // Unhook API SuspendThread dan NtSuspendThread
        UnhookSuspendThreadAPI();
        
        // Hentikan thread monitor jika sedang berjalan
        if (m_isRunning)
        {
            m_isRunning = false;
            if (m_monitorThread.joinable())
            {
                m_monitorThread.join();
            }
        }
    }

    const char* AntiSuspendThread::GetName() const
    {
        return "Anti-Suspend Thread";
    }

    std::vector<DWORD> AntiSuspendThread::GetProcessThreads()
    {
        std::vector<DWORD> threads;
        
        // Ambil snapshot dari semua thread yang berjalan
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE)
        {
            return threads;
        }
        
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        // Dapatkan informasi thread pertama
        if (!Thread32First(hThreadSnap, &te32))
        {
            CloseHandle(hThreadSnap);
            return threads;
        }
        
        // Dapatkan process ID saat ini
        DWORD currentProcessId = GetCurrentProcessId();
        
        // Iterasi melalui semua thread
        do
        {
            // Filter thread berdasarkan process ID
            if (te32.th32OwnerProcessID == currentProcessId)
            {
                threads.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hThreadSnap, &te32));
        
        CloseHandle(hThreadSnap);
        return threads;
    }

    bool AntiSuspendThread::IsThreadSuspended(DWORD threadId)
    {
        DWORD suspendCount = GetThreadSuspendCount(threadId);
        return (suspendCount > 0);
    }

    DWORD AntiSuspendThread::GetThreadSuspendCount(DWORD threadId)
    {
        // Buka handle ke thread
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread == NULL)
        {
            return 0;
        }
        
        // Suspend thread untuk mendapatkan suspend count
        DWORD suspendCount = SuspendThread(hThread);
        
        // Resume thread untuk mengembalikan ke status semula
        if (suspendCount != (DWORD)-1)
        {
            ResumeThread(hThread);
        }
        
        CloseHandle(hThread);
        return suspendCount;
    }

    bool AntiSuspendThread::ResumeThread(DWORD threadId)
    {
        // Buka handle ke thread
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread == NULL)
        {
            return false;
        }
        
        // Resume thread
        DWORD result = ::ResumeThread(hThread);
        
        CloseHandle(hThread);
        return (result != (DWORD)-1);
    }

    bool AntiSuspendThread::ProtectThreadFromSuspend(DWORD threadId)
    {
        // Buka handle ke thread
        HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
        if (hThread == NULL)
        {
            return false;
        }
        
        // Load ntdll.dll
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll)
        {
            CloseHandle(hThread);
            return false;
        }
        
        // Dapatkan alamat fungsi NtSetInformationThread
        typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
            IN HANDLE ThreadHandle,
            IN ULONG ThreadInformationClass,
            IN PVOID ThreadInformation,
            IN ULONG ThreadInformationLength
            );
        
        pfnNtSetInformationThread pNtSetInformationThread = (pfnNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (!pNtSetInformationThread)
        {
            FreeLibrary(hNtdll);
            CloseHandle(hThread);
            return false;
        }
        
        // ThreadHideFromDebugger = 0x11
        NTSTATUS status = pNtSetInformationThread(hThread, 0x11, NULL, 0);
        
        FreeLibrary(hNtdll);
        CloseHandle(hThread);
        
        return NT_SUCCESS(status);
    }

    void AntiSuspendThread::MonitorThreadFunc()
    {
        while (m_isRunning)
        {
            // Periksa thread setiap 1 detik
            Scan();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void AntiSuspendThread::UpdateThreadInfo()
    {
        // Dapatkan daftar thread dari proses saat ini
        std::vector<DWORD> currentThreads = GetProcessThreads();
        
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Perbarui informasi thread yang sudah ada
        for (DWORD threadId : currentThreads)
        {
            DWORD suspendCount = GetThreadSuspendCount(threadId);
            DWORD currentTime = GetTickCount();
            
            // Jika thread sudah ada dalam map
            if (m_monitoredThreads.find(threadId) != m_monitoredThreads.end())
            {
                ThreadMonitorInfo& info = m_monitoredThreads[threadId];
                
                // Deteksi perubahan suspend count
                if (DetectSuspendCountChange(threadId, suspendCount))
                {
                    // Jika thread di-suspend, coba resume
                    if (suspendCount > 0)
                    {
                        ResumeThread(threadId);
                    }
                }
                
                // Perbarui informasi
                info.suspendCount = suspendCount;
                info.lastCheckTime = currentTime;
                info.wasRunning = (suspendCount == 0);
            }
            else
            {
                // Tambahkan thread baru ke map
                ThreadMonitorInfo info;
                info.threadId = threadId;
                info.suspendCount = suspendCount;
                info.lastCheckTime = currentTime;
                info.wasRunning = (suspendCount == 0);
                
                m_monitoredThreads[threadId] = info;
            }
        }
        
        // Hapus thread yang sudah tidak ada
        for (auto it = m_monitoredThreads.begin(); it != m_monitoredThreads.end();)
        {
            if (std::find(currentThreads.begin(), currentThreads.end(), it->first) == currentThreads.end())
            {
                it = m_monitoredThreads.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    bool AntiSuspendThread::CheckSuspendedThreads()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (const auto& pair : m_monitoredThreads)
        {
            const ThreadMonitorInfo& info = pair.second;
            
            // Jika thread di-suspend
            if (info.suspendCount > 0)
            {
                // Buat laporan deteksi
                CheatDetection detection;
                detection.type = CheatType::SUSPENDED_THREAD;
                detection.details = "Terdeteksi thread yang di-suspend: " + std::to_string(info.threadId) +
                                   " (Suspend Count: " + std::to_string(info.suspendCount) + ")";
                detection.processId = GetCurrentProcessId();
                detection.processName = "RRO.exe";
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                return true;
            }
        }
        
        return false;
    }

    bool AntiSuspendThread::DetectSuspendCountChange(DWORD threadId, DWORD currentSuspendCount)
    {
        const ThreadMonitorInfo& info = m_monitoredThreads[threadId];
        
        // Jika suspend count berubah
        if (info.suspendCount != currentSuspendCount)
        {
            // Jika thread sebelumnya running dan sekarang di-suspend
            if (info.wasRunning && currentSuspendCount > 0)
            {
                std::cout << "Thread " << threadId << " di-suspend! Suspend Count: " << currentSuspendCount << std::endl;
                return true;
            }
            
            // Jika suspend count bertambah
            if (currentSuspendCount > info.suspendCount)
            {
                std::cout << "Suspend Count thread " << threadId << " bertambah: " << info.suspendCount << " -> " << currentSuspendCount << std::endl;
                return true;
            }
        }
        
        return false;
    }

    bool AntiSuspendThread::HookSuspendThreadAPI()
    {
        // Dapatkan alamat fungsi asli
        g_originalSuspendThread = (pfnSuspendThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SuspendThread");
        if (!g_originalSuspendThread)
        {
            std::cerr << "Gagal mendapatkan alamat fungsi SuspendThread." << std::endl;
            return false;
        }
        
        // Dapatkan alamat fungsi NtSuspendThread
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        if (hNtdll)
        {
            g_originalNtSuspendThread = (pfnNtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
            FreeLibrary(hNtdll);
        }
        
        // Mulai transaksi hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        // Hook SuspendThread
        LONG error = DetourAttach(&(PVOID&)g_originalSuspendThread, HookedSuspendThread);
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal hook SuspendThread. Error: " << error << std::endl;
            DetourTransactionAbort();
            return false;
        }
        
        // Hook NtSuspendThread jika tersedia
        if (g_originalNtSuspendThread)
        {
            error = DetourAttach(&(PVOID&)g_originalNtSuspendThread, HookedNtSuspendThread);
            if (error != NO_ERROR)
            {
                std::cerr << "Gagal hook NtSuspendThread. Error: " << error << std::endl;
                DetourTransactionAbort();
                return false;
            }
        }
        
        // Commit transaksi hook
        error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal commit hook transaction. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "API SuspendThread dan NtSuspendThread berhasil di-hook." << std::endl;
        return true;
    }

    void AntiSuspendThread::UnhookSuspendThreadAPI()
    {
        // Jika fungsi asli tersedia
        if (g_originalSuspendThread || g_originalNtSuspendThread)
        {
            // Mulai transaksi unhook
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            
            // Unhook SuspendThread
            if (g_originalSuspendThread)
            {
                DetourDetach(&(PVOID&)g_originalSuspendThread, HookedSuspendThread);
            }
            
            // Unhook NtSuspendThread
            if (g_originalNtSuspendThread)
            {
                DetourDetach(&(PVOID&)g_originalNtSuspendThread, HookedNtSuspendThread);
            }
            
            // Commit transaksi unhook
            DetourTransactionCommit();
            
            std::cout << "API SuspendThread dan NtSuspendThread berhasil di-unhook." << std::endl;
        }
    }

    std::string AntiSuspendThread::GetThreadName(DWORD threadId)
    {
        // Implementasi untuk mendapatkan nama thread
        // Catatan: Windows tidak menyediakan API standar untuk mendapatkan nama thread
        // Kita bisa menggunakan informasi debug atau TIB (Thread Information Block)
        
        return "Thread-" + std::to_string(threadId);
    }
}