#include "../include/ProcessWatcher.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <filesystem>

namespace GarudaHS
{
    ProcessWatcher::ProcessWatcher()
        : m_isRunning(false)
    {
        // Inisialisasi daftar proses cheat yang dikenal
        // Nama-nama proses ini case-insensitive
        m_knownCheatProcesses = {
            "cheatengine",
            "cheatengine-x86_64",
            "cheatengine-i386",
            "cheat engine",
            "ce",
            "openkore",
            "wpe",
            "wpe pro",
            "rpe",
            "artmoney",
            "gamehacker",
            "gameguardian",
            "frida",
            "frida-server",
            "fridaserver",
            "ollydbg",
            "x64dbg",
            "x32dbg",
            "ida",
            "ida64",
            "ida32",
            "ghidra",
            "dnspy",
            "process hacker",
            "processhacker",
            "memory editor",
            "memoryeditor",
            "memory hacker",
            "memoryhacker",
            "speed hack",
            "speedhack",
            "autoclicker",
            "auto clicker",
            "macro recorder",
            "macrorecorder",
            "autohotkey",
            "auto hot key",
            "ahk",
            "wireshark",
            "fiddler",
            "charles",
            "burp",
            "burpsuite",
            "packet editor",
            "packeteditor",
            "packet sniffer",
            "packetsniffer"
        };
    }

    ProcessWatcher::~ProcessWatcher()
    {
        Shutdown();
    }

    bool ProcessWatcher::Initialize()
    {
        std::cout << "Menginisialisasi Process Watcher..." << std::endl;
        
        // Mulai thread watcher jika belum berjalan
        if (!m_isRunning)
        {
            m_isRunning = true;
            m_watcherThread = std::thread(&ProcessWatcher::WatcherThreadFunc, this);
        }
        
        return true;
    }

    bool ProcessWatcher::Scan()
    {
        // Periksa apakah ada proses cheat yang berjalan
        if (IsCheatProcessRunning())
        {
            return false; // Terdeteksi cheat
        }
        
        // Periksa apakah ada thread yang di-suspend pada proses game
        DWORD gameProcessId = GetCurrentProcessId();
        if (HasSuspendedThreads(gameProcessId))
        {
            return false; // Terdeteksi thread yang di-suspend
        }
        
        return true; // Tidak ada cheat yang terdeteksi
    }

    void ProcessWatcher::Shutdown()
    {
        // Hentikan thread watcher jika sedang berjalan
        if (m_isRunning)
        {
            m_isRunning = false;
            if (m_watcherThread.joinable())
            {
                m_watcherThread.join();
            }
        }
    }

    const char* ProcessWatcher::GetName() const
    {
        return "Process & Thread Watcher";
    }

    std::vector<ProcessInfo> ProcessWatcher::GetRunningProcesses()
    {
        std::vector<ProcessInfo> processes;
        
        // Ambil snapshot dari semua proses yang berjalan
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            return processes;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        // Dapatkan informasi proses pertama
        if (!Process32First(hProcessSnap, &pe32))
        {
            CloseHandle(hProcessSnap);
            return processes;
        }
        
        // Iterasi melalui semua proses
        do
        {
            ProcessInfo processInfo;
            processInfo.processId = pe32.th32ProcessID;
            processInfo.processName = pe32.szExeFile;
            processInfo.executablePath = GetProcessPath(pe32.th32ProcessID);
            
            processes.push_back(processInfo);
        } while (Process32Next(hProcessSnap, &pe32));
        
        CloseHandle(hProcessSnap);
        return processes;
    }

    std::vector<ThreadInfo> ProcessWatcher::GetProcessThreads(DWORD processId)
    {
        std::vector<ThreadInfo> threads;
        
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
        
        // Iterasi melalui semua thread
        do
        {
            // Filter thread berdasarkan process ID
            if (te32.th32OwnerProcessID == processId)
            {
                ThreadInfo threadInfo;
                threadInfo.threadId = te32.th32ThreadID;
                threadInfo.processId = te32.th32OwnerProcessID;
                threadInfo.basePriority = te32.tpBasePri;
                
                // Periksa apakah thread di-suspend
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread != NULL)
                {
                    DWORD suspendCount = 0;
                    suspendCount = SuspendThread(hThread);
                    if (suspendCount != (DWORD)-1)
                    {
                        ResumeThread(hThread); // Kembalikan thread ke status semula
                        threadInfo.isSuspended = (suspendCount > 0);
                    }
                    else
                    {
                        threadInfo.isSuspended = false;
                    }
                    
                    CloseHandle(hThread);
                }
                else
                {
                    threadInfo.isSuspended = false;
                }
                
                threads.push_back(threadInfo);
            }
        } while (Thread32Next(hThreadSnap, &te32));
        
        CloseHandle(hThreadSnap);
        return threads;
    }

    bool ProcessWatcher::IsCheatProcessRunning()
    {
        std::vector<ProcessInfo> processes = GetRunningProcesses();
        
        for (const auto& process : processes)
        {
            if (IsCheatProcess(process.processName))
            {
                // Buat laporan deteksi
                CheatDetection detection;
                detection.type = CheatType::PROCESS_INJECTION;
                detection.details = "Terdeteksi proses cheat: " + process.processName;
                detection.processId = process.processId;
                detection.processName = process.processName;
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                return true;
            }
        }
        
        return false;
    }

    bool ProcessWatcher::HasSuspendedThreads(DWORD processId)
    {
        std::vector<ThreadInfo> threads = GetProcessThreads(processId);
        
        for (const auto& thread : threads)
        {
            if (thread.isSuspended)
            {
                // Buat laporan deteksi
                CheatDetection detection;
                detection.type = CheatType::SUSPENDED_THREAD;
                detection.details = "Terdeteksi thread yang di-suspend: " + std::to_string(thread.threadId);
                detection.processId = processId;
                detection.processName = GetProcessName(processId);
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                return true;
            }
        }
        
        return false;
    }

    void ProcessWatcher::WatcherThreadFunc()
    {
        while (m_isRunning)
        {
            // Periksa proses setiap 1 detik
            Scan();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    bool ProcessWatcher::IsCheatProcess(const std::string& processName)
    {
        // Konversi nama proses ke lowercase untuk perbandingan case-insensitive
        std::string lowerProcessName = processName;
        std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        // Periksa apakah nama proses ada dalam daftar proses cheat yang dikenal
        for (const auto& cheatProcess : m_knownCheatProcesses)
        {
            if (lowerProcessName.find(cheatProcess) != std::string::npos)
            {
                return true;
            }
        }
        
        return false;
    }

    std::string ProcessWatcher::GetProcessPath(DWORD processId)
    {
        std::string path;
        
        // Buka handle ke proses
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess != NULL)
        {
            WCHAR szProcessPath[MAX_PATH];
            DWORD dwSize = MAX_PATH;
            
            if (QueryFullProcessImageNameW(hProcess, 0, szProcessPath, &dwSize))
            {
                // Konversi WCHAR ke string
                std::wstring wPath(szProcessPath);
                path = std::string(wPath.begin(), wPath.end());
            }
            
            CloseHandle(hProcess);
        }
        
        return path;
    }

    std::string ProcessWatcher::GetProcessName(DWORD processId)
    {
        std::string name;
        
        // Ambil snapshot dari semua proses yang berjalan
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            return name;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        // Dapatkan informasi proses pertama
        if (!Process32First(hProcessSnap, &pe32))
        {
            CloseHandle(hProcessSnap);
            return name;
        }
        
        // Iterasi melalui semua proses
        do
        {
            if (pe32.th32ProcessID == processId)
            {
                name = pe32.szExeFile;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
        
        CloseHandle(hProcessSnap);
        return name;
    }
}