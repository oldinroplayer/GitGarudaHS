#include "../include/HijackedThreadDetector.h"
#include <iostream>
#include <Psapi.h>
#include <sstream>
#include <algorithm>

// Untuk mendapatkan alamat awal thread
#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// Thread Information Class untuk mendapatkan alamat awal thread
#define ThreadQuerySetWin32StartAddress 9

namespace GarudaHS
{
    HijackedThreadDetector::HijackedThreadDetector()
        : m_initialized(false)
    {
    }

    HijackedThreadDetector::~HijackedThreadDetector()
    {
        Shutdown();
    }

    bool HijackedThreadDetector::Initialize()
    {
        std::cout << "Menginisialisasi Hijacked Thread Detector..." << std::endl;
        
        // Tambahkan modul-modul yang dipercaya
        AddTrustedModule("kernel32.dll");
        AddTrustedModule("ntdll.dll");
        AddTrustedModule("user32.dll");
        AddTrustedModule("gdi32.dll");
        AddTrustedModule("advapi32.dll");
        AddTrustedModule("msvcrt.dll");
        
        // Tambahkan modul game yang dipercaya
        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        std::string moduleName = PathFindFileNameA(modulePath);
        AddTrustedModule(moduleName);
        
        // Simpan alamat awal thread yang sah
        SaveLegitimateThreadStartAddresses();
        
        m_initialized = true;
        std::cout << "Hijacked Thread Detector berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool HijackedThreadDetector::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "Hijacked Thread Detector belum diinisialisasi." << std::endl;
            return false;
        }

        // Bersihkan hasil deteksi sebelumnya
        ClearHijackedThreads();
        
        // Dapatkan informasi semua thread dalam proses saat ini
        std::vector<ThreadInfo> threads = GetCurrentProcessThreads();
        
        bool allClean = true;
        
        // Periksa setiap thread
        for (auto& thread : threads)
        {
            if (IsThreadHijacked(thread))
            {
                std::cout << "Thread yang dibajak terdeteksi: " << thread.threadId << " - " << thread.reason << std::endl;
                m_hijackedThreads.push_back(thread);
                
                // Buat objek CheatDetection untuk melaporkan deteksi
                CheatDetection detection;
                detection.type = CheatType::HIJACKED_THREAD;
                detection.details = "Thread yang dibajak terdeteksi: " + std::to_string(thread.threadId) + " - " + thread.reason;
                detection.processId = GetCurrentProcessId();
                
                char processName[MAX_PATH];
                GetModuleFileNameA(NULL, processName, MAX_PATH);
                detection.processName = PathFindFileNameA(processName);
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                allClean = false;
            }
        }
        
        return allClean;
    }

    void HijackedThreadDetector::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan Hijacked Thread Detector..." << std::endl;
            m_hijackedThreads.clear();
            m_trustedModules.clear();
            m_threadStartAddresses.clear();
            m_initialized = false;
        }
    }

    const char* HijackedThreadDetector::GetName() const
    {
        return "Hijacked Thread Detector";
    }

    std::vector<ThreadInfo> HijackedThreadDetector::GetCurrentProcessThreads()
    {
        return GetProcessThreads(GetCurrentProcessId());
    }

    std::vector<ThreadInfo> HijackedThreadDetector::GetProcessThreads(DWORD processId)
    {
        std::vector<ThreadInfo> threads;
        
        // Ambil snapshot dari semua thread
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Gagal membuat snapshot thread. Error: " << GetLastError() << std::endl;
            return threads;
        }
        
        // Iterasi semua thread
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te32))
        {
            do
            {
                // Hanya proses thread yang dimiliki oleh proses yang ditentukan
                if (te32.th32OwnerProcessID == processId)
                {
                    ThreadInfo threadInfo;
                    threadInfo.threadId = te32.th32ThreadID;
                    threadInfo.ownerProcessId = te32.th32OwnerProcessID;
                    
                    // Buka handle ke thread
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                    if (hThread != NULL)
                    {
                        // Dapatkan alamat awal thread
                        threadInfo.startAddress = GetThreadStartAddress(hThread);
                        
                        // Dapatkan alamat saat ini thread
                        threadInfo.currentAddress = GetThreadCurrentAddress(hThread);
                        
                        // Dapatkan nama modul yang berisi alamat awal
                        threadInfo.moduleName = GetModuleNameFromAddress(processId, threadInfo.startAddress);
                        
                        // Periksa apakah thread dibuat oleh proses lain
                        threadInfo.isRemoteThread = IsRemoteThread(te32.th32ThreadID, processId);
                        
                        // Tutup handle thread
                        CloseHandle(hThread);
                    }
                    else
                    {
                        threadInfo.startAddress = NULL;
                        threadInfo.currentAddress = NULL;
                        threadInfo.moduleName = "Unknown";
                        threadInfo.isRemoteThread = false;
                    }
                    
                    threadInfo.isHijacked = false;
                    threadInfo.reason = "";
                    
                    threads.push_back(threadInfo);
                }
                
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        // Tutup handle snapshot
        CloseHandle(hSnapshot);
        
        return threads;
    }

    std::vector<ThreadInfo> HijackedThreadDetector::GetAllThreads()
    {
        std::vector<ThreadInfo> threads;
        
        // Ambil snapshot dari semua thread
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Gagal membuat snapshot thread. Error: " << GetLastError() << std::endl;
            return threads;
        }
        
        // Iterasi semua thread
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te32))
        {
            do
            {
                ThreadInfo threadInfo;
                threadInfo.threadId = te32.th32ThreadID;
                threadInfo.ownerProcessId = te32.th32OwnerProcessID;
                
                // Buka handle ke thread
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread != NULL)
                {
                    // Dapatkan alamat awal thread
                    threadInfo.startAddress = GetThreadStartAddress(hThread);
                    
                    // Dapatkan alamat saat ini thread
                    threadInfo.currentAddress = GetThreadCurrentAddress(hThread);
                    
                    // Dapatkan nama modul yang berisi alamat awal
                    threadInfo.moduleName = GetModuleNameFromAddress(te32.th32OwnerProcessID, threadInfo.startAddress);
                    
                    // Periksa apakah thread dibuat oleh proses lain
                    threadInfo.isRemoteThread = IsRemoteThread(te32.th32ThreadID, te32.th32OwnerProcessID);
                    
                    // Tutup handle thread
                    CloseHandle(hThread);
                }
                else
                {
                    threadInfo.startAddress = NULL;
                    threadInfo.currentAddress = NULL;
                    threadInfo.moduleName = "Unknown";
                    threadInfo.isRemoteThread = false;
                }
                
                threadInfo.isHijacked = false;
                threadInfo.reason = "";
                
                threads.push_back(threadInfo);
                
            } while (Thread32Next(hSnapshot, &te32));
        }
        
        // Tutup handle snapshot
        CloseHandle(hSnapshot);
        
        return threads;
    }

    bool HijackedThreadDetector::IsThreadHijacked(ThreadInfo& threadInfo)
    {
        // Jika thread dibuat oleh proses lain, itu mencurigakan
        if (threadInfo.isRemoteThread)
        {
            threadInfo.isHijacked = true;
            threadInfo.reason = "Thread dibuat oleh proses lain";
            return true;
        }
        
        // Jika alamat awal thread tidak berada dalam modul yang dipercaya, itu mencurigakan
        if (!threadInfo.moduleName.empty() && !IsModuleTrusted(threadInfo.moduleName))
        {
            threadInfo.isHijacked = true;
            threadInfo.reason = "Thread dimulai dari modul yang tidak dipercaya: " + threadInfo.moduleName;
            return true;
        }
        
        // Jika alamat awal thread berubah, itu mencurigakan
        if (HasThreadStartAddressChanged(threadInfo.threadId, threadInfo.startAddress))
        {
            threadInfo.isHijacked = true;
            threadInfo.reason = "Alamat awal thread berubah";
            return true;
        }
        
        // Jika alamat saat ini thread tidak berada dalam modul yang dipercaya, itu mencurigakan
        std::string currentModule = GetModuleNameFromAddress(threadInfo.ownerProcessId, threadInfo.currentAddress);
        if (!currentModule.empty() && !IsModuleTrusted(currentModule))
        {
            threadInfo.isHijacked = true;
            threadInfo.reason = "Thread saat ini berada di modul yang tidak dipercaya: " + currentModule;
            return true;
        }
        
        return false;
    }

    const std::vector<ThreadInfo>& HijackedThreadDetector::GetHijackedThreads() const
    {
        return m_hijackedThreads;
    }

    void HijackedThreadDetector::ClearHijackedThreads()
    {
        m_hijackedThreads.clear();
    }

    void HijackedThreadDetector::AddTrustedModule(const std::string& moduleName)
    {
        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
        m_trustedModules[lowerModuleName] = true;
    }

    void HijackedThreadDetector::RemoveTrustedModule(const std::string& moduleName)
    {
        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
        m_trustedModules.erase(lowerModuleName);
    }

    bool HijackedThreadDetector::IsModuleTrusted(const std::string& moduleName)
    {
        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
        return m_trustedModules.find(lowerModuleName) != m_trustedModules.end();
    }

    std::string HijackedThreadDetector::GetModuleNameFromAddress(DWORD processId, void* address)
    {
        if (address == NULL)
        {
            return "Unknown";
        }
        
        std::string moduleName = "Unknown";
        
        // Buka handle ke proses
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL)
        {
            return moduleName;
        }
        
        // Dapatkan informasi tentang semua modul dalam proses
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                // Dapatkan informasi tentang modul ini
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(MODULEINFO)))
                {
                    // Periksa apakah alamat berada dalam rentang modul ini
                    if ((BYTE*)address >= (BYTE*)modInfo.lpBaseOfDll && 
                        (BYTE*)address < (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)
                    {
                        // Dapatkan nama modul
                        char szModName[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, hModules[i], szModName, sizeof(szModName)))
                        {
                            moduleName = PathFindFileNameA(szModName);
                            break;
                        }
                    }
                }
            }
        }
        
        // Tutup handle proses
        CloseHandle(hProcess);
        
        return moduleName;
    }

    void* HijackedThreadDetector::GetThreadStartAddress(HANDLE hThread)
    {
        PVOID startAddress = NULL;
        ULONG returnLength;
        
        NTSTATUS status = NtQueryInformationThread(
            hThread,
            ThreadQuerySetWin32StartAddress,
            &startAddress,
            sizeof(startAddress),
            &returnLength
        );
        
        if (status != 0)
        {
            return NULL;
        }
        
        return startAddress;
    }

    void* HijackedThreadDetector::GetThreadCurrentAddress(HANDLE hThread)
    {
        // Mendapatkan alamat saat ini thread memerlukan suspend thread dan mendapatkan context
        // Ini bisa berbahaya dan menyebabkan crash, jadi kita hanya mengembalikan alamat awal
        // sebagai pendekatan
        return GetThreadStartAddress(hThread);
    }

    bool HijackedThreadDetector::IsRemoteThread(DWORD threadId, DWORD processId)
    {
        // Thread yang dibuat oleh proses lain biasanya memiliki ID thread yang jauh berbeda
        // dari ID proses. Ini hanya pendekatan sederhana dan tidak selalu akurat.
        // Untuk deteksi yang lebih akurat, kita perlu melacak semua thread yang dibuat
        // oleh proses saat ini.
        
        // Untuk saat ini, kita anggap semua thread adalah thread yang sah
        return false;
    }

    void HijackedThreadDetector::SaveLegitimateThreadStartAddresses()
    {
        // Dapatkan informasi semua thread dalam proses saat ini
        std::vector<ThreadInfo> threads = GetCurrentProcessThreads();
        
        // Simpan alamat awal thread
        for (const auto& thread : threads)
        {
            m_threadStartAddresses[thread.threadId].push_back(thread.startAddress);
        }
    }

    bool HijackedThreadDetector::HasThreadStartAddressChanged(DWORD threadId, void* currentStartAddress)
    {
        // Jika thread tidak ada dalam daftar, itu adalah thread baru
        if (m_threadStartAddresses.find(threadId) == m_threadStartAddresses.end())
        {
            // Simpan alamat awal thread baru
            m_threadStartAddresses[threadId].push_back(currentStartAddress);
            return false;
        }
        
        // Periksa apakah alamat awal thread berubah
        for (const auto& startAddress : m_threadStartAddresses[threadId])
        {
            if (startAddress == currentStartAddress)
            {
                return false;
            }
        }
        
        // Alamat awal thread berubah
        return true;
    }
}