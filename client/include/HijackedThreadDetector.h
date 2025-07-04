#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi thread
    struct ThreadInfo
    {
        DWORD threadId;                 // ID thread
        DWORD ownerProcessId;           // ID proses pemilik thread
        void* startAddress;             // Alamat awal thread
        void* currentAddress;           // Alamat saat ini
        std::string moduleName;         // Nama modul yang berisi alamat awal
        bool isRemoteThread;            // Apakah thread dibuat oleh proses lain
        bool isHijacked;                // Apakah thread dibajak
        std::string reason;             // Alasan mengapa thread dianggap dibajak
    };

    // Kelas untuk mendeteksi thread yang dibajak
    class HijackedThreadDetector : public IAntiCheatModule
    {
    public:
        HijackedThreadDetector();
        virtual ~HijackedThreadDetector();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk mendapatkan informasi semua thread dalam proses saat ini
        std::vector<ThreadInfo> GetCurrentProcessThreads();
        
        // Fungsi untuk mendapatkan informasi semua thread dalam proses tertentu
        std::vector<ThreadInfo> GetProcessThreads(DWORD processId);
        
        // Fungsi untuk mendapatkan informasi semua thread dalam sistem
        std::vector<ThreadInfo> GetAllThreads();
        
        // Fungsi untuk memeriksa apakah thread dibajak
        bool IsThreadHijacked(ThreadInfo& threadInfo);
        
        // Fungsi untuk mendapatkan hasil deteksi
        const std::vector<ThreadInfo>& GetHijackedThreads() const;
        
        // Fungsi untuk membersihkan hasil deteksi
        void ClearHijackedThreads();
        
        // Fungsi untuk menambahkan modul yang dipercaya
        void AddTrustedModule(const std::string& moduleName);
        
        // Fungsi untuk menghapus modul yang dipercaya
        void RemoveTrustedModule(const std::string& moduleName);
        
        // Fungsi untuk memeriksa apakah modul dipercaya
        bool IsModuleTrusted(const std::string& moduleName);

    private:
        std::vector<ThreadInfo> m_hijackedThreads;
        std::unordered_map<std::string, bool> m_trustedModules;
        std::map<DWORD, std::vector<void*>> m_threadStartAddresses;
        bool m_initialized;
        
        // Fungsi untuk mendapatkan nama modul yang berisi alamat
        std::string GetModuleNameFromAddress(DWORD processId, void* address);
        
        // Fungsi untuk mendapatkan alamat awal thread
        void* GetThreadStartAddress(HANDLE hThread);
        
        // Fungsi untuk mendapatkan alamat saat ini thread
        void* GetThreadCurrentAddress(HANDLE hThread);
        
        // Fungsi untuk memeriksa apakah thread dibuat oleh proses lain
        bool IsRemoteThread(DWORD threadId, DWORD processId);
        
        // Fungsi untuk menyimpan alamat awal thread yang sah
        void SaveLegitimateThreadStartAddresses();
        
        // Fungsi untuk memeriksa apakah alamat awal thread berubah
        bool HasThreadStartAddressChanged(DWORD threadId, void* currentStartAddress);
    };
}