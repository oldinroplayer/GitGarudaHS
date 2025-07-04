#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi fungsi yang di-import
    struct ImportFunctionInfo
    {
        std::string moduleName;      // Nama modul yang mengimpor fungsi
        std::string functionName;    // Nama fungsi yang diimpor
        void* originalAddress;       // Alamat asli fungsi
        void* currentAddress;        // Alamat saat ini fungsi
        bool isHooked;               // Apakah fungsi di-hook
    };

    // Kelas untuk mendeteksi IAT Hook
    class IATHookScanner : public IAntiCheatModule
    {
    public:
        IATHookScanner();
        virtual ~IATHookScanner();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk memindai IAT modul tertentu
        bool ScanModuleIAT(HMODULE hModule);
        
        // Fungsi untuk memindai IAT semua modul dalam proses saat ini
        bool ScanAllModulesIAT();
        
        // Fungsi untuk mendapatkan hasil deteksi
        const std::vector<ImportFunctionInfo>& GetHookedFunctions() const;
        
        // Fungsi untuk membersihkan hasil deteksi
        void ClearHookedFunctions();
        
        // Fungsi untuk menambahkan fungsi yang diizinkan untuk di-hook
        void AddAllowedHook(const std::string& moduleName, const std::string& functionName);
        
        // Fungsi untuk memeriksa apakah hook diizinkan
        bool IsHookAllowed(const std::string& moduleName, const std::string& functionName);

    private:
        std::vector<ImportFunctionInfo> m_hookedFunctions;
        std::unordered_map<std::string, std::unordered_map<std::string, bool>> m_allowedHooks;
        std::unordered_map<std::string, std::unordered_map<std::string, void*>> m_originalAddresses;
        bool m_initialized;
        
        // Fungsi untuk mendapatkan nama modul dari alamat
        std::string GetModuleNameFromAddress(void* address);
        
        // Fungsi untuk mendapatkan alamat asli fungsi
        void* GetOriginalFunctionAddress(const std::string& moduleName, const std::string& functionName);
        
        // Fungsi untuk memeriksa apakah alamat berada dalam modul yang valid
        bool IsAddressInValidModule(void* address);
        
        // Fungsi untuk menyimpan alamat asli fungsi yang diimpor
        void SaveOriginalImportAddresses();
    };
}