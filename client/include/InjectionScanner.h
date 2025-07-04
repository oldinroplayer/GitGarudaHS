#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi modul
    struct ModuleInfo
    {
        std::string name;
        std::string path;
        HMODULE baseAddress;
        DWORD size;
        bool isVerified;
    };

    // Enum untuk jenis teknik injection
    enum class InjectionType
    {
        UNKNOWN,
        LOADLIBRARY,
        MANUAL_MAP,
        REFLECTIVE,
        THREAD_HIJACKING,
        SETWINDOWSHOOK,
        APPINIT_DLL,
        REGISTRY_MODIFICATION
    };

    // Struktur untuk menyimpan informasi injeksi yang terdeteksi
    struct InjectionDetection
    {
        InjectionType type;
        std::string moduleName;
        std::string modulePath;
        HMODULE moduleBase;
        DWORD moduleSize;
        std::string details;
    };

    // Kelas untuk mendeteksi DLL injection
    class InjectionScanner : public IAntiCheatModule
    {
    public:
        InjectionScanner();
        ~InjectionScanner();

        // Implementasi dari IAntiCheatModule
        bool Initialize() override;
        bool Scan() override;
        void Shutdown() override;
        const char* GetName() const override;

        // Fungsi untuk mendapatkan daftar modul yang dimuat
        std::vector<ModuleInfo> GetLoadedModules();

        // Fungsi untuk memeriksa apakah modul adalah DLL yang sah
        bool IsLegitimateModule(const ModuleInfo& module);

        // Fungsi untuk memeriksa apakah ada DLL yang diinjeksi
        bool HasInjectedDLL();

        // Fungsi untuk mendeteksi teknik injeksi yang digunakan
        InjectionType DetectInjectionType(const ModuleInfo& module);

        // Fungsi untuk memverifikasi digital signature dari modul
        bool VerifyModuleSignature(const std::string& modulePath);

    private:
        // Daftar modul yang diketahui sah
        std::unordered_set<std::string> m_knownLegitimateModules;
        
        // Daftar modul yang diketahui berbahaya
        std::unordered_set<std::string> m_knownMaliciousModules;

        // Daftar modul yang dimuat saat inisialisasi
        std::unordered_map<std::string, ModuleInfo> m_initialModules;

        // Thread untuk memantau modul secara periodik
        std::thread m_scannerThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_mutex;

        // Fungsi yang dijalankan oleh thread scanner
        void ScannerThreadFunc();

        // Fungsi untuk mendeteksi LoadLibrary injection
        bool DetectLoadLibraryInjection();

        // Fungsi untuk mendeteksi manual mapping
        bool DetectManualMapping();

        // Fungsi untuk mendeteksi reflective injection
        bool DetectReflectiveInjection();

        // Fungsi untuk mendeteksi thread hijacking
        bool DetectThreadHijacking();

        // Fungsi untuk mendeteksi SetWindowsHook injection
        bool DetectSetWindowsHookInjection();

        // Fungsi untuk mendeteksi AppInit_DLLs injection
        bool DetectAppInitDllInjection();

        // Fungsi untuk mendeteksi registry modification
        bool DetectRegistryModification();

        // Fungsi untuk hook API yang digunakan untuk injection
        bool HookInjectionAPI();

        // Fungsi untuk unhook API
        void UnhookInjectionAPI();

        // Fungsi untuk mendapatkan path dari modul
        std::string GetModulePath(HMODULE hModule);

        // Fungsi untuk memeriksa apakah path modul valid
        bool IsValidModulePath(const std::string& path);

        // Fungsi untuk memeriksa apakah modul dimuat dari folder sistem
        bool IsSystemModule(const std::string& path);

        // Fungsi untuk memeriksa apakah modul dimuat dari folder game
        bool IsGameModule(const std::string& path);
    };
}