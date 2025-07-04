#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

// Namespace untuk GarudaHS
namespace GarudaHS
{
    // Konstanta dan definisi
    constexpr const char* VERSION = "1.0.0";
    constexpr const char* NAME = "Garuda Hack Shield";
    
    // Enum untuk jenis cheat yang terdeteksi
    enum class CheatType
    {
        NONE,
        PROCESS_INJECTION,
        MEMORY_MODIFICATION,
        DEBUGGER_DETECTED,
        SUSPENDED_THREAD,
        DLL_INJECTION,
        INVALID_SIGNATURE,
        MEMORY_SIGNATURE,
        HIJACKED_THREAD,
        IAT_HOOK,
        FILE_INTEGRITY,
        OVERLAY_DETECTED
    };

    // Struktur untuk menyimpan informasi cheat yang terdeteksi
    struct CheatDetection
    {
        CheatType type;
        std::string details;
        DWORD processId;
        std::string processName;
    };

    // Interface dasar untuk modul anti-cheat
    class IAntiCheatModule
    {
    public:
        virtual ~IAntiCheatModule() = default;
        virtual bool Initialize() = 0;
        virtual bool Scan() = 0;
        virtual void Shutdown() = 0;
        virtual const char* GetName() const = 0;
    };

    // Kelas utama untuk client anti-cheat
    class AntiCheatClient
    {
    public:
        static AntiCheatClient& GetInstance();
        
        bool Initialize();
        bool Scan();
        void Shutdown();
        
        void RegisterModule(std::shared_ptr<IAntiCheatModule> module);
        void ReportDetection(const CheatDetection& detection);
        
    private:
        AntiCheatClient() = default;
        ~AntiCheatClient() = default;
        
        AntiCheatClient(const AntiCheatClient&) = delete;
        AntiCheatClient& operator=(const AntiCheatClient&) = delete;
        
        std::vector<std::shared_ptr<IAntiCheatModule>> m_modules;
        bool m_initialized = false;
    };
}

// Fungsi ekspor yang dapat dipanggil dari game
extern "C"
{
    __declspec(dllexport) void Initialize();
}