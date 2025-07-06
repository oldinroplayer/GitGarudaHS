#pragma once
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <memory>
#include <atomic>

// Forward declarations for NT API
typedef LONG NTSTATUS;

// Konstanta dan definisi tipe
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// NT API function declaration
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Kelas informasi sistem kustom untuk kernel debugger
#define SystemKernelDebuggerInformation 35

// Deklarasi forward - hindari konflik dengan winternl.h
#ifndef _SYSTEM_KERNEL_DEBUGGER_INFORMATION_DEFINED
#define _SYSTEM_KERNEL_DEBUGGER_INFORMATION_DEFINED
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
#endif

// Struktur untuk menyimpan informasi region yang dilindungi
struct ProtectedRegion {
    PVOID baseAddress;
    SIZE_T size;
    DWORD originalProtect;
    DWORD currentProtect;
    bool isActive;
};

// Struktur konfigurasi untuk mengurangi false positive
struct ProtectionConfig {
    bool enableAntiDebug;
    bool enableStringObfuscation;
    bool enableIntegrityCheck;
    bool enableVEHHandler;
    bool allowDevelopmentMode;
    DWORD debugCheckInterval;
    DWORD maxProtectedRegions;

    ProtectionConfig() :
        enableAntiDebug(true),
        enableStringObfuscation(false), // Dinonaktifkan secara default untuk mencegah masalah
        enableIntegrityCheck(true),
        enableVEHHandler(true),
        allowDevelopmentMode(false),
        debugCheckInterval(5000),
        maxProtectedRegions(100) {
    }
};

class MemoryProtector {
private:
    HMODULE hModule;
    std::vector<std::unique_ptr<ProtectedRegion>> protectedRegions;
    std::atomic<bool> isInitialized;
    std::atomic<bool> isShuttingDown;
    ProtectionConfig config;
    DWORD originalChecksum;

    // Handler untuk VEH
    static LONG WINAPI VehHandler(PEXCEPTION_POINTERS pExceptionInfo);
    static MemoryProtector* instance;

    // Metode helper
    bool IsLegitimateDebugger();
    bool IsInDevelopmentEnvironment();
    bool IsValidAddress(PVOID address);
    bool IsSystemProcess();
    DWORD CalculateChecksum(BYTE* data, SIZE_T size);
    void LogProtectionEvent(const std::string& event);

    // Metode proteksi yang diperbaiki
    bool ProtectRegionSafely(PVOID address, SIZE_T size, DWORD newProtect);
    bool RestoreRegionProtection(ProtectedRegion* region);

public:
    MemoryProtector(HMODULE hMod, const ProtectionConfig& cfg = ProtectionConfig());
    ~MemoryProtector();

    // Metode proteksi utama
    bool InitializeProtection();
    void Shutdown();

    // Komponen proteksi individual
    void ProtectCodeSection();
    void ProtectDataSection();
    void AddAntiDebugProtection();
    void ObfuscateStrings();
    bool ValidateIntegrity();

    // Konfigurasi dan status
    void UpdateConfig(const ProtectionConfig& newConfig);
    bool IsActive() const { return isInitialized.load() && !isShuttingDown.load(); }
    size_t GetProtectedRegionCount() const { return protectedRegions.size(); }
};

// Fungsi global yang diperbaiki
void proteksi_memori_dll(HMODULE hModule, const ProtectionConfig& config = ProtectionConfig());
void cleanup_memory_protection();
bool is_valid_module_range(HMODULE hModule, LPVOID address);

// API yang diperkuat dengan penanganan error yang lebih baik
bool proteksi_memori_dll_enhanced(HMODULE hModule, const ProtectionConfig& config = ProtectionConfig());
bool verify_dll_integrity(HMODULE hModule);

// Fungsi ramah development
bool is_development_environment();
void enable_development_mode(bool enable);
bool is_legitimate_debugger_attached();