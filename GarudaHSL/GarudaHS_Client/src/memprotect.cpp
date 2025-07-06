#include "memprotect.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <mutex>
#include <random>
#include <algorithm>
#include <iostream>
#include <tlhelp32.h>
#include <winternl.h>
#include <string>
#include <map>
#include <set>

// Manajemen state global
static std::mutex g_protect_mutex;
static std::vector<LPVOID> g_protected_regions;
static PVOID g_veh_handler = nullptr;
static bool g_development_mode = false;
static bool g_shutting_down = false;

// Pointer instance statis
MemoryProtector* MemoryProtector::instance = nullptr;

// Daftar debugger dan tools pengembangan yang sah
static const std::set<std::string> LEGITIMATE_DEBUGGERS = {
    "devenv.exe",     // Visual Studio
    "vshost.exe",     // Visual Studio Host
    "windbg.exe",     // WinDbg
    "x64dbg.exe",     // x64dbg
    "x32dbg.exe",     // x32dbg
    "ida.exe",        // IDA Pro (untuk tim reverse engineering)
    "ida64.exe",      // IDA Pro 64-bit
    "ollydbg.exe",    // OllyDbg
    "cheatengine.exe" // Hanya jika dalam mode pengembangan
};

// Daftar proses sistem yang sah
static const std::set<std::string> SYSTEM_PROCESSES = {
    "system",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "taskhost.exe",
    "conhost.exe"
};

// Deteksi lingkungan pengembangan
bool is_development_environment() {
    // Periksa indikator pengembangan umum melalui environment variables
    std::vector<std::string> dev_indicators = {
        "VSLANG", "VSAPPIDNAME", "VSAPPIDDIR", // Visual Studio
        "MSBUILDDISABLENODEREUSE", // MSBuild
        "COMPUTERNAME", // Periksa nama mesin pengembangan
        "USERNAME"
    };

    for (const auto& indicator : dev_indicators) {
        char buffer[256];
        if (GetEnvironmentVariableA(indicator.c_str(), buffer, sizeof(buffer)) > 0) {
            std::string value(buffer);
            if (value.find("DEV") != std::string::npos ||
                value.find("DEBUG") != std::string::npos ||
                value.find("TEST") != std::string::npos) {
                return true;
            }
        }
    }

    // Periksa apakah ada development tools yang sedang berjalan
    std::vector<std::wstring> dev_processes = {
        L"devenv.exe",     // Visual Studio
        L"Code.exe",       // VS Code
        L"windbg.exe",     // WinDbg
        L"ida64.exe",      // IDA Pro
        L"ida.exe",        // IDA Pro 32-bit
        L"x64dbg.exe",     // x64dbg
        L"x32dbg.exe",     // x32dbg
        L"procmon.exe",    // Process Monitor
        L"ollydbg.exe"     // OllyDbg
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                for (const auto& dev_process : dev_processes) {
                    if (_wcsicmp(pe.szExeFile, dev_process.c_str()) == 0) {
                        CloseHandle(snapshot);
                        return true;
                    }
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }

    // Periksa apakah berjalan di bawah debugger dalam konteks pengembangan
    if (IsDebuggerPresent()) {
        DWORD processId = GetCurrentProcessId();
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == processId) {
                        // Convert WCHAR to std::string
                        int len = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                        std::string parentName(len - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &parentName[0], len, nullptr, nullptr);
                        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);

                        for (const auto& debugger : LEGITIMATE_DEBUGGERS) {
                            if (parentName.find(debugger) != std::string::npos) {
                                CloseHandle(hSnapshot);
                                return true;
                            }
                        }
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }

    return false;
}

bool is_legitimate_debugger_attached() {
    if (!IsDebuggerPresent()) {
        return false;
    }

    // Dapatkan informasi proses induk
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    // Periksa apakah proses induk adalah debugger yang sah
    if (parentPid != 0 && Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == parentPid) {
                // Convert WCHAR to std::string
                int len = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                std::string parentName(len - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &parentName[0], len, nullptr, nullptr);
                std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);

                for (const auto& debugger : LEGITIMATE_DEBUGGERS) {
                    if (parentName.find(debugger) != std::string::npos) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

// Fungsi untuk memeriksa apakah proses adalah proses sistem
bool is_system_process(const std::string& processName) {
    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    return SYSTEM_PROCESSES.find(lowerName) != SYSTEM_PROCESSES.end();
}

void enable_development_mode(bool enable) {
    std::lock_guard<std::mutex> lock(g_protect_mutex);
    g_development_mode = enable;
}

bool is_valid_module_range(HMODULE hModule, LPVOID address) {
    if (!hModule || !address) return false;

    try {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }

        BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        BYTE* end = base + modInfo.SizeOfImage;
        BYTE* addr = static_cast<BYTE*>(address);

        return (addr >= base && addr < end);
    }
    catch (...) {
        return false;
    }
}

void proteksi_memori_dll(HMODULE hModule, const ProtectionConfig& config) {
    std::lock_guard<std::mutex> lock(g_protect_mutex);

    if (!hModule || g_shutting_down) return;

    // Periksa apakah dalam lingkungan pengembangan
    if (config.allowDevelopmentMode && is_development_environment()) {
        g_development_mode = true;
        return; // Lewati proteksi dalam pengembangan
    }

    try {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return;
        }

        BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        SIZE_T size = modInfo.SizeOfImage;

        // Validasi ukuran yang diperbaiki
        if (size == 0 || size > 0x10000000) { // Batas 256MB
            return;
        }

        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = base;
        DWORD protectedCount = 0;

        while (addr < base + size && protectedCount < config.maxProtectedRegions) {
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                break;
            }

            if (mbi.State == MEM_COMMIT &&
                mbi.Protect != PAGE_NOACCESS &&
                mbi.Protect != PAGE_GUARD) {

                // Validasi alamat masih dalam rentang modul
                if (is_valid_module_range(hModule, mbi.BaseAddress)) {
                    DWORD oldProtect;
                    DWORD newProtect = PAGE_EXECUTE_READ;

                    // Lebih konservatif dengan proteksi
                    if (mbi.Protect & PAGE_EXECUTE) {
                        newProtect = PAGE_EXECUTE_READ;
                    }
                    else if (mbi.Protect & PAGE_READWRITE) {
                        newProtect = PAGE_READONLY;
                    }

                    if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, newProtect, &oldProtect)) {
                        g_protected_regions.push_back(mbi.BaseAddress);
                        protectedCount++;
                    }
                }
            }

            addr += mbi.RegionSize;
        }
    }
    catch (...) {
        // Tangani pengecualian dengan diam selama proteksi
    }
}

void cleanup_memory_protection() {
    std::lock_guard<std::mutex> lock(g_protect_mutex);
    g_shutting_down = true;

    // Pulihkan proteksi asli
    for (auto& region : g_protected_regions) {
        try {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(region, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                DWORD oldProtect;
                VirtualProtect(region, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            }
        }
        catch (...) {
            // Abaikan kesalahan selama pembersihan
        }
    }

    g_protected_regions.clear();

    if (g_veh_handler) {
        RemoveVectoredExceptionHandler(g_veh_handler);
        g_veh_handler = nullptr;
    }
}

// Implementasi MemoryProtector

LONG WINAPI MemoryProtector::VehHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (g_shutting_down || g_development_mode) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Periksa apakah ini akses yang sah atau potensi serangan
        ULONG_PTR addr = pExceptionInfo->ExceptionRecord->ExceptionInformation[1];

        // Analisis lebih canggih sebelum menghentikan
        if (instance && instance->IsValidAddress(reinterpret_cast<PVOID>(addr))) {
            // Periksa apakah ini dari debugger yang sah
            if (is_legitimate_debugger_attached()) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Catat peristiwa sebelum menghentikan
            if (instance) {
                instance->LogProtectionEvent("Akses memori tidak sah terdeteksi");
            }

            // Penutupan yang elegan daripada penghentian langsung
            Sleep(100); // Beri waktu untuk pencatatan
            ExitProcess(0xDEADBEEF);
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

MemoryProtector::MemoryProtector(HMODULE hMod, const ProtectionConfig& cfg)
    : hModule(hMod), config(cfg), isInitialized(false), isShuttingDown(false), originalChecksum(0) {
    instance = this;

    if (config.enableVEHHandler && !g_veh_handler) {
        g_veh_handler = AddVectoredExceptionHandler(1, VehHandler);
    }
}

MemoryProtector::~MemoryProtector() {
    Shutdown();
    instance = nullptr;
}

bool MemoryProtector::InitializeProtection() {
    if (isInitialized.load()) return true;

    // Periksa lingkungan pengembangan
    if (config.allowDevelopmentMode && IsInDevelopmentEnvironment()) {
        g_development_mode = true;
        return true; // Lewati proteksi dalam pengembangan
    }

    if (!hModule) return false;

    try {
        if (config.enableAntiDebug) {
            AddAntiDebugProtection();
        }

        ProtectCodeSection();
        ProtectDataSection();

        if (config.enableIntegrityCheck) {
            ValidateIntegrity();
        }

        if (config.enableStringObfuscation) {
            ObfuscateStrings();
        }

        isInitialized.store(true);
        return true;
    }
    catch (...) {
        return false;
    }
}

void MemoryProtector::Shutdown() {
    if (isShuttingDown.load()) return;

    isShuttingDown.store(true);

    // Pulihkan semua wilayah yang dilindungi
    for (auto& region : protectedRegions) {
        if (region && region->isActive) {
            RestoreRegionProtection(region.get());
        }
    }

    protectedRegions.clear();
    isInitialized.store(false);
}

void MemoryProtector::AddAntiDebugProtection() {
    if (g_development_mode) return;

    // Deteksi debugger yang lebih canggih
    if (IsDebuggerPresent()) {
        if (!is_legitimate_debugger_attached()) {
            LogProtectionEvent("Debugger tidak sah terdeteksi");
            Sleep(100);
            ExitProcess(0xDEADBEEF);
        }
    }

    // Periksa debugger jarak jauh
    BOOL isRemoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent) &&
        isRemoteDebuggerPresent) {
        if (!is_legitimate_debugger_attached()) {
            LogProtectionEvent("Debugger jarak jauh terdeteksi");
            Sleep(100);
            ExitProcess(0xDEADBEEF);
        }
    }

    // Pemeriksaan debugger kernel dengan penanganan kesalahan yang diperbaiki
    try {
        typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pfnNtQuerySystemInformation pNtQuerySystemInformation =
                reinterpret_cast<pfnNtQuerySystemInformation>(
                    GetProcAddress(hNtdll, "NtQuerySystemInformation"));

            if (pNtQuerySystemInformation) {
                SYSTEM_KERNEL_DEBUGGER_INFORMATION skdi;
                NTSTATUS status = pNtQuerySystemInformation(
                    SystemKernelDebuggerInformation,
                    &skdi, sizeof(skdi), nullptr);

                if (NT_SUCCESS(status) && skdi.KernelDebuggerEnabled) {
                    if (!IsInDevelopmentEnvironment()) {
                        LogProtectionEvent("Debugger kernel terdeteksi");
                        Sleep(100);
                        ExitProcess(0xDEADBEEF);
                    }
                }
            }
        }
    }
    catch (...) {
        // Tangani pengecualian dengan diam
    }
}

bool MemoryProtector::IsInDevelopmentEnvironment() {
    return is_development_environment();
}

bool MemoryProtector::IsValidAddress(PVOID address) {
    return is_valid_module_range(hModule, address);
}

// Implementasi fungsi IsLegitimateDebugger yang hilang
bool MemoryProtector::IsLegitimateDebugger() {
    return is_legitimate_debugger_attached();
}

// Implementasi fungsi IsSystemProcess yang hilang
bool MemoryProtector::IsSystemProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD currentPid = GetCurrentProcessId();

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPid) {
                // Convert WCHAR to std::string
                int len = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                std::string processName(len - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &processName[0], len, nullptr, nullptr);
                CloseHandle(hSnapshot);
                return is_system_process(processName);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

// Implementasi fungsi UpdateConfig yang hilang
void MemoryProtector::UpdateConfig(const ProtectionConfig& newConfig) {
    std::lock_guard<std::mutex> lock(g_protect_mutex);

    // Simpan konfigurasi lama untuk perbandingan
    ProtectionConfig oldConfig = config;
    config = newConfig;

    // Jika proteksi sudah diinisialisasi, terapkan perubahan
    if (isInitialized.load()) {
        // Jika anti-debug dinonaktifkan, tidak perlu melakukan apa-apa
        // Jika anti-debug diaktifkan dan sebelumnya tidak aktif, aktifkan
        if (config.enableAntiDebug && !oldConfig.enableAntiDebug) {
            AddAntiDebugProtection();
        }

        // Jika pemeriksaan integritas diaktifkan dan sebelumnya tidak aktif
        if (config.enableIntegrityCheck && !oldConfig.enableIntegrityCheck) {
            ValidateIntegrity();
        }

        // Jika mode pengembangan berubah
        if (config.allowDevelopmentMode != oldConfig.allowDevelopmentMode) {
            g_development_mode = config.allowDevelopmentMode && is_development_environment();
        }
    }

    LogProtectionEvent("Konfigurasi proteksi diperbarui");
}

void MemoryProtector::LogProtectionEvent(const std::string& event) {
    // Pencatatan sederhana - dalam produksi, gunakan framework pencatatan yang tepat
#ifdef _DEBUG
    OutputDebugStringA(("MemoryProtector: " + event + "\n").c_str());
#endif
}

bool MemoryProtector::ProtectRegionSafely(PVOID address, SIZE_T size, DWORD newProtect) {
    if (!address || size == 0) return false;

    try {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return false;
        }

        DWORD oldProtect;
        if (VirtualProtect(address, size, newProtect, &oldProtect)) {
            auto region = std::make_unique<ProtectedRegion>();
            region->baseAddress = address;
            region->size = size;
            region->originalProtect = oldProtect;
            region->currentProtect = newProtect;
            region->isActive = true;

            protectedRegions.push_back(std::move(region));
            return true;
        }
    }
    catch (...) {
        // Tangani pengecualian
    }

    return false;
}

bool MemoryProtector::RestoreRegionProtection(ProtectedRegion* region) {
    if (!region || !region->isActive) return false;

    try {
        DWORD oldProtect;
        bool success = VirtualProtect(region->baseAddress, region->size,
            region->originalProtect, &oldProtect);
        region->isActive = false;
        return success;
    }
    catch (...) {
        return false;
    }
}

void MemoryProtector::ProtectCodeSection() {
    if (!hModule || g_development_mode) return;

    try {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return;
        }

        BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                BYTE* sectionBase = base + sectionHeader[i].VirtualAddress;
                ProtectRegionSafely(sectionBase, sectionHeader[i].Misc.VirtualSize, PAGE_EXECUTE_READ);
            }
        }
    }
    catch (...) {
        // Tangani pengecualian dengan diam
    }
}

void MemoryProtector::ProtectDataSection() {
    if (!hModule || g_development_mode) return;

    try {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return;
        }

        BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                BYTE* sectionBase = base + sectionHeader[i].VirtualAddress;
                ProtectRegionSafely(sectionBase, sectionHeader[i].Misc.VirtualSize, PAGE_READONLY);
            }
        }
    }
    catch (...) {
        // Tangani pengecualian dengan diam
    }
}

void MemoryProtector::ObfuscateStrings() {
    // Dinonaktifkan secara default untuk mencegah false positive
    // Hanya aktifkan jika dikonfigurasi secara khusus
    if (!config.enableStringObfuscation || g_development_mode) return;

    // Implementasi akan ditempatkan di sini jika diperlukan
}

bool MemoryProtector::ValidateIntegrity() {
    if (!hModule) return false;

    try {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }

        BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        SIZE_T size = modInfo.SizeOfImage;

        DWORD checksum = CalculateChecksum(base, size);

        if (originalChecksum == 0) {
            originalChecksum = checksum;
            return true;
        }

        return (checksum == originalChecksum);
    }
    catch (...) {
        return false;
    }
}

DWORD MemoryProtector::CalculateChecksum(BYTE* data, SIZE_T size) {
    DWORD checksum = 0;

    try {
        for (SIZE_T i = 0; i < size; i++) {
            checksum += data[i];
            checksum = (checksum << 1) | (checksum >> 31);
        }
    }
    catch (...) {
        return 0;
    }

    return checksum;
}

// Implementasi API yang ditingkatkan
bool proteksi_memori_dll_enhanced(HMODULE hModule, const ProtectionConfig& config) {
    if (!hModule) return false;

    try {
        static std::unique_ptr<MemoryProtector> protector;
        protector = std::make_unique<MemoryProtector>(hModule, config);

        if (protector->InitializeProtection()) {
            proteksi_memori_dll(hModule, config);
            return true;
        }
    }
    catch (...) {
        return false;
    }

    return false;
}

bool verify_dll_integrity(HMODULE hModule) {
    if (!hModule) return false;

    try {
        MemoryProtector protector(hModule);
        return protector.ValidateIntegrity();
    }
    catch (...) {
        return false;
    }
}