#include "memprotect.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <mutex>
#include <random>
#include <algorithm>
#include <iostream>
#include <tlhelp32.h>

static std::mutex g_protect_mutex;
static std::vector<LPVOID> g_protected_regions;
static PVOID g_veh_handler = nullptr;

bool is_valid_module_range(HMODULE hModule, LPVOID address) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return false;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    BYTE* end = base + modInfo.SizeOfImage;
    BYTE* addr = static_cast<BYTE*>(address);

    return (addr >= base && addr < end);
}

void proteksi_memori_dll(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(g_protect_mutex);

    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    SIZE_T size = modInfo.SizeOfImage;

    // Validasi size untuk mencegah overflow
    if (size > 0x10000000) { // 256MB limit
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = base;

    while (addr < base + size) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }

        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
            // Validasi address masih dalam range module
            if (is_valid_module_range(hModule, mbi.BaseAddress)) {
                DWORD oldProtect;
                if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                    PAGE_EXECUTE_READ, &oldProtect)) {
                    g_protected_regions.push_back(mbi.BaseAddress);
                }
            }
        }

        addr += mbi.RegionSize;
    }
}

// Cleanup function
void cleanup_memory_protection() {
    std::lock_guard<std::mutex> lock(g_protect_mutex);
    g_protected_regions.clear();
}

// MemoryProtector Class Implementation

// Static VEH Handler
LONG WINAPI MemoryProtector::VehHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Handle access violation - could be debugger or memory tampering
        ULONG_PTR addr = pExceptionInfo->ExceptionRecord->ExceptionInformation[1];

        // Check if the address is in our protected regions
        std::lock_guard<std::mutex> lock(g_protect_mutex);
        for (const auto& region : g_protected_regions) {
            if (addr >= reinterpret_cast<ULONG_PTR>(region) &&
                addr < reinterpret_cast<ULONG_PTR>(region) + 0x1000) {
                // This is an access to our protected region - terminate process
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
                return EXCEPTION_EXECUTE_HANDLER;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Constructor
MemoryProtector::MemoryProtector(HMODULE hMod) : hModule(hMod) {
    if (!g_veh_handler) {
        g_veh_handler = AddVectoredExceptionHandler(1, VehHandler);
    }
}

// Destructor
MemoryProtector::~MemoryProtector() {
    if (g_veh_handler) {
        RemoveVectoredExceptionHandler(g_veh_handler);
        g_veh_handler = nullptr;
    }

    // Restore original protection
    for (PVOID section : protectedSections) {
        DWORD oldProtect;
        VirtualProtect(section, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
    }
    protectedSections.clear();
}

bool MemoryProtector::InitializeProtection() {
    if (!hModule) return false;

    try {
        ProtectCodeSection();
        ProtectDataSection();
        AddAntiDebugProtection();
        ObfuscateStrings();
        return ValidateIntegrity();
    }
    catch (...) {
        return false;
    }
}

void MemoryProtector::ProtectCodeSection() {
    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            BYTE* sectionBase = base + sectionHeader[i].VirtualAddress;
            DWORD oldProtect;

            if (VirtualProtect(sectionBase, sectionHeader[i].Misc.VirtualSize,
                PAGE_EXECUTE_READ, &oldProtect)) {
                protectedSections.push_back(sectionBase);
            }
        }
    }
}

void MemoryProtector::ProtectDataSection() {
    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            BYTE* sectionBase = base + sectionHeader[i].VirtualAddress;
            DWORD oldProtect;

            if (VirtualProtect(sectionBase, sectionHeader[i].Misc.VirtualSize,
                PAGE_READONLY, &oldProtect)) {
                protectedSections.push_back(sectionBase);
            }
        }
    }
}

void MemoryProtector::AddAntiDebugProtection() {
    // Check for debugger presence
    if (IsDebuggerPresent()) {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
    }

    // Check for remote debugger
    BOOL isRemoteDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent) &&
        isRemoteDebuggerPresent) {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
    }

    // Check for kernel debugger using function pointer
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
                SystemKernelDebuggerInformation, // 35
                &skdi, sizeof(skdi), nullptr);

            if (NT_SUCCESS(status) && skdi.KernelDebuggerEnabled) {
                TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
            }
        }
    }
}

void MemoryProtector::ObfuscateStrings() {
    // Simple XOR obfuscation for strings in memory
    // This is a basic implementation - in production, use more sophisticated methods

    if (!hModule) return;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    SIZE_T size = modInfo.SizeOfImage;

    // Generate random key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 255);
    BYTE key = static_cast<BYTE>(dis(gen));

    // Simple string obfuscation (be careful with this in production)
    for (SIZE_T i = 0; i < size; i++) {
        if (base[i] >= 0x20 && base[i] <= 0x7E) { // Printable ASCII
            base[i] ^= key;
        }
    }
}

bool MemoryProtector::ValidateIntegrity() {
    if (!hModule) return false;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return false;
    }

    BYTE* base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
    SIZE_T size = modInfo.SizeOfImage;

    // Simple checksum validation
    DWORD checksum = 0;
    for (SIZE_T i = 0; i < size; i++) {
        checksum += base[i];
        checksum = (checksum << 1) | (checksum >> 31); // Rotate left
    }

    // Store and compare with expected checksum
    // In production, you'd store the expected checksum securely
    static DWORD expectedChecksum = 0;
    if (expectedChecksum == 0) {
        expectedChecksum = checksum;
        return true;
    }

    return (checksum == expectedChecksum);
}

// Enhanced API implementations
void proteksi_memori_dll_enhanced(HMODULE hModule) {
    if (!hModule) return;

    MemoryProtector protector(hModule);
    protector.InitializeProtection();

    // Also call the basic protection
    proteksi_memori_dll(hModule);
}

bool verify_dll_integrity(HMODULE hModule) {
    if (!hModule) return false;

    MemoryProtector protector(hModule);
    return protector.ValidateIntegrity();
}