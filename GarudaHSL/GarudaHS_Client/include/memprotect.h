#pragma once
#include <windows.h>
#include <vector>
#include <string>

// Constants and type definitions
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// Custom system information class for kernel debugger
#define SystemKernelDebuggerInformation 35

// Forward declarations - avoid conflicts with winternl.h
#ifndef _SYSTEM_KERNEL_DEBUGGER_INFORMATION_DEFINED
#define _SYSTEM_KERNEL_DEBUGGER_INFORMATION_DEFINED
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
#endif

class MemoryProtector {
private:
    HMODULE hModule;
    std::vector<PVOID> protectedSections;
    static LONG WINAPI VehHandler(PEXCEPTION_POINTERS pExceptionInfo);

public:
    MemoryProtector(HMODULE hMod);
    ~MemoryProtector();

    bool InitializeProtection();
    void ProtectCodeSection();
    void ProtectDataSection();
    void AddAntiDebugProtection();
    void ObfuscateStrings();
    bool ValidateIntegrity();
};

// Basic protection functions
void proteksi_memori_dll(HMODULE hModule);
void cleanup_memory_protection();
bool is_valid_module_range(HMODULE hModule, LPVOID address);

// Enhanced API
void proteksi_memori_dll_enhanced(HMODULE hModule);
bool verify_dll_integrity(HMODULE hModule);