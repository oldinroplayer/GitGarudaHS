#include "memprotect.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <mutex>
#include <random>

static std::mutex g_protect_mutex;
static std::vector<LPVOID> g_protected_regions;

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