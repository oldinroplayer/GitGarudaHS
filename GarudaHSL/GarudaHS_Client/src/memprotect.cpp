#include "memprotect.h"
#include <windows.h>
#include <psapi.h>

void proteksi_memori_dll(HMODULE hModule) {
    MEMORY_BASIC_INFORMATION mbi;

    BYTE* addr = reinterpret_cast<BYTE*>(hModule);
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
            DWORD oldProtect;
            // Proteksi ke read-only + execute
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &oldProtect);
        }
        addr += mbi.RegionSize;
        if (addr >= (BYTE*)hModule + 0x100000) break; // proteksi hanya range wajar DLL
    }
}
