#include "unloadprotect.h"
#include <cstdint> // ini yang mendefinisikan int32_t

// Pointer ke fungsi asli
static HMODULE g_hModule = NULL;
using PFN_FreeLibrary = BOOL(WINAPI*)(HMODULE);
using PFN_FreeLibraryEx = BOOL(WINAPI*)(HMODULE, DWORD);

static PFN_FreeLibrary   TrueFreeLibrary = nullptr;
static PFN_FreeLibraryEx TrueFreeLibraryEx = nullptr;

// Hooked functions
BOOL WINAPI HookedFreeLibrary(HMODULE hLibModule) {
    // Jika targetnya GarudaHS.dll, tolak unload
    if (hLibModule == g_hModule) {
        return FALSE;
    }
    // otherwise panggil fungsi asli
    return TrueFreeLibrary(hLibModule);
}

BOOL WINAPI HookedFreeLibraryEx(HMODULE hLibModule, DWORD dwFlags) {
    if (hLibModule == g_hModule) {
        return FALSE;
    }
    return TrueFreeLibraryEx(hLibModule, dwFlags);
}

static bool hook_function(LPCSTR name, LPVOID hookFunc, LPVOID* origFunc) {
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return false;
    BYTE* pFunc = (BYTE*)GetProcAddress(hKernel, name);
    if (!pFunc) return false;

    DWORD old;
    // ubah protection
    if (!VirtualProtect(pFunc, 16, PAGE_EXECUTE_READWRITE, &old)) return false;

    // save original pointer
    *origFunc = pFunc;

    // tulis JMP relatif: jump from pFunc to hookFunc
    intptr_t rel = (BYTE*)hookFunc - pFunc - 5;
    pFunc[0] = 0xE9;                                // opcode JMP
    *reinterpret_cast<int32_t*>(pFunc + 1) = (int32_t)rel;
    // isi sisa dengan NOP
    memset(pFunc + 5, 0x90, 11);

    // kembalikan protection
    VirtualProtect(pFunc, 16, old, &old);
    return true;
}

void init_unload_protect(HMODULE hModule) {
    g_hModule = hModule;

    // setup hook
    hook_function("FreeLibrary", (LPVOID)HookedFreeLibrary, (LPVOID*)&TrueFreeLibrary);
    hook_function("FreeLibraryEx", (LPVOID)HookedFreeLibraryEx, (LPVOID*)&TrueFreeLibraryEx);
}
