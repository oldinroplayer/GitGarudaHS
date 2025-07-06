#include "unloadprotect.h"
#include <cstdint>
#include <vector>
#include <mutex>
#include <random>

// Function pointer types
typedef BOOL(WINAPI* PFN_FreeLibrary)(HMODULE hLibModule);
typedef BOOL(WINAPI* PFN_FreeLibraryEx)(HMODULE hLibModule, DWORD dwFlags);

static std::mutex g_hook_mutex;
static HMODULE g_hModule = NULL;
static std::vector<BYTE> g_original_bytes;
static bool g_hooks_active = false;

// Structure untuk menyimpan informasi hook
struct HookInfo {
    LPVOID target_function;
    LPVOID hook_function;
    std::vector<BYTE> original_bytes;
    std::vector<BYTE> trampoline;
    LPVOID original_func_ptr;
    bool is_active;
};

static std::vector<HookInfo> g_hooks;

// Generate random NOP sled untuk obfuscation
std::vector<BYTE> generate_nop_sled(size_t size) {
    std::vector<BYTE> nops;
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<BYTE> nop_variants = { 0x90, 0x66, 0x67 }; // NOP variants

    for (size_t i = 0; i < size; ++i) {
        nops.push_back(nop_variants[gen() % nop_variants.size()]);
    }

    return nops;
}

// Advanced hook dengan trampoline
bool advanced_hook_function(LPCSTR name, LPVOID hookFunc, LPVOID* origFunc) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) return false;

    BYTE* pFunc = (BYTE*)GetProcAddress(hKernel, name);
    if (!pFunc) return false;

    // Validate function pointer
    if (IsBadCodePtr((FARPROC)pFunc)) return false;

    HookInfo hookInfo;
    hookInfo.target_function = pFunc;
    hookInfo.hook_function = hookFunc;

    // Save original bytes (extended untuk trampoline)
    hookInfo.original_bytes.resize(32);
    memcpy(hookInfo.original_bytes.data(), pFunc, 32);

    // Create trampoline
    hookInfo.trampoline.resize(64);
    memcpy(hookInfo.trampoline.data(), pFunc, 32);

    // Add JMP back to original function + 32
    BYTE* trampoline_end = hookInfo.trampoline.data() + 32;
    trampoline_end[0] = 0xE9; // JMP
    intptr_t rel = (pFunc + 32) - (trampoline_end + 5);
    *reinterpret_cast<int32_t*>(trampoline_end + 1) = (int32_t)rel;

    // Make trampoline executable
    DWORD old_protect;
    if (!VirtualProtect(hookInfo.trampoline.data(), 64, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    // Set original function pointer ke trampoline
    hookInfo.original_func_ptr = hookInfo.trampoline.data();
    *origFunc = hookInfo.original_func_ptr;

    // Install hook dengan random padding
    if (!VirtualProtect(pFunc, 32, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    // Install JMP ke hook function
    intptr_t hook_rel = (BYTE*)hookFunc - pFunc - 5;
    pFunc[0] = 0xE9;
    *reinterpret_cast<int32_t*>(pFunc + 1) = (int32_t)hook_rel;

    // Fill dengan random NOPs
    auto nops = generate_nop_sled(27);
    memcpy(pFunc + 5, nops.data(), 27);

    // Restore protection
    VirtualProtect(pFunc, 32, old_protect, &old_protect);

    hookInfo.is_active = true;
    g_hooks.push_back(hookInfo);

    return true;
}

// Hooked functions dengan tambahan validation
BOOL WINAPI HookedFreeLibrary(HMODULE hLibModule) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);

    if (!g_hooks_active) return FALSE;

    // Validasi module handle
    if (!hLibModule || IsBadCodePtr((FARPROC)hLibModule)) {
        return FALSE;
    }

    // Jika target GarudaHS.dll, tolak unload
    if (hLibModule == g_hModule) {
        // Log attempt
        OutputDebugStringA("Attempt to unload GarudaHS blocked");
        return FALSE;
    }

    // Call original via trampoline
    if (g_hooks.size() > 0 && g_hooks[0].original_func_ptr) {
        return ((PFN_FreeLibrary)g_hooks[0].original_func_ptr)(hLibModule);
    }

    return FALSE;
}

BOOL WINAPI HookedFreeLibraryEx(HMODULE hLibModule, DWORD dwFlags) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);

    if (!g_hooks_active) return FALSE;

    if (!hLibModule || IsBadCodePtr((FARPROC)hLibModule)) {
        return FALSE;
    }

    if (hLibModule == g_hModule) {
        OutputDebugStringA("Attempt to unload GarudaHS (Ex) blocked");
        return FALSE;
    }

    // Call original via trampoline
    if (g_hooks.size() > 1 && g_hooks[1].original_func_ptr) {
        return ((PFN_FreeLibraryEx)g_hooks[1].original_func_ptr)(hLibModule, dwFlags);
    }

    return FALSE;
}

void init_unload_protect(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(g_hook_mutex);

    g_hModule = hModule;
    g_hooks_active = true;

    // Reserve space for hooks
    g_hooks.reserve(2);

    // Setup hooks dengan error handling
    LPVOID original_freelibrary = nullptr;
    if (advanced_hook_function("FreeLibrary", (LPVOID)HookedFreeLibrary, &original_freelibrary)) {
        OutputDebugStringA("FreeLibrary hook installed successfully");
    }
    else {
        OutputDebugStringA("Failed to hook FreeLibrary");
    }

    LPVOID original_freelibraryex = nullptr;
    if (advanced_hook_function("FreeLibraryEx", (LPVOID)HookedFreeLibraryEx, &original_freelibraryex)) {
        OutputDebugStringA("FreeLibraryEx hook installed successfully");
    }
    else {
        OutputDebugStringA("Failed to hook FreeLibraryEx");
    }
}

void cleanup_unload_protect() {
    std::lock_guard<std::mutex> lock(g_hook_mutex);

    g_hooks_active = false;

    // Restore original functions
    for (auto& hook : g_hooks) {
        if (hook.is_active) {
            DWORD old_protect;
            VirtualProtect(hook.target_function, 32, PAGE_EXECUTE_READWRITE, &old_protect);
            memcpy(hook.target_function, hook.original_bytes.data(), 32);
            VirtualProtect(hook.target_function, 32, old_protect, &old_protect);
        }
    }

    g_hooks.clear();
}