#include <windows.h>
#include <thread>
#include <atomic>
#include <memory>
#include <iostream>
#include "watcher.h"
#include "selfprotect.h"
#include "memprotect.h"
#include "unloadprotect.h"
#include "whitelist.h"

// Manajemen state global
static std::atomic<bool> g_protection_active(false);
static std::atomic<bool> g_shutting_down(false);
static std::unique_ptr<MemoryProtector> g_memory_protector;
static HANDLE g_watcher_thread = nullptr;

DWORD WINAPI MulaiThread(LPVOID lpParam) {
    // Thread yang diperkuat dengan penanganan error yang lebih baik
    DWORD lastError = 0;
    int consecutiveErrors = 0;
    const int MAX_CONSECUTIVE_ERRORS = 3;

    while (g_protection_active.load() && !g_shutting_down.load()) {
        try {
            // Cek apakah kita dalam mode development
            if (is_development_environment()) {
                Sleep(10000); // Sleep lebih lama dalam development
                continue;
            }

            cek_proses_cheat();
            consecutiveErrors = 0; // Reset counter error saat berhasil

            // Sleep adaptif berdasarkan beban sistem
            DWORD sleepTime = 3000; // Default 3 detik

            // Cek performa sistem
            MEMORYSTATUSEX memStatus;
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                // Jika penggunaan memori tinggi, tingkatkan waktu sleep
                if (memStatus.dwMemoryLoad > 80) {
                    sleepTime = 5000; // 5 detik
                }
            }

            Sleep(sleepTime);
        }
        catch (...) {
            consecutiveErrors++;
            lastError = GetLastError();

            // Jika terlalu banyak error berturut-turut, hentikan thread
            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                break;
            }

            // Progressive backoff saat error
            Sleep(1000 * consecutiveErrors);
        }
    }

    return 0;
}

// Fungsi inisialisasi yang aman
bool InitializeProtection(HMODULE hModule) {
    if (g_protection_active.load()) {
        return true; // Sudah diinisialisasi
    }

    try {
        // Initialize intelligent whitelist system first
        IntelligentWhitelist::Initialize();

        // Konfigurasi proteksi berdasarkan environment
        ProtectionConfig config;

        // Deteksi jika kita dalam environment development
        if (is_development_environment()) {
            config.allowDevelopmentMode = true;
            config.enableAntiDebug = false;
            config.enableStringObfuscation = false;
            config.debugCheckInterval = 10000; // 10 detik
            enable_development_mode(true);
            std::wcout << L"[INIT] Development mode enabled" << std::endl;
        }

        // Inisialisasi proteksi memori
        g_memory_protector = std::make_unique<MemoryProtector>(hModule, config);
        if (!g_memory_protector->InitializeProtection()) {
            std::wcout << L"[ERROR] Failed to initialize memory protection" << std::endl;
            return false;
        }

        // Mulai self-protection
        g_protection_active.store(true);
        std::wcout << L"[INIT] Protection system activated" << std::endl;

        // Buat watcher thread
        g_watcher_thread = CreateThread(nullptr, 0, MulaiThread, nullptr, 0, nullptr);
        if (!g_watcher_thread) {
            g_protection_active.store(false);
            std::wcout << L"[ERROR] Failed to create watcher thread" << std::endl;
            return false;
        }

        std::wcout << L"[INIT] GarudaHS Client initialized successfully" << std::endl;
        return true;
    }
    catch (...) {
        std::wcout << L"[ERROR] Exception during initialization" << std::endl;
        return false;
    }
}

// Fungsi cleanup yang aman
void CleanupProtection() {
    std::wcout << L"[CLEANUP] Starting GarudaHS cleanup" << std::endl;
    g_shutting_down.store(true);
    g_protection_active.store(false);

    // Tunggu thread selesai
    if (g_watcher_thread) {
        WaitForSingleObject(g_watcher_thread, 5000); // Tunggu maksimal 5 detik
        CloseHandle(g_watcher_thread);
        g_watcher_thread = nullptr;
    }

    // Cleanup memory protector
    if (g_memory_protector) {
        g_memory_protector->Shutdown();
        g_memory_protector.reset();
    }

    // Cleanup proteksi memori global
    cleanup_memory_protection();

    // Cleanup whitelist system
    IntelligentWhitelist::Cleanup();

    std::wcout << L"[CLEANUP] GarudaHS cleanup completed" << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Inisialisasi proteksi saat DLL dimuat
        if (!InitializeProtection(hModule)) {
            return FALSE;
        }
        break;

    case DLL_THREAD_ATTACH:
        // Tidak perlu tindakan khusus
        break;

    case DLL_THREAD_DETACH:
        // Tidak perlu tindakan khusus
        break;

    case DLL_PROCESS_DETACH:
        // Cleanup saat DLL di-unload
        CleanupProtection();
        break;
    }
    return TRUE;
}