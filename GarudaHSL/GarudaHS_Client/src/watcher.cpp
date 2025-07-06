#include "watcher.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <algorithm>
#include "threadwatch.h"
#include "windowwatch.h"
#include "overlaywatch.h"
#include "whitelist.h"
#include "netclient.h"
#include "memscan.h"

static std::vector<std::wstring> proses_cheat = {
    L"cheatengine.exe",
    L"cheatengine-x86_64.exe",
    L"openkore.exe",
    L"wpe.exe",
    L"rpe.exe"
};

// Process cache untuk mengurangi overhead
struct ProcessInfo {
    std::wstring name;
    DWORD pid;
    FILETIME creation_time;
    bool is_suspicious;
};

static std::vector<ProcessInfo> process_cache;
static DWORD last_cache_update = 0;
static const DWORD CACHE_VALIDITY_MS = 5000; // 5 seconds cache

bool update_process_cache() {
    DWORD current_time = GetTickCount();
    if (current_time - last_cache_update < CACHE_VALIDITY_MS && !process_cache.empty()) {
        return true; // Cache still valid
    }

    process_cache.clear();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            ProcessInfo info;
            info.name = pe.szExeFile;
            info.pid = pe.th32ProcessID;

            // Convert to lowercase for case-insensitive comparison
            std::transform(info.name.begin(), info.name.end(), info.name.begin(), ::tolower);

            // Pre-check if suspicious
            info.is_suspicious = false;
            for (const auto& cheat_process : proses_cheat) {
                std::wstring lower_cheat = cheat_process;
                std::transform(lower_cheat.begin(), lower_cheat.end(), lower_cheat.begin(), ::tolower);
                if (info.name == lower_cheat) {
                    info.is_suspicious = true;
                    break;
                }
            }

            process_cache.push_back(info);
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    last_cache_update = current_time;
    return true;
}

bool proses_ada(const std::wstring& nama_proses) {
    if (!update_process_cache()) return false;

    std::wstring lower_name = nama_proses;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    for (const auto& process : process_cache) {
        if (process.name == lower_name) {
            return true;
        }
    }
    return false;
}

// Optimized function to get all suspicious processes at once
std::vector<std::wstring> get_suspicious_processes() {
    std::vector<std::wstring> suspicious;
    if (!update_process_cache()) return suspicious;

    for (const auto& process : process_cache) {
        if (process.is_suspicious) {
            suspicious.push_back(process.name);
        }
    }
    return suspicious;
}


// Scan cycle counter untuk intelligent scheduling
static int scan_cycle = 0;
static DWORD last_full_scan = 0;

void cek_proses_cheat() {
    scan_cycle++;
    DWORD current_time = GetTickCount();

    // Always check for suspicious processes (lightweight)
    auto suspicious_processes = get_suspicious_processes();
    if (!suspicious_processes.empty()) {
        for (const auto& proses : suspicious_processes) {
            std::wstring laporan = L"CHEAT TERDETEKSI: " + proses;
            std::wcout << L"[DETECTION] Suspicious process found: " << proses << std::endl;
            kirim_laporan_ke_server(laporan);
            MessageBoxW(NULL, laporan.c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
            system("taskkill /IM RRO.exe /F");
            return; // Exit early if cheat found
        }
    }

    // Intelligent scheduling of heavy operations
    bool should_run_heavy_scan = (current_time - last_full_scan > 15000); // 15 seconds

    // Rotate different types of scans to distribute load
    switch (scan_cycle % 4) {
        case 0:
            // Light scan: Only process and basic checks
            std::wcout << L"[SCAN] Light scan cycle" << std::endl;
            break;

        case 1:
            // Thread monitoring
            std::wcout << L"[SCAN] Thread monitoring cycle" << std::endl;
            cek_thread_mencurigakan();
            break;

        case 2:
            // Window and overlay checking
            std::wcout << L"[SCAN] Window/overlay monitoring cycle" << std::endl;
            cek_jendela_cheat();
            cek_overlay_cheat();
            break;

        case 3:
            // Memory signature scanning (most expensive)
            if (should_run_heavy_scan) {
                std::wcout << L"[SCAN] Memory signature scan cycle" << std::endl;
                scan_signature_cheat();
                last_full_scan = current_time;
            } else {
                std::wcout << L"[SCAN] Skipping memory scan (too soon)" << std::endl;
            }
            break;
    }
}


DWORD WINAPI MulaiPemantauan(LPVOID lpParam) {
    while (true) {
        cek_proses_cheat();
        Sleep(3000);
    }
    return 0;
}

// Fungsi yang bisa dipanggil secara manual setelah di-export
extern "C" __declspec(dllexport) void StartGarudaHS() {
    CreateThread(nullptr, 0, MulaiPemantauan, nullptr, 0, nullptr);
}
