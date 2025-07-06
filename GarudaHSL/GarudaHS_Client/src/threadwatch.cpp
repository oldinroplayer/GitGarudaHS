#include "threadwatch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

// Thread monitoring cache and state
struct ThreadInfo {
    DWORD thread_id;
    DWORD creation_time;
    bool is_suspicious;
    std::wstring module_name;
};

static std::vector<ThreadInfo> thread_cache;
static DWORD last_thread_scan = 0;
static const DWORD THREAD_SCAN_INTERVAL = 10000; // 10 seconds

bool is_suspicious_module(const std::wstring& module_path) {
    std::wstring lower_path = module_path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);

    // Known cheat engine patterns
    static const std::vector<std::wstring> suspicious_patterns = {
        L"cheatengine", L"ce.exe", L"rpe", L"wpe", L"speedhack",
        L"gamehack", L"trainer", L"injector", L"hook",
        L"bypass", L"crack", L"patch"
    };

    for (const auto& pattern : suspicious_patterns) {
        if (lower_path.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool analyze_thread_modules(DWORD threadId) {
    // This is a simplified check - in reality, determining which module
    // a thread belongs to is complex and may not be reliable
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    bool is_suspicious = false;
    HMODULE hMods[1024];
    DWORD cbNeeded;

    // Enumerate all modules in the process
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);

        for (DWORD i = 0; i < moduleCount; i++) {
            TCHAR modName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], modName, sizeof(modName) / sizeof(TCHAR))) {
                if (is_suspicious_module(modName)) {
                    std::wcout << L"[THREAD] Suspicious module detected: " << modName << std::endl;
                    is_suspicious = true;
                    break;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return is_suspicious;
}

bool modul_dari_thread_bukan_RRO(DWORD threadId) {
    // Use cached results if available and recent
    DWORD current_time = GetTickCount();

    for (const auto& thread_info : thread_cache) {
        if (thread_info.thread_id == threadId) {
            return thread_info.is_suspicious;
        }
    }

    // If not in cache or cache is old, perform analysis
    bool is_suspicious = analyze_thread_modules(threadId);

    // Cache the result
    ThreadInfo info;
    info.thread_id = threadId;
    info.creation_time = current_time;
    info.is_suspicious = is_suspicious;
    thread_cache.push_back(info);

    // Limit cache size
    if (thread_cache.size() > 100) {
        thread_cache.erase(thread_cache.begin());
    }

    return is_suspicious;
}

void cek_thread_mencurigakan() {
    DWORD current_time = GetTickCount();

    // Throttle thread scanning to reduce performance impact
    if (current_time - last_thread_scan < THREAD_SCAN_INTERVAL) {
        return;
    }

    std::wcout << L"[THREAD] Starting thread monitoring scan" << std::endl;

    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcout << L"[THREAD] Failed to create thread snapshot" << std::endl;
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    int suspicious_thread_count = 0;
    int total_threads = 0;

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                total_threads++;

                // Only check threads that are not system threads
                if (te32.th32ThreadID != GetCurrentThreadId()) {
                    if (modul_dari_thread_bukan_RRO(te32.th32ThreadID)) {
                        suspicious_thread_count++;
                        std::wcout << L"[THREAD] Suspicious thread detected: " << te32.th32ThreadID << std::endl;
                    }
                }
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
    last_thread_scan = current_time;

    std::wcout << L"[THREAD] Scan complete. Total threads: " << total_threads
               << L", Suspicious: " << suspicious_thread_count << std::endl;

    // Only take action if multiple suspicious threads detected
    // This reduces false positives from legitimate injected DLLs
    if (suspicious_thread_count >= 2) {
        std::wstring message = L"Multiple suspicious threads detected (" +
                              std::to_wstring(suspicious_thread_count) + L")";
        std::wcout << L"[ACTION] " << message << std::endl;

        MessageBoxW(NULL, message.c_str(), L"GarudaHS - Thread Detection", MB_ICONERROR);
        system("taskkill /IM RRO.exe /F");
    } else if (suspicious_thread_count == 1) {
        std::wcout << L"[WARNING] Single suspicious thread detected, monitoring..." << std::endl;
    }
}
