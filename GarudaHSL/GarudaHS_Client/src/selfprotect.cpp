#include "selfprotect.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <thread>
#include <iostream>

// Daftar proses pembunuh yang ingin dicegah
std::vector<std::wstring> pembunuh_dilarang = {
    L"taskmgr.exe",
    L"processhacker.exe",
    L"procexp.exe",
    L"cheatengine.exe",
    L"reclass.net.exe",
    L"rweverything.exe"
};

bool cari_proses_berbahaya() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            std::wstring nama(pe.szExeFile);
            for (const auto& berbahaya : pembunuh_dilarang) {
                if (_wcsicmp(nama.c_str(), berbahaya.c_str()) == 0) {
                    CloseHandle(hSnap);
                    return true;
                }
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return false;
}

void thread_self_protect() {
    while (true) {
        if (cari_proses_berbahaya()) {
            MessageBoxW(NULL, L"Deteksi usaha pembunuhan anti-cheat!", L"GarudaHS", MB_OK | MB_ICONERROR);
            system("taskkill /IM RRO.exe /F");
        }
        Sleep(3000);
    }
}

void mulai_self_protect() {
    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)thread_self_protect, nullptr, 0, nullptr);
}
