#include "threadwatch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>

bool modul_dari_thread_bukan_RRO(DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
    if (!hThread) return false;

    HMODULE hMod = NULL;
    DWORD hModSize;
    DWORD pid = GetCurrentProcessId();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        CloseHandle(hThread);
        return false;
    }

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &hModSize)) {
        TCHAR modName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hMod, modName, sizeof(modName) / sizeof(TCHAR))) {
            std::wstring nama(modName);
            if (nama.find(L"cheatengine") != std::wstring::npos ||
                nama.find(L"rpe") != std::wstring::npos ||
                nama.find(L"wpe") != std::wstring::npos) {
                CloseHandle(hProcess);
                CloseHandle(hThread);
                return true;
            }
        }
    }

    CloseHandle(hProcess);
    CloseHandle(hThread);
    return false;
}

void cek_thread_mencurigakan() {
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                if (modul_dari_thread_bukan_RRO(te32.th32ThreadID)) {
                    MessageBoxW(NULL, L"Thread mencurigakan terdeteksi", L"GarudaHS", MB_ICONERROR);
                    system("taskkill /IM RRO.exe /F");
                }
            }
        } while (Thread32Next(hSnap, &te32));
    }

    CloseHandle(hSnap);
}
