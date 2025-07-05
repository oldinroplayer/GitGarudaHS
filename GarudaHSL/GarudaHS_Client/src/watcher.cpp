#include "watcher.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include "threadwatch.h"
#include "windowwatch.h"

std::vector<std::wstring> proses_cheat = {
    L"cheatengine.exe",
    L"cheatengine-x86_64.exe",
    L"openkore.exe",
    L"wpe.exe",
    L"rpe.exe"
};

bool proses_ada(const std::wstring& nama_proses) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (nama_proses == pe.szExeFile) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}


void cek_proses_cheat() {
    for (const auto& proses : proses_cheat) {
        if (proses_ada(proses)) {
            MessageBoxW(NULL, (L"Deteksi Cheat: " + proses).c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
            system("taskkill /IM RRO.exe /F");
        }
    }

    cek_thread_mencurigakan(); //  panggil di akhir scan
    cek_jendela_cheat(); //  panggil window scan
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
