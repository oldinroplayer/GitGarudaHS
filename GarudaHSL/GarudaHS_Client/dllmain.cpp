#include <windows.h>
#include <thread>
#include "watcher.h"
#include "selfprotect.h"  //  Tambahkan header ini
#include "memprotect.h"

DWORD WINAPI MulaiThread(LPVOID lpParam) {
    while (true) {
        cek_proses_cheat();
        Sleep(3000); // Scan tiap 3 detik
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, MulaiThread, nullptr, 0, nullptr);
        mulai_self_protect(); // Tambahkan pemanggilan thread proteksi
		mulai_self_protect(); // Proteksi memori DLL
    }
    return TRUE;
}
