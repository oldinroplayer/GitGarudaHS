#include "memscan.h"
#include "netclient.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <iostream>

bool cari_signature(const BYTE* data, SIZE_T size, const std::vector<BYTE>& pattern) {
    for (SIZE_T i = 0; i < size - pattern.size(); ++i) {
        bool match = true;
        for (SIZE_T j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != 0xCC && data[i + j] != pattern[j]) { // 0xCC = wildcard
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

void scan_signature_cheat() {
    HANDLE hProcess = GetCurrentProcess();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;

    // Contoh: pattern byte khas Cheat Engine (bisa kamu kembangkan sendiri)
    std::vector<BYTE> cheat_signature = {
        0x43, 0x68, 0x65, 0x61, 0x74, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65 // "Cheat Engine"
    };

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    if (cari_signature(buffer.data(), bytesRead, cheat_signature)) {
                        std::wstring laporan = L"CHEAT SIGNATURE TERDETEKSI DI MEMORY!";
                        kirim_laporan_ke_server(laporan);
                        MessageBoxW(NULL, laporan.c_str(), L"GarudaHS", MB_OK | MB_ICONERROR);
                        system("taskkill /IM RRO.exe /F");
                        return;
                    }
                }
            }
            addr += mbi.RegionSize;
        }
    }
}
