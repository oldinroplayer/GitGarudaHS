#include "memscan.h"
#include "memprotect.h"
#include "netclient.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <set>
#include <algorithm>
#include <shlwapi.h>
#include <winternl.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

// Typedef untuk fungsi NtQuerySystemInformation
typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Whitelist proses yang diizinkan
static const std::vector<ProcessWhitelist> PROCESS_WHITELIST = {
    {L"devenv.exe", L"Microsoft Corporation", L"Visual Studio"},
    {L"Code.exe", L"Microsoft Corporation", L"Visual Studio Code"},
    {L"chrome.exe", L"Google LLC", L"Google Chrome"},
    {L"firefox.exe", L"Mozilla Corporation", L"Firefox"},
    {L"edge.exe", L"Microsoft Corporation", L"Microsoft Edge"},
    {L"explorer.exe", L"Microsoft Corporation", L"Windows Explorer"},
    {L"taskmgr.exe", L"Microsoft Corporation", L"Task Manager"},
    {L"procmon.exe", L"Microsoft Corporation", L"Process Monitor"},
    {L"perfmon.exe", L"Microsoft Corporation", L"Performance Monitor"},
    {L"windbg.exe", L"Microsoft Corporation", L"Windows Debugger"},
    {L"ida64.exe", L"Hex-Rays SA", L"IDA Pro"}, // Legitimate reverse engineering
    {L"x64dbg.exe", L"", L"x64dbg"}, // Legitimate debugger
};

// Signature yang lebih spesifik dan akurat
static const std::vector<CheatSignature> CHEAT_SIGNATURES = {
    // Cheat Engine dengan context verification yang lebih ketat
    {
        {0x43, 0x68, 0x65, 0x61, 0x74, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65}, // "Cheat Engine"
        "CheatEngine_String",
        80, // Tingkatkan confidence weight
        true
    },
    // Cheat Engine executable signature dengan verifikasi tambahan
    {
        {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
        "CheatEngine_PE",
        90, // Tingkatkan confidence weight
        true
    },
    // Memory modification patterns yang lebih spesifik
    {
        {0x89, 0x15, 0xCC, 0xCC, 0xCC, 0xCC, 0xC7, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x90, 0x90}, // MOV pattern dengan NOP padding
        "Memory_Modification",
        60, // Kurangi confidence weight
        true
    },
    // DLL injection patterns yang lebih spesifik
    {
        {0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0x15, 0xCC, 0xCC, 0xCC, 0xCC}, // PUSH/CALL pattern dengan context
        "DLL_Injection",
        70, // Kurangi confidence weight
        true
    },
    // Speed hack patterns yang lebih spesifik
    {
        {0xF3, 0x0F, 0x11, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0xF3, 0x0F, 0x10, 0x05, 0xCC, 0xCC, 0xCC, 0xCC}, // SSE speed manipulation dengan context
        "Speed_Hack",
        75, // Kurangi confidence weight
        true
    },
    // Tambahkan signature untuk cheat tools yang lebih spesifik
    {
        {0x4F, 0x70, 0x65, 0x6E, 0x4B, 0x6F, 0x72, 0x65}, // "OpenKore"
        "OpenKore_String",
        85,
        true
    },
    {
        {0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x50, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x20, 0x45, 0x64, 0x69, 0x74, 0x6F, 0x72}, // "Windows Packet Editor"
        "WPE_String",
        85,
        true
    }
};

// Daftar region memory yang aman untuk diabaikan
static const std::set<std::wstring> SAFE_MEMORY_REGIONS = {
    L"ntdll.dll",
    L"kernel32.dll",
    L"user32.dll",
    L"gdi32.dll",
    L"advapi32.dll",
    L"msvcrt.dll",
    L"ole32.dll",
    L"shell32.dll",
    L"wininet.dll",
    L"ws2_32.dll"
};

bool advanced_signature_search(const BYTE* data, SIZE_T size, const CheatSignature& signature) {
    if (size < signature.pattern.size()) return false;

    for (SIZE_T i = 0; i <= size - signature.pattern.size(); ++i) {
        bool match = true;
        for (SIZE_T j = 0; j < signature.pattern.size(); ++j) {
            if (signature.pattern[j] != 0xCC && data[i + j] != signature.pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            // Jika signature membutuhkan context verification
            if (signature.require_context) {
                return verify_cheat_context(data, size, i);
            }
            return true;
        }
    }
    return false;
}

bool verify_cheat_context(const BYTE* data, SIZE_T size, SIZE_T found_offset) {
    // Verifikasi context di sekitar signature yang ditemukan
    const SIZE_T context_size = 512; // Perbesar context window
    SIZE_T start = (found_offset > context_size) ? found_offset - context_size : 0;
    SIZE_T end = (found_offset + context_size < size) ? found_offset + context_size : size;

    // Cek apakah ada indicator legitimate yang menunjukkan false positive
    std::vector<BYTE> pe_header = { 0x4D, 0x5A }; // MZ header
    std::vector<BYTE> dll_pattern = { 0x44, 0x4C, 0x4C }; // "DLL"
    std::vector<BYTE> exe_pattern = { 0x45, 0x58, 0x45 }; // "EXE"
    
    // Tambahan pattern untuk legitimate software
    std::vector<BYTE> microsoft_pattern = { 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74 }; // "Microsoft"
    std::vector<BYTE> windows_pattern = { 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73 }; // "Windows"

    // Cari dalam context window
    for (SIZE_T i = start; i < end - 8; ++i) {
        // Jika ditemukan dalam context PE header, kemungkinan false positive
        if (data[i] == pe_header[0] && data[i + 1] == pe_header[1]) {
            // Cek apakah ini bagian dari legitimate executable
            SIZE_T pe_offset = i;
            if (pe_offset + 64 < size) {
                DWORD pe_signature_offset = *(DWORD*)(data + pe_offset + 60);
                if (pe_signature_offset < size - 4) {
                    DWORD pe_signature = *(DWORD*)(data + pe_offset + pe_signature_offset);
                    if (pe_signature == 0x00004550) { // "PE\0\0"
                        return false; // Legitimate PE file
                    }
                }
            }
        }
        
        // Cek untuk Microsoft/Windows patterns yang menunjukkan legitimate software
        if (i + 8 < end) {
            bool is_microsoft = true;
            for (size_t j = 0; j < microsoft_pattern.size(); ++j) {
                if (data[i + j] != microsoft_pattern[j]) {
                    is_microsoft = false;
                    break;
                }
            }
            if (is_microsoft) {
                return false; // Kemungkinan legitimate Microsoft software
            }
        }
        
        if (i + 6 < end) {
            bool is_windows = true;
            for (size_t j = 0; j < windows_pattern.size(); ++j) {
                if (data[i + j] != windows_pattern[j]) {
                    is_windows = false;
                    break;
                }
            }
            if (is_windows) {
                return false; // Kemungkinan legitimate Windows component
            }
        }
    }

    // Cek apakah signature ditemukan di area yang mencurigakan
    // Tambahan verifikasi: cek apakah ada pattern cheat yang berulang
    int cheat_pattern_count = 0;
    for (const auto& signature : CHEAT_SIGNATURES) {
        if (advanced_signature_search(data, size, signature)) {
            cheat_pattern_count++;
        }
    }
    
    // Jika hanya 1 pattern yang ditemukan, kemungkinan false positive
    if (cheat_pattern_count <= 1) {
        return false;
    }

    return true; // Context menunjukkan kemungkinan cheat
}

bool is_process_whitelisted(const std::wstring& process_name) {
    std::wstring lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

    for (const auto& whitelist : PROCESS_WHITELIST) {
        std::wstring lower_whitelist = whitelist.process_name;
        std::transform(lower_whitelist.begin(), lower_whitelist.end(), lower_whitelist.begin(), ::towlower);

        if (lower_name == lower_whitelist) {
            return true;
        }
    }
    return false;
}



bool is_memory_region_safe(const MEMORY_BASIC_INFORMATION& mbi) {
    // Skip memory regions yang kemungkinan mengandung false positive

    // Skip memory yang tidak executable dan tidak writable
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE))) {
        return true; // Safe to skip
    }

    // Skip memory regions yang terlalu kecil
    if (mbi.RegionSize < 8192) { // Tingkatkan minimum size ke 8KB
        return true; // Safe to skip
    }

    // Skip memory regions yang terlalu besar (kemungkinan legitimate)
    if (mbi.RegionSize > 104857600) { // Skip regions > 100MB
        return true;
    }

    // Skip memory yang hanya readable (kemungkinan legitimate data)
    if (mbi.Protect == PAGE_READONLY) {
        return true;
    }

    // Skip memory yang merupakan image (executable files)
    if (mbi.Type == MEM_IMAGE) {
        return true;
    }

    // Skip memory yang merupakan mapped files
    if (mbi.Type == MEM_MAPPED) {
        return true;
    }

    return false; // Not safe, perlu di-scan
}

int calculate_threat_score(const std::vector<std::string>& detected_signatures) {
    int total_score = 0;

    for (const auto& sig_name : detected_signatures) {
        for (const auto& signature : CHEAT_SIGNATURES) {
            if (signature.name == sig_name) {
                total_score += signature.confidence_weight;
                break;
            }
        }
    }

    return total_score;
}

std::vector<std::string> get_running_processes() {
    std::vector<std::string> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            // Convert wide string to string
            int size = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            std::string process_name(size, 0);
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, &process_name[0], size, nullptr, nullptr);
            process_name.pop_back(); // Remove null terminator

            processes.push_back(process_name);
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return processes;
}

void scan_signature_cheat() {
    // Cek apakah dalam development environment
    if (is_development_environment()) {
        std::wcout << L"[DEBUG] Development environment detected, skipping scan" << std::endl;
        return;
    }

    HANDLE hProcess = GetCurrentProcess();
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = 0;

    std::vector<std::string> detected_signatures;
    int scan_count = 0;
    int skip_count = 0;
    int consecutive_detections = 0; // Tambahkan counter untuk deteksi berturut-turut

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                // Cek apakah region ini aman untuk diabaikan
                if (is_memory_region_safe(mbi)) {
                    skip_count++;
                    addr += mbi.RegionSize;
                    continue;
                }

                // Hanya scan memory yang readable dan executable
                if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(hProcess, addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                        scan_count++;

                        // Scan dengan semua signature
                        for (const auto& signature : CHEAT_SIGNATURES) {
                            if (advanced_signature_search(buffer.data(), bytesRead, signature)) {
                                detected_signatures.push_back(signature.name);
                                consecutive_detections++;
                            }
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        }
        else {
            addr += 0x1000; // Skip 4KB if VirtualQuery fails
        }
    }

    // Hitung threat score
    int threat_score = calculate_threat_score(detected_signatures);

    // Threshold untuk menentukan apakah ini cheat atau false positive
    const int THREAT_THRESHOLD = 150; // Tingkatkan threshold agar tidak mudah false positive

    if (threat_score >= THREAT_THRESHOLD && consecutive_detections > 2) { // Pastikan deteksi berulang
        std::wstring laporan = L"CHEAT TERDETEKSI! Threat Score: " + std::to_wstring(threat_score);
        laporan += L"\nSignatures detected: ";

        for (const auto& sig : detected_signatures) {
            int size = MultiByteToWideChar(CP_UTF8, 0, sig.c_str(), -1, nullptr, 0);
            std::wstring wide_sig(size, 0);
            MultiByteToWideChar(CP_UTF8, 0, sig.c_str(), -1, &wide_sig[0], size);
            wide_sig.pop_back(); // Remove null terminator
            laporan += wide_sig + L", ";
        }

        kirim_laporan_ke_server(laporan);
        MessageBoxW(NULL, laporan.c_str(), L"GarudaHS - Cheat Detected", MB_OK | MB_ICONERROR);
        system("taskkill /IM RRO.exe /F");
    }
    else if (threat_score > 0) {
        // Low threat score - log saja, jangan terminate
        std::wstring log_msg = L"[WARNING] Low threat signatures detected. Score: " + std::to_wstring(threat_score);
        std::wcout << log_msg << std::endl;

        // Kirim log ke server tapi tidak terminate game
        kirim_laporan_ke_server(log_msg);
    }

    // Debug info
    std::wcout << L"[DEBUG] Scanned " << scan_count << L" regions, skipped " << skip_count << L" safe regions" << std::endl;
    std::wcout << L"[DEBUG] Total threat score: " << threat_score << std::endl;
}