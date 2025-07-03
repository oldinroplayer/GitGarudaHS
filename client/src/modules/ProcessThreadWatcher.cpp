#include "pch.h"
#include "../include/ProcessThreadWatcher.h"
#include "../include/Utils.h" // <-- Tambahkan ini
#include <tlhelp32.h>
#include <iostream>
#include <algorithm>

// deklarasi helper logging
extern void LogToServer(const std::string& msg);
extern std::string Narrow(const std::wstring& ws);

using namespace GarudaHS;

std::vector<ProcInfo> ProcessThreadWatcher::knownProcs;

static const std::vector<std::wstring> cheatProcessNames = {
    L"cheatengine.exe",
    L"cheatengine-x86_64.exe",
    L"openkore.exe",
    L"wpe.exe",
    L"rpe.exe"
};

void ProcessThreadWatcher::Initialize() {
    knownProcs = EnumerateProcesses();
    LogToServer("[PTW] Initialized: " +
        std::to_string(knownProcs.size()) +
        "\n");
}

void ProcessThreadWatcher::Tick() {
    auto current = EnumerateProcesses();
    for (auto& pi : current) {
        bool found = false;
        for (auto& old : knownProcs) {
            if (old.pid == pi.pid) { found = true; break; }
        }
        if (!found) OnNewProcess(pi);
    }
    knownProcs = std::move(current);
}

std::vector<ProcInfo> ProcessThreadWatcher::EnumerateProcesses() {
    std::vector<ProcInfo> list;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            list.push_back({ pe.th32ProcessID, pe.szExeFile });
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return list;
}

void TerminateRRO() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"RRO.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 1);
                    CloseHandle(hProc);
                    LogToServer("[PTW] Terminated RRO.exe due to cheat detection\n");
                }
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void ProcessThreadWatcher::OnNewProcess(const ProcInfo& pi) {
    for (const auto& cheat : cheatProcessNames) {
        if (ContainsIgnoreCase(pi.exeName, cheat)) {
            LogToServer("[PTW] Detected cheat process: " +
                Narrow(pi.exeName) +
                " (PID=" + std::to_string(pi.pid) + ")\n");

            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pi.pid);
            if (hProc != NULL) {
                if (TerminateProcess(hProc, 1)) {
                    LogToServer("[PTW] Terminated cheat process: " +
                        Narrow(pi.exeName) + "\n");
                }
                else {
                    LogToServer("[PTW] Failed to terminate cheat process\n");
                }
                CloseHandle(hProc);
            }

            // Terminate RRO.exe langsung juga
            TerminateRRO();

            break;
        }
    }
}
