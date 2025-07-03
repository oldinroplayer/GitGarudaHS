#include "pch.h"
#include "../include/AntiDebugChecker.h"
#include "../include/Utils.h"
#include <windows.h>
#include <iostream>

// logging dari dllmain
extern void LogToServer(const std::string& msg);
extern void TerminateRRO();

using namespace GarudaHS;

// ————————————————
// Definisi tipe NT yang dibutuhkan:
using NTSTATUS = LONG;
using PULONG = ULONG*;
// Kelas informasi proses untuk debug port
constexpr DWORD ProcessDebugPort = 7;
// ————————————————

void AntiDebugChecker::Initialize() {
    LogToServer("[AntiDebug] Module loaded\n");
}

bool IsDebuggerAttached_NtQuery() {
    // pointer ke NtQueryInformationProcess
    using NtQueryInformationProcessPtr =
        NTSTATUS(WINAPI*)(HANDLE, DWORD, PVOID, ULONG, PULONG);

    auto hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    auto NtQueryInfo = reinterpret_cast<NtQueryInformationProcessPtr>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInfo) return false;

    DWORD debugPort = 0;
    NTSTATUS status = NtQueryInfo(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        nullptr
    );

    return (status == 0 && debugPort != 0);
}

void AntiDebugChecker::Tick() {
    bool detected = false;

    if (IsDebuggerPresent()) {
        LogToServer("[AntiDebug] IsDebuggerPresent triggered!\n");
        detected = true;
    }

    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        LogToServer("[AntiDebug] RemoteDebugger detected!\n");
        detected = true;
    }

    if (IsDebuggerAttached_NtQuery()) {
        LogToServer("[AntiDebug] NtQueryInformationProcess detected!\n");
        detected = true;
    }

    if (detected) {
        LogToServer("[AntiDebug] >>> DEBUGGER DETECTED, killing RRO.exe\n");
        TerminateRRO();
    }
}