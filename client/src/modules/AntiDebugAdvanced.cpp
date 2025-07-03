#include "pch.h"
#include "../include/AntiDebugAdvanced.h"
#include "pch.h"
#include "../include/AntiDebugAdvanced.h"
#include "../include/Utils.h"
#include <windows.h>
#include <dbghelp.h>      // untuk RtlCaptureContext, bila perlu
#include <iostream>

// logging dari dllmain
extern void LogToServer(const std::string& msg);
extern void TerminateRRO();

using namespace GarudaHS;

// -------------------------------------
// 1) TLS Callback
//    akan dieksekusi oleh loader sebelum DllMain
// -------------------------------------
// **Baris #pragma INCLUDE dihapus di sini**
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_cb = [](PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        LogToServer("[AntiDebugAdv] TLS_CALLBACK: process attach\n");
    }
    };
#pragma const_seg()

// -------------------------------------
// 2) SEH Trap: memancing exception INT 3
//    Debugger biasanya menyambut INT3; kita tangkap
// -------------------------------------
static LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        LogToServer("[AntiDebugAdv] SEH Trap: breakpoint exception caught\n");
        // jika ingin terminate:
        TerminateRRO();
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// -------------------------------------
// Inisialisasi advanced anti?debug
// -------------------------------------
void AntiDebugAdvanced::Initialize() {
    LogToServer("[AntiDebugAdv] Initializing advanced anti?debug\n");
    // pasang vectored exception handler
    AddVectoredExceptionHandler(1, VectoredHandler);
}

// -------------------------------------
// Tick() memancing INT3
// -------------------------------------
void AntiDebugAdvanced::Tick() {
    __try {
        // INT 3 instruction: 0xCC
        __asm { int 3 }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // exception sudah tertangani di VectoredHandler
    }
}
