#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

// Definisi tipe untuk fungsi NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

namespace GarudaHS
{
    // Enum untuk jenis teknik anti-debug
    enum class AntiDebugTechnique
    {
        IS_DEBUGGER_PRESENT,
        NT_QUERY_INFORMATION_PROCESS,
        DEBUG_PORT,
        PROCESS_DEBUG_FLAGS,
        PROCESS_DEBUG_OBJECT_HANDLE,
        SYSTEM_KERNEL_DEBUGGER_INFORMATION,
        DEBUG_REGISTERS,
        HARDWARE_BREAKPOINTS,
        TIMING_CHECK,
        EXCEPTION_HANDLING,
        THREAD_HIDE_FROM_DEBUGGER
    };

    // Struktur untuk menyimpan hasil deteksi debugger
    struct DebuggerDetection
    {
        AntiDebugTechnique technique;
        bool detected;
        std::string details;
    };

    // Kelas untuk mendeteksi dan mencegah debugger
    class AntiDebug : public IAntiCheatModule
    {
    public:
        AntiDebug();
        ~AntiDebug();

        // Implementasi dari IAntiCheatModule
        bool Initialize() override;
        bool Scan() override;
        void Shutdown() override;
        const char* GetName() const override;

        // Fungsi untuk memeriksa keberadaan debugger
        bool IsDebuggerPresent();
        bool CheckNtQueryInformationProcess();
        bool CheckDebugPort();
        bool CheckProcessDebugFlags();
        bool CheckProcessDebugObjectHandle();
        bool CheckSystemKernelDebuggerInformation();
        bool CheckDebugRegisters();
        bool CheckHardwareBreakpoints();
        bool CheckTimingAnomaly();
        bool CheckExceptionHandling();
        bool SetThreadHideFromDebugger();

        // Fungsi untuk mendapatkan semua hasil deteksi
        std::vector<DebuggerDetection> GetDetectionResults();

    private:
        // Thread untuk memantau debugger secara periodik
        std::thread m_debuggerThread;
        std::atomic<bool> m_isRunning;
        std::mutex m_mutex;

        // Hasil deteksi terakhir
        std::vector<DebuggerDetection> m_detectionResults;

        // Handle ke ntdll.dll
        HMODULE m_hNtdll;
        pfnNtQueryInformationProcess m_pNtQueryInformationProcess;

        // Fungsi yang dijalankan oleh thread debugger
        void DebuggerThreadFunc();

        // Fungsi untuk menambahkan hasil deteksi
        void AddDetectionResult(AntiDebugTechnique technique, bool detected, const std::string& details);
    };
}