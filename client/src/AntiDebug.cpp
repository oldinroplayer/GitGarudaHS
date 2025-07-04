#include "../include/AntiDebug.h"
#include <iostream>
#include <chrono>
#include <intrin.h>

// Definisi struktur yang tidak tersedia di Windows.h
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Definisi konstanta yang tidak tersedia di Windows.h
#define SystemKernelDebuggerInformation 0x23
#define ProcessDebugPort 0x7
#define ProcessDebugFlags 0x1F
#define ProcessDebugObjectHandle 0x1E

namespace GarudaHS
{
    AntiDebug::AntiDebug()
        : m_isRunning(false), m_hNtdll(NULL), m_pNtQueryInformationProcess(NULL)
    {
        // Load ntdll.dll
        m_hNtdll = LoadLibraryA("ntdll.dll");
        if (m_hNtdll)
        {
            // Dapatkan alamat fungsi NtQueryInformationProcess
            m_pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(m_hNtdll, "NtQueryInformationProcess");
        }
    }

    AntiDebug::~AntiDebug()
    {
        Shutdown();
        
        // Free library
        if (m_hNtdll)
        {
            FreeLibrary(m_hNtdll);
            m_hNtdll = NULL;
        }
    }

    bool AntiDebug::Initialize()
    {
        std::cout << "Menginisialisasi Anti-Debug..." << std::endl;
        
        // Mulai thread debugger jika belum berjalan
        if (!m_isRunning)
        {
            m_isRunning = true;
            m_debuggerThread = std::thread(&AntiDebug::DebuggerThreadFunc, this);
        }
        
        return true;
    }

    bool AntiDebug::Scan()
    {
        // Reset hasil deteksi
        m_detectionResults.clear();
        
        // Jalankan semua teknik deteksi
        bool debuggerDetected = false;
        
        // 1. IsDebuggerPresent
        if (IsDebuggerPresent())
        {
            debuggerDetected = true;
        }
        
        // 2. NtQueryInformationProcess
        if (CheckNtQueryInformationProcess())
        {
            debuggerDetected = true;
        }
        
        // 3. Debug Port
        if (CheckDebugPort())
        {
            debuggerDetected = true;
        }
        
        // 4. Process Debug Flags
        if (CheckProcessDebugFlags())
        {
            debuggerDetected = true;
        }
        
        // 5. Process Debug Object Handle
        if (CheckProcessDebugObjectHandle())
        {
            debuggerDetected = true;
        }
        
        // 6. System Kernel Debugger Information
        if (CheckSystemKernelDebuggerInformation())
        {
            debuggerDetected = true;
        }
        
        // 7. Debug Registers
        if (CheckDebugRegisters())
        {
            debuggerDetected = true;
        }
        
        // 8. Hardware Breakpoints
        if (CheckHardwareBreakpoints())
        {
            debuggerDetected = true;
        }
        
        // 9. Timing Anomaly
        if (CheckTimingAnomaly())
        {
            debuggerDetected = true;
        }
        
        // 10. Exception Handling
        if (CheckExceptionHandling())
        {
            debuggerDetected = true;
        }
        
        // 11. Thread Hide From Debugger
        SetThreadHideFromDebugger();
        
        if (debuggerDetected)
        {
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::DEBUGGER_DETECTED;
            detection.details = "Terdeteksi debugger";
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            return false; // Terdeteksi debugger
        }
        
        return true; // Tidak ada debugger yang terdeteksi
    }

    void AntiDebug::Shutdown()
    {
        // Hentikan thread debugger jika sedang berjalan
        if (m_isRunning)
        {
            m_isRunning = false;
            if (m_debuggerThread.joinable())
            {
                m_debuggerThread.join();
            }
        }
    }

    const char* AntiDebug::GetName() const
    {
        return "Anti-Debug";
    }

    bool AntiDebug::IsDebuggerPresent()
    {
        bool result = ::IsDebuggerPresent();
        
        AddDetectionResult(AntiDebugTechnique::IS_DEBUGGER_PRESENT, result,
            "Deteksi menggunakan IsDebuggerPresent API");
        
        return result;
    }

    bool AntiDebug::CheckNtQueryInformationProcess()
    {
        if (!m_pNtQueryInformationProcess)
        {
            AddDetectionResult(AntiDebugTechnique::NT_QUERY_INFORMATION_PROCESS, false,
                "Gagal mendapatkan alamat fungsi NtQueryInformationProcess");
            return false;
        }
        
        DWORD isDebugged = 0;
        NTSTATUS status = m_pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessInformationClass(7), // ProcessDebugPort
            &isDebugged,
            sizeof(DWORD),
            NULL
        );
        
        bool result = (NT_SUCCESS(status) && isDebugged != 0);
        
        AddDetectionResult(AntiDebugTechnique::NT_QUERY_INFORMATION_PROCESS, result,
            "Deteksi menggunakan NtQueryInformationProcess API");
        
        return result;
    }

    bool AntiDebug::CheckDebugPort()
    {
        if (!m_pNtQueryInformationProcess)
        {
            AddDetectionResult(AntiDebugTechnique::DEBUG_PORT, false,
                "Gagal mendapatkan alamat fungsi NtQueryInformationProcess");
            return false;
        }
        
        DWORD debugPort = 0;
        NTSTATUS status = m_pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessInformationClass(ProcessDebugPort),
            &debugPort,
            sizeof(DWORD),
            NULL
        );
        
        bool result = (NT_SUCCESS(status) && debugPort != 0);
        
        AddDetectionResult(AntiDebugTechnique::DEBUG_PORT, result,
            "Deteksi menggunakan ProcessDebugPort");
        
        return result;
    }

    bool AntiDebug::CheckProcessDebugFlags()
    {
        if (!m_pNtQueryInformationProcess)
        {
            AddDetectionResult(AntiDebugTechnique::PROCESS_DEBUG_FLAGS, false,
                "Gagal mendapatkan alamat fungsi NtQueryInformationProcess");
            return false;
        }
        
        DWORD noDebugInherit = 0;
        NTSTATUS status = m_pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessInformationClass(ProcessDebugFlags),
            &noDebugInherit,
            sizeof(DWORD),
            NULL
        );
        
        // Jika NoDebugInherit adalah 0, maka proses sedang di-debug
        bool result = (NT_SUCCESS(status) && noDebugInherit == 0);
        
        AddDetectionResult(AntiDebugTechnique::PROCESS_DEBUG_FLAGS, result,
            "Deteksi menggunakan ProcessDebugFlags");
        
        return result;
    }

    bool AntiDebug::CheckProcessDebugObjectHandle()
    {
        if (!m_pNtQueryInformationProcess)
        {
            AddDetectionResult(AntiDebugTechnique::PROCESS_DEBUG_OBJECT_HANDLE, false,
                "Gagal mendapatkan alamat fungsi NtQueryInformationProcess");
            return false;
        }
        
        HANDLE debugHandle = NULL;
        NTSTATUS status = m_pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessInformationClass(ProcessDebugObjectHandle),
            &debugHandle,
            sizeof(HANDLE),
            NULL
        );
        
        bool result = (NT_SUCCESS(status) && debugHandle != NULL);
        
        AddDetectionResult(AntiDebugTechnique::PROCESS_DEBUG_OBJECT_HANDLE, result,
            "Deteksi menggunakan ProcessDebugObjectHandle");
        
        return result;
    }

    bool AntiDebug::CheckSystemKernelDebuggerInformation()
    {
        if (!m_pNtQueryInformationProcess)
        {
            AddDetectionResult(AntiDebugTechnique::SYSTEM_KERNEL_DEBUGGER_INFORMATION, false,
                "Gagal mendapatkan alamat fungsi NtQueryInformationProcess");
            return false;
        }
        
        SYSTEM_KERNEL_DEBUGGER_INFORMATION info = { 0 };
        NTSTATUS status = m_pNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessInformationClass(SystemKernelDebuggerInformation),
            &info,
            sizeof(info),
            NULL
        );
        
        bool result = (NT_SUCCESS(status) && info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent);
        
        AddDetectionResult(AntiDebugTechnique::SYSTEM_KERNEL_DEBUGGER_INFORMATION, result,
            "Deteksi menggunakan SystemKernelDebuggerInformation");
        
        return result;
    }

    bool AntiDebug::CheckDebugRegisters()
    {
        // Periksa debug register DR0-DR7
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (!GetThreadContext(GetCurrentThread(), &context))
        {
            AddDetectionResult(AntiDebugTechnique::DEBUG_REGISTERS, false,
                "Gagal mendapatkan thread context");
            return false;
        }
        
        bool result = (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0);
        
        AddDetectionResult(AntiDebugTechnique::DEBUG_REGISTERS, result,
            "Deteksi menggunakan Debug Registers");
        
        return result;
    }

    bool AntiDebug::CheckHardwareBreakpoints()
    {
        // Periksa hardware breakpoints menggunakan SEH
        bool result = false;
        
        __try
        {
            __debugbreak();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Jika kita sampai di sini, tidak ada debugger yang menangkap exception
            result = false;
        }
        
        AddDetectionResult(AntiDebugTechnique::HARDWARE_BREAKPOINTS, result,
            "Deteksi menggunakan Hardware Breakpoints");
        
        return result;
    }

    bool AntiDebug::CheckTimingAnomaly()
    {
        // Periksa timing anomaly yang disebabkan oleh debugger
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Operasi yang cepat
        for (int i = 0; i < 1000; i++)
        {
            __nop();
        }
        
        QueryPerformanceCounter(&end);
        
        // Hitung waktu eksekusi dalam mikrodetik
        double elapsedMicroseconds = (end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart;
        
        // Jika waktu eksekusi terlalu lama, mungkin ada debugger
        bool result = (elapsedMicroseconds > 1000.0); // Threshold 1 ms
        
        AddDetectionResult(AntiDebugTechnique::TIMING_CHECK, result,
            "Deteksi menggunakan Timing Anomaly");
        
        return result;
    }

    bool AntiDebug::CheckExceptionHandling()
    {
        // Periksa exception handling yang tidak normal
        bool result = false;
        
        __try
        {
            RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Jika kita sampai di sini, tidak ada debugger yang menangkap exception
            result = false;
        }
        
        AddDetectionResult(AntiDebugTechnique::EXCEPTION_HANDLING, result,
            "Deteksi menggunakan Exception Handling");
        
        return result;
    }

    bool AntiDebug::SetThreadHideFromDebugger()
    {
        if (!m_hNtdll)
        {
            AddDetectionResult(AntiDebugTechnique::THREAD_HIDE_FROM_DEBUGGER, false,
                "Gagal load ntdll.dll");
            return false;
        }
        
        // Dapatkan alamat fungsi NtSetInformationThread
        typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
            IN HANDLE ThreadHandle,
            IN ULONG ThreadInformationClass,
            IN PVOID ThreadInformation,
            IN ULONG ThreadInformationLength
            );
        
        pfnNtSetInformationThread pNtSetInformationThread = (pfnNtSetInformationThread)GetProcAddress(m_hNtdll, "NtSetInformationThread");
        if (!pNtSetInformationThread)
        {
            AddDetectionResult(AntiDebugTechnique::THREAD_HIDE_FROM_DEBUGGER, false,
                "Gagal mendapatkan alamat fungsi NtSetInformationThread");
            return false;
        }
        
        // ThreadHideFromDebugger = 0x11
        NTSTATUS status = pNtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
        
        bool result = NT_SUCCESS(status);
        
        AddDetectionResult(AntiDebugTechnique::THREAD_HIDE_FROM_DEBUGGER, result,
            "Set ThreadHideFromDebugger");
        
        return result;
    }

    std::vector<DebuggerDetection> AntiDebug::GetDetectionResults()
    {
        return m_detectionResults;
    }

    void AntiDebug::DebuggerThreadFunc()
    {
        while (m_isRunning)
        {
            // Periksa debugger setiap 3 detik
            Scan();
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    }

    void AntiDebug::AddDetectionResult(AntiDebugTechnique technique, bool detected, const std::string& details)
    {
        DebuggerDetection result;
        result.technique = technique;
        result.detected = detected;
        result.details = details;
        
        m_detectionResults.push_back(result);
        
        if (detected)
        {
            std::cout << "Debugger terdeteksi: " << details << std::endl;
        }
    }
}