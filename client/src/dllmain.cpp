#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <chrono>

#include "../include/GarudaHS.h"
#include "../include/ProcessWatcher.h"
#include "../include/OverlayScanner.h"
#include "../include/AntiDebug.h"
#include "../include/AntiSuspendThread.h"
#include "../include/InjectionScanner.h"
#include "../include/DigitalSignatureValidator.h"
#include "../include/MemorySignatureScanner.h"
#include "../include/HijackedThreadDetector.h"
#include "../include/IATHookScanner.h"
#include "../include/HWIDSystem.h"
#include "../include/FileIntegrityCheck.h"
#include "../include/ServerSideValidation.h"

// Global variables
HMODULE g_hModule = NULL;
std::thread g_scanThread;
bool g_isRunning = false;

// Function declarations
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
void ScanThreadFunc();

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Store the module handle for later use
        g_hModule = hModule;
        // Disable thread notifications
        DisableThreadLibraryCalls(hModule);
        // Initialize your anti-cheat here
        MessageBoxA(NULL, "Garuda Hack Shield telah diaktifkan", "GarudaHS", MB_ICONINFORMATION);
        
        // Inisialisasi AntiCheatClient
        Initialize();
        break;
        
    case DLL_PROCESS_DETACH:
        // Cleanup resources before unloading
        g_isRunning = false;
        if (g_scanThread.joinable())
        {
            g_scanThread.join();
        }
        
        // Matikan AntiCheatClient
        GarudaHS::AntiCheatClient::GetInstance().Shutdown();
        break;
    }
    return TRUE;
}

// Fungsi thread untuk melakukan scan secara periodik
void ScanThreadFunc()
{
    while (g_isRunning)
    {
        // Lakukan scan setiap 2 detik
        GarudaHS::AntiCheatClient::GetInstance().Scan();
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

// Export function that can be called from the game
extern "C" __declspec(dllexport) void Initialize()
{
    // Daftarkan modul Process Watcher
    auto processWatcher = std::make_shared<GarudaHS::ProcessWatcher>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(processWatcher);
    
    // Daftarkan modul Overlay Scanner
    auto overlayScanner = std::make_shared<GarudaHS::OverlayScanner>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(overlayScanner);
    
    // Daftarkan modul Anti-Debug
    auto antiDebug = std::make_shared<GarudaHS::AntiDebug>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(antiDebug);
    
    // Daftarkan modul Anti-Suspend Thread
    auto antiSuspendThread = std::make_shared<GarudaHS::AntiSuspendThread>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(antiSuspendThread);
    
    // Daftarkan modul Injection Scanner
    auto injectionScanner = std::make_shared<GarudaHS::InjectionScanner>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(injectionScanner);
    
    // Daftarkan modul Digital Signature Validator
    auto signatureValidator = std::make_shared<GarudaHS::DigitalSignatureValidator>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(signatureValidator);
    
    // Tambahkan file-file penting untuk divalidasi
    if (signatureValidator)
    {
        // Dapatkan path aplikasi utama
        wchar_t mainAppPath[MAX_PATH];
        GetModuleFileNameW(NULL, mainAppPath, MAX_PATH);
        signatureValidator->AddFileToVerify(mainAppPath);
        
        // Dapatkan path direktori aplikasi
        wchar_t appDir[MAX_PATH];
        wcscpy_s(appDir, mainAppPath);
        PathRemoveFileSpecW(appDir);
        
        // Tambahkan direktori aplikasi untuk divalidasi
        signatureValidator->AddDirectoryToVerify(appDir);
    }
    
    // Daftarkan modul Memory Signature Scanner
    auto memorySignatureScanner = std::make_shared<GarudaHS::MemorySignatureScanner>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(memorySignatureScanner);
    
    // Daftarkan modul Hijacked Thread Detector
    auto hijackedThreadDetector = std::make_shared<GarudaHS::HijackedThreadDetector>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(hijackedThreadDetector);
    
    // Daftarkan modul IAT Hook Scanner
    auto iatHookScanner = std::make_shared<GarudaHS::IATHookScanner>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(iatHookScanner);
    
    // Daftarkan modul HWID System
    auto hwidSystem = std::make_shared<GarudaHS::HWIDSystem>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(hwidSystem);
    
    // Daftarkan modul File Integrity Check
    auto fileIntegrityCheck = std::make_shared<GarudaHS::FileIntegrityCheck>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(fileIntegrityCheck);
    
    // Tambahkan file-file penting untuk dipantau
    if (fileIntegrityCheck)
    {
        // Dapatkan path aplikasi utama
        wchar_t mainAppPath[MAX_PATH];
        GetModuleFileNameW(NULL, mainAppPath, MAX_PATH);
        fileIntegrityCheck->AddFileToMonitor(mainAppPath);
        
        // Dapatkan path direktori aplikasi
        wchar_t appDir[MAX_PATH];
        wcscpy_s(appDir, mainAppPath);
        PathRemoveFileSpecW(appDir);
        
        // Tambahkan file-file DLL penting untuk dipantau
        std::wstring dllPath = std::wstring(appDir) + L"\\*.dll";
        fileIntegrityCheck->AddDirectoryToMonitor(appDir, L"*.dll");
        
        // Tambahkan file-file EXE penting untuk dipantau
        fileIntegrityCheck->AddDirectoryToMonitor(appDir, L"*.exe");
    }
    
    // Daftarkan modul Server-Side Validation
    auto serverSideValidation = std::make_shared<GarudaHS::ServerSideValidation>();
    GarudaHS::AntiCheatClient::GetInstance().RegisterModule(serverSideValidation);
    
    // Konfigurasi Server-Side Validation
    if (serverSideValidation)
    {
        // Set URL server (ganti dengan URL server yang sebenarnya)
        serverSideValidation->SetServerUrl("https://api.garudahs.com/validate");
        
        // Set interval validasi (dalam detik)
        serverSideValidation->SetValidationInterval(300); // 5 menit
        
        // Set game ID
        serverSideValidation->SetGameId("garuda-game-1");
        
        // Set client version
        serverSideValidation->SetClientVersion("1.0.0");
        
        // Set callback untuk status validasi
        serverSideValidation->SetValidationStatusCallback(
            [](ValidationStatus status, const std::string& message) {
                if (status == ValidationStatus::INVALID)
                {
                    // Tampilkan pesan error
                    MessageBoxA(NULL, message.c_str(), "GarudaHS - Validasi Gagal", MB_ICONERROR);
                }
            }
        );
        
        // Set callback untuk tindakan server
        serverSideValidation->SetServerActionCallback(
            [](const std::string& actionType, const std::string& actionData) {
                if (actionType == "shutdown")
                {
                    // Matikan aplikasi
                    MessageBoxA(NULL, actionData.c_str(), "GarudaHS - Perintah Server", MB_ICONWARNING);
                    ExitProcess(0);
                }
                else if (actionType == "message")
                {
                    // Tampilkan pesan
                    MessageBoxA(NULL, actionData.c_str(), "GarudaHS - Pesan Server", MB_ICONINFORMATION);
                }
            }
        );
    }
    
    // Inisialisasi AntiCheatClient
    if (GarudaHS::AntiCheatClient::GetInstance().Initialize())
    {
        MessageBoxA(NULL, "GarudaHS berhasil diinisialisasi", "GarudaHS", MB_ICONINFORMATION);
        
        // Mulai thread untuk melakukan scan secara periodik
        g_isRunning = true;
        g_scanThread = std::thread(ScanThreadFunc);
    }
    else
    {
        MessageBoxA(NULL, "Gagal menginisialisasi GarudaHS", "GarudaHS", MB_ICONERROR);
    }
}