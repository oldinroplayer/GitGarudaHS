#include "../include/InjectionScanner.h"
#include <iostream>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <Shlwapi.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")

// Definisi untuk hook API
#include <detours/detours.h>
#pragma comment(lib, "detours.lib")

namespace GarudaHS
{
    // Tipe fungsi untuk LoadLibraryA, LoadLibraryW, LoadLibraryExA, LoadLibraryExW
    typedef HMODULE (WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);
    typedef HMODULE (WINAPI* pfnLoadLibraryW)(LPCWSTR lpLibFileName);
    typedef HMODULE (WINAPI* pfnLoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
    typedef HMODULE (WINAPI* pfnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

    // Pointer ke fungsi asli
    pfnLoadLibraryA g_originalLoadLibraryA = nullptr;
    pfnLoadLibraryW g_originalLoadLibraryW = nullptr;
    pfnLoadLibraryExA g_originalLoadLibraryExA = nullptr;
    pfnLoadLibraryExW g_originalLoadLibraryExW = nullptr;

    // Fungsi hook untuk LoadLibraryA
    HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName)
    {
        // Periksa apakah file DLL adalah sah
        std::string libFileName = lpLibFileName;
        
        // Dapatkan instance InjectionScanner dari AntiCheatClient
        InjectionScanner* scanner = static_cast<InjectionScanner*>(AntiCheatClient::GetInstance().GetModule("Injection Scanner"));
        
        // Periksa apakah file DLL adalah sah
        if (scanner && !scanner->IsValidModulePath(libFileName))
        {
            std::cout << "Upaya load library terdeteksi! File: " << libFileName << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::DLL_INJECTION;
            detection.details = "Upaya load library terdeteksi! File: " + libFileName;
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return NULL untuk mencegah loading
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        
        // Jika file DLL sah, lanjutkan ke fungsi asli
        return g_originalLoadLibraryA(lpLibFileName);
    }

    // Fungsi hook untuk LoadLibraryW
    HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName)
    {
        // Konversi WCHAR ke string
        char libFileNameA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, libFileNameA, MAX_PATH, NULL, NULL);
        std::string libFileName = libFileNameA;
        
        // Dapatkan instance InjectionScanner dari AntiCheatClient
        InjectionScanner* scanner = static_cast<InjectionScanner*>(AntiCheatClient::GetInstance().GetModule("Injection Scanner"));
        
        // Periksa apakah file DLL adalah sah
        if (scanner && !scanner->IsValidModulePath(libFileName))
        {
            std::cout << "Upaya load library (W) terdeteksi! File: " << libFileName << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::DLL_INJECTION;
            detection.details = "Upaya load library (W) terdeteksi! File: " + libFileName;
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return NULL untuk mencegah loading
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        
        // Jika file DLL sah, lanjutkan ke fungsi asli
        return g_originalLoadLibraryW(lpLibFileName);
    }

    // Fungsi hook untuk LoadLibraryExA
    HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        // Periksa apakah file DLL adalah sah
        std::string libFileName = lpLibFileName;
        
        // Dapatkan instance InjectionScanner dari AntiCheatClient
        InjectionScanner* scanner = static_cast<InjectionScanner*>(AntiCheatClient::GetInstance().GetModule("Injection Scanner"));
        
        // Periksa apakah file DLL adalah sah
        if (scanner && !scanner->IsValidModulePath(libFileName))
        {
            std::cout << "Upaya load library ex terdeteksi! File: " << libFileName << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::DLL_INJECTION;
            detection.details = "Upaya load library ex terdeteksi! File: " + libFileName;
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return NULL untuk mencegah loading
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        
        // Jika file DLL sah, lanjutkan ke fungsi asli
        return g_originalLoadLibraryExA(lpLibFileName, hFile, dwFlags);
    }

    // Fungsi hook untuk LoadLibraryExW
    HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        // Konversi WCHAR ke string
        char libFileNameA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, lpLibFileName, -1, libFileNameA, MAX_PATH, NULL, NULL);
        std::string libFileName = libFileNameA;
        
        // Dapatkan instance InjectionScanner dari AntiCheatClient
        InjectionScanner* scanner = static_cast<InjectionScanner*>(AntiCheatClient::GetInstance().GetModule("Injection Scanner"));
        
        // Periksa apakah file DLL adalah sah
        if (scanner && !scanner->IsValidModulePath(libFileName))
        {
            std::cout << "Upaya load library ex (W) terdeteksi! File: " << libFileName << std::endl;
            
            // Buat laporan deteksi
            CheatDetection detection;
            detection.type = CheatType::DLL_INJECTION;
            detection.details = "Upaya load library ex (W) terdeteksi! File: " + libFileName;
            detection.processId = GetCurrentProcessId();
            detection.processName = "RRO.exe";
            
            // Laporkan deteksi ke AntiCheatClient
            AntiCheatClient::GetInstance().ReportDetection(detection);
            
            // Return NULL untuk mencegah loading
            SetLastError(ERROR_ACCESS_DENIED);
            return NULL;
        }
        
        // Jika file DLL sah, lanjutkan ke fungsi asli
        return g_originalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }

    InjectionScanner::InjectionScanner()
        : m_isRunning(false)
    {
        // Inisialisasi daftar modul yang diketahui sah
        m_knownLegitimateModules = {
            "kernel32.dll",
            "user32.dll",
            "gdi32.dll",
            "advapi32.dll",
            "shell32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "comctl32.dll",
            "comdlg32.dll",
            "ntdll.dll",
            "msvcrt.dll",
            "ws2_32.dll",
            "wininet.dll",
            "d3d9.dll",
            "d3d11.dll",
            "dxgi.dll",
            "opengl32.dll",
            "glu32.dll",
            "dinput8.dll",
            "xinput1_3.dll",
            "dsound.dll",
            "winmm.dll",
            "version.dll",
            "setupapi.dll",
            "dbghelp.dll",
            "psapi.dll",
            "mswsock.dll",
            "wldap32.dll",
            "crypt32.dll",
            "iphlpapi.dll",
            "garudahs_client.dll" // DLL anti-cheat kita sendiri
        };
        
        // Inisialisasi daftar modul yang diketahui berbahaya
        m_knownMaliciousModules = {
            "cheatengine",
            "ce",
            "trainer",
            "hack",
            "esp",
            "aimbot",
            "wallhack",
            "speedhack",
            "openkore",
            "wpe",
            "rpe",
            "artmoney",
            "gamehacker",
            "gameguardian",
            "frida",
            "ollydbg",
            "x64dbg",
            "x32dbg",
            "ida",
            "ghidra",
            "dnspy",
            "wireshark",
            "fiddler",
            "charles",
            "burp",
            "packeteditor",
            "packetsniffer",
            "memoryeditor",
            "memoryhacker",
            "autoclicker",
            "macrorecorder",
            "autohotkey",
            "ahk"
        };
    }

    InjectionScanner::~InjectionScanner()
    {
        Shutdown();
    }

    bool InjectionScanner::Initialize()
    {
        std::cout << "Menginisialisasi Injection Scanner..." << std::endl;
        
        // Dapatkan daftar modul yang dimuat saat inisialisasi
        std::vector<ModuleInfo> initialModules = GetLoadedModules();
        
        // Simpan modul awal ke map
        for (const auto& module : initialModules)
        {
            m_initialModules[module.name] = module;
        }
        
        // Hook API yang digunakan untuk injection
        if (!HookInjectionAPI())
        {
            std::cerr << "Gagal hook API injection." << std::endl;
            return false;
        }
        
        // Mulai thread scanner jika belum berjalan
        if (!m_isRunning)
        {
            m_isRunning = true;
            m_scannerThread = std::thread(&InjectionScanner::ScannerThreadFunc, this);
        }
        
        return true;
    }

    bool InjectionScanner::Scan()
    {
        // Periksa apakah ada DLL yang diinjeksi
        if (HasInjectedDLL())
        {
            return false; // Terdeteksi DLL yang diinjeksi
        }
        
        // Deteksi berbagai teknik injeksi
        if (DetectLoadLibraryInjection() ||
            DetectManualMapping() ||
            DetectReflectiveInjection() ||
            DetectThreadHijacking() ||
            DetectSetWindowsHookInjection() ||
            DetectAppInitDllInjection() ||
            DetectRegistryModification())
        {
            return false; // Terdeteksi teknik injeksi
        }
        
        return true; // Tidak ada injeksi yang terdeteksi
    }

    void InjectionScanner::Shutdown()
    {
        // Unhook API
        UnhookInjectionAPI();
        
        // Hentikan thread scanner jika sedang berjalan
        if (m_isRunning)
        {
            m_isRunning = false;
            if (m_scannerThread.joinable())
            {
                m_scannerThread.join();
            }
        }
    }

    const char* InjectionScanner::GetName() const
    {
        return "Injection Scanner";
    }

    std::vector<ModuleInfo> InjectionScanner::GetLoadedModules()
    {
        std::vector<ModuleInfo> modules;
        
        // Dapatkan handle proses saat ini
        HANDLE hProcess = GetCurrentProcess();
        
        // Alokasi buffer untuk daftar modul
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        // Dapatkan daftar modul
        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
        {
            // Hitung jumlah modul
            int moduleCount = cbNeeded / sizeof(HMODULE);
            
            // Iterasi melalui semua modul
            for (int i = 0; i < moduleCount; i++)
            {
                ModuleInfo moduleInfo;
                moduleInfo.baseAddress = hModules[i];
                
                // Dapatkan nama modul
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hModules[i], szModName, sizeof(szModName)))
                {
                    moduleInfo.name = szModName;
                }
                
                // Dapatkan path modul
                char szModPath[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, hModules[i], szModPath, sizeof(szModPath)))
                {
                    moduleInfo.path = szModPath;
                }
                
                // Dapatkan ukuran modul
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(modInfo)))
                {
                    moduleInfo.size = modInfo.SizeOfImage;
                }
                
                // Verifikasi digital signature
                moduleInfo.isVerified = VerifyModuleSignature(moduleInfo.path);
                
                modules.push_back(moduleInfo);
            }
        }
        
        return modules;
    }

    bool InjectionScanner::IsLegitimateModule(const ModuleInfo& module)
    {
        // Konversi nama modul ke lowercase untuk perbandingan case-insensitive
        std::string lowerName = module.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        // Periksa apakah modul ada dalam daftar modul yang diketahui sah
        for (const auto& legitModule : m_knownLegitimateModules)
        {
            if (lowerName == legitModule)
            {
                return true;
            }
        }
        
        // Periksa apakah modul ada dalam daftar modul awal
        if (m_initialModules.find(module.name) != m_initialModules.end())
        {
            return true;
        }
        
        // Periksa apakah modul berasal dari folder sistem
        if (IsSystemModule(module.path))
        {
            return true;
        }
        
        // Periksa apakah modul berasal dari folder game
        if (IsGameModule(module.path))
        {
            return true;
        }
        
        // Periksa apakah modul memiliki digital signature yang valid
        if (module.isVerified)
        {
            return true;
        }
        
        // Periksa apakah nama modul mengandung nama yang mencurigakan
        for (const auto& maliciousModule : m_knownMaliciousModules)
        {
            if (lowerName.find(maliciousModule) != std::string::npos)
            {
                return false;
            }
        }
        
        // Jika tidak ada kondisi yang terpenuhi, anggap modul tidak sah
        return false;
    }

    bool InjectionScanner::HasInjectedDLL()
    {
        // Dapatkan daftar modul yang dimuat saat ini
        std::vector<ModuleInfo> currentModules = GetLoadedModules();
        
        // Periksa setiap modul
        for (const auto& module : currentModules)
        {
            // Jika modul tidak sah
            if (!IsLegitimateModule(module))
            {
                // Deteksi jenis injeksi
                InjectionType injectionType = DetectInjectionType(module);
                
                // Buat laporan deteksi
                CheatDetection detection;
                detection.type = CheatType::DLL_INJECTION;
                detection.details = "Terdeteksi DLL yang diinjeksi: " + module.name + " (" + module.path + ")";
                detection.processId = GetCurrentProcessId();
                detection.processName = "RRO.exe";
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                return true;
            }
        }
        
        return false;
    }

    InjectionType InjectionScanner::DetectInjectionType(const ModuleInfo& module)
    {
        // Implementasi deteksi jenis injeksi
        // Catatan: Deteksi jenis injeksi yang akurat memerlukan analisis mendalam
        
        // Untuk saat ini, kita hanya mengembalikan UNKNOWN
        return InjectionType::UNKNOWN;
    }

    bool InjectionScanner::VerifyModuleSignature(const std::string& modulePath)
    {
        // Konversi string ke WCHAR
        WCHAR wModulePath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, modulePath.c_str(), -1, wModulePath, MAX_PATH);
        
        // Inisialisasi struktur WINTRUST_FILE_INFO
        WINTRUST_FILE_INFO fileInfo;
        ZeroMemory(&fileInfo, sizeof(fileInfo));
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = wModulePath;
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;
        
        // Inisialisasi struktur WINTRUST_DATA
        WINTRUST_DATA wintrustData;
        ZeroMemory(&wintrustData, sizeof(wintrustData));
        wintrustData.cbStruct = sizeof(WINTRUST_DATA);
        wintrustData.dwUIChoice = WTD_UI_NONE;
        wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
        wintrustData.pFile = &fileInfo;
        wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        wintrustData.hWVTStateData = NULL;
        wintrustData.pwszURLReference = NULL;
        wintrustData.dwProvFlags = WTD_SAFER_FLAG;
        
        // Verifikasi signature
        GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG result = WinVerifyTrust(NULL, &guidAction, &wintrustData);
        
        // Cleanup
        wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guidAction, &wintrustData);
        
        // Jika result adalah 0, signature valid
        return (result == 0);
    }

    void InjectionScanner::ScannerThreadFunc()
    {
        while (m_isRunning)
        {
            // Periksa injeksi setiap 2 detik
            Scan();
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }

    bool InjectionScanner::DetectLoadLibraryInjection()
    {
        // Implementasi deteksi LoadLibrary injection
        // Catatan: Deteksi ini sudah dilakukan melalui hook API
        
        return false;
    }

    bool InjectionScanner::DetectManualMapping()
    {
        // Implementasi deteksi manual mapping
        // Catatan: Deteksi manual mapping memerlukan analisis memori yang kompleks
        
        return false;
    }

    bool InjectionScanner::DetectReflectiveInjection()
    {
        // Implementasi deteksi reflective injection
        // Catatan: Deteksi reflective injection memerlukan analisis memori yang kompleks
        
        return false;
    }

    bool InjectionScanner::DetectThreadHijacking()
    {
        // Implementasi deteksi thread hijacking
        // Catatan: Deteksi thread hijacking memerlukan analisis thread yang kompleks
        
        return false;
    }

    bool InjectionScanner::DetectSetWindowsHookInjection()
    {
        // Implementasi deteksi SetWindowsHook injection
        // Catatan: Deteksi SetWindowsHook injection memerlukan analisis hook yang kompleks
        
        return false;
    }

    bool InjectionScanner::DetectAppInitDllInjection()
    {
        // Implementasi deteksi AppInit_DLLs injection
        // Catatan: Deteksi AppInit_DLLs injection memerlukan analisis registry
        
        return false;
    }

    bool InjectionScanner::DetectRegistryModification()
    {
        // Implementasi deteksi registry modification
        // Catatan: Deteksi registry modification memerlukan analisis registry
        
        return false;
    }

    bool InjectionScanner::HookInjectionAPI()
    {
        // Dapatkan alamat fungsi asli
        g_originalLoadLibraryA = (pfnLoadLibraryA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        g_originalLoadLibraryW = (pfnLoadLibraryW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
        g_originalLoadLibraryExA = (pfnLoadLibraryExA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA");
        g_originalLoadLibraryExW = (pfnLoadLibraryExW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExW");
        
        if (!g_originalLoadLibraryA || !g_originalLoadLibraryW || !g_originalLoadLibraryExA || !g_originalLoadLibraryExW)
        {
            std::cerr << "Gagal mendapatkan alamat fungsi LoadLibrary." << std::endl;
            return false;
        }
        
        // Mulai transaksi hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        // Hook LoadLibraryA
        LONG error = DetourAttach(&(PVOID&)g_originalLoadLibraryA, HookedLoadLibraryA);
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal hook LoadLibraryA. Error: " << error << std::endl;
            DetourTransactionAbort();
            return false;
        }
        
        // Hook LoadLibraryW
        error = DetourAttach(&(PVOID&)g_originalLoadLibraryW, HookedLoadLibraryW);
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal hook LoadLibraryW. Error: " << error << std::endl;
            DetourTransactionAbort();
            return false;
        }
        
        // Hook LoadLibraryExA
        error = DetourAttach(&(PVOID&)g_originalLoadLibraryExA, HookedLoadLibraryExA);
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal hook LoadLibraryExA. Error: " << error << std::endl;
            DetourTransactionAbort();
            return false;
        }
        
        // Hook LoadLibraryExW
        error = DetourAttach(&(PVOID&)g_originalLoadLibraryExW, HookedLoadLibraryExW);
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal hook LoadLibraryExW. Error: " << error << std::endl;
            DetourTransactionAbort();
            return false;
        }
        
        // Commit transaksi hook
        error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            std::cerr << "Gagal commit hook transaction. Error: " << error << std::endl;
            return false;
        }
        
        std::cout << "API LoadLibrary berhasil di-hook." << std::endl;
        return true;
    }

    void InjectionScanner::UnhookInjectionAPI()
    {
        // Jika fungsi asli tersedia
        if (g_originalLoadLibraryA || g_originalLoadLibraryW || g_originalLoadLibraryExA || g_originalLoadLibraryExW)
        {
            // Mulai transaksi unhook
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            
            // Unhook LoadLibraryA
            if (g_originalLoadLibraryA)
            {
                DetourDetach(&(PVOID&)g_originalLoadLibraryA, HookedLoadLibraryA);
            }
            
            // Unhook LoadLibraryW
            if (g_originalLoadLibraryW)
            {
                DetourDetach(&(PVOID&)g_originalLoadLibraryW, HookedLoadLibraryW);
            }
            
            // Unhook LoadLibraryExA
            if (g_originalLoadLibraryExA)
            {
                DetourDetach(&(PVOID&)g_originalLoadLibraryExA, HookedLoadLibraryExA);
            }
            
            // Unhook LoadLibraryExW
            if (g_originalLoadLibraryExW)
            {
                DetourDetach(&(PVOID&)g_originalLoadLibraryExW, HookedLoadLibraryExW);
            }
            
            // Commit transaksi unhook
            DetourTransactionCommit();
            
            std::cout << "API LoadLibrary berhasil di-unhook." << std::endl;
        }
    }

    std::string InjectionScanner::GetModulePath(HMODULE hModule)
    {
        char szModPath[MAX_PATH];
        if (GetModuleFileNameExA(GetCurrentProcess(), hModule, szModPath, sizeof(szModPath)))
        {
            return szModPath;
        }
        
        return "";
    }

    bool InjectionScanner::IsValidModulePath(const std::string& path)
    {
        // Periksa apakah path kosong
        if (path.empty())
        {
            return false;
        }
        
        // Periksa apakah file ada
        if (!std::filesystem::exists(path))
        {
            return false;
        }
        
        // Periksa apakah path adalah file DLL
        if (PathFindExtensionA(path.c_str()) != std::string(".dll"))
        {
            return false;
        }
        
        // Periksa apakah modul berasal dari folder sistem atau folder game
        if (IsSystemModule(path) || IsGameModule(path))
        {
            return true;
        }
        
        // Periksa apakah modul memiliki digital signature yang valid
        if (VerifyModuleSignature(path))
        {
            return true;
        }
        
        // Periksa apakah nama file mengandung nama yang mencurigakan
        std::string fileName = PathFindFileNameA(path.c_str());
        std::transform(fileName.begin(), fileName.end(), fileName.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        for (const auto& maliciousModule : m_knownMaliciousModules)
        {
            if (fileName.find(maliciousModule) != std::string::npos)
            {
                return false;
            }
        }
        
        // Jika tidak ada kondisi yang terpenuhi, anggap path tidak valid
        return false;
    }

    bool InjectionScanner::IsSystemModule(const std::string& path)
    {
        // Dapatkan path folder sistem
        char systemDir[MAX_PATH];
        GetSystemDirectoryA(systemDir, MAX_PATH);
        
        // Konversi ke lowercase untuk perbandingan case-insensitive
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        std::string lowerSystemDir = systemDir;
        std::transform(lowerSystemDir.begin(), lowerSystemDir.end(), lowerSystemDir.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        // Periksa apakah path dimulai dengan path folder sistem
        return (lowerPath.find(lowerSystemDir) == 0);
    }

    bool InjectionScanner::IsGameModule(const std::string& path)
    {
        // Dapatkan path folder game
        char gameDir[MAX_PATH];
        GetModuleFileNameA(NULL, gameDir, MAX_PATH);
        
        // Hapus nama file dari path
        PathRemoveFileSpecA(gameDir);
        
        // Konversi ke lowercase untuk perbandingan case-insensitive
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        std::string lowerGameDir = gameDir;
        std::transform(lowerGameDir.begin(), lowerGameDir.end(), lowerGameDir.begin(),
            [](unsigned char c) { return std::tolower(c); });
        
        // Periksa apakah path dimulai dengan path folder game
        return (lowerPath.find(lowerGameDir) == 0);
    }
}