#include "../include/IATHookScanner.h"
#include <iostream>
#include <Psapi.h>
#include <algorithm>
#include <sstream>

namespace GarudaHS
{
    IATHookScanner::IATHookScanner()
        : m_initialized(false)
    {
    }

    IATHookScanner::~IATHookScanner()
    {
        Shutdown();
    }

    bool IATHookScanner::Initialize()
    {
        std::cout << "Menginisialisasi IAT Hook Scanner..." << std::endl;
        
        // Tambahkan hook yang diizinkan (misalnya untuk overlay game yang sah)
        // Contoh: AddAllowedHook("user32.dll", "SetWindowsHookExA");
        
        // Simpan alamat asli fungsi yang diimpor
        SaveOriginalImportAddresses();
        
        m_initialized = true;
        std::cout << "IAT Hook Scanner berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool IATHookScanner::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "IAT Hook Scanner belum diinisialisasi." << std::endl;
            return false;
        }

        // Bersihkan hasil deteksi sebelumnya
        ClearHookedFunctions();
        
        // Pindai IAT semua modul dalam proses saat ini
        bool result = ScanAllModulesIAT();
        
        // Jika ada fungsi yang di-hook, laporkan sebagai cheat
        if (!m_hookedFunctions.empty())
        {
            for (const auto& hookedFunc : m_hookedFunctions)
            {
                std::cout << "IAT Hook terdeteksi: " << hookedFunc.moduleName << "::" << hookedFunc.functionName 
                          << " (0x" << std::hex << hookedFunc.originalAddress << " -> 0x" << hookedFunc.currentAddress << std::dec << ")" << std::endl;
                
                // Buat objek CheatDetection untuk melaporkan deteksi
                CheatDetection detection;
                detection.type = CheatType::IAT_HOOK;
                
                std::stringstream ss;
                ss << "IAT Hook terdeteksi: " << hookedFunc.moduleName << "::" << hookedFunc.functionName 
                   << " (0x" << std::hex << hookedFunc.originalAddress << " -> 0x" << hookedFunc.currentAddress << std::dec << ")";
                
                detection.details = ss.str();
                detection.processId = GetCurrentProcessId();
                
                char processName[MAX_PATH];
                GetModuleFileNameA(NULL, processName, MAX_PATH);
                detection.processName = PathFindFileNameA(processName);
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
            }
            
            return false;
        }
        
        return result;
    }

    void IATHookScanner::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan IAT Hook Scanner..." << std::endl;
            m_hookedFunctions.clear();
            m_allowedHooks.clear();
            m_originalAddresses.clear();
            m_initialized = false;
        }
    }

    const char* IATHookScanner::GetName() const
    {
        return "IAT Hook Scanner";
    }

    bool IATHookScanner::ScanModuleIAT(HMODULE hModule)
    {
        if (hModule == NULL)
        {
            return false;
        }
        
        // Dapatkan DOS header
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }
        
        // Dapatkan NT header
        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        
        // Dapatkan data directory untuk import table
        PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (pImportDir->Size == 0 || pImportDir->VirtualAddress == 0)
        {
            return false;
        }
        
        // Dapatkan import descriptor
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pImportDir->VirtualAddress);
        
        // Dapatkan nama modul
        char moduleName[MAX_PATH];
        GetModuleFileNameA(hModule, moduleName, MAX_PATH);
        std::string moduleBaseName = PathFindFileNameA(moduleName);
        
        // Iterasi semua modul yang diimpor
        for (; pImportDesc->Name != 0; pImportDesc++)
        {
            // Dapatkan nama modul yang diimpor
            const char* importedModuleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
            
            // Dapatkan first thunk (IAT)
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            
            // Dapatkan original first thunk (INT)
            PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
            if (pImportDesc->OriginalFirstThunk != 0)
            {
                pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
            }
            
            // Iterasi semua fungsi yang diimpor
            for (int i = 0; pFirstThunk[i].u1.Function != 0; i++)
            {
                // Dapatkan alamat fungsi saat ini
                void* currentFuncAddr = (void*)pFirstThunk[i].u1.Function;
                
                // Dapatkan nama fungsi
                std::string functionName = "Unknown";
                if (pOriginalFirstThunk != NULL && !(pOriginalFirstThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOriginalFirstThunk[i].u1.AddressOfData);
                    functionName = (const char*)pImportByName->Name;
                }
                
                // Dapatkan alamat asli fungsi
                void* originalFuncAddr = GetOriginalFunctionAddress(importedModuleName, functionName);
                
                // Jika alamat asli tidak ditemukan, gunakan alamat saat ini sebagai alamat asli
                if (originalFuncAddr == NULL)
                {
                    originalFuncAddr = currentFuncAddr;
                    
                    // Simpan alamat asli untuk pemindaian berikutnya
                    m_originalAddresses[importedModuleName][functionName] = originalFuncAddr;
                }
                
                // Periksa apakah fungsi di-hook
                if (originalFuncAddr != currentFuncAddr)
                {
                    // Periksa apakah hook diizinkan
                    if (!IsHookAllowed(importedModuleName, functionName))
                    {
                        // Periksa apakah alamat saat ini berada dalam modul yang valid
                        if (!IsAddressInValidModule(currentFuncAddr))
                        {
                            // Fungsi di-hook dan tidak diizinkan
                            ImportFunctionInfo hookInfo;
                            hookInfo.moduleName = importedModuleName;
                            hookInfo.functionName = functionName;
                            hookInfo.originalAddress = originalFuncAddr;
                            hookInfo.currentAddress = currentFuncAddr;
                            hookInfo.isHooked = true;
                            
                            m_hookedFunctions.push_back(hookInfo);
                        }
                    }
                }
            }
        }
        
        return true;
    }

    bool IATHookScanner::ScanAllModulesIAT()
    {
        // Dapatkan handle ke semua modul dalam proses saat ini
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        if (!EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded))
        {
            std::cerr << "Gagal mendapatkan daftar modul. Error: " << GetLastError() << std::endl;
            return false;
        }
        
        // Hitung jumlah modul
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        
        // Pindai IAT setiap modul
        for (DWORD i = 0; i < moduleCount; i++)
        {
            ScanModuleIAT(hModules[i]);
        }
        
        return true;
    }

    const std::vector<ImportFunctionInfo>& IATHookScanner::GetHookedFunctions() const
    {
        return m_hookedFunctions;
    }

    void IATHookScanner::ClearHookedFunctions()
    {
        m_hookedFunctions.clear();
    }

    void IATHookScanner::AddAllowedHook(const std::string& moduleName, const std::string& functionName)
    {
        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
        
        std::string lowerFunctionName = functionName;
        std::transform(lowerFunctionName.begin(), lowerFunctionName.end(), lowerFunctionName.begin(), ::tolower);
        
        m_allowedHooks[lowerModuleName][lowerFunctionName] = true;
    }

    bool IATHookScanner::IsHookAllowed(const std::string& moduleName, const std::string& functionName)
    {
        std::string lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);
        
        std::string lowerFunctionName = functionName;
        std::transform(lowerFunctionName.begin(), lowerFunctionName.end(), lowerFunctionName.begin(), ::tolower);
        
        // Periksa apakah hook diizinkan
        auto moduleIt = m_allowedHooks.find(lowerModuleName);
        if (moduleIt != m_allowedHooks.end())
        {
            auto funcIt = moduleIt->second.find(lowerFunctionName);
            if (funcIt != moduleIt->second.end())
            {
                return funcIt->second;
            }
        }
        
        return false;
    }

    std::string IATHookScanner::GetModuleNameFromAddress(void* address)
    {
        if (address == NULL)
        {
            return "Unknown";
        }
        
        std::string moduleName = "Unknown";
        
        // Dapatkan informasi tentang semua modul dalam proses
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                // Dapatkan informasi tentang modul ini
                MODULEINFO modInfo;
                if (GetModuleInformation(GetCurrentProcess(), hModules[i], &modInfo, sizeof(MODULEINFO)))
                {
                    // Periksa apakah alamat berada dalam rentang modul ini
                    if ((BYTE*)address >= (BYTE*)modInfo.lpBaseOfDll && 
                        (BYTE*)address < (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)
                    {
                        // Dapatkan nama modul
                        char szModName[MAX_PATH];
                        if (GetModuleFileNameA(hModules[i], szModName, sizeof(szModName)))
                        {
                            moduleName = PathFindFileNameA(szModName);
                            break;
                        }
                    }
                }
            }
        }
        
        return moduleName;
    }

    void* IATHookScanner::GetOriginalFunctionAddress(const std::string& moduleName, const std::string& functionName)
    {
        // Periksa apakah alamat asli sudah disimpan
        auto moduleIt = m_originalAddresses.find(moduleName);
        if (moduleIt != m_originalAddresses.end())
        {
            auto funcIt = moduleIt->second.find(functionName);
            if (funcIt != moduleIt->second.end())
            {
                return funcIt->second;
            }
        }
        
        // Jika tidak, dapatkan alamat asli dari DLL
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (hModule == NULL)
        {
            // Coba load DLL jika belum di-load
            hModule = LoadLibraryA(moduleName.c_str());
            if (hModule == NULL)
            {
                return NULL;
            }
        }
        
        // Dapatkan alamat fungsi
        void* funcAddr = (void*)GetProcAddress(hModule, functionName.c_str());
        if (funcAddr != NULL)
        {
            // Simpan alamat asli
            m_originalAddresses[moduleName][functionName] = funcAddr;
        }
        
        return funcAddr;
    }

    bool IATHookScanner::IsAddressInValidModule(void* address)
    {
        if (address == NULL)
        {
            return false;
        }
        
        // Dapatkan informasi tentang semua modul dalam proses
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded))
        {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                // Dapatkan informasi tentang modul ini
                MODULEINFO modInfo;
                if (GetModuleInformation(GetCurrentProcess(), hModules[i], &modInfo, sizeof(MODULEINFO)))
                {
                    // Periksa apakah alamat berada dalam rentang modul ini
                    if ((BYTE*)address >= (BYTE*)modInfo.lpBaseOfDll && 
                        (BYTE*)address < (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage)
                    {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    void IATHookScanner::SaveOriginalImportAddresses()
    {
        // Dapatkan handle ke semua modul dalam proses saat ini
        HMODULE hModules[1024];
        DWORD cbNeeded;
        
        if (!EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded))
        {
            std::cerr << "Gagal mendapatkan daftar modul. Error: " << GetLastError() << std::endl;
            return;
        }
        
        // Hitung jumlah modul
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        
        // Iterasi semua modul
        for (DWORD i = 0; i < moduleCount; i++)
        {
            HMODULE hModule = hModules[i];
            
            // Dapatkan DOS header
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            {
                continue;
            }
            
            // Dapatkan NT header
            PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
            if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
            {
                continue;
            }
            
            // Dapatkan data directory untuk import table
            PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (pImportDir->Size == 0 || pImportDir->VirtualAddress == 0)
            {
                continue;
            }
            
            // Dapatkan import descriptor
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pImportDir->VirtualAddress);
            
            // Iterasi semua modul yang diimpor
            for (; pImportDesc->Name != 0; pImportDesc++)
            {
                // Dapatkan nama modul yang diimpor
                const char* importedModuleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
                
                // Dapatkan first thunk (IAT)
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
                
                // Dapatkan original first thunk (INT)
                PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
                if (pImportDesc->OriginalFirstThunk != 0)
                {
                    pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
                }
                
                // Iterasi semua fungsi yang diimpor
                for (int j = 0; pFirstThunk[j].u1.Function != 0; j++)
                {
                    // Dapatkan alamat fungsi saat ini
                    void* currentFuncAddr = (void*)pFirstThunk[j].u1.Function;
                    
                    // Dapatkan nama fungsi
                    std::string functionName = "Unknown";
                    if (pOriginalFirstThunk != NULL && !(pOriginalFirstThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG))
                    {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOriginalFirstThunk[j].u1.AddressOfData);
                        functionName = (const char*)pImportByName->Name;
                    }
                    
                    // Simpan alamat asli
                    m_originalAddresses[importedModuleName][functionName] = currentFuncAddr;
                }
            }
        }
    }
}