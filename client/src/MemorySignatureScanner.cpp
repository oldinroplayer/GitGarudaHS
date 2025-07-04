#include "../include/MemorySignatureScanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <Psapi.h>

namespace GarudaHS
{
    MemorySignatureScanner::MemorySignatureScanner()
        : m_initialized(false)
    {
    }

    MemorySignatureScanner::~MemorySignatureScanner()
    {
        Shutdown();
    }

    bool MemorySignatureScanner::Initialize()
    {
        std::cout << "Menginisialisasi Memory Signature Scanner..." << std::endl;
        
        // Tambahkan pola-pola cheat yang umum digunakan
        // Contoh pola untuk godmode, infinite ammo, speedhack, dll.
        
        // Contoh pola untuk godmode (hanya contoh, sesuaikan dengan game yang sebenarnya)
        AddPatternFromHexString("GodMode", "90 90 ?? 01 00 00 00 ?? FF FF FF FF");
        
        // Contoh pola untuk infinite ammo
        AddPatternFromHexString("InfiniteAmmo", "89 ?? 8B ?? 85 ?? 7E ?? 83 ?? 01");
        
        // Contoh pola untuk speedhack
        AddPatternFromHexString("SpeedHack", "D9 ?? ?? ?? ?? ?? D9 ?? ?? ?? ?? ?? D9 ?? ?? D9 ?? ?? ??");
        
        // Contoh pola untuk wallhack
        AddPatternFromHexString("WallHack", "0F 84 ?? ?? ?? ?? 83 ?? ?? 01 0F 85");
        
        m_initialized = true;
        std::cout << "Memory Signature Scanner berhasil diinisialisasi dengan " << m_patterns.size() << " pola." << std::endl;
        
        return true;
    }

    bool MemorySignatureScanner::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "Memory Signature Scanner belum diinisialisasi." << std::endl;
            return false;
        }

        // Bersihkan hasil pencarian sebelumnya
        ClearMatches();
        
        // Pindai proses saat ini
        bool result = ScanCurrentProcess();
        
        // Jika ada pola yang cocok, laporkan sebagai cheat
        if (!m_matches.empty())
        {
            for (const auto& match : m_matches)
            {
                std::cout << "Pola cheat terdeteksi: " << match.patternName << " di alamat " << match.address << std::endl;
                
                // Buat objek CheatDetection untuk melaporkan deteksi
                CheatDetection detection;
                detection.type = CheatType::MEMORY_SIGNATURE;
                detection.details = "Pola cheat terdeteksi: " + match.patternName + " di alamat " + std::to_string(reinterpret_cast<uintptr_t>(match.address));
                detection.processId = match.processId;
                
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

    void MemorySignatureScanner::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan Memory Signature Scanner..." << std::endl;
            m_patterns.clear();
            m_matches.clear();
            m_initialized = false;
        }
    }

    const char* MemorySignatureScanner::GetName() const
    {
        return "Memory Signature Scanner";
    }

    void MemorySignatureScanner::AddPattern(const BytePattern& pattern)
    {
        m_patterns.push_back(pattern);
    }

    void MemorySignatureScanner::AddPatternFromHexString(const std::string& name, const std::string& hexString)
    {
        std::vector<BYTE> pattern;
        std::vector<bool> mask;
        
        if (HexStringToPattern(hexString, pattern, mask))
        {
            BytePattern bytePattern(name, pattern, mask);
            AddPattern(bytePattern);
            std::cout << "Pola '" << name << "' berhasil ditambahkan." << std::endl;
        }
        else
        {
            std::cerr << "Gagal menambahkan pola '" << name << "'. Format hex string tidak valid." << std::endl;
        }
    }

    bool MemorySignatureScanner::ScanProcess(DWORD processId)
    {
        if (m_patterns.empty())
        {
            std::cerr << "Tidak ada pola yang ditambahkan untuk dipindai." << std::endl;
            return false;
        }
        
        // Buka handle ke proses
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL)
        {
            std::cerr << "Gagal membuka proses dengan ID " << processId << ". Error: " << GetLastError() << std::endl;
            return false;
        }
        
        // Dapatkan informasi tentang region memori proses
        MEMORY_BASIC_INFORMATION memInfo;
        void* address = NULL;
        
        while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo)))
        {
            // Pindai region memori ini
            ScanMemoryRegion(hProcess, processId, memInfo);
            
            // Pindah ke region berikutnya
            address = (BYTE*)memInfo.BaseAddress + memInfo.RegionSize;
        }
        
        // Tutup handle proses
        CloseHandle(hProcess);
        
        return true;
    }

    bool MemorySignatureScanner::ScanAllProcesses()
    {
        // Ambil snapshot dari semua proses
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Gagal membuat snapshot proses. Error: " << GetLastError() << std::endl;
            return false;
        }
        
        // Iterasi semua proses
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                // Pindai proses ini
                ScanProcess(pe32.th32ProcessID);
                
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        // Tutup handle snapshot
        CloseHandle(hSnapshot);
        
        return true;
    }

    bool MemorySignatureScanner::ScanCurrentProcess()
    {
        return ScanProcess(GetCurrentProcessId());
    }

    const std::vector<SignatureMatch>& MemorySignatureScanner::GetMatches() const
    {
        return m_matches;
    }

    void MemorySignatureScanner::ClearMatches()
    {
        m_matches.clear();
    }

    bool MemorySignatureScanner::ScanMemoryRegion(HANDLE hProcess, DWORD processId, MEMORY_BASIC_INFORMATION& memInfo)
    {
        // Hanya pindai region yang dapat dibaca dan bukan image (executable)
        if ((memInfo.State == MEM_COMMIT) && 
            (memInfo.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) && 
            !(memInfo.Protect & PAGE_GUARD))
        {
            // Alokasi buffer untuk membaca memori
            SIZE_T bufferSize = memInfo.RegionSize;
            BYTE* buffer = new BYTE[bufferSize];
            
            // Baca memori dari proses
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, bufferSize, &bytesRead))
            {
                // Pindai buffer untuk setiap pola
                for (const auto& pattern : m_patterns)
                {
                    // Pindai buffer untuk pola ini
                    for (SIZE_T i = 0; i <= bytesRead - pattern.pattern.size(); i++)
                    {
                        if (MatchPattern(pattern, buffer + i, bytesRead - i))
                        {
                            // Pola cocok, tambahkan ke hasil
                            SignatureMatch match;
                            match.patternName = pattern.name;
                            match.processId = processId;
                            match.address = (BYTE*)memInfo.BaseAddress + i;
                            match.size = pattern.pattern.size();
                            
                            m_matches.push_back(match);
                        }
                    }
                }
            }
            
            // Bersihkan buffer
            delete[] buffer;
        }
        
        return true;
    }

    bool MemorySignatureScanner::MatchPattern(const BytePattern& pattern, const BYTE* data, SIZE_T dataSize)
    {
        // Pastikan data cukup besar untuk pola
        if (dataSize < pattern.pattern.size())
        {
            return false;
        }
        
        // Periksa apakah pola cocok
        for (SIZE_T i = 0; i < pattern.pattern.size(); i++)
        {
            // Jika mask[i] adalah true, byte harus cocok
            // Jika mask[i] adalah false, byte adalah wildcard dan selalu cocok
            if (pattern.mask[i] && pattern.pattern[i] != data[i])
            {
                return false;
            }
        }
        
        return true;
    }

    bool MemorySignatureScanner::HexStringToPattern(const std::string& hexString, std::vector<BYTE>& pattern, std::vector<bool>& mask)
    {
        std::istringstream iss(hexString);
        std::string token;
        
        pattern.clear();
        mask.clear();
        
        while (iss >> token)
        {
            if (token == "??")
            {
                // Wildcard
                pattern.push_back(0);
                mask.push_back(false);
            }
            else
            {
                // Konversi hex string ke byte
                try
                {
                    BYTE value = static_cast<BYTE>(std::stoi(token, nullptr, 16));
                    pattern.push_back(value);
                    mask.push_back(true);
                }
                catch (const std::exception&)
                {
                    // Format tidak valid
                    return false;
                }
            }
        }
        
        return !pattern.empty();
    }
}