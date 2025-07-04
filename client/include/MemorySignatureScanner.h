#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <memory>

namespace GarudaHS
{
    // Struktur untuk menyimpan pola byte (signature)
    struct BytePattern
    {
        std::string name;           // Nama pola/cheat
        std::vector<BYTE> pattern;  // Pola byte
        std::vector<bool> mask;     // Mask untuk wildcard (true = harus cocok, false = wildcard)
        
        // Constructor untuk pola dengan mask
        BytePattern(const std::string& name, const std::vector<BYTE>& pattern, const std::vector<bool>& mask)
            : name(name), pattern(pattern), mask(mask) {}
        
        // Constructor untuk pola tanpa wildcard
        BytePattern(const std::string& name, const std::vector<BYTE>& pattern)
            : name(name), pattern(pattern), mask(std::vector<bool>(pattern.size(), true)) {}
    };

    // Struktur untuk menyimpan hasil pencarian
    struct SignatureMatch
    {
        std::string patternName;    // Nama pola yang cocok
        DWORD processId;            // ID proses
        void* address;              // Alamat di memori
        SIZE_T size;                // Ukuran pola
    };

    // Kelas untuk memindai memori proses untuk pola byte tertentu
    class MemorySignatureScanner : public IAntiCheatModule
    {
    public:
        MemorySignatureScanner();
        virtual ~MemorySignatureScanner();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk menambahkan pola byte untuk dipindai
        void AddPattern(const BytePattern& pattern);
        
        // Fungsi untuk menambahkan pola byte dari string hex
        // Format: "90 90 ?? 90" (dimana ?? adalah wildcard)
        void AddPatternFromHexString(const std::string& name, const std::string& hexString);
        
        // Fungsi untuk memindai proses tertentu
        bool ScanProcess(DWORD processId);
        
        // Fungsi untuk memindai semua proses
        bool ScanAllProcesses();
        
        // Fungsi untuk memindai memori proses saat ini
        bool ScanCurrentProcess();
        
        // Fungsi untuk mendapatkan hasil pencarian
        const std::vector<SignatureMatch>& GetMatches() const;
        
        // Fungsi untuk membersihkan hasil pencarian
        void ClearMatches();

    private:
        std::vector<BytePattern> m_patterns;
        std::vector<SignatureMatch> m_matches;
        bool m_initialized;
        
        // Fungsi helper untuk memindai region memori tertentu
        bool ScanMemoryRegion(HANDLE hProcess, DWORD processId, MEMORY_BASIC_INFORMATION& memInfo);
        
        // Fungsi helper untuk memeriksa apakah pola cocok pada alamat tertentu
        bool MatchPattern(const BytePattern& pattern, const BYTE* data, SIZE_T dataSize);
        
        // Fungsi helper untuk mengkonversi string hex ke vector byte dan mask
        static bool HexStringToPattern(const std::string& hexString, std::vector<BYTE>& pattern, std::vector<bool>& mask);
    };
}