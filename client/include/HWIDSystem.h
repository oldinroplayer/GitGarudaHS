#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace GarudaHS
{
    // Enum untuk jenis informasi hardware
    enum class HardwareInfoType
    {
        CPU_INFO,
        DISK_INFO,
        MAC_ADDRESS,
        MOTHERBOARD_INFO,
        BIOS_INFO,
        GPU_INFO,
        SYSTEM_INFO
    };

    // Struktur untuk menyimpan informasi hardware
    struct HardwareInfo
    {
        HardwareInfoType type;
        std::string name;
        std::string value;
    };

    // Kelas untuk sistem HWID
    class HWIDSystem : public IAntiCheatModule
    {
    public:
        HWIDSystem();
        virtual ~HWIDSystem();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk mendapatkan HWID
        std::string GetHWID() const;
        
        // Fungsi untuk mendapatkan informasi hardware
        std::vector<HardwareInfo> GetHardwareInfo() const;
        
        // Fungsi untuk mendapatkan informasi CPU
        std::vector<HardwareInfo> GetCPUInfo() const;
        
        // Fungsi untuk mendapatkan informasi disk
        std::vector<HardwareInfo> GetDiskInfo() const;
        
        // Fungsi untuk mendapatkan MAC address
        std::vector<HardwareInfo> GetMACAddress() const;
        
        // Fungsi untuk mendapatkan informasi motherboard
        std::vector<HardwareInfo> GetMotherboardInfo() const;
        
        // Fungsi untuk mendapatkan informasi BIOS
        std::vector<HardwareInfo> GetBIOSInfo() const;
        
        // Fungsi untuk mendapatkan informasi GPU
        std::vector<HardwareInfo> GetGPUInfo() const;
        
        // Fungsi untuk mendapatkan informasi sistem
        std::vector<HardwareInfo> GetSystemInfo() const;
        
        // Fungsi untuk menyimpan HWID ke file
        bool SaveHWIDToFile(const std::string& filePath) const;
        
        // Fungsi untuk memuat HWID dari file
        bool LoadHWIDFromFile(const std::string& filePath);
        
        // Fungsi untuk memverifikasi HWID
        bool VerifyHWID(const std::string& hwid) const;
        
        // Fungsi untuk mengenkripsi HWID
        std::string EncryptHWID(const std::string& hwid) const;
        
        // Fungsi untuk mendekripsi HWID
        std::string DecryptHWID(const std::string& encryptedHwid) const;

    private:
        std::vector<HardwareInfo> m_hardwareInfo;
        std::string m_hwid;
        bool m_initialized;
        
        // Fungsi untuk mengumpulkan informasi hardware
        void CollectHardwareInfo();
        
        // Fungsi untuk menghitung hash dari informasi hardware
        std::string CalculateHash() const;
        
        // Fungsi untuk mendapatkan informasi dari WMI
        std::vector<std::unordered_map<std::string, std::string>> QueryWMI(const std::string& wmiClass, const std::vector<std::string>& properties) const;
        
        // Fungsi untuk mendapatkan nilai registry
        std::string GetRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName) const;
        
        // Fungsi untuk menghasilkan salt untuk hashing
        std::string GenerateSalt() const;
        
        // Kunci enkripsi untuk HWID
        const std::string ENCRYPTION_KEY = "GarudaHSHWIDEncryptionKey";
    };
}