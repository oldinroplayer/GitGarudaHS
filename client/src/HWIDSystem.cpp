#include "../include/HWIDSystem.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <wbemidl.h>
#include <comdef.h>
#include <Iphlpapi.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "cryptopp.lib")

namespace GarudaHS
{
    HWIDSystem::HWIDSystem()
        : m_initialized(false)
    {
    }

    HWIDSystem::~HWIDSystem()
    {
        Shutdown();
    }

    bool HWIDSystem::Initialize()
    {
        std::cout << "Menginisialisasi HWID System..." << std::endl;
        
        // Kumpulkan informasi hardware
        CollectHardwareInfo();
        
        // Hitung HWID
        m_hwid = CalculateHash();
        
        std::cout << "HWID: " << m_hwid << std::endl;
        
        m_initialized = true;
        std::cout << "HWID System berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool HWIDSystem::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "HWID System belum diinisialisasi." << std::endl;
            return false;
        }

        // Tidak ada pemindaian yang perlu dilakukan untuk HWID System
        return true;
    }

    void HWIDSystem::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan HWID System..." << std::endl;
            m_hardwareInfo.clear();
            m_hwid.clear();
            m_initialized = false;
        }
    }

    const char* HWIDSystem::GetName() const
    {
        return "HWID System";
    }

    std::string HWIDSystem::GetHWID() const
    {
        return m_hwid;
    }

    std::vector<HardwareInfo> HWIDSystem::GetHardwareInfo() const
    {
        return m_hardwareInfo;
    }

    std::vector<HardwareInfo> HWIDSystem::GetCPUInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::CPU_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetDiskInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::DISK_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetMACAddress() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::MAC_ADDRESS)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetMotherboardInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::MOTHERBOARD_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetBIOSInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::BIOS_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetGPUInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::GPU_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetSystemInfo() const
    {
        std::vector<HardwareInfo> result;
        
        for (const auto& info : m_hardwareInfo)
        {
            if (info.type == HardwareInfoType::SYSTEM_INFO)
            {
                result.push_back(info);
            }
        }
        
        return result;
    }

    bool HWIDSystem::SaveHWIDToFile(const std::string& filePath) const
    {
        try
        {
            // Enkripsi HWID sebelum menyimpan
            std::string encryptedHWID = EncryptHWID(m_hwid);
            
            // Simpan ke file
            std::ofstream file(filePath, std::ios::binary);
            if (!file.is_open())
            {
                std::cerr << "Gagal membuka file untuk menyimpan HWID: " << filePath << std::endl;
                return false;
            }
            
            file << encryptedHWID;
            file.close();
            
            return true;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat menyimpan HWID: " << e.what() << std::endl;
            return false;
        }
    }

    bool HWIDSystem::LoadHWIDFromFile(const std::string& filePath)
    {
        try
        {
            // Baca dari file
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open())
            {
                std::cerr << "Gagal membuka file untuk memuat HWID: " << filePath << std::endl;
                return false;
            }
            
            std::string encryptedHWID;
            file >> encryptedHWID;
            file.close();
            
            // Dekripsi HWID
            std::string loadedHWID = DecryptHWID(encryptedHWID);
            
            // Verifikasi HWID
            if (!VerifyHWID(loadedHWID))
            {
                std::cerr << "HWID tidak valid!" << std::endl;
                return false;
            }
            
            return true;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat memuat HWID: " << e.what() << std::endl;
            return false;
        }
    }

    bool HWIDSystem::VerifyHWID(const std::string& hwid) const
    {
        // Bandingkan dengan HWID saat ini
        return (hwid == m_hwid);
    }

    std::string HWIDSystem::EncryptHWID(const std::string& hwid) const
    {
        try
        {
            // Gunakan CryptoPP untuk enkripsi AES
            CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
            
            // Derive key dan IV dari ENCRYPTION_KEY
            std::string derivedKey = CalculateHash();
            
            // Gunakan 16 byte pertama untuk key
            memcpy(key, derivedKey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
            
            // Gunakan 16 byte berikutnya untuk IV
            memcpy(iv, derivedKey.c_str() + CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
            
            // Enkripsi
            std::string encrypted;
            
            CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
            CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
            
            CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encrypted));
            stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(hwid.c_str()), hwid.length());
            stfEncryptor.MessageEnd();
            
            // Konversi ke Base64
            std::string base64Encoded;
            CryptoPP::StringSource(encrypted, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(base64Encoded)));
            
            return base64Encoded;
        }
        catch (const CryptoPP::Exception& e)
        {
            std::cerr << "Error saat mengenkripsi HWID: " << e.what() << std::endl;
            return "";
        }
    }

    std::string HWIDSystem::DecryptHWID(const std::string& encryptedHwid) const
    {
        try
        {
            // Konversi dari Base64
            std::string base64Decoded;
            CryptoPP::StringSource(encryptedHwid, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(base64Decoded)));
            
            // Gunakan CryptoPP untuk dekripsi AES
            CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
            
            // Derive key dan IV dari ENCRYPTION_KEY
            std::string derivedKey = CalculateHash();
            
            // Gunakan 16 byte pertama untuk key
            memcpy(key, derivedKey.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
            
            // Gunakan 16 byte berikutnya untuk IV
            memcpy(iv, derivedKey.c_str() + CryptoPP::AES::DEFAULT_KEYLENGTH, CryptoPP::AES::BLOCKSIZE);
            
            // Dekripsi
            std::string decrypted;
            
            CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
            CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
            
            CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
            stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(base64Decoded.c_str()), base64Decoded.size());
            stfDecryptor.MessageEnd();
            
            return decrypted;
        }
        catch (const CryptoPP::Exception& e)
        {
            std::cerr << "Error saat mendekripsi HWID: " << e.what() << std::endl;
            return "";
        }
    }

    void HWIDSystem::CollectHardwareInfo()
    {
        // Bersihkan informasi sebelumnya
        m_hardwareInfo.clear();
        
        // Kumpulkan informasi CPU
        std::vector<HardwareInfo> cpuInfo = GetCPUInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), cpuInfo.begin(), cpuInfo.end());
        
        // Kumpulkan informasi disk
        std::vector<HardwareInfo> diskInfo = GetDiskInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), diskInfo.begin(), diskInfo.end());
        
        // Kumpulkan MAC address
        std::vector<HardwareInfo> macAddress = GetMACAddress();
        m_hardwareInfo.insert(m_hardwareInfo.end(), macAddress.begin(), macAddress.end());
        
        // Kumpulkan informasi motherboard
        std::vector<HardwareInfo> motherboardInfo = GetMotherboardInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), motherboardInfo.begin(), motherboardInfo.end());
        
        // Kumpulkan informasi BIOS
        std::vector<HardwareInfo> biosInfo = GetBIOSInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), biosInfo.begin(), biosInfo.end());
        
        // Kumpulkan informasi GPU
        std::vector<HardwareInfo> gpuInfo = GetGPUInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), gpuInfo.begin(), gpuInfo.end());
        
        // Kumpulkan informasi sistem
        std::vector<HardwareInfo> systemInfo = GetSystemInfo();
        m_hardwareInfo.insert(m_hardwareInfo.end(), systemInfo.begin(), systemInfo.end());
    }

    std::string HWIDSystem::CalculateHash() const
    {
        // Gabungkan semua informasi hardware
        std::string hardwareString;
        
        for (const auto& info : m_hardwareInfo)
        {
            // Hanya gunakan informasi yang penting dan stabil
            if (info.name == "ProcessorId" || 
                info.name == "SerialNumber" || 
                info.name == "VolumeSerialNumber" || 
                info.name == "MACAddress" || 
                info.name == "BaseBoardSerialNumber" || 
                info.name == "BIOSSerialNumber")
            {
                hardwareString += info.value;
            }
        }
        
        // Tambahkan salt
        hardwareString += GenerateSalt();
        
        // Hitung SHA-256 hash
        CryptoPP::SHA256 hash;
        std::string digest;
        
        CryptoPP::StringSource(hardwareString, true, 
            new CryptoPP::HashFilter(hash, 
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest)
                )
            )
        );
        
        return digest;
    }

    std::vector<std::unordered_map<std::string, std::string>> HWIDSystem::QueryWMI(const std::string& wmiClass, const std::vector<std::string>& properties) const
    {
        std::vector<std::unordered_map<std::string, std::string>> result;
        
        // Inisialisasi COM
        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hr))
        {
            std::cerr << "Gagal menginisialisasi COM. Error: 0x" << std::hex << hr << std::endl;
            return result;
        }
        
        // Inisialisasi security
        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );
        
        if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        {
            std::cerr << "Gagal menginisialisasi security. Error: 0x" << std::hex << hr << std::endl;
            CoUninitialize();
            return result;
        }
        
        // Dapatkan locator ke WMI
        IWbemLocator* pLoc = NULL;
        hr = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );
        
        if (FAILED(hr))
        {
            std::cerr << "Gagal membuat IWbemLocator. Error: 0x" << std::hex << hr << std::endl;
            CoUninitialize();
            return result;
        }
        
        // Connect ke WMI
        IWbemServices* pSvc = NULL;
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL,
            NULL,
            0,
            NULL,
            0,
            0,
            &pSvc
        );
        
        if (FAILED(hr))
        {
            std::cerr << "Gagal connect ke WMI. Error: 0x" << std::hex << hr << std::endl;
            pLoc->Release();
            CoUninitialize();
            return result;
        }
        
        // Set security levels
        hr = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        
        if (FAILED(hr))
        {
            std::cerr << "Gagal set proxy blanket. Error: 0x" << std::hex << hr << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return result;
        }
        
        // Buat query WMI
        std::wstring query = L"SELECT * FROM " + std::wstring(wmiClass.begin(), wmiClass.end());
        IEnumWbemClassObject* pEnumerator = NULL;
        hr = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        
        if (FAILED(hr))
        {
            std::cerr << "Gagal eksekusi query. Error: 0x" << std::hex << hr << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return result;
        }
        
        // Ambil hasil query
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        
        while (pEnumerator)
        {
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            
            if (uReturn == 0)
            {
                break;
            }
            
            std::unordered_map<std::string, std::string> row;
            
            for (const auto& prop : properties)
            {
                VARIANT vtProp;
                VariantInit(&vtProp);
                
                // Konversi string ke BSTR
                BSTR propName = SysAllocString(std::wstring(prop.begin(), prop.end()).c_str());
                
                // Dapatkan properti
                hr = pclsObj->Get(propName, 0, &vtProp, 0, 0);
                SysFreeString(propName);
                
                if (SUCCEEDED(hr))
                {
                    // Konversi VARIANT ke string
                    if (vtProp.vt == VT_BSTR)
                    {
                        _bstr_t bstr(vtProp.bstrVal, false);
                        row[prop] = static_cast<const char*>(bstr);
                    }
                    else if (vtProp.vt == VT_I4)
                    {
                        row[prop] = std::to_string(vtProp.lVal);
                    }
                    else if (vtProp.vt == VT_BOOL)
                    {
                        row[prop] = vtProp.boolVal ? "true" : "false";
                    }
                    else
                    {
                        row[prop] = "N/A";
                    }
                }
                
                VariantClear(&vtProp);
            }
            
            result.push_back(row);
            pclsObj->Release();
        }
        
        // Cleanup
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        
        return result;
    }

    std::string HWIDSystem::GetRegistryValue(HKEY hKey, const std::string& subKey, const std::string& valueName) const
    {
        HKEY hSubKey;
        DWORD dwType;
        DWORD dwSize = 0;
        std::string result;
        
        // Buka registry key
        LONG lResult = RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey);
        if (lResult != ERROR_SUCCESS)
        {
            return result;
        }
        
        // Dapatkan ukuran data
        lResult = RegQueryValueExA(hSubKey, valueName.c_str(), NULL, &dwType, NULL, &dwSize);
        if (lResult != ERROR_SUCCESS || dwSize == 0)
        {
            RegCloseKey(hSubKey);
            return result;
        }
        
        // Alokasi buffer
        std::vector<BYTE> buffer(dwSize);
        
        // Dapatkan data
        lResult = RegQueryValueExA(hSubKey, valueName.c_str(), NULL, &dwType, buffer.data(), &dwSize);
        if (lResult == ERROR_SUCCESS)
        {
            if (dwType == REG_SZ || dwType == REG_EXPAND_SZ)
            {
                result = reinterpret_cast<char*>(buffer.data());
            }
            else if (dwType == REG_DWORD)
            {
                DWORD value = *reinterpret_cast<DWORD*>(buffer.data());
                result = std::to_string(value);
            }
        }
        
        RegCloseKey(hSubKey);
        return result;
    }

    std::string HWIDSystem::GenerateSalt() const
    {
        // Gunakan nama komputer sebagai salt
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        
        if (GetComputerNameA(computerName, &size))
        {
            return std::string(computerName);
        }
        
        return "GarudaHSSalt";
    }

    std::vector<HardwareInfo> HWIDSystem::GetCPUInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi CPU
        std::vector<std::string> properties = {"Name", "ProcessorId", "Manufacturer", "MaxClockSpeed"};
        auto wmiResult = QueryWMI("Win32_Processor", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::CPU_INFO;
                info.name = prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetDiskInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi disk
        std::vector<std::string> properties = {"DeviceID", "Model", "SerialNumber", "Size"};
        auto wmiResult = QueryWMI("Win32_DiskDrive", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::DISK_INFO;
                info.name = prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        // Query WMI untuk informasi volume
        properties = {"DeviceID", "VolumeSerialNumber", "FileSystem", "Size"};
        wmiResult = QueryWMI("Win32_LogicalDisk", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::DISK_INFO;
                info.name = prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetMACAddress() const
    {
        std::vector<HardwareInfo> result;
        
        // Alokasi memori untuk adapter info
        ULONG outBufLen = sizeof(IP_ADAPTER_INFO);
        PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        
        // Dapatkan ukuran buffer yang diperlukan
        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW)
        {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
        }
        
        // Dapatkan adapter info
        if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR)
        {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter)
            {
                // Format MAC address
                std::stringstream ss;
                for (UINT i = 0; i < pAdapter->AddressLength; i++)
                {
                    if (i > 0)
                    {
                        ss << "-";
                    }
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
                }
                
                HardwareInfo info;
                info.type = HardwareInfoType::MAC_ADDRESS;
                info.name = "MACAddress";
                info.value = ss.str();
                result.push_back(info);
                
                HardwareInfo adapterInfo;
                adapterInfo.type = HardwareInfoType::MAC_ADDRESS;
                adapterInfo.name = "AdapterName";
                adapterInfo.value = pAdapter->AdapterName;
                result.push_back(adapterInfo);
                
                HardwareInfo descInfo;
                descInfo.type = HardwareInfoType::MAC_ADDRESS;
                descInfo.name = "Description";
                descInfo.value = pAdapter->Description;
                result.push_back(descInfo);
                
                pAdapter = pAdapter->Next;
            }
        }
        
        if (pAdapterInfo)
        {
            free(pAdapterInfo);
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetMotherboardInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi motherboard
        std::vector<std::string> properties = {"Manufacturer", "Product", "SerialNumber", "Version"};
        auto wmiResult = QueryWMI("Win32_BaseBoard", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::MOTHERBOARD_INFO;
                info.name = "BaseBoard" + prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetBIOSInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi BIOS
        std::vector<std::string> properties = {"Manufacturer", "Name", "SerialNumber", "Version", "ReleaseDate"};
        auto wmiResult = QueryWMI("Win32_BIOS", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::BIOS_INFO;
                info.name = "BIOS" + prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetGPUInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi GPU
        std::vector<std::string> properties = {"Name", "AdapterRAM", "DriverVersion", "VideoProcessor"};
        auto wmiResult = QueryWMI("Win32_VideoController", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::GPU_INFO;
                info.name = "GPU" + prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }

    std::vector<HardwareInfo> HWIDSystem::GetSystemInfo() const
    {
        std::vector<HardwareInfo> result;
        
        // Query WMI untuk informasi sistem
        std::vector<std::string> properties = {"Manufacturer", "Model", "SystemType", "TotalPhysicalMemory"};
        auto wmiResult = QueryWMI("Win32_ComputerSystem", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::SYSTEM_INFO;
                info.name = "System" + prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        // Dapatkan informasi OS
        properties = {"Caption", "Version", "BuildNumber", "OSArchitecture"};
        wmiResult = QueryWMI("Win32_OperatingSystem", properties);
        
        for (const auto& row : wmiResult)
        {
            for (const auto& prop : row)
            {
                HardwareInfo info;
                info.type = HardwareInfoType::SYSTEM_INFO;
                info.name = "OS" + prop.first;
                info.value = prop.second;
                result.push_back(info);
            }
        }
        
        return result;
    }
}