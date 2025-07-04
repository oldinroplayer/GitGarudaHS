#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>

// Link dengan library yang diperlukan
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace GarudaHS
{
    // Kelas untuk memvalidasi tanda tangan digital file
    class DigitalSignatureValidator : public IAntiCheatModule
    {
    public:
        DigitalSignatureValidator();
        virtual ~DigitalSignatureValidator();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk memverifikasi tanda tangan digital file
        bool VerifyFileSignature(const std::wstring& filePath);
        
        // Fungsi untuk menambahkan file yang akan diverifikasi
        void AddFileToVerify(const std::wstring& filePath);
        
        // Fungsi untuk menambahkan direktori yang akan diverifikasi (semua file .exe dan .dll)
        void AddDirectoryToVerify(const std::wstring& directoryPath);
        
        // Fungsi untuk memeriksa apakah sertifikat berasal dari publisher yang terpercaya
        bool VerifyCertificateTrust(const std::wstring& filePath);
        
        // Fungsi untuk mendapatkan informasi sertifikat
        std::string GetCertificateInfo(const std::wstring& filePath);

    private:
        std::vector<std::wstring> m_filesToVerify;
        bool m_initialized;
        
        // Fungsi helper untuk mendapatkan semua file .exe dan .dll dalam direktori
        std::vector<std::wstring> GetExecutableFilesInDirectory(const std::wstring& directoryPath);
    };
}