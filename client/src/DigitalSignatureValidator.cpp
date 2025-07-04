#include "../include/DigitalSignatureValidator.h"
#include <iostream>
#include <filesystem>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace GarudaHS
{
    DigitalSignatureValidator::DigitalSignatureValidator()
        : m_initialized(false)
    {
    }

    DigitalSignatureValidator::~DigitalSignatureValidator()
    {
        Shutdown();
    }

    bool DigitalSignatureValidator::Initialize()
    {
        std::cout << "Menginisialisasi Digital Signature Validator..." << std::endl;
        m_initialized = true;
        return true;
    }

    bool DigitalSignatureValidator::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "Digital Signature Validator belum diinisialisasi." << std::endl;
            return false;
        }

        bool allValid = true;

        for (const auto& filePath : m_filesToVerify)
        {
            std::cout << "Memverifikasi tanda tangan digital: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            
            if (!VerifyFileSignature(filePath))
            {
                std::cerr << "Tanda tangan digital tidak valid: " << std::string(filePath.begin(), filePath.end()) << std::endl;
                
                // Buat objek CheatDetection untuk melaporkan deteksi
                CheatDetection detection;
                detection.type = CheatType::INVALID_SIGNATURE;
                detection.details = "File dengan tanda tangan digital tidak valid: " + std::string(filePath.begin(), filePath.end());
                detection.processId = GetCurrentProcessId();
                
                char processName[MAX_PATH];
                GetModuleFileNameA(NULL, processName, MAX_PATH);
                detection.processName = PathFindFileNameA(processName);
                
                // Laporkan deteksi ke AntiCheatClient
                AntiCheatClient::GetInstance().ReportDetection(detection);
                
                allValid = false;
            }
        }

        return allValid;
    }

    void DigitalSignatureValidator::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan Digital Signature Validator..." << std::endl;
            m_filesToVerify.clear();
            m_initialized = false;
        }
    }

    const char* DigitalSignatureValidator::GetName() const
    {
        return "Digital Signature Validator";
    }

    bool DigitalSignatureValidator::VerifyFileSignature(const std::wstring& filePath)
    {
        // Struktur untuk WinVerifyTrust
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        // Struktur untuk data WinVerifyTrust
        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.hWVTStateData = NULL;
        trustData.pwszURLReference = NULL;
        trustData.dwProvFlags = WTD_SAFER_FLAG;
        trustData.pFile = &fileInfo;

        // GUID untuk WINTRUST_ACTION_GENERIC_VERIFY_V2
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Verifikasi tanda tangan
        LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

        // Bersihkan state
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);

        // Periksa hasil
        return (result == ERROR_SUCCESS);
    }

    void DigitalSignatureValidator::AddFileToVerify(const std::wstring& filePath)
    {
        // Periksa apakah file ada
        if (std::filesystem::exists(filePath))
        {
            m_filesToVerify.push_back(filePath);
            std::cout << "File ditambahkan untuk verifikasi: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        }
        else
        {
            std::cerr << "File tidak ditemukan: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        }
    }

    void DigitalSignatureValidator::AddDirectoryToVerify(const std::wstring& directoryPath)
    {
        // Periksa apakah direktori ada
        if (std::filesystem::exists(directoryPath) && std::filesystem::is_directory(directoryPath))
        {
            std::vector<std::wstring> files = GetExecutableFilesInDirectory(directoryPath);
            for (const auto& file : files)
            {
                m_filesToVerify.push_back(file);
                std::cout << "File ditambahkan untuk verifikasi: " << std::string(file.begin(), file.end()) << std::endl;
            }
        }
        else
        {
            std::cerr << "Direktori tidak ditemukan: " << std::string(directoryPath.begin(), directoryPath.end()) << std::endl;
        }
    }

    std::vector<std::wstring> DigitalSignatureValidator::GetExecutableFilesInDirectory(const std::wstring& directoryPath)
    {
        std::vector<std::wstring> result;

        try
        {
            // Iterasi semua file dalam direktori dan subdirektori
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath))
            {
                if (entry.is_regular_file())
                {
                    std::wstring extension = entry.path().extension().wstring();
                    // Ubah ke lowercase untuk perbandingan
                    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                    
                    // Hanya tambahkan file .exe dan .dll
                    if (extension == L".exe" || extension == L".dll")
                    {
                        result.push_back(entry.path().wstring());
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat mencari file dalam direktori: " << e.what() << std::endl;
        }

        return result;
    }

    bool DigitalSignatureValidator::VerifyCertificateTrust(const std::wstring& filePath)
    {
        // Implementasi verifikasi kepercayaan sertifikat
        // Ini adalah verifikasi tambahan yang dapat memeriksa apakah sertifikat
        // berasal dari CA yang terpercaya dan belum dicabut

        // Struktur untuk WinVerifyTrust
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        // Struktur untuk data WinVerifyTrust
        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // Periksa seluruh rantai sertifikat
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.hWVTStateData = NULL;
        trustData.pwszURLReference = NULL;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // Gunakan cache untuk pemeriksaan pencabutan
        trustData.pFile = &fileInfo;

        // GUID untuk WINTRUST_ACTION_GENERIC_VERIFY_V2
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Verifikasi tanda tangan
        LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

        // Bersihkan state
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);

        // Periksa hasil
        return (result == ERROR_SUCCESS);
    }

    std::string DigitalSignatureValidator::GetCertificateInfo(const std::wstring& filePath)
    {
        std::string certInfo = "Tidak dapat memperoleh informasi sertifikat";

        // Buka file
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return "Gagal membuka file";
        }

        // Dapatkan konteks sertifikat
        DWORD dwEncoding, dwContentType, dwFormatType;
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        
        if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            &hMsg,
            NULL))
        {
            CloseHandle(hFile);
            return "File tidak memiliki tanda tangan digital";
        }

        // Dapatkan informasi signer
        DWORD dwSignerInfo = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo))
        {
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mendapatkan informasi penandatangan";
        }

        // Alokasi memori untuk signer info
        PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo)
        {
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mengalokasikan memori";
        }

        // Dapatkan signer info
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo))
        {
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mendapatkan informasi penandatangan";
        }

        // Cari sertifikat penandatangan di store
        CERT_INFO CertInfo;
        CertInfo.Issuer = pSignerInfo->Issuer;
        CertInfo.SerialNumber = pSignerInfo->SerialNumber;

        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            (PVOID)&CertInfo,
            NULL);

        if (!pCertContext)
        {
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Sertifikat penandatangan tidak ditemukan";
        }

        // Dapatkan nama subjek
        DWORD dwData = 0;
        if (!CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0))
        {
            CertFreeCertificateContext(pCertContext);
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mendapatkan nama subjek";
        }

        dwData = CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            NULL,
            0);

        char* szSubjectName = new char[dwData];
        if (!CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            szSubjectName,
            dwData))
        {
            delete[] szSubjectName;
            CertFreeCertificateContext(pCertContext);
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mendapatkan nama subjek";
        }

        // Dapatkan nama penerbit
        dwData = CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            NULL,
            NULL,
            0);

        char* szIssuerName = new char[dwData];
        if (!CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            NULL,
            szIssuerName,
            dwData))
        {
            delete[] szSubjectName;
            delete[] szIssuerName;
            CertFreeCertificateContext(pCertContext);
            LocalFree(pSignerInfo);
            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
            CloseHandle(hFile);
            return "Gagal mendapatkan nama penerbit";
        }

        // Format informasi sertifikat
        certInfo = "Subjek: ";
        certInfo += szSubjectName;
        certInfo += "\nPenerbit: ";
        certInfo += szIssuerName;

        // Tambahkan informasi tanggal validitas
        SYSTEMTIME stNotBefore, stNotAfter;
        FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &stNotBefore);
        FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stNotAfter);

        char szNotBefore[64], szNotAfter[64];
        sprintf_s(szNotBefore, "%.2d/%.2d/%.4d", stNotBefore.wMonth, stNotBefore.wDay, stNotBefore.wYear);
        sprintf_s(szNotAfter, "%.2d/%.2d/%.4d", stNotAfter.wMonth, stNotAfter.wDay, stNotAfter.wYear);

        certInfo += "\nValid Dari: ";
        certInfo += szNotBefore;
        certInfo += "\nValid Sampai: ";
        certInfo += szNotAfter;

        // Bersihkan
        delete[] szSubjectName;
        delete[] szIssuerName;
        CertFreeCertificateContext(pCertContext);
        LocalFree(pSignerInfo);
        CryptMsgClose(hMsg);
        CertCloseStore(hStore, 0);
        CloseHandle(hFile);

        return certInfo;
    }
}