#include "../include/FileIntegrityCheck.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#pragma comment(lib, "cryptopp.lib")

namespace GarudaHS
{
    FileIntegrityCheck::FileIntegrityCheck()
        : m_initialized(false)
    {
    }

    FileIntegrityCheck::~FileIntegrityCheck()
    {
        Shutdown();
    }

    bool FileIntegrityCheck::Initialize()
    {
        std::cout << "Menginisialisasi File Integrity Check..." << std::endl;
        
        // Reset status
        m_initialized = false;
        
        // Perbarui informasi file yang dipantau
        for (auto& fileInfo : m_monitoredFiles)
        {
            UpdateFileInfo(fileInfo);
        }
        
        m_initialized = true;
        std::cout << "File Integrity Check berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool FileIntegrityCheck::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "File Integrity Check belum diinisialisasi." << std::endl;
            return false;
        }

        std::cout << "Memeriksa integritas file..." << std::endl;
        
        bool allFilesIntact = true;
        
        // Periksa setiap file yang dipantau
        for (const auto& fileInfo : m_monitoredFiles)
        {
            if (CheckFileModification(fileInfo))
            {
                std::cerr << "File telah dimodifikasi: " << std::string(fileInfo.path.begin(), fileInfo.path.end()) << std::endl;
                
                // Panggil callback jika ada
                if (m_fileModifiedCallback)
                {
                    m_fileModifiedCallback(fileInfo.path);
                }
                
                allFilesIntact = false;
            }
        }
        
        if (allFilesIntact)
        {
            std::cout << "Semua file dalam keadaan baik." << std::endl;
        }
        else
        {
            std::cerr << "Beberapa file telah dimodifikasi!" << std::endl;
        }
        
        return allFilesIntact;
    }

    void FileIntegrityCheck::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan File Integrity Check..." << std::endl;
            m_monitoredFiles.clear();
            m_initialized = false;
        }
    }

    const char* FileIntegrityCheck::GetName() const
    {
        return "File Integrity Check";
    }

    bool FileIntegrityCheck::AddFileToMonitor(const std::wstring& filePath)
    {
        // Periksa apakah file sudah ada dalam daftar
        auto it = std::find_if(m_monitoredFiles.begin(), m_monitoredFiles.end(),
            [&filePath](const FileInfo& info) { return info.path == filePath; });
        
        if (it != m_monitoredFiles.end())
        {
            // File sudah ada, perbarui informasinya
            UpdateFileInfo(*it);
            return true;
        }
        
        // Dapatkan informasi file baru
        FileInfo fileInfo = GetFileInfo(filePath);
        
        // Periksa apakah file valid
        if (fileInfo.hash.empty())
        {
            std::cerr << "Gagal menambahkan file: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            return false;
        }
        
        // Tambahkan ke daftar
        m_monitoredFiles.push_back(fileInfo);
        
        std::cout << "File ditambahkan untuk pemantauan: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        return true;
    }

    bool FileIntegrityCheck::AddDirectoryToMonitor(const std::wstring& directoryPath, const std::wstring& filePattern)
    {
        // Dapatkan semua file dalam direktori
        std::vector<std::wstring> files = GetFilesInDirectory(directoryPath, filePattern);
        
        if (files.empty())
        {
            std::cerr << "Tidak ada file yang ditemukan di direktori: " << std::string(directoryPath.begin(), directoryPath.end()) << std::endl;
            return false;
        }
        
        bool success = true;
        
        // Tambahkan setiap file
        for (const auto& file : files)
        {
            if (!AddFileToMonitor(file))
            {
                success = false;
            }
        }
        
        return success;
    }

    bool FileIntegrityCheck::RemoveFileFromMonitoring(const std::wstring& filePath)
    {
        auto it = std::find_if(m_monitoredFiles.begin(), m_monitoredFiles.end(),
            [&filePath](const FileInfo& info) { return info.path == filePath; });
        
        if (it != m_monitoredFiles.end())
        {
            m_monitoredFiles.erase(it);
            std::cout << "File dihapus dari pemantauan: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            return true;
        }
        
        std::cerr << "File tidak ditemukan dalam daftar pemantauan: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        return false;
    }

    std::vector<FileInfo> FileIntegrityCheck::GetMonitoredFiles() const
    {
        return m_monitoredFiles;
    }

    bool FileIntegrityCheck::IsFileModified(const std::wstring& filePath) const
    {
        auto it = std::find_if(m_monitoredFiles.begin(), m_monitoredFiles.end(),
            [&filePath](const FileInfo& info) { return info.path == filePath; });
        
        if (it != m_monitoredFiles.end())
        {
            return CheckFileModification(*it);
        }
        
        std::cerr << "File tidak ditemukan dalam daftar pemantauan: " << std::string(filePath.begin(), filePath.end()) << std::endl;
        return false;
    }

    void FileIntegrityCheck::SetFileModifiedCallback(std::function<void(const std::wstring&)> callback)
    {
        m_fileModifiedCallback = callback;
    }

    std::string FileIntegrityCheck::CalculateFileHash(const std::wstring& filePath) const
    {
        try
        {
            // Gunakan CryptoPP untuk menghitung SHA-256 hash
            CryptoPP::SHA256 hash;
            std::string digest;
            
            // Konversi wstring ke string
            std::string path(filePath.begin(), filePath.end());
            
            // Hitung hash dari file
            CryptoPP::HashFilter filter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest)));
            CryptoPP::FileSource(path.c_str(), true, new CryptoPP::Redirector(filter));
            
            return digest;
        }
        catch (const CryptoPP::Exception& e)
        {
            std::cerr << "Error saat menghitung hash file: " << e.what() << std::endl;
            return "";
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat menghitung hash file: " << e.what() << std::endl;
            return "";
        }
    }

    FileInfo FileIntegrityCheck::GetFileInfo(const std::wstring& filePath) const
    {
        FileInfo fileInfo;
        fileInfo.path = filePath;
        
        // Buka file
        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Gagal membuka file: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            return fileInfo;
        }
        
        // Dapatkan ukuran file
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE)
        {
            std::cerr << "Gagal mendapatkan ukuran file: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            CloseHandle(hFile);
            return fileInfo;
        }
        
        fileInfo.fileSize = fileSize;
        
        // Dapatkan waktu modifikasi terakhir
        FILETIME creationTime, lastAccessTime, lastWriteTime;
        if (!GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime))
        {
            std::cerr << "Gagal mendapatkan waktu file: " << std::string(filePath.begin(), filePath.end()) << std::endl;
            CloseHandle(hFile);
            return fileInfo;
        }
        
        fileInfo.lastModified = lastWriteTime;
        
        // Tutup file
        CloseHandle(hFile);
        
        // Hitung hash
        fileInfo.hash = CalculateFileHash(filePath);
        
        return fileInfo;
    }

    void FileIntegrityCheck::UpdateFileInfo(FileInfo& fileInfo)
    {
        // Dapatkan informasi file terbaru
        FileInfo newInfo = GetFileInfo(fileInfo.path);
        
        // Perbarui informasi
        fileInfo.hash = newInfo.hash;
        fileInfo.lastModified = newInfo.lastModified;
        fileInfo.fileSize = newInfo.fileSize;
    }

    bool FileIntegrityCheck::CheckFileModification(const FileInfo& fileInfo) const
    {
        // Dapatkan informasi file saat ini
        FileInfo currentInfo = GetFileInfo(fileInfo.path);
        
        // Periksa apakah hash berubah
        if (currentInfo.hash != fileInfo.hash)
        {
            return true;
        }
        
        // Periksa apakah ukuran berubah
        if (currentInfo.fileSize != fileInfo.fileSize)
        {
            return true;
        }
        
        // Periksa apakah waktu modifikasi berubah
        LONG result = CompareFileTime(&currentInfo.lastModified, &fileInfo.lastModified);
        if (result != 0)
        {
            return true;
        }
        
        return false;
    }

    std::vector<std::wstring> FileIntegrityCheck::GetFilesInDirectory(const std::wstring& directoryPath, const std::wstring& filePattern) const
    {
        std::vector<std::wstring> files;
        
        try
        {
            // Gunakan std::filesystem untuk mendapatkan file dalam direktori
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath))
            {
                if (entry.is_regular_file())
                {
                    // Periksa apakah file cocok dengan pola
                    std::wstring filename = entry.path().filename().wstring();
                    
                    // Implementasi sederhana untuk pencocokan pola wildcard
                    if (filePattern == L"*.*" || filename == filePattern)
                    {
                        files.push_back(entry.path().wstring());
                    }
                    else if (filePattern.find(L"*.") == 0)
                    {
                        // Pola ekstensi (misalnya *.exe)
                        std::wstring ext = filePattern.substr(1);
                        if (filename.size() >= ext.size() && 
                            filename.substr(filename.size() - ext.size()) == ext)
                        {
                            files.push_back(entry.path().wstring());
                        }
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat membaca direktori: " << e.what() << std::endl;
        }
        
        return files;
    }
}