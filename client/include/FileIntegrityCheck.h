#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace GarudaHS
{
    // Struktur untuk menyimpan informasi file
    struct FileInfo
    {
        std::wstring path;
        std::string hash;
        FILETIME lastModified;
        DWORD fileSize;
    };

    // Kelas untuk memeriksa integritas file
    class FileIntegrityCheck : public IAntiCheatModule
    {
    public:
        FileIntegrityCheck();
        virtual ~FileIntegrityCheck();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk menambahkan file yang akan dipantau
        bool AddFileToMonitor(const std::wstring& filePath);

        // Fungsi untuk menambahkan direktori yang akan dipantau
        bool AddDirectoryToMonitor(const std::wstring& directoryPath, const std::wstring& filePattern = L"*.*");

        // Fungsi untuk menghapus file dari pemantauan
        bool RemoveFileFromMonitoring(const std::wstring& filePath);

        // Fungsi untuk mendapatkan daftar file yang dipantau
        std::vector<FileInfo> GetMonitoredFiles() const;

        // Fungsi untuk memeriksa apakah file telah dimodifikasi
        bool IsFileModified(const std::wstring& filePath) const;

        // Fungsi untuk menetapkan callback ketika file dimodifikasi
        void SetFileModifiedCallback(std::function<void(const std::wstring&)> callback);

    private:
        std::vector<FileInfo> m_monitoredFiles;
        bool m_initialized;
        std::function<void(const std::wstring&)> m_fileModifiedCallback;

        // Fungsi untuk menghitung hash file
        std::string CalculateFileHash(const std::wstring& filePath) const;

        // Fungsi untuk mendapatkan informasi file
        FileInfo GetFileInfo(const std::wstring& filePath) const;

        // Fungsi untuk memperbarui informasi file
        void UpdateFileInfo(FileInfo& fileInfo);

        // Fungsi untuk memeriksa apakah file telah dimodifikasi
        bool CheckFileModification(const FileInfo& fileInfo) const;

        // Fungsi untuk memuat daftar file dari direktori
        std::vector<std::wstring> GetFilesInDirectory(const std::wstring& directoryPath, const std::wstring& filePattern) const;
    };
}