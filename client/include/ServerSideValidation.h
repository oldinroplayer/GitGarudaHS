#pragma once

#include "GarudaHS.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

namespace GarudaHS
{
    // Enum untuk status validasi
    enum class ValidationStatus
    {
        UNKNOWN,
        VALID,
        INVALID,
        CONNECTION_ERROR
    };

    // Struktur untuk data validasi
    struct ValidationData
    {
        std::string hwid;
        std::string clientVersion;
        std::string gameId;
        std::string sessionId;
        std::vector<std::string> detectedCheats;
        std::vector<std::string> modifiedFiles;
    };

    // Struktur untuk respons server
    struct ServerResponse
    {
        bool success;
        std::string message;
        ValidationStatus status;
        bool requiresAction;
        std::string actionType;
        std::string actionData;
    };

    // Kelas untuk validasi sisi server
    class ServerSideValidation : public IAntiCheatModule
    {
    public:
        ServerSideValidation();
        virtual ~ServerSideValidation();

        // Implementasi interface IAntiCheatModule
        virtual bool Initialize() override;
        virtual bool Scan() override;
        virtual void Shutdown() override;
        virtual const char* GetName() const override;

        // Fungsi untuk mengatur URL server
        void SetServerUrl(const std::string& url);

        // Fungsi untuk mengatur interval validasi (dalam detik)
        void SetValidationInterval(int intervalSeconds);

        // Fungsi untuk mengatur game ID
        void SetGameId(const std::string& gameId);

        // Fungsi untuk mengatur session ID
        void SetSessionId(const std::string& sessionId);

        // Fungsi untuk mengatur client version
        void SetClientVersion(const std::string& version);

        // Fungsi untuk mendapatkan status validasi terakhir
        ValidationStatus GetLastValidationStatus() const;

        // Fungsi untuk mendapatkan pesan validasi terakhir
        std::string GetLastValidationMessage() const;

        // Fungsi untuk menetapkan callback ketika status validasi berubah
        void SetValidationStatusCallback(std::function<void(ValidationStatus, const std::string&)> callback);

        // Fungsi untuk menetapkan callback ketika server meminta tindakan
        void SetServerActionCallback(std::function<void(const std::string&, const std::string&)> callback);

        // Fungsi untuk melakukan validasi manual
        bool ValidateNow();

        // Fungsi untuk menambahkan data cheat yang terdeteksi
        void AddDetectedCheat(const std::string& cheatName);

        // Fungsi untuk menambahkan data file yang dimodifikasi
        void AddModifiedFile(const std::string& filePath);

    private:
        std::string m_serverUrl;
        int m_validationInterval;
        std::string m_gameId;
        std::string m_sessionId;
        std::string m_clientVersion;
        ValidationStatus m_lastStatus;
        std::string m_lastMessage;
        bool m_initialized;
        std::atomic<bool> m_isRunning;
        std::thread m_validationThread;
        std::mutex m_dataMutex;
        ValidationData m_validationData;
        std::function<void(ValidationStatus, const std::string&)> m_statusCallback;
        std::function<void(const std::string&, const std::string&)> m_actionCallback;

        // Fungsi untuk thread validasi
        void ValidationThreadFunc();

        // Fungsi untuk mengirim data ke server
        ServerResponse SendValidationData(const ValidationData& data);

        // Fungsi untuk memproses respons server
        void ProcessServerResponse(const ServerResponse& response);

        // Fungsi untuk mengumpulkan data validasi
        ValidationData CollectValidationData();

        // Fungsi untuk membuat HTTP request
        std::string MakeHttpRequest(const std::string& url, const std::string& data);

        // Fungsi untuk mengurai respons JSON
        ServerResponse ParseServerResponse(const std::string& jsonResponse);
    };
}