#include "../include/ServerSideValidation.h"
#include "../include/HWIDSystem.h"
#include <iostream>
#include <sstream>
#include <winhttp.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace GarudaHS
{
    ServerSideValidation::ServerSideValidation()
        : m_serverUrl("https://api.garudahs.com/validate")
        , m_validationInterval(300) // Default 5 menit
        , m_gameId("")
        , m_sessionId("")
        , m_clientVersion("1.0.0")
        , m_lastStatus(ValidationStatus::UNKNOWN)
        , m_lastMessage("")
        , m_initialized(false)
        , m_isRunning(false)
    {
    }

    ServerSideValidation::~ServerSideValidation()
    {
        Shutdown();
    }

    bool ServerSideValidation::Initialize()
    {
        std::cout << "Menginisialisasi Server-Side Validation..." << std::endl;
        
        // Reset status
        m_initialized = false;
        m_lastStatus = ValidationStatus::UNKNOWN;
        m_lastMessage = "";
        
        // Validasi parameter
        if (m_serverUrl.empty())
        {
            std::cerr << "URL server tidak valid." << std::endl;
            return false;
        }
        
        if (m_gameId.empty())
        {
            std::cerr << "Game ID tidak valid." << std::endl;
            return false;
        }
        
        // Mulai thread validasi
        m_isRunning = true;
        m_validationThread = std::thread(&ServerSideValidation::ValidationThreadFunc, this);
        
        m_initialized = true;
        std::cout << "Server-Side Validation berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool ServerSideValidation::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "Server-Side Validation belum diinisialisasi." << std::endl;
            return false;
        }

        // Lakukan validasi manual
        return ValidateNow();
    }

    void ServerSideValidation::Shutdown()
    {
        if (m_initialized)
        {
            std::cout << "Mematikan Server-Side Validation..." << std::endl;
            
            // Hentikan thread validasi
            m_isRunning = false;
            if (m_validationThread.joinable())
            {
                m_validationThread.join();
            }
            
            m_initialized = false;
        }
    }

    const char* ServerSideValidation::GetName() const
    {
        return "Server-Side Validation";
    }

    void ServerSideValidation::SetServerUrl(const std::string& url)
    {
        m_serverUrl = url;
    }

    void ServerSideValidation::SetValidationInterval(int intervalSeconds)
    {
        if (intervalSeconds > 0)
        {
            m_validationInterval = intervalSeconds;
        }
    }

    void ServerSideValidation::SetGameId(const std::string& gameId)
    {
        m_gameId = gameId;
    }

    void ServerSideValidation::SetSessionId(const std::string& sessionId)
    {
        m_sessionId = sessionId;
    }

    void ServerSideValidation::SetClientVersion(const std::string& version)
    {
        m_clientVersion = version;
    }

    ValidationStatus ServerSideValidation::GetLastValidationStatus() const
    {
        return m_lastStatus;
    }

    std::string ServerSideValidation::GetLastValidationMessage() const
    {
        return m_lastMessage;
    }

    void ServerSideValidation::SetValidationStatusCallback(std::function<void(ValidationStatus, const std::string&)> callback)
    {
        m_statusCallback = callback;
    }

    void ServerSideValidation::SetServerActionCallback(std::function<void(const std::string&, const std::string&)> callback)
    {
        m_actionCallback = callback;
    }

    bool ServerSideValidation::ValidateNow()
    {
        try
        {
            // Kumpulkan data validasi
            ValidationData data = CollectValidationData();
            
            // Kirim ke server
            ServerResponse response = SendValidationData(data);
            
            // Proses respons
            ProcessServerResponse(response);
            
            return (response.status == ValidationStatus::VALID);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat melakukan validasi: " << e.what() << std::endl;
            m_lastStatus = ValidationStatus::CONNECTION_ERROR;
            m_lastMessage = e.what();
            
            if (m_statusCallback)
            {
                m_statusCallback(m_lastStatus, m_lastMessage);
            }
            
            return false;
        }
    }

    void ServerSideValidation::AddDetectedCheat(const std::string& cheatName)
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_validationData.detectedCheats.push_back(cheatName);
    }

    void ServerSideValidation::AddModifiedFile(const std::string& filePath)
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_validationData.modifiedFiles.push_back(filePath);
    }

    void ServerSideValidation::ValidationThreadFunc()
    {
        while (m_isRunning)
        {
            // Lakukan validasi
            ValidateNow();
            
            // Tunggu interval
            for (int i = 0; i < m_validationInterval && m_isRunning; ++i)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    ServerResponse ServerSideValidation::SendValidationData(const ValidationData& data)
    {
        // Konversi data ke JSON
        json jsonData;
        jsonData["hwid"] = data.hwid;
        jsonData["clientVersion"] = data.clientVersion;
        jsonData["gameId"] = data.gameId;
        jsonData["sessionId"] = data.sessionId;
        jsonData["detectedCheats"] = data.detectedCheats;
        jsonData["modifiedFiles"] = data.modifiedFiles;
        
        std::string jsonStr = jsonData.dump();
        
        // Kirim HTTP request
        std::string response = MakeHttpRequest(m_serverUrl, jsonStr);
        
        // Parse respons
        return ParseServerResponse(response);
    }

    void ServerSideValidation::ProcessServerResponse(const ServerResponse& response)
    {
        // Update status
        m_lastStatus = response.status;
        m_lastMessage = response.message;
        
        // Panggil callback status
        if (m_statusCallback)
        {
            m_statusCallback(m_lastStatus, m_lastMessage);
        }
        
        // Proses tindakan jika diperlukan
        if (response.requiresAction && m_actionCallback)
        {
            m_actionCallback(response.actionType, response.actionData);
        }
    }

    ValidationData ServerSideValidation::CollectValidationData()
    {
        ValidationData data;
        
        // Dapatkan HWID dari modul HWID System
        auto& client = AntiCheatClient::GetInstance();
        auto hwidSystem = std::dynamic_pointer_cast<HWIDSystem>(client.GetModuleByName("HWID System"));
        
        if (hwidSystem)
        {
            data.hwid = hwidSystem->GetHWID();
        }
        
        // Set data lainnya
        data.clientVersion = m_clientVersion;
        data.gameId = m_gameId;
        data.sessionId = m_sessionId;
        
        // Salin data yang dikumpulkan
        {
            std::lock_guard<std::mutex> lock(m_dataMutex);
            data.detectedCheats = m_validationData.detectedCheats;
            data.modifiedFiles = m_validationData.modifiedFiles;
            
            // Reset data yang dikumpulkan
            m_validationData.detectedCheats.clear();
            m_validationData.modifiedFiles.clear();
        }
        
        return data;
    }

    std::string ServerSideValidation::MakeHttpRequest(const std::string& url, const std::string& data)
    {
        // Parse URL
        URL_COMPONENTS urlComp = { 0 };
        urlComp.dwStructSize = sizeof(urlComp);
        
        // Alokasi buffer untuk komponen URL
        wchar_t hostName[256] = { 0 };
        wchar_t urlPath[1024] = { 0 };
        
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = sizeof(hostName) / sizeof(hostName[0]);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(urlPath[0]);
        urlComp.dwSchemeLength = 1;
        
        // Konversi URL ke wstring
        std::wstring wUrl(url.begin(), url.end());
        
        // Parse URL
        if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp))
        {
            throw std::runtime_error("Gagal mem-parse URL");
        }
        
        // Buat session
        HINTERNET hSession = WinHttpOpen(
            L"GarudaHS/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        
        if (!hSession)
        {
            throw std::runtime_error("Gagal membuat session HTTP");
        }
        
        // Buat koneksi
        HINTERNET hConnect = WinHttpConnect(
            hSession,
            hostName,
            urlComp.nPort,
            0
        );
        
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Gagal membuat koneksi HTTP");
        }
        
        // Buat request
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            urlPath,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0
        );
        
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Gagal membuat request HTTP");
        }
        
        // Set header
        if (!WinHttpAddRequestHeaders(
            hRequest,
            L"Content-Type: application/json",
            -1,
            WINHTTP_ADDREQ_FLAG_ADD
        ))
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Gagal menambahkan header HTTP");
        }
        
        // Konversi data ke wstring
        std::wstring wData(data.begin(), data.end());
        
        // Kirim request
        if (!WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            (LPVOID)data.c_str(),
            (DWORD)data.length(),
            (DWORD)data.length(),
            0
        ))
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Gagal mengirim request HTTP");
        }
        
        // Terima respons
        if (!WinHttpReceiveResponse(hRequest, NULL))
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Gagal menerima respons HTTP");
        }
        
        // Baca respons
        std::string response;
        DWORD bytesAvailable = 0;
        DWORD bytesRead = 0;
        
        do
        {
            bytesAvailable = 0;
            
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable))
            {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                throw std::runtime_error("Gagal mendapatkan ukuran data HTTP");
            }
            
            if (bytesAvailable == 0)
            {
                break;
            }
            
            // Alokasi buffer
            std::vector<char> buffer(bytesAvailable + 1);
            
            if (!WinHttpReadData(
                hRequest,
                buffer.data(),
                bytesAvailable,
                &bytesRead
            ))
            {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                throw std::runtime_error("Gagal membaca data HTTP");
            }
            
            buffer[bytesRead] = '\0';
            response += buffer.data();
            
        } while (bytesAvailable > 0);
        
        // Cleanup
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return response;
    }

    ServerResponse ServerSideValidation::ParseServerResponse(const std::string& jsonResponse)
    {
        ServerResponse response;
        
        try
        {
            // Parse JSON
            json j = json::parse(jsonResponse);
            
            // Ambil data
            response.success = j["success"].get<bool>();
            response.message = j["message"].get<std::string>();
            
            // Parse status
            std::string statusStr = j["status"].get<std::string>();
            if (statusStr == "valid")
            {
                response.status = ValidationStatus::VALID;
            }
            else if (statusStr == "invalid")
            {
                response.status = ValidationStatus::INVALID;
            }
            else
            {
                response.status = ValidationStatus::UNKNOWN;
            }
            
            // Parse action
            response.requiresAction = j["requiresAction"].get<bool>();
            if (response.requiresAction)
            {
                response.actionType = j["actionType"].get<std::string>();
                response.actionData = j["actionData"].get<std::string>();
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saat mem-parse respons JSON: " << e.what() << std::endl;
            response.success = false;
            response.message = "Error parsing response: " + std::string(e.what());
            response.status = ValidationStatus::CONNECTION_ERROR;
            response.requiresAction = false;
        }
        
        return response;
    }
}