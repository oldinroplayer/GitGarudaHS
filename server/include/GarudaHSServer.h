#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <WinSock2.h>
#include <Windows.h>

// Konstanta
constexpr int SERVER_PORT = 8080;
constexpr const char* SERVER_VERSION = "1.0.0";
constexpr const char* SERVER_NAME = "Garuda Hack Shield Server";

// Struktur untuk menyimpan informasi client
struct ClientInfo
{
    std::string username;
    std::string hwid;
    std::string ipAddress;
    SOCKET socket;
    bool isConnected;
    std::chrono::system_clock::time_point lastHeartbeat;
};

// Struktur untuk menyimpan informasi cheat yang terdeteksi
struct CheatReport
{
    int cheatType;
    std::string details;
    std::string processName;
    DWORD processId;
    std::string timestamp;
    std::string hwid;
};

// Kelas untuk mengelola server
class GarudaHSServer
{
public:
    static GarudaHSServer& GetInstance();
    
    bool Initialize();
    void Start();
    void Stop();
    bool IsRunning() const;
    
    void AddClient(const std::string& hwid, const ClientInfo& client);
    void RemoveClient(const std::string& hwid);
    void AddCheatReport(const CheatReport& report);
    
    std::vector<ClientInfo> GetConnectedClients() const;
    std::vector<CheatReport> GetCheatReports() const;
    
private:
    GarudaHSServer() = default;
    ~GarudaHSServer() = default;
    
    GarudaHSServer(const GarudaHSServer&) = delete;
    GarudaHSServer& operator=(const GarudaHSServer&) = delete;
    
    bool InitializeWinsock();
    SOCKET CreateServerSocket();
    void HandleClient(SOCKET clientSocket, const std::string& clientIp);
    void RunServer();
    
    std::map<std::string, ClientInfo> m_clients;
    std::vector<CheatReport> m_cheatReports;
    std::mutex m_clientsMutex;
    std::mutex m_reportsMutex;
    bool m_serverRunning = false;
    SOCKET m_serverSocket = INVALID_SOCKET;
};

// Fungsi untuk menampilkan menu
void ShowMenu();