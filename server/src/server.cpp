#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

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

// Variabel global
std::map<std::string, ClientInfo> g_clients;
std::vector<CheatReport> g_cheatReports;
std::mutex g_clientsMutex;
std::mutex g_reportsMutex;
bool g_serverRunning = false;

// Fungsi untuk menginisialisasi Winsock
bool InitializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        std::cerr << "WSAStartup gagal: " << result << std::endl;
        return false;
    }
    return true;
}

// Fungsi untuk membuat socket server
SOCKET CreateServerSocket()
{
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        std::cerr << "Gagal membuat socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return INVALID_SOCKET;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_PORT);

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Bind gagal: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "Listen gagal: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return listenSocket;
}

// Fungsi untuk menangani koneksi client
void HandleClient(SOCKET clientSocket, const std::string& clientIp)
{
    // Implementasi penanganan client akan ditambahkan nanti
    std::cout << "Client terhubung dari: " << clientIp << std::endl;
    
    // Tutup socket client ketika selesai
    closesocket(clientSocket);
}

// Fungsi untuk menjalankan server
void RunServer()
{
    if (!InitializeWinsock())
    {
        return;
    }

    SOCKET serverSocket = CreateServerSocket();
    if (serverSocket == INVALID_SOCKET)
    {
        return;
    }

    std::cout << SERVER_NAME << " v" << SERVER_VERSION << " berjalan pada port " << SERVER_PORT << std::endl;
    g_serverRunning = true;

    while (g_serverRunning)
    {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET)
        {
            std::cerr << "Accept gagal: " << WSAGetLastError() << std::endl;
            continue;
        }

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        
        // Buat thread baru untuk menangani client
        std::thread clientThread(HandleClient, clientSocket, std::string(clientIp));
        clientThread.detach();
    }

    // Cleanup
    closesocket(serverSocket);
    WSACleanup();
}

// Fungsi untuk menampilkan menu
void ShowMenu()
{
    std::cout << "=== " << SERVER_NAME << " v" << SERVER_VERSION << " ===" << std::endl;
    std::cout << "1. Mulai Server" << std::endl;
    std::cout << "2. Lihat Client Terhubung" << std::endl;
    std::cout << "3. Lihat Laporan Cheat" << std::endl;
    std::cout << "4. Keluar" << std::endl;
    std::cout << "Pilihan: ";
}

// Fungsi utama
int main()
{
    std::cout << "Menginisialisasi " << SERVER_NAME << "..." << std::endl;
    
    int choice;
    std::thread serverThread;
    
    while (true)
    {
        ShowMenu();
        std::cin >> choice;
        
        switch (choice)
        {
        case 1:
            if (!g_serverRunning)
            {
                std::cout << "Memulai server..." << std::endl;
                serverThread = std::thread(RunServer);
                serverThread.detach();
            }
            else
            {
                std::cout << "Server sudah berjalan." << std::endl;
            }
            break;
        case 2:
            {
                std::lock_guard<std::mutex> lock(g_clientsMutex);
                std::cout << "Client terhubung: " << g_clients.size() << std::endl;
                for (const auto& client : g_clients)
                {
                    std::cout << "Username: " << client.second.username << ", IP: " << client.second.ipAddress << std::endl;
                }
            }
            break;
        case 3:
            {
                std::lock_guard<std::mutex> lock(g_reportsMutex);
                std::cout << "Laporan cheat: " << g_cheatReports.size() << std::endl;
                for (const auto& report : g_cheatReports)
                {
                    std::cout << "Waktu: " << report.timestamp << ", Proses: " << report.processName << ", Tipe: " << report.cheatType << std::endl;
                }
            }
            break;
        case 4:
            std::cout << "Menutup server..." << std::endl;
            g_serverRunning = false;
            WSACleanup();
            return 0;
        default:
            std::cout << "Pilihan tidak valid." << std::endl;
            break;
        }
        
        std::cout << std::endl;
    }
    
    return 0;
}