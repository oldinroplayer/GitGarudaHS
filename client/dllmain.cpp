#include "pch.h"
#include "../include/ProcessThreadWatcher.h"
#include "../include/OverlayScanner.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

static SOCKET g_logSocket = INVALID_SOCKET;

// Inisialisasi koneksi ke server logging (127.0.0.1:9876)
void InitLogSocket() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return;
    }
    g_logSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_logSocket == INVALID_SOCKET) {
        return;
    }
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(9876);
    inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr);
    connect(g_logSocket, (sockaddr*)&serv, sizeof(serv));
}

// Kirim string ke server
void LogToServer(const std::string& msg) {
    if (g_logSocket != INVALID_SOCKET) {
        send(g_logSocket, msg.c_str(), static_cast<int>(msg.size()), 0);
    }
}

// Konversi std::wstring ke UTF?8 std::string
std::string Narrow(const std::wstring& ws) {
    int len = WideCharToMultiByte(
        CP_UTF8, 0,
        ws.c_str(), -1,
        nullptr, 0,
        nullptr, nullptr
    );
    if (len <= 0) return {};
    std::string s(len, '\0');
    WideCharToMultiByte(
        CP_UTF8, 0,
        ws.c_str(), -1,
        &s[0], len,
        nullptr, nullptr
    );
    return s;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    static std::thread worker;
    if (reason == DLL_PROCESS_ATTACH) {
        // Tampilkan pesan bahwa DLL ter-load
        MessageBoxA(NULL, "GarudaHS Loaded!", "Garuda Hack Shield", MB_OK);

        // Setup logging ke server
        InitLogSocket();
        LogToServer("[GarudaHS] Connected to server\n");

        // Inisialisasi modul?modul
        GarudaHS::ProcessThreadWatcher::Initialize();
        GarudaHS::OverlayScanner::Initialize();

        // Jalankan loop tick di thread terpisah
        worker = std::thread([]() {
            while (true) {
                GarudaHS::ProcessThreadWatcher::Tick();
                GarudaHS::OverlayScanner::Tick();
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            });
        worker.detach();
    }
    return TRUE;
}
