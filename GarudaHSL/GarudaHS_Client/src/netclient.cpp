#include "netclient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

void kirim_laporan_ke_server(const std::wstring& laporan) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    sockaddr_in clientService;

    // Konversi laporan ke UTF-8
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, laporan.c_str(), -1, NULL, 0, NULL, NULL);
    std::string laporan_utf8(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, laporan.c_str(), -1, &laporan_utf8[0], size_needed, NULL, NULL);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // IP dan port server diubah sesuai konfigurasi kamu
    clientService.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &clientService.sin_addr); // ubah IP jika perlu
    clientService.sin_port = htons(5555); // ubah port jika perlu

    if (connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        WSACleanup();
        return;
    }

    send(ConnectSocket, laporan_utf8.c_str(), laporan_utf8.length(), 0);

    char buffer[512] = { 0 };
    int result = recv(ConnectSocket, buffer, sizeof(buffer), 0);
    if (result > 0) {
        std::string response(buffer, result);
        if (response == "TERMINATE") {
            system("taskkill /IM RRO.exe /F");
        }
    }

    closesocket(ConnectSocket);
    WSACleanup();
}
