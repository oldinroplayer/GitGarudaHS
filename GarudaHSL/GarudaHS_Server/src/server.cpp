#include "server.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

void jalankan_server() {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;

    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Gagal init WinSock\n";
        return;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr); // localhost
    serverAddr.sin_port = htons(5555);

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind gagal\n";
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen gagal\n";
        closesocket(listenSocket);
        WSACleanup();
        return;
    }

    std::cout << "GarudaHS Server aktif di port 5555...\n";

    while (true) {
        clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept gagal\n";
            continue;
        }

        char buffer[1024] = { 0 };
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived > 0) {
            std::string laporan(buffer, bytesReceived);
            std::cout << "[CLIENT] " << laporan << "\n";

            // Jika laporan berisi "CHEAT", kirim perintah TERMINATE
            if (laporan.find("CHEAT") != std::string::npos) {
                std::string response = "TERMINATE";
                send(clientSocket, response.c_str(), response.size(), 0);
            }
            else {
                std::string response = "OK";
                send(clientSocket, response.c_str(), response.size(), 0);
            }
        }

        closesocket(clientSocket);
    }

    closesocket(listenSocket);
    WSACleanup();
}
