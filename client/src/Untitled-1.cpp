#include "pch.h"
#include "../include/ClientSocket.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

namespace {
    SOCKET clientSocket = INVALID_SOCKET;
    bool initialized = false;

    void ListenToServer() {
        char buffer[1024];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0)
                break;

            std::string msg(buffer);

            if (msg.find("DISCONNECT:") == 0) {
                MessageBoxA(NULL, "HWID kamu tidak terdaftar di whitelist.\nSilakan hubungi admin.", "GarudaHS", MB_ICONERROR);
                ExitProcess(0);
            }
        }
    }
}

void ClientSocket::Initialize(const std::string& serverIP, int port) {
    if (initialized)
        return;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET)
        return;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        return;

    initialized = true;
    std::thread(ListenToServer).detach(); // Start listener thread
}

void ClientSocket::SendMessageToServer(const std::string& message) {
    if (!initialized)
        return;

    send(clientSocket, message.c_str(), static_cast<int>(message.length()), 0);
}

void ClientSocket::Shutdown() {
    if (initialized) {
        closesocket(clientSocket);
        WSACleanup();
        initialized = false;
    }
}
