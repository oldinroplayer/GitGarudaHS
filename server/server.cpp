#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

int main() {
    // Inisialisasi Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    // Setup listening socket
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in svc{ AF_INET, htons(9876), INADDR_ANY };
    bind(listenSock, (sockaddr*)&svc, sizeof(svc));
    listen(listenSock, SOMAXCONN);
    std::cout << "GarudaHS Server listening on port 9876...\n";

    // Accept client
    SOCKET clientSock = accept(listenSock, nullptr, nullptr);
    std::cout << "Client connected for logging\n";

    // Terima dan print log
    const int BUF_SIZE = 1024;
    char buffer[BUF_SIZE];
    int received;
    while ((received = recv(clientSock, buffer, BUF_SIZE - 1, 0)) > 0) {
        buffer[received] = '\0';
        std::cout << buffer;
    }

    // Cleanup
    closesocket(clientSock);
    closesocket(listenSock);
    WSACleanup();
    return 0;
}
