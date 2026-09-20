#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

int main(void) {
    if (GetFileAttributesW(L"hang") != INVALID_FILE_ATTRIBUTES) Sleep(60000);
    if (GetFileAttributesW(L"flood") != INVALID_FILE_ATTRIBUTES) {
        for (int i=0; i<600000; i++) putchar('x');
        return 0;
    }
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data)) return 5;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int socketError = WSAGetLastError();
    u_long nonblocking = 1;
    if (s != INVALID_SOCKET) ioctlsocket(s, FIONBIO, &nonblocking);
    struct sockaddr_in address = {0};
    unsigned short port = 9;
    FILE *portFile = NULL;
    if (fopen_s(&portFile, "network-port", "r") == 0 && portFile) { fscanf_s(portFile, "%hu", &port); fclose(portFile); }
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int connected = s == INVALID_SOCKET ? SOCKET_ERROR : connect(s, (struct sockaddr*)&address, sizeof(address));
    int networkError = s == INVALID_SOCKET ? socketError : WSAGetLastError();
    if (connected == SOCKET_ERROR && networkError == WSAEWOULDBLOCK) {
        fd_set writes, errors;
        FD_ZERO(&writes); FD_SET(s, &writes); FD_ZERO(&errors); FD_SET(s, &errors);
        struct timeval deadline = {2, 0};
        int selected = select(0, NULL, &writes, &errors, &deadline);
        if (selected == 0) networkError = WSAETIMEDOUT;
        else { int size = sizeof(networkError); getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&networkError, &size); if (networkError == 0) connected = 0; }
    }
    closesocket(s);
    WSACleanup();
    HANDLE file = CreateFileW(L"denied-write.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    int writeDenied = file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED;
    if(file != INVALID_HANDLE_VALUE) CloseHandle(file);
    printf("{\"networkDenied\":%s,\"writeDenied\":%s,\"networkError\":%d}", connected == SOCKET_ERROR && (networkError == WSAEACCES || networkError == WSAETIMEDOUT) ? "true" : "false", writeDenied ? "true" : "false", networkError);
    return 0;
}
