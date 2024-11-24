#include "peer_connection.hpp"


peer_connection::peer_connection(short port, int type, int protocol) {
    timeval tv = { .tv_sec = 5 };
    int enable = 1;
        
    sock_fd = socket(AF_INET, type, protocol);
    if (sock_fd <= 0) {
        printf("failed to open socket\n");
        return;
    }
    
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_family = AF_INET;
    local.sin_port = htons(port);

    bind(sock_fd, (struct sockaddr *)&local, sizeof(local));
};

peer_connection::peer_connection(short port) : peer_connection(port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::~peer_connection() {
    close(sock_fd);
};