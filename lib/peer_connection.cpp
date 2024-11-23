#include "peer_connection.hpp"


udp_peer_connection::udp_peer_connection(short port) {
    timeval tv = { .tv_sec = 5 };
    int enable = 1;
        
    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd > 0) {
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
        setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_family = AF_INET;
    local.sin_port = htons(port);

    bind(sock_fd, (struct sockaddr *)&local, sizeof(local));
};

udp_peer_connection::~udp_peer_connection() {
    close(sock_fd);
};