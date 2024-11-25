#include <vector>
#include "lite-p2p/peer_connection.hpp"

using namespace lite_p2p;

peer_connection::peer_connection(int family, short port, std::string addr, int type, int protocol) : 
    family {family}, type{type}, protocol{protocol}, local_addr{addr} {
    timeval tv = { .tv_sec = 5 };
    int enable = 1;
        
    sock_fd = socket(family, type, protocol);
    if (sock_fd <= 0) {
        printf("failed to open socket\n");
        return;
    }
    
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    
    if (family == AF_INET) {
        if (addr.length() == 0)
        {
            local.ipv4_addr.sin_addr.s_addr = INADDR_ANY;
        }
        else {
            inet_pton(AF_INET, addr.c_str(), &local.ipv4_addr.sin_addr.s_addr);
        }

        local.ipv4_addr.sin_family = AF_INET;
        local.ipv4_addr.sin_port = htons(port);
        bind(sock_fd, (struct sockaddr *)&local.ipv4_addr, sizeof(local.ipv4_addr));
    }
    else if (family == AF_INET6) {
        if (addr.length() == 0) {
            memcpy(&local.ipv6_addr.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
        }
        else {
            inet_pton(AF_INET6, addr.c_str(), &local.ipv6_addr.sin6_addr);
        }
        
        local.ipv6_addr.sin6_family = AF_INET6;
        local.ipv6_addr.sin6_port = htons(port);
        bind(sock_fd, (struct sockaddr *)&local.ipv6_addr, sizeof(local.ipv6_addr));
    }
};

peer_connection::peer_connection(short port) : peer_connection(AF_INET, port, std::string(""), SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::peer_connection(int _family, short _port) : peer_connection(_family, _port, std::string(""), SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::~peer_connection() {
    close(sock_fd);
};