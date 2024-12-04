#include <vector>
#include "lite-p2p/peer_connection.hpp"

using namespace lite_p2p;

peer_connection::peer_connection(int _family, std::string _addr, short _port, int _type, int _protocol) : 
    family {_family}, local_addr{_addr}, type{_type}, protocol{_protocol} {
    timeval tv = { .tv_sec = 30 };
    int enable = 1;
        
    sock_fd = socket(family, type, protocol);
    if (sock_fd <= 0) {
        printf("failed to open socket\n");
        return;
    }
    
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    
    if (family == AF_INET) {
        struct sockaddr_in *saddr = network::inet_address(&local);
        if (_addr.length() == 0)
        {
            saddr->sin_addr.s_addr = INADDR_ANY;
        }
        else {
            inet_pton(AF_INET, _addr.c_str(), &saddr->sin_addr.s_addr);
        }

        local.sa_family = saddr->sin_family = AF_INET;
        saddr->sin_port = htons(_port);
        bind(sock_fd, (struct sockaddr *)saddr, sizeof(struct sockaddr_in));
    }
    else if (family == AF_INET6) {
        struct sockaddr_in6 *saddr6 = network::inet6_address(&local);
        if (_addr.length() == 0) {
            memcpy(&saddr6->sin6_addr, &in6addr_any, sizeof(struct in6_addr));
        }
        else {
            inet_pton(AF_INET6, _addr.c_str(), &saddr6->sin6_addr);
        }
        local.sa_family = saddr6->sin6_family = AF_INET6;
        saddr6->sin6_port = htons(_port);

        bind(sock_fd, (struct sockaddr *)saddr6, sizeof(struct sockaddr_in6));
    }
};

peer_connection::peer_connection(short _port) : peer_connection(AF_INET, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::peer_connection(int _family, short _port) : peer_connection(_family, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::peer_connection(int _family, std::string _addr, short _port) : peer_connection(_family, _addr, _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::~peer_connection() {
    close(sock_fd);
};