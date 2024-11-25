#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include "stun_client.hpp"
#include "string"

namespace lite_p2p
{

    class peer_connection
    {

    public:
        union
        {
            uint8_t address_buf[32];
            struct sockaddr_in ipv4_addr;
            struct sockaddr_in6 ipv6_addr;
        } local;

        union
        {
            uint8_t address_buf[32];
            struct sockaddr_in ipv4_addr;
            struct sockaddr_in6 ipv6_addr;
        } remote;

        std::string local_addr;
        stun_client *s_client;
        int sock_fd, type, protocol, family;

        peer_connection(int family, short port, std::string addr, int type, int protocol);
        peer_connection(int family, short port);
        peer_connection(short port);
        ~peer_connection();
    };
};

#endif