#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include <string>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/network.hpp"

namespace lite_p2p
{

    class peer_connection
    {

    public:
        struct sockaddr_t local;
        struct sockaddr_t remote;

        std::string local_addr;
        stun_client *s_client;
        int sock_fd, type, protocol, family;

        peer_connection(int _family, std::string _addr, short _port, int _type, int _protocol);
        peer_connection(int _family, std::string _addr, short _port);
        peer_connection(int family, short port);
        peer_connection(short port);
        ~peer_connection();
    };
};

#endif