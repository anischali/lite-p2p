#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include <string>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/network.hpp"


enum _peer_connection_type {
    PEER_DIRECT_CONNECTION = 1,
    PEER_RELAYED_CONNECTION,
};

namespace lite_p2p
{

    class peer_connection
    {

    public:
        struct sockaddr_t local;
        struct sockaddr_t remote;

        struct stun_session_t *session;
        struct turn_client *relay;

        int sock_fd; 
        int family;
        std::string local_addr;
        int type;
        int protocol;
        int connection_type;

        peer_connection(int _family, std::string _addr, uint16_t _port, int _type, int _protocol);
        peer_connection(int _family, std::string _addr, uint16_t _port);
        peer_connection(int family, uint16_t port);
        peer_connection(uint16_t port);

        ssize_t send(std::vector<uint8_t> &buf);
        ssize_t recv(std::vector<uint8_t> &buf, struct sockaddr_t *r);
        
        ~peer_connection();
    };
};

#endif