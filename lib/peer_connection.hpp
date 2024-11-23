#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include "stun_client.hpp"

class udp_peer_connection {

public:
    struct sockaddr_in local;
    struct sockaddr_in remote;
    stun_client *s_client;
    int sock_fd;

    udp_peer_connection(short port);
    ~udp_peer_connection();
};


#endif