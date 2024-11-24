#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include "stun_client.hpp"

class peer_connection {

public:
    struct sockaddr_in local;
    struct sockaddr_in remote;
    stun_client *s_client;
    int sock_fd, type, protocol;

    peer_connection(short port, int type, int protocol);
    peer_connection(short port);
    ~peer_connection();
};


#endif