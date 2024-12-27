#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include <string>
#include <lite-p2p/protocol/turn/client.hpp>
#include <lite-p2p/protocol/stun/client.hpp>
#include <lite-p2p/network/network.hpp>
#include <lite-p2p/network/socket.hpp>
#include <lite-p2p/types/types.hpp>

enum _peer_connection_type {
    PEER_DIRECT_CONNECTION = 1,
    PEER_RELAYED_CONNECTION,
};

namespace lite_p2p::peer
{
    template <typename T> class peer_info {
        public:
            peer_info(T s_key) {
                key = s_key;
            };

            peer_info() {
                key = lite_p2p::crypto::crypto_random_bytes(sizeof(T) * 8);
            };

        T key;
        struct sockaddr_t addr;
        struct timeval last_seen;
        int status;
    };

    class connection
    {
    public:
        struct sockaddr_t local;
        struct sockaddr_t remote;

        struct stun_session_t *session;
        lite_p2p::protocol::turn::client *relay;

        lite_p2p::base_socket *sock; 
        std::string local_addr;
        int connection_type;

        connection(sa_family_t _family, std::string _addr, uint16_t _port, int _type, int _protocol);
        connection(sa_family_t _family, std::string _addr, uint16_t _port);
        connection(sa_family_t family, uint16_t port);
        connection(base_socket s);
        connection(uint16_t port);

        int socket_fd() {return sock->fd; };

        ssize_t send(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len, struct sockaddr_t *r);
        ssize_t send(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len);
        ssize_t send(uint8_t *buf, size_t len);
        ssize_t send(lite_p2p::base_socket *nsock, std::vector<uint8_t> &buf);
        ssize_t send(std::vector<uint8_t> &buf);

        ssize_t recv(std::vector<uint8_t> &buf, struct sockaddr_t *r);
        ssize_t recv(lite_p2p::base_socket *nsock, std::vector<uint8_t> &buf, struct sockaddr_t *r);
        ssize_t recv(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len, struct sockaddr_t *r);
        ssize_t recv(uint8_t *buf, size_t len, struct sockaddr_t *r);
              
        ~connection();
    };
};

#endif