#ifndef __PEER_CONNECTION_HPP__
#define __PEER_CONNECTION_HPP__
#include <string>
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/protocol/turn/client.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/litetypes.hpp"

enum _peer_connection_type {
    PEER_DIRECT_CONNECTION = 1,
    PEER_RELAYED_CONNECTION,
};

namespace lite_p2p
{
    template <typename T> class lite_peer {
        public:
            lite_peer(T s_key) {
                key = s_key;
            };

            lite_peer() {
                key = lite_p2p::crypto::crypto_random_bytes(sizeof(T) * 8);
            };

        T key;
        struct sockaddr_t addr;
        struct timeval last_seen;
        int status;
    };

    class peer_connection
    {
    public:
        int fd;
        struct sockaddr_t local;
        struct sockaddr_t remote;

        struct stun_session_t *session;
        lite_p2p::protocol::turn::client *relay;

        int sock_fd; 
        sa_family_t family;
        std::string local_addr;
        int type;
        int protocol;
        int connection_type;

        peer_connection(sa_family_t _family, std::string _addr, uint16_t _port, int _type, int _protocol);
        peer_connection(sa_family_t _family, std::string _addr, uint16_t _port);
        peer_connection(sa_family_t family, uint16_t port);
        peer_connection(uint16_t port);

        ssize_t send(int fd, uint8_t *buf, size_t len, struct sockaddr_t *r);
        ssize_t send(int fd, uint8_t *buf, size_t len);
        ssize_t send(uint8_t *buf, size_t len);
        ssize_t send(int fd, std::vector<uint8_t> &buf);
        ssize_t send(std::vector<uint8_t> &buf);

        ssize_t recv(std::vector<uint8_t> &buf, struct sockaddr_t *r);
        ssize_t recv(int new_fd, std::vector<uint8_t> &buf, struct sockaddr_t *r);
        ssize_t recv(int new_fd, uint8_t *buf, size_t len, struct sockaddr_t *r);
        ssize_t recv(uint8_t *buf, size_t len, struct sockaddr_t *r);
              
        ~peer_connection();
    };
};

#endif