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

enum PEER_CON_FLAGS {
    PEER_CON_TCP_CLIENT = 1,
    PEER_CON_TCP_SERVER = 2,
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
        long uptime;
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

        lite_p2p::base_socket *sock = NULL;
        lite_p2p::base_socket *new_sock = NULL;
        std::string local_addr;
        int connection_type;
        int type = PEER_CON_TCP_SERVER;

        connection(sa_family_t _family, std::string _addr, uint16_t _port, int _type, int _protocol);
        connection(sa_family_t _family, std::string _addr, uint16_t _port);
        connection(sa_family_t family, uint16_t port);
        connection(lite_p2p::base_socket *s, std::string _addr, uint16_t _port);
        connection(uint16_t port);

        base_socket * connect(struct sockaddr_t *remote);
        base_socket * listen(struct sockaddr_t *remote, int n);
        base_socket * estabilish(struct sockaddr_t *remote, int n);

        ssize_t send(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len, int flags, struct sockaddr_t *r);
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