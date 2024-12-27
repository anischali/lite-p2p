#ifndef __SOCKET_HPP__
#define __SOCKET_HPP__
#include <unistd.h>
#include <stdexcept>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <lite-p2p/crypto/crypto.hpp>
#include <lite-p2p/network/network.hpp>


namespace lite_p2p
{
    class base_socket
    {
    public:
        int fd;
        sa_family_t family;
        int type;
        int protocol;
        explicit base_socket(sa_family_t _family, int _type, int _protocol) : 
            family{_family}, type{_type}, protocol{_protocol}
        {
            try
            {
                fd = socket(family, type, protocol);
                if (fd <= 0)
                    throw std::runtime_error("failed to open socket");

            }
            catch (const std::exception &e)
            {
                throw e;
            }
        };

        explicit base_socket(int _fd) {
            try
            {

                fd = _fd;
                if (fd <= 0)
                    throw std::runtime_error("failed to open socket");
            }
            catch (const std::exception &e)
            {
                throw e;
            }
        };

        virtual ~base_socket() {
            close(fd);
        };

        virtual int bind(struct sockaddr_t *addr) = 0;
        virtual int connect(struct sockaddr_t *addr) = 0;
        virtual base_socket *listen(int n) = 0;
        virtual base_socket *accept(struct sockaddr_t *addr) = 0;
        virtual size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr) = 0;
        virtual size_t send(void *buf, size_t len) = 0;
        virtual size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote) = 0;
        virtual size_t recv(void *buf, size_t len) = 0;
        int set_sockopt(int level, int opt, const void *value, size_t len) { return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, value, len); };
    };

    class n_socket : public base_socket
    {
    public:
        n_socket(sa_family_t _family, int _type, int _protocol) : base_socket(_family, _type, _protocol) {};
        n_socket(int _fd) : base_socket(_fd) {};

        int bind(struct sockaddr_t *addr) override { return lite_p2p::network::bind_socket(fd, addr); };
        int connect(struct sockaddr_t *addr) override { return lite_p2p::network::connect_socket(fd, addr); };
        base_socket *listen(int n) { return new n_socket(lite_p2p::network::listen_socket(fd, n)); };
        base_socket *accept(struct sockaddr_t *addr) override { return new n_socket(lite_p2p::network::accept_socket(fd, addr)); };
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr) override { return lite_p2p::network::send_to(fd, buf, len, flags, addr); };
        size_t send(void *buf, size_t len) override { return write(fd, buf, len); };
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote) override { return lite_p2p::network::recv_from(fd, buf, len, flags, remote); };
        size_t recv(void *buf, size_t len) override { return read(fd, buf, len); };
    };

    class s_socket : public base_socket
    {
    private:
        const SSL_METHOD *method;
        SSL_CTX *ctx;
        EVP_PKEY *keys;
    
    public:
        s_socket(sa_family_t _family, int _type, int _protocol, EVP_PKEY *pkey);
        ~s_socket();

        int bind(struct sockaddr_t *addr);
        int connect(struct sockaddr_t *addr);
        base_socket *listen(int n);
        base_socket *accept(struct sockaddr_t *addr);
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr);
        size_t send(void *buf, size_t len);
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote);
        size_t recv(void *buf, size_t len);
    };
};

#endif