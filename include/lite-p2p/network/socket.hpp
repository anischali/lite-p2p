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

struct sockctx_t
{
    sa_family_t family;
    int type;
    int protocol;
};

struct secure_sockctx_t
{
    sa_family_t family;
    int type;
    int protocol;
    EVP_PKEY *pkey;
};

namespace lite_p2p
{
    class base_socket
    {
    protected:
        int fd;

    public:
        virtual int bind(struct sockaddr_t *addr);
        virtual int connect(struct sockaddr_t *addr);
        virtual base_socket listen(int n);
        virtual base_socket accept(struct sockaddr_t *addr);
        virtual size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr);
        virtual size_t send(void *buf, size_t len);
        virtual size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote);
        virtual size_t recv(void *buf, size_t len, int flags);
        virtual int set_sockopt(int level, int opt, void *value, size_t len);
    };

    class n_socket : base_socket
    {
    public:
        n_socket(struct sockctx_t &ctx)
        {
            try
            {
                fd = socket(ctx.family, ctx.type, ctx.protocol);
                if (fd <= 0)
                    throw std::runtime_error("failed to open socket");

            }
            catch (const std::exception &e)
            {
                throw e;
            }
        };

        n_socket(int _fd)
        {
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

        ~n_socket()
        {
            close(fd);
        };

        int bind(struct sockaddr_t *addr) { return lite_p2p::network::bind_socket(fd, addr); };
        int connect(struct sockaddr_t *addr) { return lite_p2p::network::connect_socket(fd, addr); };
        base_socket listen(int n) { return n_socket(lite_p2p::network::listen_socket(fd, n)); };
        base_socket accept(struct sockaddr_t *addr) { return n_socket(lite_p2p::network::accept_socket(fd, addr)); };
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr) { return lite_p2p::network::send_to(fd, buf, len, flags, addr); };
        size_t send(void *buf, size_t len) { return write(fd, buf, len); };
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote) { return lite_p2p::network::recv_from(fd, buf, len, flags, remote); };
        size_t recv(void *buf, size_t len) { return read(fd, buf, len); };
        int set_sockopt(int level, int opt, void *value, size_t len) { return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, value, len); };
    };

    class s_socket : base_socket
    {
    private:
        SSL_CTX *ctx;
        EVP_PKEY *keys;
    
    public:
        s_socket(struct secure_sockctx_t &ctx);
        ~s_socket();

        int bind(struct sockaddr_t *addr);
        int connect(struct sockaddr_t *addr);
        base_socket listen(int n);
        base_socket accept(struct sockaddr_t *addr);
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr);
        size_t send(void *buf, size_t len);
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote);
        size_t recv(void *buf, size_t len, int flags);
        int set_sockopt(int level, int opt, void *value, size_t len) { return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, value, len); };
    };
};

#endif