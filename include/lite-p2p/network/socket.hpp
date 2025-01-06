#ifndef __SOCKET_HPP__
#define __SOCKET_HPP__
#include <unistd.h>
#include <stdexcept>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <lite-p2p/crypto/crypto.hpp>
#include <lite-p2p/types/types.hpp>
#include <lite-p2p/common/common.hpp>
#include <lite-p2p/network/network.hpp>

struct tls_ops_t
{
    int (*ssl_peer_validate)(X509 *cert) = NULL;
    int (*ssl_peer_verify)(int ok, X509_STORE_CTX *x509_ctx) = NULL;
    void (*ssl_info)(const SSL *ssl, int where, int ret) = NULL;
    void (*msg_callback) (int write_p, int version, int content_type, const void *buf,
                        size_t len, SSL *ssl, void *arg) = NULL;
    int (*generate_cookie) (SSL *ssl, uint8_t *cookie, uint32_t *len) = NULL;
    int (*verify_cookie) (SSL *ssl, const uint8_t *cookie, uint32_t len) = NULL;
    int (*generate_stateless_cookie) (SSL *ssl, uint8_t *cookie, size_t *len) = NULL;
    int (*verify_stateless_cookie) (SSL *ssl, const uint8_t *cookie, size_t len) = NULL;
};

static inline struct tls_ops_t *lite_tls_default_ops() {
    extern struct tls_ops_t lite_tls_ops;

    return &lite_tls_ops;
}
struct tls_context_t
{
    int ctx_id = lite_p2p::common::rand_int(INT_MAX / 2, INT_MAX);
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    SSL *session = NULL;
    BIO *bio = NULL;
    std::vector<uint8_t> cookie_secret;
    bool cookie_initialized = false;
    struct tls_config_t *cfg = NULL;
};

struct tls_config_t
{
    EVP_PKEY *keys = NULL;
    X509 *x509 = NULL;
    long int x509_expiration = 0;
    long int timeout = 30;
    bool x509_auto_generate = false;
    bool mtu_discover = false;
    int verify_mode = 0;
    int min_version = 0;
    int max_version = 0;
    int cache_mode = SSL_SESS_CACHE_OFF;
    bool stateless = false;

    std::string ciphers = "";
    std::map<std::string, std::string> x509_info = {
        {"C", "US"},
        {"O", "My organization"},
        {"CN", "example.com"}};

    struct tls_ops_t *ops;
};

namespace lite_p2p
{
    class base_socket
    {
    public:
        int fd;
        sa_family_t family;
        int type;
        int protocol;
        explicit base_socket(sa_family_t _family, int _type, int _protocol) : family{_family}, type{_type}, protocol{_protocol}
        {
            try
            {
                fd = socket(family, type, protocol);
                if (fd <= 0)
                    throw std::runtime_error("failed to open socket");

            }
            catch (...)
            {
                throw;
            }
        };

        explicit base_socket(int _fd)
        {
            try
            {
                int ret;
                socklen_t len;
                fd = _fd;
                if (fd <= 0)
                    throw std::runtime_error("failed to open socket");

                ret = get_sockopt(SOL_SOCKET, SO_TYPE, (void *)&type, &(len = sizeof(type)));
                if (ret < 0)
                    std::runtime_error("failed to get socket type");

                ret = get_sockopt(SOL_SOCKET, SO_PROTOCOL, (void *)&protocol, &(len = sizeof(protocol)));
                if (ret < 0)
                    std::runtime_error("failed to get socket protocol");

                ret = get_sockopt(SOL_SOCKET, SO_DOMAIN, (void *)&family, &(len = sizeof(family)));
                if (ret < 0)
                    std::runtime_error("failed to get socket protocol");
            }
            catch (...)
            {
                if (fd > 0)
                    close(fd);

                throw;
            }
        };

        virtual ~base_socket()
        {
            if (fd > 0)
                close(fd);
        };

        virtual bool is_secure() = 0;
        virtual base_socket *duplicate() = 0;
        virtual int bind(struct sockaddr_t *addr) = 0;
        virtual int connect(struct sockaddr_t *addr) = 0;
        virtual int listen(int n) = 0;
        virtual base_socket *accept(struct sockaddr_t *addr) = 0;
        virtual size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr) = 0;
        virtual size_t send(void *buf, size_t len) = 0;
        virtual size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote) = 0;
        virtual size_t recv(void *buf, size_t len) = 0;
        int set_sockopt(int level, int opt, const void *value, size_t len) { return setsockopt(fd, level, opt, value, len); };
        int get_sockopt(int level, int opt, void *value, socklen_t *len) { return getsockopt(fd, level, opt, value, len); };
        int get_sockname(struct sockaddr_t *addr) { return lite_p2p::network::get_sockname(fd, addr); };
        void close_socket(void) {
            close(fd);
            fd = 0;
        };
    };

    class ssocket : public base_socket
    {
    public:
        ssocket(sa_family_t _family, int _type, int _protocol) : base_socket(_family, _type, _protocol) {};
        ssocket(int _fd) : base_socket(_fd) {};

        bool is_secure() override { return false; };
        base_socket *duplicate();

        int bind(struct sockaddr_t *addr) override { return lite_p2p::network::bind_socket(fd, addr); };
        int connect(struct sockaddr_t *addr) override { return lite_p2p::network::connect_socket(fd, addr); };
        int listen(int n) { return lite_p2p::network::listen_socket(fd, n); };
        base_socket *accept(struct sockaddr_t *addr) override { return new ssocket(lite_p2p::network::accept_socket(fd, addr)); };
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr) override { return lite_p2p::network::send_to(fd, buf, len, flags, addr); };
        size_t send(void *buf, size_t len) override { return write(fd, buf, len); };
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote) override { return lite_p2p::network::recv_from(fd, buf, len, flags, remote); };
        size_t recv(void *buf, size_t len) override { return read(fd, buf, len); };
    };

    class tsocket : public base_socket
    {
    private:
        struct tls_context_t tls;
        struct tls_config_t *config;

        int tsocket_ssl_init();
        int tsocket_ssl_accept(struct sockaddr_t *addr, long int timeout_s);
        int tsocket_ssl_connect(struct sockaddr_t *addr, long int timeout_s);
        void tsocket_ssl_cleanup();

    public:
        tsocket(sa_family_t _family, int _type, int _protocol, struct tls_config_t *cfg);
        tsocket(int fd, struct tls_config_t *cfg);
        ~tsocket();


        base_socket *duplicate();
        bool is_secure() override { return true; };
        int bind(struct sockaddr_t *addr);
        int connect(struct sockaddr_t *addr);
        int listen(int n);
        base_socket *accept(struct sockaddr_t *addr);
        size_t send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr);
        size_t send(void *buf, size_t len);
        size_t recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote);
        size_t recv(void *buf, size_t len);

        void tsocket_set_ssl_ops(struct tls_ops_t *ops);
    };
};

#endif 