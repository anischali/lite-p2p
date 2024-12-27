#include <lite-p2p/network/socket.hpp>

using namespace lite_p2p;

static inline const SSL_METHOD *ssl_method_by_type(int type)
{

    return (type == SOCK_DGRAM) ? DTLS_method() : nullptr;
}

int s_socket::s_socket_ssl_init()
{
    int ret;

    ctx = SSL_CTX_new(method);
    if (!ctx)
        throw std::runtime_error("failed to create ssl context");

    x509 = lite_p2p::crypto::crypto_pkey_to_x509(keys, x509_info, 86400L); // until tomorrow
    if (!x509)
        throw std::runtime_error("failed to generate x509 certificate");

    ret = SSL_CTX_use_PrivateKey(ctx, keys);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given private key");

    ret = SSL_CTX_use_certificate(ctx, x509);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given certificate key");

    return 0;
}

s_socket::s_socket(sa_family_t _family, int _type, int _protocol, EVP_PKEY *pkey, SSL_METHOD *_method) : base_socket(_family, _type, _protocol),
                                                                                                         keys{pkey}, method{_method}
{
    try
    {
        if (method)
        {
            s_socket_ssl_init();
        }
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

s_socket::s_socket(int _fd, SSL_METHOD *_method) : base_socket(_fd), method{_method}
{
    s_socket_ssl_init();
}

s_socket::~s_socket()
{
    SSL_CTX_free(ctx);
    lite_p2p::crypto::crypto_free_x509(&x509);
    close(fd);
}

int s_socket::bind(struct sockaddr_t *addr)
{
    lite_p2p::network::bind_socket(fd, addr);
}

int s_socket::connect(struct sockaddr_t *addr)
{
    return 0;
}

int s_socket::listen(int n)
{
    return network::listen_socket(fd, n);
}

base_socket *s_socket::accept(struct sockaddr_t *addr)
{
    int nfd = lite_p2p::network::accept_socket(fd, addr);

    
}

size_t s_socket::send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr)
{
    return 0;
}

size_t s_socket::send(void *buf, size_t len)
{
    return 0;
}

size_t s_socket::recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote)
{
    return 0;
}

size_t s_socket::recv(void *buf, size_t len)
{
    return 0;
}