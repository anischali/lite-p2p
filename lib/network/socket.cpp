#include <lite-p2p/network/socket.hpp>

using namespace lite_p2p;

static inline const SSL_METHOD *ssl_method_by_type(int type) {
    
    return (type == SOCK_DGRAM) ? DTLS_method() : nullptr;
}

s_socket::s_socket(sa_family_t _family, int _type, int _protocol, EVP_PKEY *pkey) : base_socket(_family, _type, _protocol), keys{pkey}
{
    try
    {
        method = ssl_method_by_type(type);
        if (method) {
            ctx = SSL_CTX_new(method);
            if (!ctx)
                throw std::runtime_error("failed to create ssl context");
        }
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

s_socket::~s_socket()
{
    close(fd);
}

int s_socket::bind(struct sockaddr_t *addr)
{
    return 0;
}

int s_socket::connect(struct sockaddr_t *addr)
{
    return 0;
}

/*
base_socket s_socket::listen(int n)
{
    return base_socket();
}

base_socket s_socket::accept(struct sockaddr_t *addr)
{
    return base_socket();
}*/

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