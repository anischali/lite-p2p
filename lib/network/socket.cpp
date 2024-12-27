#include <lite-p2p/network/socket.hpp>

using namespace lite_p2p;

s_socket::s_socket(struct secure_sockctx_t &ctx)
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

base_socket s_socket::listen(int n)
{
    return base_socket();
}

base_socket s_socket::accept(struct sockaddr_t *addr)
{
    return base_socket();
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

size_t s_socket::recv(void *buf, size_t len, int flags)
{
    return 0;
}