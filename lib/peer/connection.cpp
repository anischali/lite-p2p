#include <vector>
#include "lite-p2p/peer/connection.hpp"
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/protocol/stun/attrs.hpp"

using namespace lite_p2p;
using namespace lite_p2p::peer;
using namespace lite_p2p::protocol::stun;
using namespace lite_p2p::protocol::turn;

connection::connection(sa_family_t family, std::string _addr, uint16_t _port, int type, int protocol) : local_addr{_addr}
{
    timeval tv = {.tv_sec = 5};
    const int enable = 1;

    sock = new lite_p2p::ssocket(family, type, protocol);
    if (!sock)
    {
        throw std::runtime_error("failed to create socket");
    }

    sock->set_sockopt(SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    sock->set_sockopt(SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    sock->set_sockopt(SOL_SOCKET, SO_RCVTIMEO_NEW, &tv, sizeof(tv));

    network::string_to_addr(family, _addr, &local);
    network::set_port(&local, _port);

    sock->bind(&local);
};

connection::connection(uint16_t _port) : connection(AF_INET, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP) {
                                         };

connection::connection(sa_family_t _family, uint16_t _port) : connection(_family, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP) {
                                                              };

connection::connection(sa_family_t _family, std::string _addr, uint16_t _port) : connection(_family, _addr, _port, SOCK_DGRAM, IPPROTO_UDP) {
                                                                                 };

connection::connection(lite_p2p::base_socket *s, std::string _addr, uint16_t _port) : sock{s}, local_addr{_addr}
{
    timeval tv = {.tv_sec = 5};
    const int enable = 1;

    sock->set_sockopt(SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    sock->set_sockopt(SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    sock->set_sockopt(SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    network::string_to_addr(s->family, _addr, &local);
    network::set_port(&local, _port);

    sock->bind(&local);
}

connection::~connection()
{
    if (new_sock != NULL && sock != new_sock)
        delete new_sock;

    new_sock = NULL;
    sock = NULL;
};

ssize_t connection::send(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len, struct sockaddr_t *r)
{

    if (!nsock)
        return -ENOENT;

    switch (connection_type)
    {
    case PEER_DIRECT_CONNECTION:
        if (nsock->protocol == IPPROTO_TCP)
            return nsock->send(buf, len);

        return nsock->send_to(buf, len, 0, r);

    case PEER_RELAYED_CONNECTION:
        if (!relay || !session)
            return -1;

        std::vector<uint8_t> s_buf(buf, buf + len);
        if (session->channel != 0)
            return relay->send_channel(r, session->channel, s_buf);

        return relay->send_request_data(r, s_buf);
    }

    return -EINVAL;
}

ssize_t connection::send(uint8_t *buf, size_t len)
{

    return sock->send_to(buf, len, 0, &remote);
}

ssize_t connection::send(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len)
{

    return send(nsock, buf, len, &remote);
}

ssize_t connection::send(lite_p2p::base_socket *nsock, std::vector<uint8_t> &buf)
{
    return send(nsock, buf.data(), buf.size(), &remote);
}

ssize_t connection::send(std::vector<uint8_t> &buf)
{

    return send(sock, buf.data(), buf.size(), &remote);
}

ssize_t connection::recv(lite_p2p::base_socket *nsock, uint8_t *buf, size_t len, struct sockaddr_t *r)
{
    if (nsock->protocol == IPPROTO_TCP)
        return nsock->recv(buf, len);

    return nsock->recv_from(buf, len, 0, r);
}

ssize_t connection::recv(uint8_t *buf, size_t len, struct sockaddr_t *r)
{
    int ret = 0, offset;
    struct stun_packet_t *p;
    struct stun_attr_t attr;
    size_t length;

    ret = recv(sock, buf, len, r);
    if (ret <= 0)
        return -errno;

    switch (connection_type)
    {
    case PEER_DIRECT_CONNECTION:
        return ret;

    case PEER_RELAYED_CONNECTION:
        if (session->channel != 0)
        {
            length = std::min(len, (size_t)htons(*(uint16_t *)&buf[2]));
            if (length > 0)
                memmove(&buf[0], &buf[4], length);
            return length;
        }

        p = (struct stun_packet_t *)&buf[0];
        offset = stun_attr_find_offset(p, STUN_ATTR_DATA);
        attr = STUN_ATTR_H(&p->attributes[offset], &p->attributes[offset + 2], &p->attributes[offset + 4]);
        if (attr.type != STUN_ATTR_DATA)
            return -EINVAL;

        length = std::min(len, (size_t)attr.length);
        if (length > 0)
            memmove(&buf[0], &attr.value[0], attr.length);

        return length;
    }

    return -EINVAL;
}

ssize_t connection::recv(lite_p2p::base_socket *nsock, std::vector<uint8_t> &buf, struct sockaddr_t *r)
{
    return recv(nsock, buf.data(), buf.size(), r);
}

ssize_t connection::recv(std::vector<uint8_t> &buf, struct sockaddr_t *r)
{

    return recv(sock, buf.data(), buf.size(), r);
};
