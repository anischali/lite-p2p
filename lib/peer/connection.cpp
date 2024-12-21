#include <vector>
#include "lite-p2p/peer/connection.hpp"
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/protocol/stun/attrs.hpp"

using namespace lite_p2p;
using namespace lite_p2p::peer;
using namespace lite_p2p::protocol::stun;
using namespace lite_p2p::protocol::turn;


connection::connection(sa_family_t _family, std::string _addr, uint16_t _port, int _type, int _protocol) : 
    family {_family}, local_addr{_addr}, type{_type}, protocol{_protocol} {
    timeval tv = { .tv_sec = 5 };
    const int enable = 1;
        
    sock_fd = socket(family, type, protocol);
    if (sock_fd <= 0) {
        printf("failed to open socket\n");
        return;
    }
    
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    network::string_to_addr(family, _addr, &local);
    network::set_port(&local, _port);

    network::bind_socket(sock_fd, &local);
};

connection::connection(uint16_t _port) : connection(AF_INET, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

connection::connection(sa_family_t _family, uint16_t _port) : connection(_family, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

connection::connection(sa_family_t _family, std::string _addr, uint16_t _port) : connection(_family, _addr, _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

connection::~connection() {
    close(sock_fd);
};

ssize_t connection::send(int fd, uint8_t *buf, size_t len, struct sockaddr_t *r) {

    switch (connection_type)
    {
    case PEER_DIRECT_CONNECTION:
        if (protocol == IPPROTO_TCP)
            return write(fd, buf, len);
        
        return network::send_to(fd, buf, len, r);
    
    case PEER_RELAYED_CONNECTION:
        if (!relay || !session)
            return -1;

        std::vector<uint8_t> s_buf(buf, buf + len);
        if (session->channel != 0)
            return relay->send_channel(session, r, session->channel, s_buf);

        return relay->send_request_data(session, r, s_buf);
    }

    return -EINVAL;
}


ssize_t connection::send(uint8_t *buf, size_t len) {

    return send(sock_fd, buf, len, &remote);
}

ssize_t connection::send(int fd, uint8_t *buf, size_t len) {

    return send(fd, buf, len, &remote);
}


ssize_t connection::send(int new_fd, std::vector<uint8_t> &buf) {
    return send(new_fd, buf.data(), buf.size(), &remote);
}



ssize_t connection::send(std::vector<uint8_t> &buf) {

    return send(sock_fd, buf.data(), buf.size(), &remote);
}

ssize_t connection::recv(int new_fd, uint8_t *buf, size_t len, struct sockaddr_t *r) {
    if (protocol == IPPROTO_TCP)
        return read(new_fd, buf, len);    
    
    return network::recv_from(new_fd, buf, len, r);   
}

ssize_t connection::recv(uint8_t *buf, size_t len, struct sockaddr_t *r) {
    int ret = 0, offset;
    struct stun_packet_t *p;
    struct stun_attr_t attr;
    size_t length;

    if (protocol == IPPROTO_TCP)
        return read(sock_fd, buf, len);    
    
    ret = network::recv_from(sock_fd, buf, len, r);   
    if (ret <= 0)
        return -errno;
    
    switch (connection_type)
    {
    case PEER_DIRECT_CONNECTION:
        return ret;
    
    case PEER_RELAYED_CONNECTION:
        if (session->channel != 0) {
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

ssize_t connection::recv(int new_fd, std::vector<uint8_t> &buf, struct sockaddr_t *r) {
    return recv(new_fd, buf.data(), buf.size(), r);
}

ssize_t connection::recv(std::vector<uint8_t> &buf, struct sockaddr_t *r) {

    return recv(sock_fd, buf.data(), buf.size(), r);
};
