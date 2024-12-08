#include <vector>
#include "lite-p2p/peer_connection.hpp"

using namespace lite_p2p;

peer_connection::peer_connection(sa_family_t _family, std::string _addr, uint16_t _port, int _type, int _protocol) : 
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

peer_connection::peer_connection(uint16_t _port) : peer_connection(AF_INET, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::peer_connection(sa_family_t _family, uint16_t _port) : peer_connection(_family, std::string(""), _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::peer_connection(sa_family_t _family, std::string _addr, uint16_t _port) : peer_connection(_family, _addr, _port, SOCK_DGRAM, IPPROTO_UDP)
{
};

peer_connection::~peer_connection() {
    close(sock_fd);
};

ssize_t peer_connection::send(int fd, uint8_t *buf, size_t len, struct sockaddr_t *r) {

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
        return relay->send_request_data(session, r, s_buf);
    }

    return -EINVAL;
}


ssize_t peer_connection::send(uint8_t *buf, size_t len) {

    return send(sock_fd, buf, len, &remote);
}

ssize_t peer_connection::send(int fd, uint8_t *buf, size_t len) {

    return send(fd, buf, len, &remote);
}


ssize_t peer_connection::send(int new_fd, std::vector<uint8_t> &buf) {
    return send(new_fd, buf.data(), buf.size(), &remote);
}



ssize_t peer_connection::send(std::vector<uint8_t> &buf) {

    return send(sock_fd, buf.data(), buf.size(), &remote);
}

ssize_t peer_connection::recv(int new_fd, uint8_t *buf, size_t len, struct sockaddr_t *r) {
    if (protocol == IPPROTO_TCP)
        return read(new_fd, buf, len);    
    
    return network::recv_from(new_fd, buf, len, r);   
}

ssize_t peer_connection::recv(uint8_t *buf, size_t len, struct sockaddr_t *r) {
    if (protocol == IPPROTO_TCP)
        return read(sock_fd, buf, len);    
    
    return network::recv_from(sock_fd, buf, len, r);   
}

ssize_t peer_connection::recv(int new_fd, std::vector<uint8_t> &buf, struct sockaddr_t *r) {
    return recv(new_fd, buf.data(), buf.size(), r);
}

ssize_t peer_connection::recv(std::vector<uint8_t> &buf, struct sockaddr_t *r) {

    return recv(sock_fd, buf.data(), buf.size(), r);
};
