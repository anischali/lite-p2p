#include "lite-p2p/turn_client.hpp"


using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}

int turn_client::allocate_request(const char *turn_hostname, short turn_port, int family) {
    struct stun_packet_t packet(STUN_ALLOCATE);
    int ret;

    ret = resolve(family, turn_hostname, &stun_server);
    if (ret < 0)
        return ret;

    return request(&stun_server, &packet);
}