#include <map>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}

int turn_client::allocate_request(struct stun_session_t *session) {
    struct stun_packet_t packet(STUN_ALLOCATE);
    int ret = 0;
    bool retry_attrs = false;

retry:
    packet.msg_type = htons(STUN_ALLOCATE);
    packet.msg_len = 0;
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, retry_attrs));
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet);
    if (ret == -STUN_ERR_UNAUTH) {
        retry_attrs = true;
        goto retry;
    }

    return ret;
}

struct sockaddr_t * turn_client::stun_get_relayed_addr(struct sockaddr_t *stun_server) {
    std::string s_sha, s_tmp = network::addr_to_string(stun_server) + ":" +
                               std::to_string(network::get_port(stun_server)) + ":" +
                               std::to_string(stun_server->sa_family);

    s_sha = crypto::crypto_base64_encode(crypto::checksum(SHA_ALGO(sha1), s_tmp));

    if (auto s = stun_client::session_db.find(s_sha); s != stun_client::session_db.end())
    {
        return &s->second->mapped_addr;
    }

    return nullptr;
}


