#include <map>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}

int turn_client::allocate_request(struct stun_session_t *session) {
    int ret = 0;
    bool retry_attrs = false;
    struct stun_packet_t packet(STUN_ALLOCATE);
    session->liftime = 3600;
retry:
    packet.msg_type = htons(STUN_ALLOCATE);
    packet.msg_len = 0;
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, &packet.attributes[0], retry_attrs));
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

int turn_client::refresh_request(struct stun_session_t *session) {
    int ret = 0;
    struct stun_packet_t packet(STUN_REFRESH);
    session->liftime = 3600;
retry:
    packet.msg_type = htons(STUN_REFRESH);
    packet.msg_len = 0;
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, &packet.attributes[0], true));
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet);
    if (ret == -STUN_ERR_UNAUTH)
        goto retry;

    return ret;
}

int turn_client::send_request_data(struct stun_session_t *session, struct sockaddr_t *peer, std::vector<uint8_t> &buf) {
    int ret = 0, offset;
    struct stun_packet_t packet(STUN_SEND_REQUEST);
retry:
    packet.msg_type = htons(STUN_SEND_REQUEST);
    packet.msg_len = offset = 0;
    offset += stun_attr_peer_addr(&packet.attributes[0], packet.transaction_id, peer);
    offset += stun_attr_data(&packet.attributes[offset], buf);
    offset += stun_add_attrs(session, &packet, &packet.attributes[offset], true);
    
    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet);
    if (ret == -STUN_ERR_UNAUTH)
        goto retry;

    return ret;
}


int turn_client::create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer) {
    struct stun_packet_t packet(STUN_CREATE_PERM);
    int ret, offset;

retry:
    packet.msg_type = htons(STUN_CREATE_PERM);
    packet.msg_len = offset = 0;
    offset += stun_attr_peer_addr(&packet.attributes[0], packet.transaction_id, peer);
    offset += stun_add_attrs(session, &packet, &packet.attributes[offset], true);

    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet);
    if (ret == -STUN_ERR_UNAUTH)
        goto retry;

    return ret;
}


int turn_client::bind_channel_request(struct stun_session_t *session, struct sockaddr_t *peer, int chanel_id) {
    struct stun_packet_t packet(STUN_CHANNEL_BIND);
    int ret, offset;

retry:
    packet.msg_type = htons(STUN_CHANNEL_BIND);
    packet.msg_len = offset = 0;
    offset += stun_attr_channel_num(&packet.attributes[offset], chanel_id);
    offset += stun_attr_peer_addr(&packet.attributes[offset], packet.transaction_id, peer);
    offset += stun_add_attrs(session, &packet, &packet.attributes[offset], true);

    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet);
    if (ret == -STUN_ERR_UNAUTH)
        goto retry;

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


