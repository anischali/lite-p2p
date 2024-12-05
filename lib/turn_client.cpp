#include <map>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}

#define STUN_ATTRS_LONG_TERM \
{ \
    STUN_ATTR_USERNAME, \
    STUN_ATTR_REALM, \
    STUN_ATTR_NONCE, \
    STUN_ATTR_INTEGRITY_MSG, \
    STUN_ATTR_INTEGRITY_MSG_SHA256, \
    STUN_ATTR_FINGERPRINT \
}

#define STUN_ATTRS_ALLOCATE \
{ \
    STUN_ATTR_LIFETIME, \
    STUN_ATTR_REQUESTED_TRANSPORT, \
    STUN_ATTR_REQUESTED_ADDR_FAMILY, \
    STUN_ATTR_ADDITIONAL_ADDR_FAMILY, \
    STUN_ATTR_DONT_FRAGMENT, \
}

int turn_client::allocate_request(struct stun_session_t *session) {
    int ret = 0;
    session->liftime = 3600;
    std::vector<uint16_t> attrs(STUN_ATTRS_ALLOCATE);

retry_id:
    struct stun_packet_t packet(STUN_ALLOCATE);
retry:
    packet.msg_type = htons(STUN_ALLOCATE);
    packet.msg_len = 0;
    stun_remove_unsupported_attrs(session, attrs);
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, attrs, 0));
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH) {
        attrs.insert(attrs.end(), STUN_ATTRS_LONG_TERM);
        goto retry;
    }
    if (ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry_id;

    return ret;
}

int turn_client::refresh_request(struct stun_session_t *session) {
    struct stun_packet_t packet(STUN_REFRESH);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    int ret = 0;

    session->liftime = 3600;
retry:
    
    packet.msg_type = htons(STUN_REFRESH);
    packet.msg_len = 0;
    stun_remove_unsupported_attrs(session, attrs);
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, attrs, 0));
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry;

    return ret;
}

int turn_client::send_request_data(struct stun_session_t *session, struct sockaddr_t *peer, std::vector<uint8_t> &buf) {
    struct stun_packet_t packet(STUN_SEND_REQUEST);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret = 0, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = htons(STUN_SEND_REQUEST);
    packet.msg_len = offset = 0;
    stun_remove_unsupported_attrs(session, attrs);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_XOR_PEER_ADDR, &a_tmp);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_DATA, &buf);
    offset += stun_add_attrs(session, &packet, attrs, offset);
    
    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry;

    return ret;
}


int turn_client::create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer) {
    struct stun_packet_t packet(STUN_CREATE_PERM);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = htons(STUN_CREATE_PERM);
    packet.msg_len = offset = 0;
    stun_remove_unsupported_attrs(session, attrs);
    network::set_port(&a_tmp, 0);
    offset += stun_attr_add_value(&packet.attributes[0], STUN_ATTR_XOR_PEER_ADDR, &a_tmp);
    offset += stun_add_attrs(session, &packet, attrs, offset);

    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry;

    return ret;
}


int turn_client::bind_channel_request(struct stun_session_t *session, struct sockaddr_t *peer, int chanel_id) {
    struct stun_packet_t packet(STUN_CHANNEL_BIND);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = htons(STUN_CHANNEL_BIND);
    packet.msg_len = offset = 0;
    stun_remove_unsupported_attrs(session, attrs);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_CHANNEL_NUM, &chanel_id);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_XOR_PEER_ADDR, &a_tmp);
    offset += stun_add_attrs(session, &packet, attrs, offset);

    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_UNKNOWN_ATTR)
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


