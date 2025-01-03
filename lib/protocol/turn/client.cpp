#include <map>
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/protocol/turn/client.hpp"
#include "lite-p2p/protocol/stun/attrs.hpp"
#include "lite-p2p/crypto/crypto.hpp"

using namespace lite_p2p::protocol::turn;

client::client(base_socket *s) : lite_p2p::protocol::stun::client(s) {}

#define STUN_ATTRS_LONG_TERM \
{ \
    STUN_ATTR_USERNAME, \
    STUN_ATTR_SOFTWARE, \
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
    STUN_ATTR_DONT_FRAGMENT, \
}

#define STUN_ATTRS_ALLOCATE_REUSE \
{ \
    STUN_ATTR_LIFETIME, \
    STUN_ATTR_RESERV_TOKEN, \
    STUN_ATTR_DONT_FRAGMENT, \
}

#define STUN_ATTRS_SEND_REQUEST \
{ \
    STUN_ATTR_REALM, \
    STUN_ATTR_SOFTWARE, \
    STUN_ATTR_NONCE, \
    STUN_ATTR_INTEGRITY_MSG, \
    STUN_ATTR_DONT_FRAGMENT, \
}

int client::allocate_request(struct stun_session_t *session) {
    int ret = 0;
    uint16_t msg_type = stun_type(STUN_ALLOCATE, STUN_TYPE_REQUEST);
    std::vector<uint16_t> attrs(STUN_ATTRS_ALLOCATE);
    std::vector<uint8_t> v_tmp;
    session->family == INET_BOTH ? 
        attrs.insert(attrs.begin(), STUN_ATTR_ADDITIONAL_ADDR_FAMILY) : 
        attrs.insert(attrs.begin(), STUN_ATTR_REQUESTED_ADDR_FAMILY);

retry_id:
    struct stun_packet_t packet(msg_type);
retry:
    packet.msg_type = msg_type;
    packet.msg_len = 0;
    stun_remove_unsupported_attrs(session, attrs);
    packet.msg_len = htons((uint16_t)stun_add_attrs(session, &packet, attrs, 0));
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_STALE_NONCE) {
        attrs.insert(attrs.end(), STUN_ATTRS_LONG_TERM);
        goto retry;
    }

    if (ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry_id;
    
    return ret;
}

int client::refresh_request(struct stun_session_t *session, uint32_t lifetime) {
    uint16_t msg_type = stun_type(STUN_REFRESH, STUN_TYPE_REQUEST);
    struct stun_packet_t packet(msg_type);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    int ret = 0;

retry:
    session->lifetime = lifetime;
    packet.msg_type = msg_type;
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

int client::send_request_data(struct stun_session_t *session, struct sockaddr_t *peer, std::vector<uint8_t> &buf) {
    uint16_t msg_type = stun_type(STUN_SEND_REQUEST, STUN_TYPE_INDICATION);
    struct stun_packet_t packet(msg_type);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret = 0, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
    packet.msg_type = msg_type;
    packet.msg_len = offset = 0;
    stun_remove_unsupported_attrs(session, attrs);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_XOR_PEER_ADDR, &a_tmp);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_DATA, &buf);
    
    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet, false);
    if (ret < 0)
        return 0;
    
    return buf.size();
}

int client::send_channel(struct stun_session_t *session, struct sockaddr_t *peer, uint32_t channel_id, std::vector<uint8_t> &buf) {
    int ret = 0;
    uint8_t packet[512];

    *(uint16_t *)&packet[0] = (uint16_t)channel_id;
    *(uint16_t *)&packet[2] = (uint16_t)htons(buf.size());

    memcpy(&packet[4], buf.data(), buf.size());

    ret = send_raw(&session->server, packet, buf.size() + 4);
    if (ret < 0)
        return 0;
    
    return buf.size();
}

int client::create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer) {
    uint16_t msg_type = stun_type(STUN_CREATE_PERM, STUN_TYPE_REQUEST);
    struct stun_packet_t packet(msg_type);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = msg_type;
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


int client::bind_channel_request(struct stun_session_t *session, struct sockaddr_t *peer, uint32_t chanel_id) {
    uint16_t msg_type = stun_type(STUN_CHANNEL_BIND, STUN_TYPE_REQUEST);
    struct stun_packet_t packet(msg_type);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = msg_type;
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

struct sockaddr_t * client::stun_get_relayed_addr(struct sockaddr_t *stun_server) {
    struct stun_session_t *session = sessions.stun_session_get(stun_server);
    if (session)
        return &session->relayed_addr;

    return NULL;
}


