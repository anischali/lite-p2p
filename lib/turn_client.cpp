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

#define STUN_ATTRS_SEND_REQUEST \
{ \
    STUN_ATTR_REALM, \
    STUN_ATTR_SOFTWARE, \
    STUN_ATTR_NONCE, \
    STUN_ATTR_INTEGRITY_MSG, \
    STUN_ATTR_DONT_FRAGMENT, \
}

int turn_client::allocate_request(struct stun_session_t *session) {
    int ret = 0;
    uint16_t msg_type = stun_type(STUN_ALLOCATE, STUN_TYPE_REQUEST);
    std::vector<uint16_t> attrs(STUN_ATTRS_ALLOCATE);
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
    if (ret == -STUN_ERR_UNAUTH) {
        attrs.insert(attrs.end(), STUN_ATTRS_LONG_TERM);
        goto retry;
    }
    if (ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry_id;

    return ret;
}

int turn_client::refresh_request(struct stun_session_t *session, uint32_t lifetime) {
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

int turn_client::send_request_data(struct stun_session_t *session, struct sockaddr_t *peer, std::vector<uint8_t> &buf) {
    uint16_t msg_type = stun_type(STUN_SEND_REQUEST, STUN_TYPE_INDICATION);
    struct stun_packet_t packet(msg_type);
    std::vector<uint16_t> attrs(STUN_ATTRS_LONG_TERM);
    struct sockaddr_t a_tmp;
    int ret = 0, offset;

    stun_xor_addr(&packet, &a_tmp, peer);
retry:
    packet.msg_type = msg_type;
    packet.msg_len = offset = 0;
    stun_remove_unsupported_attrs(session, attrs);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_XOR_PEER_ADDR, &a_tmp);
    offset += stun_attr_add_value(&packet.attributes[offset], STUN_ATTR_DATA, &buf);
    //offset += stun_add_attrs(session, &packet, attrs, offset);
    
    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, attrs);
    if (ret == -STUN_ERR_UNAUTH || ret == -STUN_ERR_UNKNOWN_ATTR)
        goto retry;

    return buf.size();
}


int turn_client::create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer) {
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


int turn_client::bind_channel_request(struct stun_session_t *session, struct sockaddr_t *peer, int chanel_id) {
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

struct sockaddr_t * turn_client::stun_get_relayed_addr(struct sockaddr_t *stun_server) {
    struct stun_session_t *session = sessions.stun_session_get(stun_server);
    if (session)
        return &session->relayed_addr;

    return NULL;
}


