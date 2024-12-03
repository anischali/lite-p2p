#include <map>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}

int turn_client::allocate_request(struct stun_session_t *session) {
    struct stun_packet_t packet(STUN_ALLOCATE);
    std::vector<uint8_t> v_tmp;
    struct stun_attr_t attr = {0};
    uint8_t *attrs = &packet.attributes[0];
    int ret, len = 0, err_code = 0, offset = 0;
    bool retry_attrs = false;

retry:
    packet.msg_type = htons(STUN_ALLOCATE);
    offset = packet.msg_len = 0;
    offset += stun_add_attrs(session, &packet, retry_attrs);
    packet.msg_len = htons(offset);
    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    attrs = &packet.attributes[0];
    len = std::min((uint16_t)ntohs(packet.msg_len), (uint16_t)sizeof(packet.attributes));

    for (int i = 0; i < len; i += (4 + attr.length))
    {
        attr = STUN_ATTR_H(&attrs[i], &attrs[i + 2], &attrs[i + 4]);
        switch (attr.type)
        {
        case STUN_ATTR_XOR_MAPPED_ADDR:
            stun_attr_get_mapped_addr(&attrs[i], packet.transaction_id, &session->mapped_addr);
            break;
        case STUN_ATTR_XOR_RELAYED_ADDR:
            stun_attr_get_mapped_addr(&attrs[i], packet.transaction_id, &session->relayed_addr);
            break;
        case STUN_ATTR_ERR_CODE:
            err_code = ntohl(*(uint32_t *)&attr.value[0]);
            break;
        case STUN_ATTR_NONCE:
            v_tmp = stun_attr_get_nonce(&attr);
            if ((err_code == STUN_ERR_STALE_NONCE || 
                (err_code == STUN_ERR_UNAUTH && !retry_attrs))
                && session->nonce != v_tmp) {
                session->nonce = v_tmp;
                retry_attrs = true;
                goto retry;
            }
        case STUN_ATTR_INTEGRITY_MSG:
            if (!stun_attr_check_hmac(&algos[SHA_ALGO_SHA1], 
                    &packet, &attrs[i], 
                    session->key[session->key_algo]))
                return -STUN_ERR_UNAUTH;
            break;
        case STUN_ATTR_PASSWD_ALGS:
            // TODO: dynamicaly determine algorithms 
            break;
        case STUN_ATTR_FINGERPRINT:
            if (!stun_attr_check_fingerprint(&packet, &attrs[i]))
                return -EINVAL;
            break;
        }
    }


    return 0;
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


