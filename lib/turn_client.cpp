#include <map>
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}


int turn_client::allocate_request(struct stun_session_t *session) {
    struct stun_packet_t packet(STUN_ALLOCATE);
    struct stun_attr_t attr = {0};
    uint8_t *attrs = &packet.attributes[0];
    int ret, len = 0, err_code = 0, offset = 0;

retry:
    packet.msg_type = htons(STUN_ALLOCATE);
    offset = packet.msg_len = 0;
    offset += stun_attr_user(&attrs[offset], session->user);
    offset += stun_attr_realm(&attrs[offset], session->realm);
    offset += stun_attr_nonce(&attrs[offset], session->nonce);
    offset += stun_attr_pass_algorithm(&attrs[offset], session->selected_algo->stun_alg);
    offset += stun_attr_software(&attrs[offset], session->software);
    packet.msg_len += htons(offset + algos[SHA_ALGO_SHA1].length + 4);
    offset += stun_attr_msg_hmac(&algos[SHA_ALGO_SHA1], 
                    STUN_ATTR_INTEGRITY_MSG, 
                    (uint8_t *)&packet, &attrs[offset], 
                    session->key[session->selected_algo->type]);
    packet.msg_len += htons(8);
    offset += stun_attr_fingerprint((uint8_t *)&packet, &attrs[offset]);

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
        case STUN_ATTR_ERR_CODE:
            err_code = ntohl(*(uint32_t *)&attr.value[0]);
            break;
        case STUN_ATTR_NONCE:
            auto nonce = stun_attr_get_nonce(&attr);
            if (err_code == STUN_ERR_STALE_NONCE && session->nonce != nonce) {
                session->nonce = nonce;
                goto retry;
            }
            break;
        }
    }

    return 0;
}