#include <map>
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
    offset += stun_attr_software(&attrs[offset], session->software);
    offset += stun_attr_lifetime(&attrs[offset], htonl(3600)); // one hour
    offset += stun_attr_request_transport(&attrs[offset], session->protocol);
    offset += stun_attr_dont_fragment(&attrs[offset]);
    packet.msg_len = htons(offset);
    if (retry_attrs) {
        offset += stun_attr_user(&attrs[offset], session->user);
        offset += stun_attr_realm(&attrs[offset], session->realm);
        offset += stun_attr_nonce(&attrs[offset], session->nonce);
        offset += stun_attr_pass_algorithms(&attrs[offset], session->algorithms);
        //offset += stun_attr_pass_algorithm(&attrs[offset], algos[session->key_algo].stun_alg);
        packet.msg_len = htons(offset + algos[SHA_ALGO_SHA1].length + 4);
        offset += stun_attr_msg_hmac(&algos[SHA_ALGO_SHA1], 
                    STUN_ATTR_INTEGRITY_MSG, 
                    (uint8_t *)&packet, &attrs[offset], 
                    session->key[session->key_algo]);

        //packet.msg_len = htons(offset + algos[SHA_ALGO_SHA256].length + 4);
        //offset += stun_attr_msg_hmac(&algos[SHA_ALGO_SHA256], 
        //            STUN_ATTR_INTEGRITY_MSG_SHA256, 
        //            (uint8_t *)&packet, &attrs[offset], 
        //            session->key[session->key_algo]);
        packet.msg_len = htons(offset + 8);
        offset += stun_attr_fingerprint((uint8_t *)&packet, &attrs[offset]);
    }

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
            
            break;
        case STUN_ATTR_XOR_RELAYED_ADDR:
            
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
                    (uint8_t *)&packet, &attrs[i], 
                    session->key[session->key_algo]))
                return -STUN_ERR_UNAUTH;
            break;
            
        case STUN_ATTR_FINGERPRINT:
            if (!stun_attr_check_fingerprint((uint8_t *)&packet, &attrs[i]))
                return -EINVAL;
            break;
        }
    }

    
    return 0;
}



