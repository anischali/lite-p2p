#ifndef __STUN_ATTRS_HPP__
#define __STUN_ATTRS_HPP__
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

    struct __attribute__((packed)) stun_attr_t
    {
        uint16_t type;
        uint16_t length;
        uint8_t *value;
    };
#define STUN_ATTR_H(_type, _len, _val) \
    {.type = ntohs(*(uint16_t *)_type), .length = ntohs(*(uint16_t *)_len), .value = (uint8_t *)_val}

#define STUN_ATTR_N(_type, _len, _val) \
    {.type = htons(*(uint16_t *)_type), .length = htons(*(uint16_t *)_len), .value = (uint8_t *)_val}

#define STUN_ATTR(_type, _len, _val) \
    {.type = *(uint16_t *)_type, .length = *(uint16_t *)_len, .value = (uint8_t *)_val}

void stun_remove_unsupported_attrs(struct stun_session_t *session, std::vector<uint16_t> &attrs);
void stun_xor_addr(struct stun_packet_t *packet, struct sockaddr_t *d_addr, struct sockaddr_t *s_addr);
int stun_attr_add_value(uint8_t *attrs, uint16_t attr_type, void *value);
int stun_attr_get_value(uint8_t *attrs, uint16_t attr_type, void *value);
int stun_add_attrs(struct stun_session_t *session, struct stun_packet_t *packet, 
                    std::vector<uint16_t> &s_attrs, int offset);
int stun_process_attrs(struct stun_session_t *session, struct stun_packet_t *packet, 
                            std::vector<uint16_t> &s_attrs);

bool stun_attr_check_hmac(const struct algo_type_t *alg, struct stun_packet_t *packet, uint8_t *attrs, std::vector<uint8_t> key);
int stun_attr_msg_hmac(const struct algo_type_t *alg, uint16_t attr_type, struct stun_packet_t *packet, uint8_t *attrs, std::vector<uint8_t> key);
bool stun_attr_check_fingerprint(struct stun_packet_t *packet, uint8_t *attrs);
#endif