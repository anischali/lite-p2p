#ifndef __STUN_ATTRS_HPP__
#define __STUN_ATTRS_HPP__
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

int stun_attr_add_string(uint8_t *attrs, uint16_t attr_type, std::string s);
int stun_attr_add_u8_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint8_t> vec);
int stun_attr_add_u16_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint16_t> vec);
int stun_attr_add_u32_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint32_t> vec);
int stun_attr_add_u32(uint8_t *attrs, uint16_t attr_type, uint32_t val);
int stun_attr_add_bool(uint8_t *attrs, uint16_t attr_type);

#define stun_attr_user(attrs, user) stun_attr_add_string(attrs, STUN_ATTR_USERNAME, user)

#define stun_attr_nonce(attrs, nonce) stun_attr_add_u8_vector(attrs, STUN_ATTR_NONCE, nonce)

#define stun_attr_pass_algorithms(attrs, algs) stun_attr_add_u32_vector(attrs, STUN_ATTR_PASSWD_ALGS, algs)

#define stun_attr_pass_algorithm(attrs, alg) stun_attr_add_u32(attrs, STUN_ATTR_PASSWD_ALG, alg)

#define stun_attr_software(attrs, soft) stun_attr_add_string(attrs, STUN_ATTR_SOFTWARE, soft)

#define stun_attr_realm(attrs, realm) stun_attr_add_string(attrs, STUN_ATTR_REALM, realm)

#define stun_attr_lifetime(attrs, lifetime) stun_attr_add_u32(attrs, STUN_ATTR_LIFETIME, lifetime)

#define stun_attr_request_transport(attrs, type) stun_attr_add_u32(attrs, STUN_ATTR_REQUESTED_TRANSPORT, type)

#define stun_attr_dont_fragment(attrs) stun_attr_add_bool(attrs, STUN_ATTR_DONT_FRAGMENT)

std::vector<uint8_t> stun_attr_get_nonce(struct stun_attr_t *attr);

int stun_attr_fingerprint(uint8_t *msg, uint8_t *attrs);

bool stun_attr_check_fingerprint(uint8_t *msg, uint8_t *attrs);

int stun_attr_msg_hmac(const struct algo_type_t *alg, uint16_t attr_type, uint8_t *msg, uint8_t *attrs, std::vector<uint8_t> key);

bool stun_attr_check_hmac(const struct algo_type_t *alg, uint8_t *msg, uint8_t *attrs, std::vector<uint8_t> key);

void stun_attr_get_mapped_addr(uint8_t *attrs, uint8_t *transaction_id, struct sockaddr_t *addr);

#endif