#ifndef __STUN_ATTRS_HPP__
#define __STUN_ATTRS_HPP__
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

static inline int atun_attr_user(uint8_t *attrs, std::string user_realm) {
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_SOFTWARE,
    };

    attr.value = (uint8_t *)user_realm.c_str();
    attr.length = user_realm.length();

    return stun_add_attr(attrs, &attr);
}


static inline int atun_attr_user(uint8_t *attrs, std::vector<uint8_t> nonce) {
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_SOFTWARE,
    };

    attr.value = (uint8_t *)nonce.data();
    attr.length = nonce.size();

    return stun_add_attr(attrs, &attr);
}


static inline int stun_attr_software(uint8_t *attrs, std::string soft) {
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_SOFTWARE,
    };

    attr.value = (uint8_t *)soft.c_str();
    attr.length = soft.length();

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_fingerprint(uint8_t *msg, uint8_t *attrs) {
    uint32_t crc = 0;
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_FINGERPRINT,
        .length = sizeof(uint32_t),
    };

    crc = stun_client::crc32(msg, (size_t)(attrs - msg));
    attr.value = (uint8_t *)&crc;

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_msg_hmac_sha1(uint8_t *msg, uint8_t *attrs, std::string password) {
    std::vector<uint8_t> raw_key(password.begin(), password.end());
    std::vector<uint8_t> key = crypto::checksum(SHA_ALGO(md5), raw_key);
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(20);
    struct crypto_mac_ctx_t ctx("hmac", "", "sha1", key);
    
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_INTEGRITY_MSG,
        .length = 20,
    };

    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);
    attr.value = digest.data();

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_msg_hmac_sha256(uint8_t *msg, uint8_t *attrs, std::string password) {
    std::vector<uint8_t> raw_key(password.begin(), password.end());
    std::vector<uint8_t> key = crypto::checksum(SHA_ALGO(md5), raw_key);
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(32);
    struct crypto_mac_ctx_t ctx("hmac", "", "sha256", key);
    
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_INTEGRITY_MSG,
        .length = 32,
    };

    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);
    attr.value = digest.data();

    return stun_add_attr(attrs, &attr);
}

#endif