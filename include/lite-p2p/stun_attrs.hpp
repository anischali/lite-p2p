#ifndef __STUN_ATTRS_HPP__
#define __STUN_ATTRS_HPP__
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

static inline int stun_attr_user(uint8_t *attrs, std::string user_realm)
{
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_USERNAME,
    };

    attr.value = (uint8_t *)user_realm.c_str();
    attr.length = user_realm.length();

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_nonce(uint8_t *attrs, std::vector<uint8_t> nonce)
{
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_NONCE,
    };

    attr.value = (uint8_t *)nonce.data();
    attr.length = nonce.size();

    return stun_add_attr(attrs, &attr);
}

static inline std::vector<uint8_t> stun_attr_get_nonce(struct stun_attr_t *attr)
{
    std::vector<uint8_t> nonce;

    if (attr->type != STUN_ATTR_NONCE)
        return {};
    
    nonce.resize(attr->length);
    nonce.assign(&attr->value[0], &attr->value[attr->length - 1]);

    return nonce;
}

static inline int stun_attr_software(uint8_t *attrs, std::string soft)
{
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_SOFTWARE,
    };

    attr.value = (uint8_t *)soft.c_str();
    attr.length = soft.length();

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_fingerprint(uint8_t *msg, uint8_t *attrs)
{
    uint32_t crc = 0;
    static struct stun_attr_t attr = {
        .type = STUN_ATTR_FINGERPRINT,
        .length = sizeof(uint32_t),
    };

    crc = stun_client::crc32(0, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);
    attr.value = (uint8_t *)&crc;

    return stun_add_attr(attrs, &attr);
}

static inline bool stun_attr_check_fingerprint(uint8_t *msg, uint8_t *attrs)
{
    uint32_t crc = 0, s_crc = 0;
    struct stun_attr_t s_attr = STUN_ATTR(&attrs[0], &attrs[2], &attrs[4]);

    s_crc = *(uint32_t *)s_attr.value;
    crc = stun_client::crc32(FINGERPRINT_XOR, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);

    return crc == s_crc;
}

static inline int stun_attr_msg_hmac_sha1(uint8_t *msg, uint8_t *attrs, std::string password)
{
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

static inline bool stun_attr_check_hmac_sha1(uint8_t *msg, uint8_t *attrs, std::string password)
{
    std::vector<uint8_t> raw_key(password.begin(), password.end());
    std::vector<uint8_t> key = crypto::checksum(SHA_ALGO(md5), raw_key);
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(32), s_digest;
    struct crypto_mac_ctx_t ctx("hmac", "", "sha1", key);
    struct stun_attr_t s_attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);

    s_digest.assign(&s_attr.value[0], &s_attr.value[19]);
    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);

    return digest.size() == s_digest.size() && !CRYPTO_memcmp(digest.data(), s_digest.data(), digest.size());
}

static inline int stun_attr_msg_hmac_sha256(uint8_t *msg, uint8_t *attrs, std::string password)
{
    std::vector<uint8_t> raw_key(password.begin(), password.end());
    std::vector<uint8_t> key = crypto::checksum(SHA_ALGO(md5), raw_key);
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(32);
    struct crypto_mac_ctx_t ctx("hmac", "", "sha256", key);

    static struct stun_attr_t attr = {
        .type = STUN_ATTR_INTEGRITY_MSG_SHA256,
        .length = 32,
    };

    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);
    attr.value = digest.data();

    return stun_add_attr(attrs, &attr);
}

static inline bool stun_attr_check_hmac_sha256(uint8_t *msg, uint8_t *attrs, std::string password)
{
    std::vector<uint8_t> raw_key(password.begin(), password.end());
    std::vector<uint8_t> key = crypto::checksum(SHA_ALGO(md5), raw_key);
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(32), s_digest;
    struct crypto_mac_ctx_t ctx("hmac", "", "sha256", key);
    struct stun_attr_t s_attr = STUN_ATTR(&attrs[0], &attrs[2], &attrs[4]);

    s_digest.assign(&s_attr.value[0], &s_attr.value[31]);
    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);

    return digest.size() == s_digest.size() && !CRYPTO_memcmp(digest.data(), s_digest.data(), digest.size());
}

static inline void stun_attr_get_mapped_addr(uint8_t *attrs, uint8_t *transaction_id, struct sockaddr_t *addr)
{
    void *ext_addr;
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[5]);
    addr->sa_family = (uint16_t)(*(int8_t *)(&attr.value[0])) == 0x1 ? AF_INET : AF_INET6;
    if (addr->sa_family == AF_INET)
    {
        ext_addr = network::inet_address(addr);
        ((struct sockaddr_in *)ext_addr)->sin_family = addr->sa_family;
        ((struct sockaddr_in *)ext_addr)->sin_port = (*(int16_t *)(&attr.value[1]));
        ((struct sockaddr_in *)ext_addr)->sin_port ^= ((uint16_t)htonl(MAGIC_COOKIE));
        ((struct sockaddr_in *)ext_addr)->sin_addr.s_addr = (*(uint32_t *)&attr.value[3]);
        ((struct sockaddr_in *)ext_addr)->sin_addr.s_addr ^= htonl(MAGIC_COOKIE);
    }
    else if (addr->sa_family == AF_INET6)
    {
        ext_addr = network::inet6_address(addr);
        ((struct sockaddr_in6 *)ext_addr)->sin6_family = addr->sa_family;
        ((struct sockaddr_in6 *)ext_addr)->sin6_port = (*(int16_t *)(&attr.value[1]));
        ((struct sockaddr_in6 *)ext_addr)->sin6_port ^= ((uint16_t)htonl(MAGIC_COOKIE));
        memcpy(&((struct sockaddr_in6 *)ext_addr)->sin6_addr, (uint8_t *)&attr.value[3], sizeof(struct in6_addr));
        ((struct sockaddr_in6 *)ext_addr)->sin6_addr.s6_addr32[0] ^= htonl(MAGIC_COOKIE);
        for (int i = 0; i < 12; ++i)
        {
            ((struct sockaddr_in6 *)ext_addr)->sin6_addr.s6_addr[i + 4] ^= transaction_id[i];
        }
    }
}

#endif