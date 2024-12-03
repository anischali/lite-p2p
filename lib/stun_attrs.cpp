#include "lite-p2p/stun_attrs.hpp"

int stun_attr_add_string(uint8_t *attrs, uint16_t attr_type, std::string s)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)s.c_str();
    attr.length = s.length();

    return stun_add_attr(attrs, &attr);
}

int stun_attr_add_u8_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint8_t> vec)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)vec.data();
    attr.length = vec.size();

    return stun_add_attr(attrs, &attr);
}

int stun_attr_add_u16_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint16_t> vec)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)vec.data();
    attr.length = vec.size() * sizeof(uint16_t);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_add_u32_vector(uint8_t *attrs, uint16_t attr_type, std::vector<uint32_t> vec)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)vec.data();
    attr.length = vec.size() * sizeof(uint32_t);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_add_u32(uint8_t *attrs, uint16_t attr_type, uint32_t val)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)&val;
    attr.length = sizeof(val);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_add_bool(uint8_t *attrs, uint16_t attr_type)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = NULL;
    attr.length = 0;

    return stun_add_attr(attrs, &attr);
}

std::vector<uint8_t> stun_attr_get_nonce(struct stun_attr_t *attr)
{
    std::vector<uint8_t> nonce;

    if (attr->type != STUN_ATTR_NONCE)
        return {};

    nonce.resize(attr->length);
    memcpy(nonce.data(), &attr->value[0], attr->length);

    return nonce;
}

int stun_attr_fingerprint(uint8_t *msg, uint8_t *attrs)
{
    uint32_t crc = 0;
    struct stun_attr_t attr = {
        .type = STUN_ATTR_FINGERPRINT,
        .length = sizeof(uint32_t),
    };

    crc = stun_client::crc32(0, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);
    attr.value = (uint8_t *)&crc;

    return stun_add_attr(attrs, &attr);
}

bool stun_attr_check_fingerprint(uint8_t *msg, uint8_t *attrs)
{
    uint32_t crc = 0, s_crc = 0;
    struct stun_attr_t s_attr = STUN_ATTR(&attrs[0], &attrs[2], &attrs[4]);

    s_crc = *(uint32_t *)s_attr.value;
    crc = stun_client::crc32(FINGERPRINT_XOR, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);

    return crc == s_crc;
}

int stun_attr_msg_hmac(const struct algo_type_t *alg, uint16_t attr_type, uint8_t *msg, uint8_t *attrs, std::vector<uint8_t> key)
{
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(alg->length);
    struct crypto_mac_ctx_t ctx("hmac", "", alg->name, key);

    struct stun_attr_t attr = {
        .type = attr_type,
        .length = (uint16_t)alg->length,
    };

    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);
    auto print_hexbuf = [](const char *label, uint8_t *buf, int len)
    {
        printf("%s (%d): ", label, len);
        for (int i = 0; i < len; ++i)
        {
            printf("%02x", buf[i]);
        }
        printf("\n");
    };
    print_hexbuf("buf", msg_buf.data(), msg_buf.size());
    print_hexbuf("sha", digest.data(), digest.size());
    attr.value = digest.data();

    return stun_add_attr(attrs, &attr);
}

bool stun_attr_check_hmac(std::string dgst_algo, uint8_t *msg, uint8_t *attrs, std::vector<uint8_t> key)
{
    std::vector<uint8_t> msg_buf(&msg[0], &msg[int(attrs - msg)]);
    std::vector<uint8_t> digest(32), s_digest;
    struct crypto_mac_ctx_t ctx("hmac", "", dgst_algo, key);
    struct stun_attr_t s_attr = STUN_ATTR(&attrs[0], &attrs[2], &attrs[4]);

    s_digest.assign(&s_attr.value[0], &s_attr.value[31]);
    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);

    return digest.size() == s_digest.size() && !CRYPTO_memcmp(digest.data(), s_digest.data(), digest.size());
}

void stun_attr_get_mapped_addr(uint8_t *attrs, uint8_t *transaction_id, struct sockaddr_t *addr)
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