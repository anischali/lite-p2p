#include <map>
#include <vector>
#include <algorithm>
#include "lite-p2p/stun_attrs.hpp"

int stun_add_attr(uint8_t *attrs, struct stun_attr_t *attr)
{
    int offset = 0;
    int padding;

    *(uint16_t *)&attrs[offset] = htons(attr->type);
    offset += sizeof(attr->type);
    *(uint16_t *)&attrs[offset] = htons(attr->length);
    offset += sizeof(attr->length);

    if (attr->length > 0 && attr->value)
    {
        memcpy(&attrs[offset], attr->value, attr->length);
    }

    offset += attr->length;

    padding = offset % 4 != 0 ? (4 - (offset % 4)) : 0;

    return offset + padding;
}

int stun_attr_add_string(uint8_t *attrs, uint16_t attr_type, void *args)
{
    std::string *s = reinterpret_cast<std::string*>(args);

    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)s->c_str();
    attr.length = s->length();

    if (s->length() == 0)
        return 0;

    return stun_add_attr(attrs, &attr);
}

static inline int stun_attr_add_vector(uint8_t *attrs, uint16_t attr_type, size_t nmemb, size_t size, void *vec)
{

    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)vec;
    attr.length = size * nmemb;

    return stun_add_attr(attrs, &attr);
}

int stun_attr_get_u8_vector(uint8_t *attrs, uint16_t attr_type, void *args)
{
    std::vector<uint8_t> *vec = reinterpret_cast<std::vector<uint8_t>*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);

    if (attr.type != attr_type || attr.length == 0)
        return -1;

    vec->resize(attr.length);
    memcpy(vec->data(), &attr.value[0], attr.length);

    return vec->size();
}

int stun_attr_add_u8_vector(uint8_t *attrs, uint16_t attr_type, void *vec)
{
    std::vector<uint8_t> *v = reinterpret_cast<std::vector<uint8_t>*>(vec);
    return stun_attr_add_vector(attrs, attr_type, v->size(), sizeof(uint8_t), v->data());
}

int stun_attr_get_u16_vector(uint8_t *attrs, uint16_t attr_type, void *args)
{
    std::vector<uint16_t> *vec = reinterpret_cast<std::vector<uint16_t>*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);

    if (attr.type != attr_type || attr.length == 0)
        return -1;

    vec->resize(attr.length / sizeof(uint16_t));
    memcpy((uint8_t *)vec->data(), &attr.value[0], attr.length);

    return vec->size();
}

int stun_attr_add_u16_vector(uint8_t *attrs, uint16_t attr_type, void *vec)
{
    std::vector<uint16_t> *v = reinterpret_cast<std::vector<uint16_t>*>(vec);
    return stun_attr_add_vector(attrs, attr_type, v->size(), sizeof(uint16_t), v->data());
}

int stun_attr_get_u32_vector(uint8_t *attrs, uint16_t attr_type, void *args)
{
    std::vector<uint32_t> *vec = reinterpret_cast<std::vector<uint32_t>*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);

    if (attr.type != attr_type || attr.length == 0)
        return -1;

    vec->resize(attr.length / sizeof(uint32_t));
    memcpy((uint8_t *)vec->data(), &attr.value[0], attr.length);

    return vec->size();
}

int stun_attr_add_u32_vector(uint8_t *attrs, uint16_t attr_type, void *vec)
{
    std::vector<uint32_t> *v = reinterpret_cast<std::vector<uint32_t>*>(vec);
    return stun_attr_add_vector(attrs, attr_type, v->size(), sizeof(uint32_t), v->data());
}

int stun_attr_add_u32(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint32_t *val = reinterpret_cast<uint32_t*>(args);
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)val;
    attr.length = sizeof(uint32_t);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_get_u32(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint32_t *val = reinterpret_cast<uint32_t*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);
    
    if (attr.type != attr_type || attr.length == 0)
        return -1;

    *val = *(uint32_t *)attr.value;

    return sizeof(uint32_t);
}

int stun_attr_add_u16(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint16_t *val = reinterpret_cast<uint16_t*>(args);
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = (uint8_t *)val;
    attr.length = sizeof(uint16_t);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_get_u16(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint16_t *val = reinterpret_cast<uint16_t*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);
    if (attr.type != attr_type || attr.length == 0)
        return -1;

    *val = *(uint16_t *)attr.value;

    return sizeof(uint16_t);
}

int stun_attr_add_u8(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint8_t *val = reinterpret_cast<uint8_t*>(args);
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = val;
    attr.length = sizeof(uint8_t);

    return stun_add_attr(attrs, &attr);
}

int stun_attr_get_u8(uint8_t *attrs, uint16_t attr_type, void *args)
{
    uint8_t *val = reinterpret_cast<uint8_t*>(args);
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);
    if (attr.type != attr_type || attr.length == 0)
        return -1;

    *val = attr.value[0];

    return sizeof(uint8_t);
}

int stun_attr_add_bool(uint8_t *attrs, uint16_t attr_type, void *args)
{
    struct stun_attr_t attr = {
        .type = attr_type,
    };

    attr.value = NULL;
    attr.length = 0;

    return stun_add_attr(attrs, &attr);
}

int stun_attr_fingerprint(uint8_t *attrs, uint16_t attr_type, void *args)
{
    struct stun_packet_t *packet = reinterpret_cast<struct stun_packet_t*>(args);
    uint8_t *msg = (uint8_t *)packet;
    uint32_t crc = 0;
    struct stun_attr_t attr = {
        .type = STUN_ATTR_FINGERPRINT,
        .length = sizeof(uint32_t),
    };

    packet->msg_len = htons((int)(attrs - msg - 20 + 8));
    crc = stun_client::crc32(0, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);
    attr.value = (uint8_t *)&crc;

    return stun_add_attr(attrs, &attr);
}

bool stun_attr_check_fingerprint(struct stun_packet_t *packet, uint8_t *attrs)
{
    uint8_t *msg = reinterpret_cast<uint8_t *>(packet);
    uint32_t crc = 0, s_crc = 0;
    struct stun_attr_t s_attr = STUN_ATTR(&attrs[0], &attrs[2], &attrs[4]);

    packet->msg_len = htons((int)(attrs - msg - 20 + 8));
    s_crc = *(uint32_t *)s_attr.value;
    crc = stun_client::crc32(0, msg, (size_t)(attrs - msg));
    crc ^= FINGERPRINT_XOR;
    crc = htonl(crc);

    return crc == s_crc;
}

int stun_attr_msg_hmac(const struct algo_type_t *alg, uint16_t attr_type, struct stun_packet_t *packet, uint8_t *attrs, std::vector<uint8_t> key)
{
    uint8_t *msg = reinterpret_cast<uint8_t*>(packet);
    int len = int(attrs - msg);
    std::vector<uint8_t> digest(alg->length);
    struct crypto_mac_ctx_t ctx("hmac", "", alg->name, key);
    std::vector<uint8_t> msg_buf(len);

    struct stun_attr_t attr = {
        .type = attr_type,
        .length = (uint16_t)alg->length,
    };

    packet->msg_len = htons((int)(len - 20 + alg->length + 4));
    msg_buf.assign(&msg[0], &msg[len]);
    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);
    attr.value = digest.data();

    return stun_add_attr(attrs, &attr);
}

bool stun_attr_check_hmac(const struct algo_type_t *alg, struct stun_packet_t *packet, uint8_t *attrs, std::vector<uint8_t> key)
{
    uint8_t *msg = reinterpret_cast<uint8_t*>(packet);
    int len = int(attrs - msg);
    std::vector<uint8_t> digest(alg->length), s_digest(alg->length);
    struct crypto_mac_ctx_t ctx("hmac", "", alg->name, key);
    struct stun_attr_t s_attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);
    std::vector<uint8_t> msg_buf(len);

    packet->msg_len = htons((int)(attrs - msg - 20 + alg->length + 4));
    msg_buf.assign(&msg[0], &msg[len]);
    memcpy(s_digest.data(), &s_attr.value[0], s_attr.length);
    ctx.key = key;
    digest = crypto::crypto_mac_sign(&ctx, msg_buf);

    return digest.size() == s_digest.size() && !CRYPTO_memcmp(digest.data(), s_digest.data(), digest.size());
}

void stun_xor_addr(struct stun_packet_t *packet, struct sockaddr_t *d_addr, struct sockaddr_t *s_addr)
{
    void *addr;

    d_addr->sa_family = s_addr->sa_family;
    memcpy(&d_addr->sa_addr, &s_addr->sa_addr, sizeof(s_addr->sa_addr));

    if (d_addr->sa_family == AF_INET)
    {
        addr = network::inet_address(d_addr);
        ((struct sockaddr_in *)addr)->sin_port ^= ((uint16_t)htonl(MAGIC_COOKIE));
        ((struct sockaddr_in *)addr)->sin_addr.s_addr ^= htonl(MAGIC_COOKIE);
    }
    else if (d_addr->sa_family == AF_INET6)
    {
        addr = network::inet6_address(d_addr);
        ((struct sockaddr_in6 *)addr)->sin6_port ^= ((uint16_t)htonl(MAGIC_COOKIE));
        ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr32[0] ^= htonl(MAGIC_COOKIE);
        for (int i = 0; i < 12; ++i)
        {
            ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[i + 4] ^= packet->transaction_id[i];
        }
    }
}

int stun_attr_get_addr(uint8_t *attrs, uint16_t attr_type, void *args)
{
    struct sockaddr_t *addr = reinterpret_cast<struct sockaddr_t *>(args);
    void *ext_addr;
    struct stun_attr_t attr = STUN_ATTR_H(&attrs[0], &attrs[2], &attrs[4]);

    if (attr.length == 0 || attr.type != attr_type)
        return -1;

    addr->sa_family = (uint16_t)(*(int8_t *)(&attr.value[1])) == 0x1 ? AF_INET : AF_INET6;
    if (addr->sa_family == AF_INET)
    {
        ext_addr = network::inet_address(addr);
        ((struct sockaddr_in *)ext_addr)->sin_family = addr->sa_family;
        ((struct sockaddr_in *)ext_addr)->sin_port = (*(int16_t *)(&attr.value[2]));
        ((struct sockaddr_in *)ext_addr)->sin_addr.s_addr = (*(uint32_t *)&attr.value[4]);
    }
    else if (addr->sa_family == AF_INET6)
    {
        ext_addr = network::inet6_address(addr);
        ((struct sockaddr_in6 *)ext_addr)->sin6_family = addr->sa_family;
        ((struct sockaddr_in6 *)ext_addr)->sin6_port = (*(int16_t *)(&attr.value[2]));
        memcpy(&((struct sockaddr_in6 *)ext_addr)->sin6_addr, (uint8_t *)&attr.value[4], sizeof(struct in6_addr));
    }

    return attr.length;
}

int stun_attr_add_addr(uint8_t *attrs, uint16_t attr_type, void *args)
{
    struct sockaddr_t *addr = reinterpret_cast<struct sockaddr_t *>(args);
    void *ext_addr;
    int length = addr->sa_family == AF_INET6 ? 20 : 8;
    std::vector<uint8_t> s_addr(length);
    struct stun_attr_t attr = {
        .type = attr_type,
        .length = (uint16_t)length,
        .value = s_addr.data(),
    };

    *(int16_t *)&attr.value[1] = addr->sa_family == AF_INET6 ? 0x2 : 0x1;
    if (addr->sa_family == AF_INET)
    {
        ext_addr = network::inet_address(addr);
        (*(int16_t *)&attr.value[2]) = ((struct sockaddr_in *)ext_addr)->sin_port;
        (*(uint32_t *)&attr.value[4]) = (((struct sockaddr_in *)ext_addr)->sin_addr.s_addr);
    }
    else if (addr->sa_family == AF_INET6)
    {
        ext_addr = network::inet6_address(addr);
        (*(int16_t *)&attr.value[2]) = ((struct sockaddr_in6 *)ext_addr)->sin6_port;
        memcpy((uint8_t *)&attr.value[4], &((struct sockaddr_in6 *)ext_addr)->sin6_addr, sizeof(struct in6_addr));
    }

    return stun_add_attr(attrs, &attr);
}


void stun_remove_unsupported_attrs(struct stun_session_t *session, std::vector<uint16_t> &attrs) {
    
    for (auto &&v : session->unkown_attrs) {
        attrs.erase(std::remove(attrs.begin(), attrs.end(), ntohs(v)), attrs.end());
    }
}

struct stun_attr_ops_t
{
    int (*stun_attr_add)(uint8_t *attrs, uint16_t tag, void *value);
    int (*stun_attr_get)(uint8_t *attrs, uint16_t tag, void *value);
};

const struct stun_attr_ops_t stun_attr_string_ops = {
    .stun_attr_add = stun_attr_add_string,
    .stun_attr_get = NULL,
};

const struct stun_attr_ops_t stun_attr_bool_ops = {
    .stun_attr_add = stun_attr_add_bool,
    .stun_attr_get = NULL,
};

const struct stun_attr_ops_t stun_attr_u8_vector_ops = {
    .stun_attr_add = stun_attr_add_u8_vector,
    .stun_attr_get = stun_attr_get_u8_vector,
};

const struct stun_attr_ops_t stun_attr_u32_vector_ops = {
    .stun_attr_add = stun_attr_add_u32_vector,
    .stun_attr_get = stun_attr_get_u32_vector,
};

const struct stun_attr_ops_t stun_attr_u16_vector_ops = {
    .stun_attr_add = stun_attr_add_u16_vector,
    .stun_attr_get = stun_attr_get_u16_vector,
};

const struct stun_attr_ops_t stun_attr_u32_ops = {
    .stun_attr_add = stun_attr_add_u32,
    .stun_attr_get = stun_attr_get_u32,
};

const struct stun_attr_ops_t stun_attr_addr_ops = {
    .stun_attr_add = stun_attr_add_addr,
    .stun_attr_get = stun_attr_get_addr,
};

const struct stun_attr_ops_t stun_attr_fingerprint_ops = {
    .stun_attr_add = stun_attr_fingerprint,
    .stun_attr_get = stun_attr_get_u32,
};

const std::map<uint16_t, const struct stun_attr_ops_t *> attrs_cb = {
    {STUN_ATTR_SOFTWARE, &stun_attr_string_ops},
    {STUN_ATTR_REALM, &stun_attr_string_ops},
    {STUN_ATTR_USERNAME, &stun_attr_string_ops},
    {STUN_ATTR_NONCE, &stun_attr_u8_vector_ops},
    {STUN_ATTR_RESERV_TOKEN, &stun_attr_u8_vector_ops},
    {STUN_ATTR_DATA, &stun_attr_u8_vector_ops},
    {STUN_ATTR_UNKNOWN_ATTRS, &stun_attr_u16_vector_ops},
    {STUN_ATTR_PASSWD_ALGS, &stun_attr_u32_vector_ops},
    {STUN_ATTR_REQUESTED_TRANSPORT, &stun_attr_u32_ops},
    {STUN_ATTR_REQUESTED_ADDR_FAMILY, &stun_attr_u32_ops},
    {STUN_ATTR_ADDITIONAL_ADDR_FAMILY, &stun_attr_u32_ops},
    {STUN_ATTR_PASSWD_ALG, &stun_attr_u32_ops},
    {STUN_ATTR_LIFETIME, &stun_attr_u32_ops},
    {STUN_ATTR_CHANNEL_NUM, &stun_attr_u32_ops},
    {STUN_ATTR_DONT_FRAGMENT, &stun_attr_bool_ops},
    {STUN_ATTR_XOR_MAPPED_ADDR, &stun_attr_addr_ops},
    {STUN_ATTR_XOR_RELAYED_ADDR, &stun_attr_addr_ops},
    {STUN_ATTR_XOR_PEER_ADDR, &stun_attr_addr_ops},
    {STUN_ATTR_FINGERPRINT, &stun_attr_fingerprint_ops},
};

int stun_attr_add_value(uint8_t *attrs, uint16_t attr_type, void *value)
{
    const struct stun_attr_ops_t *ops;
    if (auto ac = attrs_cb.find(attr_type); ac != attrs_cb.end())
    {
        ops = (const struct stun_attr_ops_t *)ac->second;
        if (ops && ops->stun_attr_add)
            return ops->stun_attr_add(attrs, attr_type, value);
    }

    return 0;
}

int stun_attr_get_value(uint8_t *attrs, uint16_t attr_type, void *value)
{
    const struct stun_attr_ops_t *ops;
    if (auto ac = attrs_cb.find(attr_type); ac != attrs_cb.end())
    {
        ops = (const struct stun_attr_ops_t *)ac->second;
        if (ops && ops->stun_attr_get)
            return ops->stun_attr_get(attrs, attr_type, value);
    }

    return -ENONET;
}

int stun_add_attrs(struct stun_session_t *session, struct stun_packet_t *packet, 
                    std::vector<uint16_t> &s_attrs, int offset)
{
    uint8_t *attrs = &packet->attributes[offset];
    struct sockaddr_t a_tmp;
    uint32_t val;
    int idx = 0;

    for (auto &&attr : s_attrs)
    {
        switch (attr)
        {
        case STUN_ATTR_INTEGRITY_MSG_SHA256:
            idx += stun_attr_msg_hmac(&algos[SHA_ALGO_SHA256],
                                          STUN_ATTR_INTEGRITY_MSG_SHA256,
                                          packet, &attrs[idx],
                                          session->key);
            break;
        case STUN_ATTR_INTEGRITY_MSG:
            idx += stun_attr_msg_hmac(&algos[SHA_ALGO_SHA1],
                                          STUN_ATTR_INTEGRITY_MSG,
                                          packet, &attrs[idx],
                                          session->key);
            break;
        case STUN_ATTR_FINGERPRINT:
            idx += stun_attr_add_value(&attrs[idx], attr, packet);
            break;
        case STUN_ATTR_SOFTWARE:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->software);
            break;
        case STUN_ATTR_USERNAME:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->user);
            break;
        case STUN_ATTR_REALM:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->realm);
            break;
        case STUN_ATTR_NONCE:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->nonce);
            break;
        case STUN_ATTR_RESERV_TOKEN:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->reservation_token);
            break;
        case STUN_ATTR_PASSWD_ALGS:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->algorithms);
            break;
        case STUN_ATTR_PASSWD_ALG:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->key_algo);
            break;
        case STUN_ATTR_LIFETIME:
            val = htonl(session->lifetime);
            idx += stun_attr_add_value(&attrs[idx], attr, &val);
            break;
        case STUN_ATTR_REQUESTED_TRANSPORT:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->protocol); 
            break;
        case STUN_ATTR_REQUESTED_ADDR_FAMILY:
            idx += stun_attr_add_value(&attrs[idx], attr, &session->family);
            break;
        case STUN_ATTR_ADDITIONAL_ADDR_FAMILY:
            val = INET_IPV6;
            idx += stun_attr_add_value(&attrs[idx], attr, &val);
            break;
        case STUN_ATTR_DONT_FRAGMENT:
            idx += stun_attr_add_value(&attrs[idx], attr, NULL);
            break;
        case STUN_ATTR_XOR_RELAYED_ADDR:
            stun_xor_addr(packet, &a_tmp, &session->relayed_addr);
            idx += stun_attr_add_value(&attrs[idx], attr, &a_tmp);
        case STUN_ATTR_XOR_MAPPED_ADDR:
            stun_xor_addr(packet, &a_tmp, &session->mapped_addr);
            idx += stun_attr_add_value(&attrs[idx], attr, &a_tmp);
            break;
        }
    }

    return idx;
}

int stun_process_attrs(struct stun_session_t *session, struct stun_packet_t *packet, std::vector<uint16_t> &s_attrs)
{
    std::vector<uint8_t> v_tmp;
    std::vector<uint16_t> v16_tmp;
    struct sockaddr_t a_tmp;
    uint32_t err_code = 0;
    uint8_t *attrs;
    struct stun_attr_t attr;
    int len, offset, padding, ret;

    attrs = &packet->attributes[0];
    len = std::min((uint16_t)ntohs(packet->msg_len), (uint16_t)sizeof(packet->attributes));

    for (int i = 0; i < len; i += offset)
    {
        offset = 4;
        attr = STUN_ATTR_H(&attrs[i], &attrs[i + 2], &attrs[i + 4]);

        switch (attr.type)
        {
        case STUN_ATTR_LIFETIME:
            session->lifetime = htonl(*(uint32_t *)attr.value);
            break;
        case STUN_ATTR_XOR_MAPPED_ADDR:
            ret = stun_attr_get_value(&attrs[i], STUN_ATTR_XOR_MAPPED_ADDR, &a_tmp);
            if (ret > 0)
                stun_xor_addr(packet, &session->mapped_addr, &a_tmp);
            break;
        case STUN_ATTR_XOR_RELAYED_ADDR:
            ret = stun_attr_get_value(&attrs[i], STUN_ATTR_XOR_RELAYED_ADDR, &a_tmp);
            if (ret > 0)
                stun_xor_addr(packet, &session->relayed_addr, &a_tmp);
            break;
        case STUN_ATTR_ERR_CODE:
            err_code = ntohl(*(uint32_t *)&attr.value[0]);
            break;
        case STUN_ATTR_NONCE:
            stun_attr_get_value(&attrs[i], STUN_ATTR_NONCE, &v_tmp);
            break;
        case STUN_ATTR_INTEGRITY_MSG:
            if (!stun_attr_check_hmac(&algos[SHA_ALGO_SHA1],
                                      packet, &attrs[i],
                                      session->key))
                return -STUN_ERR_BAD_REQUEST;
            break;
        case STUN_ATTR_PASSWD_ALGS:
            // TODO: dynamicaly determine algorithms
            break;
        case STUN_ATTR_UNKNOWN_ATTRS:
            stun_attr_get_value(&attrs[i], STUN_ATTR_UNKNOWN_ATTRS, &session->unkown_attrs);
            if (ret > 0) {
                for (auto &&v : session->unkown_attrs) {
                    if (ntohs(v) == STUN_ATTR_DONT_FRAGMENT)
                        session->can_frag = true;
                }
            }
            break;
        case STUN_ATTR_RESERV_TOKEN:
            stun_attr_get_value(&attrs[i], STUN_ATTR_RESERV_TOKEN, &session->reservation_token);
            break;
        case STUN_ATTR_FINGERPRINT:
            if (!stun_attr_check_fingerprint(packet, &attrs[i]))
                return -EINVAL;
            break;
        }

        offset += attr.length;
        padding = offset % 4 != 0 ? (4 - (offset % 4)) : 0;
        offset += padding;
    }

    if (err_code == STUN_ERR_ALLOC_MISMATCH)
        return 0;
    
    else if ((err_code == STUN_ERR_STALE_NONCE ||
        err_code == STUN_ERR_UNAUTH) &&
            session->nonce != v_tmp && v_tmp.size() > 0)
    {
        session->nonce = v_tmp;
        return -STUN_ERR_UNAUTH;
    }

    if (err_code == STUN_ERR_UNKNOWN_ATTR)
        return -STUN_ERR_UNKNOWN_ATTR;


    return 0;
}
