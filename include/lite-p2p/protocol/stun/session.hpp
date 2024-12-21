#ifndef __STUN_SESSION_H__
#define __STUN_SESSION_H__
#include <vector>
#include <string>
#include <map>
#include <lite-p2p/crypto/crypto.hpp>
#include <lite-p2p/network.hpp>

enum sha_algo_type {
    SHA_ALGO_CLEAR = -1,
    SHA_ALGO_MD5 = 0,
    SHA_ALGO_SHA1 = 1,
    SHA_ALGO_SHA256 = 2,
    SHA_ALGO_SHA384 = 3,
    SHA_ALGO_SHA512 = 4,
    SHA_ALGO_MAX,
};
typedef int8_t sha_algo_type_t;

extern const std::vector<struct algo_type_t> algos;

enum stun_addr_family {
    INET_BOTH = 0,
    INET_IPV4,
    INET_IPV6,
};

#define ALGO_TYPE(t, e, s, n, l) \
    {.type = t, .ossl_alg = e, .stun_alg = s, .name = n, .length = l}
struct algo_type_t
{
    sha_algo_type_t type;
    const EVP_MD *ossl_alg;
    const uint32_t stun_alg;
    const std::string name;
    size_t length;
};


enum stun_server_type {
    STUN_SERV_TYPE_UNKNOWN = 0,
    STUN_SERV_TYPE_STUN_ONLY = 1,
    STUN_SERV_TYPE_TURN_ONLY,
    STUN_SERV_TYPE_STUN_TURN,
    STUN_SERV_TYPE_TURNS,
};
typedef uint8_t stun_server_type_t;

struct stun_server_t {
    stun_server_type_t type;
    uint16_t port;
    std::string url;
    std::string username;
    std::string credential;
    std::string realm;
    bool support_ipv6;
};

struct stun_session_t {
    std::string user;
    std::string software;
    std::string realm;
    std::vector<uint8_t> key;
    std::vector<uint32_t> algorithms;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> reservation_token;
    std::vector<uint8_t> mobility_token;
    std::vector<uint16_t> unkown_attrs;
    struct sockaddr_t server;
    struct sockaddr_t mapped_addr;
    struct sockaddr_t relayed_addr;
    sha_algo_type_t key_algo;
    sha_algo_type_t password_algo;
    sha_algo_type_t hmac_algo;
    uint32_t lifetime;
    uint32_t channel;
    int protocol;
    int family;
    bool can_frag;
    bool lt_cred_mech;
    bool mobility;
    bool valid;
};

class session_config {
private:
    std::map<std::string, struct stun_session_t *> session_db;

public:
    void stun_register_session(struct stun_session_t *session);
    void stun_generate_key(struct stun_session_t *session, std::string password);
    struct stun_session_t *stun_session_get(struct sockaddr_t *addr);
};

#endif