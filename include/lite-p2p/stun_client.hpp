#ifndef __STUN_CLIENT_HPP__
#define __STUN_CLIENT_HPP__
#include <map>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "lib_common.hpp"
#include <lite-p2p/network.hpp>
#include <lite-p2p/crypto.hpp>

#define IS_REQUEST(msg_type) (((msg_type) & 0x0110) == 0x0000)
#define IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)
#define IS_SUCCESS_RESP(msg_type) (((msg_type) & 0x0110) == 0x0100)
#define IS_ERR_RESP(msg_type) (((msg_type) & 0x0110) == 0x0110)

#define MAGIC_COOKIE 0x2112A442
#define FINGERPRINT_XOR 0x5354554e

enum sha_algo_type {
    SHA_ALGO_UNKNOWN = -1,
    SHA_ALGO_MD5 = 0,
    SHA_ALGO_SHA1 = 1,
    SHA_ALGO_SHA256 = 2,
    SHA_ALGO_SHA384 = 3,
    SHA_ALGO_SHA512 = 4,
    SHA_ALGO_MAX,
};
typedef uint8_t sha_algo_type_t;

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


struct stun_session_t {
    std::string user;
    std::string software;
    std::string realm;
    std::vector<uint8_t> key[SHA_ALGO_MAX];
    std::vector<uint32_t> algorithms;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> transaction_id;
    struct sockaddr_t server;
    struct sockaddr_t mapped_addr;
    struct sockaddr_t relayed_addr;
    sha_algo_type_t key_algo;
    sha_algo_type_t hmac_algo;
    uint32_t protocol;
    uint32_t liftime;
    bool lt_cred_mech;
    bool valid;
};


enum stun_methods
{
    STUN_REQUEST = 0x1,
    STUN_RESPONSE = 0x0101,

    /* Used for TURN service RFC 8656 */
    STUN_ALLOCATE = 0x0003,
    STUN_REFRESH = 0x0004,
    STUN_SEND = 0x0006,
    STUN_DATA = 0x0007,
    STUN_CREATE_PERM = 0x0008,
    STUN_CHANNEL_BIND = 0x0009,
};

#define STUN_ERR(class, err) (class << 8 | err)
enum stun_errors {
    STUN_ERR_ALT_SERVER = STUN_ERR(3, 0), // should use an other server
    STUN_ERR_BAD_REQUEST = STUN_ERR(4, 0), // malformed request
    STUN_ERR_UNAUTH = STUN_ERR(4, 1), // wrong credentials
    STUN_ERR_FORBIDDEN = STUN_ERR(4, 3), // stun error forbidden
    STUN_ERR_REQ_TIMEOUT = STUN_ERR(4, 8), // Request timed out
    STUN_ERR_UNKNOWN_ATTR = STUN_ERR(4, 20), //Unkown attribute
    STUN_ERR_ALLOC_MISMATCH = STUN_ERR(4, 37), // allocation mismatch
    STUN_ERR_STALE_NONCE = STUN_ERR(4, 38), // retry with the nonce present in response
    STUN_ERR_ADDR_NOTSUPP = STUN_ERR(4, 40), // address not supported
    STUN_ERR_WRONG_CRED = STUN_ERR(4, 41), // Wrong credentials
    STUN_ERR_UNSUPP_TRANSP_ADDR = STUN_ERR(4, 42), //Unsupported Transport Address
    STUN_ERR_QUOTA_REACHED = STUN_ERR(4, 86), // Allocation Quota Reached
    STUN_ERR_SERVER_ERR = STUN_ERR(5, 0), //should try again
    STUN_ERR_INSUFF_CAPACITY = STUN_ERR(5, 8), // Insufficient Capacity
};

/*
    RFC 8489
   0x0000: Reserved
   0x0001: MD5
   0x0002: SHA-256
   0x0003-0xFFFF: Unassigned
*/
enum stun_passwd_algs
{
    STUN_PASSWD_ALG_MD5 = 0x0001,
    STUN_PASSWD_ALG_SHA256 = 0x0002,
};

/*
RFC 8489
Comprehension-required range (0x0000-0x7FFF):
   0x0000: Reserved
   0x0001: MAPPED-ADDRESS
   0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
   0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
   0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
   0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
   0x0006: USERNAME
   0x0007: Reserved; was PASSWORD prior to [RFC5389]
   0x0008: MESSAGE-INTEGRITY
   0x0009: ERROR-CODE
   0x000A: UNKNOWN-ATTRIBUTES
   0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
   0x0014: REALM
   0x0015: NONCE
   0x0020: XOR-MAPPED-ADDRESS

Comprehension-optional range (0x8000-0xFFFF)
   0x8022: SOFTWARE
   0x8023: ALTERNATE-SERVER
   0x8028: FINGERPRINT

Comprehension-required range (0x0000-0x7FFF):
   0x001C: MESSAGE-INTEGRITY-SHA256
   0x001D: PASSWORD-ALGORITHM
   0x001E: USERHASH

   Comprehension-optional range (0x8000-0xFFFF)
   0x8002: PASSWORD-ALGORITHMS
   0x8003: ALTERNATE-DOMAIN

TURN used attributes RFC 8656
    0x000C	CHANNEL-NUMBER
    0x000D	LIFETIME
    0x0010	Reserved (was BANDWIDTH)
    0x0012	XOR-PEER-ADDRESS
    0x0013	DATA
    0x0016	XOR-RELAYED-ADDRESS
    0x0017	REQUESTED-ADDRESS-FAMILY
    0x0018	EVEN-PORT
    0x0019	REQUESTED-TRANSPORT
    0x001A	DONT-FRAGMENT
    0x0021	Reserved (was TIMER-VAL)
    0x0022	RESERVATION-TOKEN
    0x8000	ADDITIONAL-ADDRESS-FAMILY
    0x8001	ADDRESS-ERROR-CODE
    0x8004	ICMP

 */

enum stun_attrs
{
    STUN_ATTR_MAPPED_ADDR = 0x0001,
    STUN_ATTR_USERNAME = 0x0006,
    STUN_ATTR_INTEGRITY_MSG = 0x0008,
    STUN_ATTR_ERR_CODE = 0x0009,
    STUN_ATTR_UNKNOWN_ATTRS = 0x000A,
    STUN_ATTR_REALM = 0x0014,
    STUN_ATTR_NONCE = 0x0015,
    STUN_ATTR_INTEGRITY_MSG_SHA256 = 0x001C,
    STUN_ATTR_PASSWD_ALG = 0x001D,
    STUN_ATTR_USERHASH = 0x001E,
    STUN_ATTR_XOR_MAPPED_ADDR = 0x0020,
    STUN_ATTR_PASSWD_ALGS = 0x8002,
    STUN_ATTR_ALT_DOMAIN = 0x8003,
    STUN_ATTR_SOFTWARE = 0x8022,
    STUN_ATTR_ALT_SERVER = 0x8023,
    STUN_ATTR_FINGERPRINT = 0x8028,

    // TURN used attributes RFC 8656

    STUN_ATTR_CHANNEL_NUM = 0x000C,
    STUN_ATTR_LIFETIME = 0x000D,
    STUN_ATTR_XOR_PEER_ADDR = 0x0012,
    STUN_ATTR_DATA = 0x0013,
    STUN_ATTR_XOR_RELAYED_ADDR = 0x0016,
    STUN_ATTR_REQUESTED_ADDR_FAMILY = 0x0017,
    STUN_ATTR_EVEN_PORT = 0x0018,
    STUN_ATTR_REQUESTED_TRANSPORT = 0x0019,
    STUN_ATTR_DONT_FRAGMENT = 0x001A,
    STUN_ATTR_RESERV_TOKEN = 0x0022,
    STUN_ATTR_ADDITIONAL_ADDR_FAMILY = 0x8000,
    STUN_ATTR_ADDR_ERROR_CODE = 0x8001,
    STUN_ATTR_ICMP = 0x8004,
};

namespace lite_p2p
{

    struct __attribute__((packed)) stun_packet_t
    {
        stun_packet_t(int method)
        {
            memset(attributes, 0x0, sizeof(attributes));
            for (int i = 0; i < 12; ++i)
            {
                transaction_id[i] = rand() % 256;
            }
            msg_type = htons(method);
        }

        uint16_t msg_type;
        uint16_t msg_len = htons(0);
        const uint32_t magic_cookie = htonl(MAGIC_COOKIE);
        uint8_t transaction_id[12];
        uint8_t attributes[512];
    };

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

    static inline int stun_add_attr(uint8_t *attrs, struct stun_attr_t *attr)
    {
        int offset = 0;
        int padding;

        *(uint16_t *)&attrs[offset] = htons(attr->type);
        offset += sizeof(attr->type);
        *(uint16_t *)&attrs[offset] = htons(attr->length);
        offset += sizeof(attr->length);

        if (attr->length > 0 && attr->value) {
            memcpy(&attrs[offset], attr->value, attr->length);
        }

        offset += attr->length;

        padding = offset % 4 != 0 ? (4 - (offset % 4)) : 0;

        return offset + padding;
    }

    struct __attribute__((packed)) stun_attrs_t
    {
        // USERNAME: UTF-8-encoded sequence of fewer than 509 bytes
        struct stun_attr_t username;

        // USERHASH: (to support user anonimity)  has a fixed length of 32 bytes
        struct stun_attr_t user_hash;

        // HMAC-SHA1: (MESSAGE-INTEGRITY) the HMAC will be 20 bytes
        struct stun_attr_t hmac_sha1;

        // HMAC-SHA256: (MESSAGE-INTEGRITY-SHA256) at most 32 bytes at least 16 bytes
        struct stun_attr_t hmac_sha256;

        // REALM: sequence of fewer than 128 characters (which can be as long
        // as 509 bytes when encoding them and as long as 763 bytes when
        // decoding them. presence signify the wish to have long term credentials
        struct stun_attr_t realm;

        // NONCE: MUST be fewer than 128 characters (which can be as long as 509 bytes
        // when encoding them and a long as 763 bytes when decoding them)
        struct stun_attr_t nonce;

        struct stun_attr_t passwd_algs;
        struct stun_attr_t passwd_c_alg;
        struct stun_attr_t fingerprint;
    };

    class stun_client
    {
    private:
        int _socket;
    protected:
        const std::vector<struct algo_type_t> algos = {
            ALGO_TYPE(SHA_ALGO_MD5, EVP_md5(), htons(STUN_PASSWD_ALG_MD5), "md5", 16),
            ALGO_TYPE(SHA_ALGO_SHA1, EVP_sha1(), htons(STUN_PASSWD_ALG_SHA256), "sha1", 20),
            ALGO_TYPE(SHA_ALGO_SHA256, EVP_sha256(), htons(STUN_PASSWD_ALG_SHA256), "sha256", 32),
            ALGO_TYPE(SHA_ALGO_SHA384, EVP_sha384(), htons(STUN_PASSWD_ALG_SHA256), "sha384", 48),
            ALGO_TYPE(SHA_ALGO_SHA512, EVP_sha512(), htons(STUN_PASSWD_ALG_SHA256), "sha512", 64),
        };
        std::map<std::string, struct stun_session_t *> session_db;
        int request(struct sockaddr_t *stun_server, struct stun_packet_t *packet);
        int stun_add_attrs(struct stun_session_t *session, 
            struct stun_packet_t *packet, bool session_attrs);
        int stun_process_attrs(struct stun_session_t *session, struct stun_packet_t *packet);
    public:
        stun_client(int socket_fd);
        ~stun_client();

        int bind_request(struct stun_session_t *session);
        void stun_register_session(struct stun_session_t *session);
        void stun_generate_keys(struct stun_session_t *session, std::string password, bool lt_cred);
        struct stun_session_t *stun_session_get(struct sockaddr_t *addr);
        struct sockaddr_t *stun_get_mapped_addr(struct sockaddr_t *stun_server);
        static uint32_t crc32(uint32_t crc, uint8_t *buf, size_t size);
    };
};

#endif