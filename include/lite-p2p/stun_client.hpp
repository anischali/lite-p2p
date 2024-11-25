#ifndef __STUN_CLIENT_HPP__
#define __STUN_CLIENT_HPP__
#if __WIN32__ || __WIN64__
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "lib_common.hpp"

#define IS_REQUEST(msg_type) (((msg_type) & 0x0110) == 0x0000)
#define IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)
#define IS_SUCCESS_RESP(msg_type) (((msg_type) & 0x0110) == 0x0100)
#define IS_ERR_RESP(msg_type) (((msg_type) & 0x0110) == 0x0110)

#define MAGIC_COOKIE 0x2112A442
#define FINGERPRINT_XOR 0x5354554e

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
            for (int i = 0; i < sizeof(transaction_id); ++i)
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
#define STUN_ATTR(_type, _len, _val) \
    {.type = _type, .length = _len, .value = (uint8_t *)_val}

    static inline int stun_add_attr(uint8_t *attrs, struct stun_attr_t *attr)
    {
        int offset = 0;
        int padding;

        *(uint16_t *)&attrs[offset] = htons(attr->type);
        offset += sizeof(attr->type);
        *(uint16_t *)&attrs[offset] = htons(attr->length);
        offset += sizeof(attr->length);

        memcpy(&attrs[offset], attr->value, attr->length);

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

    public:
        struct sockaddr_in ext_ip;
        struct sockaddr_in stun_server;
        struct stun_attrs_t attributes;

        stun_client(int socket_fd);
        ~stun_client();

        int request(struct sockaddr_in stun_server);
        int request(const char *stun_hostname, short stun_port);
    };
};

#endif