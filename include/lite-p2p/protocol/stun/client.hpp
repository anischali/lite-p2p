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
#include "lite-p2p/lib_common.hpp"
#include <lite-p2p/network.hpp>
#include <lite-p2p/crypto/crypto.hpp>
#include <lite-p2p/protocol/stun/session.hpp>

enum STUN_PACKET_TYPE {
    STUN_TYPE_REQUEST,
    STUN_TYPE_INDICATION,
    STUN_TYPE_SUCCESS_RESP,
    STUN_TYPE_ERR_RESP
};

#define IS_REQUEST(msg_type) (((msg_type) & 0x0110) == 0x0000)
#define IS_INDICATION(msg_type) (((msg_type) & 0x0110) == 0x0010)
#define IS_SUCCESS_RESP(msg_type) (((msg_type) & 0x0110) == 0x0100)
#define IS_ERR_RESP(msg_type) (((msg_type) & 0x0110) == 0x0110)

static inline uint16_t stun_type(uint16_t method, int type) {
    uint16_t val;
    method = method & 0x0FFF;
    val = ((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0380) << 2) | ((method & 0x0C00) << 2));
    
    switch(type) {
        case STUN_TYPE_REQUEST:
            val &= 0xFEEF;
            break;
        case STUN_TYPE_INDICATION:
            val = ((val & 0xFEEF) | 0x0010);
            break;
        case STUN_TYPE_SUCCESS_RESP:
            val = ((val & 0xFEEF) | 0x0100);
            break;
        case STUN_TYPE_ERR_RESP:
            val = ((val & 0xFEEF) | 0x0110);
            break;

    }

    return htons(val);
}


#define MAGIC_COOKIE 0x2112A442
#define FINGERPRINT_XOR 0x5354554e

enum stun_methods
{
    STUN_REQUEST = 0x1,
    STUN_RESPONSE = 0x0101,

    /* Used for TURN service RFC 8656 */
    STUN_ALLOCATE = 0x0003,
    STUN_REFRESH = 0x0004,
    STUN_SEND_REQUEST = 0x0006,
    STUN_DATA_INDICATION = 0x0007,
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


struct __attribute__((packed)) stun_packet_t
    {
        stun_packet_t(int _msg_type)
        {
            memset(attributes, 0x0, sizeof(attributes));
            for (int i = 0; i < 12; ++i)
            {
                transaction_id[i] = rand() % 256;
            }
            msg_type = _msg_type;
        }

        uint16_t msg_type;
        uint16_t msg_len = htons(0);
        const uint32_t magic_cookie = htonl(MAGIC_COOKIE);
        uint8_t transaction_id[12];
        uint8_t attributes[512];
    };


namespace lite_p2p::protocol::stun
{
    class client
    {
    private:
        int _socket;
    protected:
        int request(struct sockaddr_t *stun_server, struct stun_packet_t *packet);
        int request(struct sockaddr_t *stun_server, struct stun_packet_t *packet, bool wait);
        int send_raw(struct sockaddr_t *stun_server, uint8_t *buf, size_t len) { 
            return network::send_to(_socket, buf, len, stun_server);
        }
    public:
        session_config sessions;

        client(int socket_fd);
        ~client();

        int bind_request(struct stun_session_t *session);
        struct sockaddr_t *stun_get_mapped_addr(struct sockaddr_t *stun_server);
        static uint32_t crc32(uint32_t crc, uint8_t *buf, size_t size);
    };
};

#endif