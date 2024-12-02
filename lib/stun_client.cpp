#include <vector>
#include <string>
#include <ranges>
#include <algorithm>
#include <net/route.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <resolv.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/network.hpp"

#define err_ret(msg, err)         \
    printf("%d: %s\n", err, msg); \
    return err

using namespace lite_p2p;

stun_client::stun_client(int socket_fd) : _socket{socket_fd}
{
}

stun_client::~stun_client()
{
}

uint32_t stun_client::crc32(uint32_t crc, uint8_t *buf, size_t len)
{
    static const std::vector<uint32_t> crc_table = []()
    {
        std::vector<uint32_t> table(256);
        std::generate(table.begin(), table.end(), [n = std::uint32_t{0}]() mutable
                      {
            uint32_t tval = n++;
            for (int j = 0; j < 8; ++j) {
                tval = (tval & 1) ? ((tval >> 1) ^ (uint32_t)(0xEDB88320)) : (tval >> 1);
            }
            return tval; });
        return table;
    }();

    crc = ~crc;
    for (size_t i = 0; i < len; i++)
    {
        crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ buf[i]];
    }

    return ~crc;
}

struct stun_session_t *stun_client::stun_session_get(struct sockaddr_t *addr) {
    std::string s_sha, s_tmp = network::addr_to_string(addr) + ":" + 
                std::to_string(network::get_port(addr)) + ":" +
                std::to_string(addr->sa_family);
    
    s_sha = crypto::crypto_base64_encode(crypto::checksum(SHA_ALGO(sha1), s_tmp));

    if (auto s = session_db.find(s_sha); s != session_db.end()) {
        return s->second;
    }

    return nullptr;
}

void stun_client::stun_register_session(struct stun_session_t *session) {

    std::string s_sha, s_tmp = network::addr_to_string(&session->server) + ":" + 
                std::to_string(network::get_port(&session->server)) + ":" +
                std::to_string(session->server.sa_family);
    
    s_sha = crypto::crypto_base64_encode(crypto::checksum(SHA_ALGO(sha1), s_tmp));

    session->nonce.assign(16, 0);
    session_db[s_sha] = session;
}

struct sockaddr_t * stun_client::stun_get_external_ip(struct sockaddr_t *stun_server) {
    std::string s_sha, s_tmp = network::addr_to_string(stun_server) + ":" + 
                std::to_string(network::get_port(stun_server)) + ":" +
                std::to_string(stun_server->sa_family);
    
    s_sha = crypto::crypto_base64_encode(crypto::checksum(SHA_ALGO(sha1), s_tmp));

    if (auto s = stun_client::session_db.find(s_sha); s != stun_client::session_db.end()) {
        return &s->second->ext_ip;
    }

    return nullptr;
}

void print_hexbuf(const char *label, uint8_t *buf, int len) {

    printf("%s (%d): ", label, len);
    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}

void stun_client::stun_generate_keys(struct stun_session_t *session, std::string password, bool lt_cred) {
    auto algos = [](int i){ 
        static const EVP_MD *algos[] = {
            [SHA_ALGO_MD5] = EVP_md5(),
            [SHA_ALGO_SHA1] = EVP_sha1(),
            [SHA_ALGO_SHA256] = EVP_sha256(),
            [SHA_ALGO_SHA384] = EVP_sha384(),
            [SHA_ALGO_SHA512] = EVP_sha512(),
        };
        
        return algos[i];
    };
    std::string s_key = lt_cred ? (session->user + ":" + session->realm + ":" + password) : password; 

    session->lt_cred_mech = lt_cred;
    printf("pass: %s\n", s_key.c_str());
    for (int i = 0; i < SHA_ALGO_MAX; ++i) {
        session->key[i] = crypto::checksum(algos(i), s_key);
        print_hexbuf("key:", session->key[i].data(), session->key[i].size());
    }

    session->algorithms = {htons(STUN_PASSWD_ALG_MD5), htons(STUN_PASSWD_ALG_SHA256)};
    session->selected_algo = htons(STUN_PASSWD_ALG_SHA256);
}

int stun_client::request(struct sockaddr_t *stun_server, struct stun_packet_t *packet)
{
    uint8_t transaction_id[12];
    int ret;

    memcpy(transaction_id, packet->transaction_id, sizeof(transaction_id));
    ret = network::send_to(_socket, (void *)packet, ntohs(packet->msg_len) + 20, stun_server);
    if (ret < 0)
    {
        err_ret("Failed to send data", ret);
    }

    ret = network::recv_from(_socket, packet, sizeof(*packet));
    if (ret < 0)
    {
        err_ret("Failed to recv data", ret);
    }

    if (packet->magic_cookie != htonl(MAGIC_COOKIE))
        return -EINVAL;

    if (c_array_cmp(packet->transaction_id, transaction_id, sizeof(transaction_id)))
        return -EINVAL;

    if (IS_ERR_RESP(packet->msg_type))
        return 0;

    return 0;
}

int stun_client::bind_request(struct stun_session_t *session)
{
    struct stun_packet_t packet(STUN_REQUEST);
    struct stun_attr_t attr;
    uint8_t *attrs = &packet.attributes[0];
    int ret, len, offset = 0;
    bool retry_attrs = false;

retry:
    if (retry_attrs) {
        packet.msg_type = htons(STUN_REQUEST);
        offset = packet.msg_len = 0;
        offset += stun_attr_user(&attrs[offset], session->user);
        offset += stun_attr_realm(&attrs[offset], session->realm);
        offset += stun_attr_nonce(&attrs[offset], session->nonce);
        offset += stun_attr_software(&attrs[offset], session->software);
        packet.msg_len += htons(offset + 24);
        offset += stun_attr_msg_hmac_sha1((uint8_t *)&packet, &attrs[offset], session->key[SHA_ALGO_SHA1]);
        packet.msg_len += htons(8);
        offset += stun_attr_fingerprint((uint8_t *)&packet, &attrs[offset]);
    }

    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    attrs = packet.attributes;
    len = std::min(packet.msg_len, (uint16_t)sizeof(packet.attributes));

    for (int i = 0; i < len; i += (4 + attr.length))
    {
        attr = STUN_ATTR_H(&attrs[i], &attrs[i + 2], &attrs[i + 4]);
        if (attr.type == STUN_ATTR_XOR_MAPPED_ADDR)
        {
            stun_attr_get_mapped_addr(&attrs[i], packet.transaction_id, &session->ext_ip);
        }

        if (attr.type == STUN_ATTR_NONCE)
        {
            auto s_nonce = stun_attr_get_nonce(&attr);
            if (!retry_attrs && session->nonce != s_nonce) {
                session->nonce = s_nonce; 
                goto retry;
            }
        }
    }

    return 0;
}

class nat_pnp
{
private:
    short s_port, r_port;
    struct sockaddr_in gateway;

    //(short)(rand() % (0xffff - 0x0fff + 1) + 0x0fff)
public:
    int request()
    {
        int fd, ret;
        struct sockaddr_in s_addr;
        struct sockaddr_in s_gateway;
        uint8_t msg_buf[256] = {0};

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0)
            return fd;

        s_addr.sin_addr.s_addr = INADDR_ANY;
        s_addr.sin_family = s_gateway.sin_family = AF_INET;
        s_addr.sin_port = htons(5351);

        ret = bind(fd, (struct sockaddr *)&s_addr, sizeof(s_addr));
        if (ret < 0)
            goto close_fd;

        memset(msg_buf, 0, sizeof(msg_buf));
        s_gateway.sin_addr.s_addr = inet_addr("192.168.0.1");
        s_gateway.sin_port = htons(5351);

        ret = sendto(fd, msg_buf, 2, 0, (struct sockaddr *)&s_gateway, sizeof(s_gateway));
        if (ret < 0)
            goto close_fd;

        ret = recvfrom(fd, msg_buf, sizeof(msg_buf), 0, NULL, 0);
        if (ret < 0)
            goto close_fd;

    close_fd:
        close(fd);
        return ret;
    };

    nat_pnp(in_addr_t gateway, short _sport, short _rport)
    {
        s_port = _sport;
        r_port = _rport;
    };
};
