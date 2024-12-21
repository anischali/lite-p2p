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
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/protocol/stun/attrs.hpp"
#include "lite-p2p/network.hpp"

#define err_ret(msg, err)         \
    printf("%d: %s\n", err, msg); \
    return err

using namespace lite_p2p::protocol::stun;

client::client(int socket_fd) : _socket{socket_fd}
{
}

client::~client()
{
}

uint32_t client::crc32(uint32_t crc, uint8_t *buf, size_t len)
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

struct sockaddr_t *client::stun_get_mapped_addr(struct sockaddr_t *stun_server)
{
    struct stun_session_t *session = sessions.stun_session_get(stun_server);
    if (session)
        return &session->mapped_addr;

    return NULL;
}


int client::request(struct sockaddr_t *stun_server, struct stun_packet_t *packet, bool wait)
{
    uint8_t transaction_id[12];
    int ret;

    memcpy(transaction_id, packet->transaction_id, sizeof(transaction_id));
    ret = network::send_to(_socket, (void *)packet, ntohs(packet->msg_len) + 20, stun_server);
    if (ret < 0)
    {
        err_ret("Failed to send data", ret);
    }

    if (!wait)
        return 0;

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


int client::request(struct sockaddr_t *stun_server, struct stun_packet_t *packet) {
    return request(stun_server, packet, true);
}

int client::bind_request(struct stun_session_t *session)
{
    uint16_t msg_type = stun_type(STUN_REQUEST, STUN_TYPE_REQUEST);
    struct stun_packet_t packet(msg_type);
    std::vector<uint8_t> s_nonce;
    int ret, offset = 0;
    bool retry_attrs = false;
    std::vector<uint16_t> p_attrs = {
        STUN_ATTR_USERNAME, STUN_ATTR_REALM, STUN_ATTR_NONCE, STUN_ATTR_SOFTWARE,
        STUN_ATTR_INTEGRITY_MSG, STUN_ATTR_FINGERPRINT   
    };

retry:
    if (retry_attrs)
    {
        packet.msg_type = msg_type;
        offset = packet.msg_len = 0;
        offset += stun_add_attrs(session, &packet, p_attrs, offset);
        packet.msg_len = htons(offset);
    }

    ret = request(&session->server, &packet);
    if (ret < 0)
        return ret;

    ret = stun_process_attrs(session, &packet, p_attrs);
    if (ret < 0) {
        if (ret == -STUN_ERR_UNAUTH) {
            retry_attrs = true;
            goto retry;
        }

        return ret;
    }


    return 0;
}

class nat_pnp
{
private:
    short s_port, r_port;
    
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
