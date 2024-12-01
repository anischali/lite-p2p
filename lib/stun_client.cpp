#include <vector>
#include <string>
#include <ranges>
#include <algorithm>
#include <net/route.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <resolv.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/stun_attrs.hpp"

#define err_ret(msg, err)         \
    printf("%d: %s\n", err, msg); \
    return err

using namespace lite_p2p;

stun_client::stun_client(int socket_fd) : _socket{socket_fd}, ext_ip{0}
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

int stun_client::resolve(int family, std::string hostname, struct sockaddr_t *hostaddr)
{
    struct addrinfo hints, *servinfo, *p;
    char *host, *service, hst[512];
    int ret;

    ret = network::string_to_addr(family, hostname, hostaddr);
    if (ret)
        return 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    memset(hst, 0, sizeof(hst));
    memcpy(hst, hostname.c_str(), std::min(512, (int)hostname.length()));
    service = strtok_r(hst, ":/", &host);

    if (host[0] == '/' && host[1] == '/')
        host = &host[2];

    ret = getaddrinfo(host, service, &hints, &servinfo);
    if (ret != 0)
    {
        return ret;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if (p->ai_family == family)
        {
            lite_p2p::network::set_address(family, hostaddr, p->ai_addr);
            return 0;
        }
    }

    freeaddrinfo(servinfo);
    servinfo = NULL;

    return -EINVAL;
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

int stun_client::bind_request(const char *stun_hostname, short stun_port, int family)
{
    struct stun_packet_t packet(STUN_REQUEST);
    struct stun_attr_t attr;
    uint8_t *attrs = &packet.attributes[0];
    uint16_t attr_len = 0;
    int ret, len, offset = 0;

    ret = resolve(family, stun_hostname, &stun_server);
    if (ret < 0)
        return ret;

    network::set_port(&stun_server, stun_port);

    offset += stun_attr_user(&attrs[offset], "bayaz");
    offset += stun_attr_software(&attrs[offset], "lite-p2p");
    offset += stun_attr_msg_hmac_sha1((uint8_t *)&packet, &attrs[offset], "test_pass123");
    packet.msg_len += htons(offset + 8);
    offset += stun_attr_fingerprint((uint8_t *)&packet, &attrs[offset]);

    ret = request(&stun_server, &packet);
    if (ret < 0)
        return ret;

    attrs = packet.attributes;
    len = std::min(packet.msg_len, (uint16_t)sizeof(packet.attributes));

    for (int i = 0; i < len; i += (4 + attr_len))
    {
        attr = STUN_ATTR_H(&attrs[i], &attrs[i + 2], &attrs[i + 5]);
        if (attr.type == STUN_ATTR_XOR_MAPPED_ADDR)
        {
            stun_attr_get_mapped_addr(&attrs[i], packet.transaction_id, &ext_ip);
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
