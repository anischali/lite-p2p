#include <vector>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "lite-p2p/stun_client.hpp"

#define err_ret(msg, err) \
    printf("%d: %s\n", err, msg); \
    return err

using namespace lite_p2p;

stun_client::stun_client(int socket_fd) : 
    _socket{socket_fd}, ext_ip{0}
{}

stun_client::~stun_client()
{
}

int stun_client::request(struct sockaddr_in stun_server) {
    struct sockaddr_in laddr;  
    struct stun_packet_t packet(STUN_REQUEST);
    uint8_t transaction_id[12];
    uint16_t attr_len = 0, attr_type = 0;
    int ret, len, i, offset = 0;
    uint8_t *attrs = &packet.attributes[0];
    bool auth_packet = false;
    struct stun_attr_t attr = STUN_ATTR(STUN_ATTR_USERNAME, 13, "tqrgssa:tweys");
    
    memcpy(transaction_id, packet.transaction_id, sizeof(transaction_id));

resend_auth:
    if (auth_packet) {
        offset += stun_add_attr(&attrs[offset], &attr);
        packet.msg_len = htons(ntohs(packet.msg_len) + offset);
    }

    ret = sendto(_socket, (char *)&packet, ntohs(packet.msg_len) + 20, 0, (struct sockaddr *)&stun_server, sizeof(stun_server));
    if (ret < 0) {
        err_ret("Failed to send data", ret);
    }

    ret = recvfrom(_socket, (char *)&packet, sizeof(packet), 0, NULL, 0);
    if (ret < 0) {
        err_ret("Failed to recv data", ret);
    }

    if (packet.magic_cookie != htonl(MAGIC_COOKIE))
        return -EINVAL;

    if (c_array_cmp(packet.transaction_id, transaction_id, sizeof(transaction_id)))
        return -EINVAL;

    if (IS_ERR_RESP(packet.msg_type)) {
        if (!auth_packet) {
            auth_packet = true;
            goto resend_auth;
        }

        return -EINVAL;
    }
    
    attrs = packet.attributes;
    len = std::min(packet.msg_len, (uint16_t)sizeof(packet.attributes));

    for (i = 0; i < len; i += (4 + attr_len)) {
        attr = STUN_ATTR(ntohs(*(int16_t*)(&attrs[i])), ntohs(*(int16_t*)(&attrs[i + 2])), &attrs[i + 5]);

        if (attr.type == STUN_ATTR_XOR_MAPPED_ADDR) {
            ext_ip.sin_family = (uint16_t )(*(int8_t *)(&attr.value[0]));
            ext_ip.sin_port = (*(int16_t *)(&attr.value[1]));
            ext_ip.sin_port ^= ((uint16_t)packet.magic_cookie);
            ext_ip.sin_addr.s_addr = (*(uint32_t *)&attr.value[3]);
            ext_ip.sin_addr.s_addr ^= packet.magic_cookie;
            
            return 0;
        }
    }

    return -ENOENT;
}


int stun_client::request(const char *stun_hostname, short stun_port) {
    struct sockaddr_in *addr = NULL; 
    struct sockaddr_in saddr = {0};
    struct addrinfo hints = {0}, *servinfo = NULL, *p = NULL;
    struct sockaddr_in *h = NULL;
    char *hostname = NULL, *service = NULL, hst[512] = {0};
    int ret = 0;
    
    if (!inet_pton(AF_INET, stun_hostname, &saddr)) {

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        memset(hst, 0, sizeof(hst));
        memcpy(hst, stun_hostname, std::min(512, (int)strlen(stun_hostname)));
        service = strtok_r(hst, ":/", &hostname);

        if (hostname[0] == '/' && hostname[1] == '/')
            hostname = &hostname[2];

        ret = getaddrinfo(hostname, service, &hints, &servinfo);
        if (ret != 0) {
            return ret;
        }
    
        for (p = servinfo; p != NULL; p = p->ai_next) {
            addr = (struct sockaddr_in*)p->ai_addr;
            memcpy(&stun_server, addr, sizeof(stun_server));
        }
    
        freeaddrinfo(servinfo);
        servinfo = NULL;
    }
    else
    {
        stun_server.sin_addr.s_addr = inet_addr(stun_hostname);
    }

    stun_server.sin_port = htons(stun_port);
    stun_server.sin_family = AF_INET;

    return request(stun_server);
}


/*
class nat_pnp {
    private:
        short s_port, r_port;
        struct sockaddr_in gateway;

        
//(short)(rand() % (0xffff - 0x0fff + 1) + 0x0fff)
    public:

        int request() {
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

        nat_pnp(in_addr_t gateway, short _sport, short _rport) {
            s_port = _sport;
            r_port = _rport;


        }; 
};

*/