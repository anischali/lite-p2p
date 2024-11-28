#include <vector>
#include <string>
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

int stun_client::request(struct sockaddr_t *stun_server, struct stun_packet_t *packet) {
    uint8_t transaction_id[12];
    int ret, i, offset = 0;
    void *addr, *ext_addr;
    size_t len;
    
    memcpy(transaction_id, packet->transaction_id, sizeof(transaction_id));

    len = stun_server->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    addr = stun_server->sa_family == AF_INET6 ? 
            (void *)network::inet6_address(stun_server) :
            (void *)network::inet_address(stun_server);

    ret = sendto(_socket, (uint8_t *)&packet, ntohs(packet->msg_len) + 20, 0, (struct sockaddr *)addr, len);
    if (ret < 0) {
        err_ret("Failed to send data", ret);
    }

    ret = recvfrom(_socket, &packet, sizeof(packet), 0, NULL, 0);
    if (ret < 0) {
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


int stun_client::bind_request(const char *stun_hostname, short stun_port, int family) { 
    void *s_addr;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    char *hostname, *service, hst[512];
    struct stun_packet_t packet(STUN_REQUEST);
    struct stun_attr_t attr;
    uint8_t *attrs = &packet.attributes[0];
    size_t sock_len;
    uint16_t attr_len = 0, attr_type = 0;
    void *addr, *ext_addr;
    int ret, len;
    
    sock_len = family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    s_addr = family == AF_INET6 ? 
        (void *)network::inet6_address(&stun_server) : 
        (void *)network::inet_address(&stun_server);

    ret = network::string_to_addr(family, stun_hostname, &stun_server);
    if (!ret) {

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = family;
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
            if (p->ai_family == family) {
                memcpy(s_addr, p->ai_addr, sock_len);
            }
        }
    
        freeaddrinfo(servinfo);
        servinfo = NULL;
    }

    if (family == AF_INET6) {
        ((struct sockaddr_in6 *)s_addr)->sin6_family = family;
        ((struct sockaddr_in6 *)s_addr)->sin6_port = htons(stun_port);
    }
    else {
        ((struct sockaddr_in *)s_addr)->sin_family = family;
        ((struct sockaddr_in *)s_addr)->sin_port = htons(stun_port);
    }

    ret = request(&stun_server, &packet);
    if (ret < 0)
        return ret;

    attrs = packet.attributes;
    len = std::min(packet.msg_len, (uint16_t)sizeof(packet.attributes));

    for (int i = 0; i < len; i += (4 + attr_len)) {
        attr = STUN_ATTR(ntohs(*(int16_t*)(&attrs[i])), ntohs(*(int16_t*)(&attrs[i + 2])), &attrs[i + 5]);

        if (attr.type == STUN_ATTR_XOR_MAPPED_ADDR) {
            ext_ip.sa_family = (uint16_t )(*(int8_t *)(&attr.value[0])) == 0x1 ? AF_INET : AF_INET6;
            if (ext_ip.sa_family == AF_INET) {
                ext_addr = network::inet_address(&ext_ip);
                ((struct sockaddr_in *)ext_addr)->sin_family = ext_ip.sa_family;
                ((struct sockaddr_in *)ext_addr)->sin_port = (*(int16_t *)(&attr.value[1]));
                ((struct sockaddr_in *)ext_addr)->sin_port ^= ((uint16_t)packet.magic_cookie);
                ((struct sockaddr_in *)ext_addr)->sin_addr.s_addr = (*(uint32_t *)&attr.value[3]);
                ((struct sockaddr_in *)ext_addr)->sin_addr.s_addr ^= packet.magic_cookie;
            }
            else if (ext_ip.sa_family == AF_INET6) {
                ext_addr = network::inet6_address(&ext_ip);
                ((struct sockaddr_in6 *)ext_addr)->sin6_family = ext_ip.sa_family;
                ((struct sockaddr_in6 *)ext_addr)->sin6_port = (*(int16_t *)(&attr.value[1]));
                ((struct sockaddr_in6 *)ext_addr)->sin6_port ^= ((uint16_t)packet.magic_cookie);
                memcpy(&((struct sockaddr_in6 *)ext_addr)->sin6_addr, (uint8_t *)&attr.value[3], sizeof(struct in6_addr));
                ((struct sockaddr_in6 *)ext_addr)->sin6_addr.__in6_u.__u6_addr32[0] ^= packet.magic_cookie;
                for (int i = 0; i < sizeof(packet.transaction_id); ++i) {
                    ((struct sockaddr_in6 *)ext_addr)->sin6_addr.__in6_u.__u6_addr8[i + 4] ^= packet.transaction_id[i];
                }
            }
            return 0;
        }
    }

    return -ENOENT;
}



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

