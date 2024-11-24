#include "stun_client.hpp"
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
#include <string>
#include <ifaddrs.h>

#define err_ret(msg, err) \
    printf("%d: %s\n", err, msg); \
    return err

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

    ret = sendto(_socket, (uint8_t *)&packet, ntohs(packet.msg_len) + 20, 0, (struct sockaddr *)&stun_server, sizeof(stun_server));
    if (ret < 0) {
        err_ret("Failed to send data", ret);
    }

    ret = recvfrom(_socket, &packet, sizeof(packet), 0, NULL, 0);
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
    struct sockaddr_in *addr;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    char *hostname, *service, hst[512];
    int ret;
    
    if (inet_addr(stun_hostname) == INADDR_ANY) {

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



class net {
    public:
        const char *iface;
        in_addr_t ip;
        in_addr_t netmask;
        in_addr_t gateway;
        in_addr_t broadcast;
        uint8_t mac[ETH_ALEN];
        int mtu;

        net(const char *__iface) {
            int fd;
            struct ifreq req = {0};
            struct rtentry rt = {0};
            struct sockaddr_in *sin;

            iface = __iface;
            strncpy(req.ifr_name, iface, IFNAMSIZ);

            fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd <= 0)
                return;
            
            ioctl(fd, SIOCGIFADDR, &req);
            ip = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr.s_addr;

            ioctl(fd, SIOCGIFNETMASK, &req);
            netmask = ((struct sockaddr_in *)&req.ifr_netmask)->sin_addr.s_addr;

            ioctl(fd, SIOCGIFBRDADDR, &req);
            broadcast = ((struct sockaddr_in *)&req.ifr_broadaddr)->sin_addr.s_addr;

            ioctl(fd, SIOCGIFMTU, &req);
            mtu = *(int *)&req.ifr_mtu;

            gateway = ((struct sockaddr_in *)&rt.rt_gateway)->sin_addr.s_addr;

            ioctl(fd, SIOCGIFHWADDR, &req);
            memcpy(&mac[0], &req.ifr_hwaddr, ETH_ALEN);

            close(fd);
        };


        void print() {
            printf("mac: ");
            for (int i = 0; i <= ETH_ALEN - 1; ++i) {
                printf("%02x%c", mac[i], i < ETH_ALEN - 1 ? ':' : '\n');
            }

            printf("ip: %s\n", inet_ntoa(in_addr {.s_addr = ip}));
            printf("netmask: %s\n", inet_ntoa(in_addr {.s_addr = netmask}));
            printf("broadcast: %s\n", inet_ntoa(in_addr {.s_addr = broadcast}));
            printf("gateway: %s\n", inet_ntoa(in_addr {.s_addr = gateway}));
            printf("mtu: %d\n", mtu);
        }

        ~net() {}
};


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

