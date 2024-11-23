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

#define min(x, y) x < y ? x : y

static inline bool c_array_cmp(uint8_t a1[], uint8_t a2[], int len) {
    
    while(len-- > 0 && *(a1++) != *(a2++));
    return len == 0;
}

stun_client::stun_client(int socket_fd) : 
    _socket{socket_fd}, ext_ip{0}
{}

stun_client::~stun_client()
{
}

int stun_client::stun_request(struct sockaddr_in stun_server) {
    struct sockaddr_in laddr;  
    struct stun_request_t request;
    struct stun_response_t response;
    uint16_t attr_len = 0, attr_type = 0;
    int ret, len, i;
    uint8_t *attrs;
    
    ret = sendto(_socket, (uint8_t *)&request, ntohs(request.msg_len) + 20, 0, (struct sockaddr *)&stun_server, sizeof(stun_server));
    if (ret < 0) {
        err_ret("Failed to send data", ret);
    }

    ret = recvfrom(_socket, &response, sizeof(response), 0, NULL, 0);
    if (ret < 0) {
        err_ret("Failed to recv data", ret);
    }

    if (response.magic_cookie != request.magic_cookie)
        return -EINVAL;

    if (c_array_cmp(response.transaction_id, request.transaction_id, sizeof(request.transaction_id)))
        return -EINVAL;

    if (response.msg_type != htons(0x0101))
        return -EINVAL;
    
    attrs = response.attributes;
    len = min(response.msg_len, sizeof(response.attributes));

    for (i = 0; i < len; i += (4 + attr_len)) {
        attr_type = ntohs(*(int16_t*)(&attrs[i]));
        attr_len = ntohs(*(int16_t*)(&attrs[i + 2]));

        if (attr_type == 0x020) {
            ext_ip.sin_port = (*(int16_t *)(&attrs[i + 6]));
            ext_ip.sin_port ^= ((uint16_t)response.magic_cookie);
            ext_ip.sin_port = ext_ip.sin_port;

            ext_ip.sin_addr.s_addr = (*(uint32_t *)&attrs[i + 8]);
            ext_ip.sin_addr.s_addr ^= response.magic_cookie;
            
            return 0;
        }
    }

    return -ENOENT;
}


int stun_client::stun_request(const char *stun_hostname, short stun_port) {
    struct sockaddr_in *addr;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    char *hostname, *service, hst[512];
    int ret;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    memset(hst, 0, sizeof(hst));
    memcpy(hst, stun_hostname, min(512, strlen(stun_hostname)));
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

    stun_server.sin_port = htons(stun_port);
    stun_server.sin_family = AF_INET;

    return stun_request(stun_server);
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

