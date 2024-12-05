#include <vector>
#include <string>
#include <set>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/route.h>
#include <net/if.h>
#include <resolv.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "lite-p2p/network.hpp"

using namespace lite_p2p;

#define STR_INFO_SZ 256

std::vector<std::string>
network::network_interfaces(void)
{
    std::set<std::string> uniq_ifaces;
    struct ifaddrs *addrs;
    getifaddrs(&addrs);

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next)
    {
        if (addr->ifa_addr && addr->ifa_name != NULL)
        {
            std::string name(addr->ifa_name);
            if (name.length() > 0 && name != "lo") {
                uniq_ifaces.insert(std::string(addr->ifa_name));
            }
        }
    }

    freeifaddrs(addrs);

    static std::vector<std::string> ifaces(uniq_ifaces.begin(), uniq_ifaces.end());
    return ifaces;
}


void network::ip_getinfo(void) {

    struct ifaddrs *addrs;
    getifaddrs(&addrs);
    std::string key;
    struct sockaddr_t saddr;

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next)
    {
        if (!addr || !addr->ifa_name || !addr->ifa_addr)
            continue;

        if (!strncmp(iface.c_str(), addr->ifa_name, std::min((int)iface.length(), IFNAMSIZ)))
        {
            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) {
                set_address(AF_INET6, &saddr, addr->ifa_addr);
                ip6.push_back(saddr);
            }

            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
                set_address(AF_INET, &ip, addr->ifa_addr);
            }

            if (addr->ifa_netmask && addr->ifa_netmask->sa_family == AF_INET) {
                set_address(AF_INET, &netmask, addr->ifa_netmask);
            }

            if (addr->ifa_ifu.ifu_broadaddr && addr->ifa_ifu.ifu_broadaddr->sa_family == AF_INET) {
                set_address(AF_INET, &broadcast, addr->ifa_ifu.ifu_broadaddr);
            }
        }
    }

    freeifaddrs(addrs);


}

network::network(const std::string __iface)
{
    int fd;
    struct ifreq req;

    iface = __iface;
    strncpy(req.ifr_name, iface.c_str(), IFNAMSIZ);

    ip_getinfo();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd <= 0)
        return;

    ioctl(fd, SIOCGIFMTU, &req);
    mtu = *(int *)&req.ifr_mtu;


    ioctl(fd, SIOCGIFHWADDR, &req);
    memcpy(&mac[0], &req.ifr_hwaddr, ETH_ALEN);

    close(fd);
};

std::string network::addr_to_string(struct sockaddr_t *addr) {
   
    switch (addr->sa_family)
    {
    case AF_INET:
        return addr_to_string(inet_address(addr));
    
    case AF_INET6:
        return addr_to_string(inet6_address(addr));
    }

    return "";
}

std::string network::addr_to_string(struct sockaddr_in *addr) {
    std::string str;
    char buf[STR_INFO_SZ];

    memset(buf, 0x0, STR_INFO_SZ);

    snprintf(buf, STR_INFO_SZ, "%s", inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    str += buf;

    return str;
}

std::string network::addr_to_string(struct sockaddr_in6 *addr) {
    std::string str;
    char buf[STR_INFO_SZ];
    char addr_buf[INET6_ADDRSTRLEN];

    memset(buf, 0x0, STR_INFO_SZ);
    memset(addr_buf, 0x0, INET6_ADDRSTRLEN);

    inet_ntop(AF_INET6, &addr->sin6_addr, addr_buf, sizeof(addr_buf));
    snprintf(buf, STR_INFO_SZ, "%s", &addr_buf[0]);

    str += buf;

    return str;
}


int network::string_to_addr(std::string saddr, struct sockaddr_in *addr) {
    int ret;

    ret = inet_pton(AF_INET, saddr.c_str(),
            (struct sockaddr *)&addr->sin_addr);
    
    return ret;
}

int network::string_to_addr(std::string saddr, struct sockaddr_in6 *addr) {
    int ret;

    ret = inet_pton(AF_INET6, saddr.c_str(),
            (struct sockaddr *)&addr->sin6_addr);
    
    return ret;
}

int network::string_to_addr(int family, std::string saddr, struct sockaddr_t *addr) {

    addr->sa_family = family;
    switch (family)
    {
    case AF_INET:
        addr->sa_addr.addr_in.sin_family = family;
        return string_to_addr(saddr, inet_address(addr));
    case AF_INET6:
        addr->sa_addr.addr_in6.sin6_family = family;
        return string_to_addr(saddr, inet6_address(addr));
    }

    errno = EAFNOSUPPORT;
    return -1;
}


std::string network::to_string()
{
    std::string str_info;

    char buf[STR_INFO_SZ];

    snprintf(buf, STR_INFO_SZ, "interface: %s\n", iface.c_str());
    str_info += buf;
    
    str_info += "mac: ";
    for (int i = 0; i <= ETH_ALEN - 1; ++i)
    {
        snprintf(buf, STR_INFO_SZ, "%02x%c", mac[i], i < ETH_ALEN - 1 ? ':' : '\n');
        str_info += buf;
    }

    snprintf(buf, STR_INFO_SZ, "inet: %s\n", network::addr_to_string(&ip).c_str());
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "netmask: %s\n", network::addr_to_string(&netmask).c_str());
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "broadcast: %s\n", network::addr_to_string(&broadcast).c_str());
    str_info += buf;

    for (auto &&a : ip6)
    {        
        snprintf(buf, STR_INFO_SZ, "inet6: %s\n", network::addr_to_string(&a).c_str());
        str_info += buf;
    }
    
    snprintf(buf, STR_INFO_SZ, "gateway: %s\n", network::addr_to_string(&gateway).c_str());
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "mtu: %d\n", mtu);
    str_info += buf;

    return str_info;
}


struct sockaddr_in * network::inet_address(struct sockaddr_t *addr) {
    return (struct sockaddr_in *)&addr->sa_addr;
}


struct sockaddr_in6 * network::inet6_address(struct sockaddr_t *addr) {
    return (struct sockaddr_in6 *)&addr->sa_addr;
}


void network::set_address(struct sockaddr_t *addr, struct sockaddr_in *__from) {
    struct sockaddr_in *s_addr = inet_address(addr);

    s_addr->sin_addr.s_addr = __from->sin_addr.s_addr;
    s_addr->sin_family = addr->sa_family = AF_INET;
}

void network::set_address(struct sockaddr_t *addr, struct sockaddr_in6 *__from) {
    struct sockaddr_in6 *s_addr = inet6_address(addr);

    memcpy(&s_addr->sin6_addr, &__from->sin6_addr, sizeof(struct in6_addr));
    s_addr->sin6_family = addr->sa_family = AF_INET6;
}


void network::set_address(int family, struct sockaddr_t *addr, struct sockaddr *__from) {

    switch (family)
    {
    case AF_INET:
        set_address(addr, (struct sockaddr_in *)__from);
        break;
    
    case AF_INET6:
        set_address(addr, (struct sockaddr_in6 *)__from);
        break;
    
    default:
        break;
    }
}


void network::set_port(struct sockaddr_t *addr, uint16_t port) {

    switch (addr->sa_family)
    {
    case AF_INET:
        inet_address(addr)->sin_port = htons(port);
        break;
    case AF_INET6:
        inet6_address(addr)->sin6_port = htons(port);
        break;
    default:
        break;
    }

}

uint16_t network::get_port(struct sockaddr_t *addr) {

    switch (addr->sa_family)
    {
    case AF_INET:
        return ntohs(inet_address(addr)->sin_port);
    case AF_INET6:
        return ntohs(inet6_address(addr)->sin6_port);
    default:
        break;
    }

    return -1;
}


ssize_t network::send_to(int fd, void *buf, size_t len, int flags, struct sockaddr_t *remote) {

    switch (remote->sa_family)
    {
    case AF_INET6:
        
        return sendto(fd, buf, len, flags, 
            (struct sockaddr *)inet6_address(remote), 
            sizeof(struct sockaddr_in6));
    
    case AF_INET:
    
        return sendto(fd, buf, len, flags, 
            (struct sockaddr *)inet_address(remote), 
            sizeof(struct sockaddr_in));
    
    default:
        break;
    }

    return -1;
}

ssize_t network::send_to(int fd, void *buf, size_t len, struct sockaddr_t *remote) {

    return send_to(fd, buf, len, 0, remote);
}


ssize_t network::recv_from(int fd, void *buf, size_t len, int flags, struct sockaddr_t *remote) {

    socklen_t slen;
    struct sockaddr_in *addr;
    struct sockaddr_in6 *addr6;

    if (!remote) {
        return recvfrom(fd, buf, len, flags, 
            NULL, NULL);
    }

    switch (remote->sa_family)
    {
    case AF_INET6:
        addr6 = network::inet6_address(remote);
        return recvfrom(fd, buf, len, flags, 
            (struct sockaddr *)addr6, &slen);
    
    case AF_INET:
        addr = network::inet_address(remote);
        return recvfrom(fd, buf, len, flags, 
            (struct sockaddr *)addr, &slen);
    }

    return -1;
}

ssize_t network::recv_from(int fd, void *buf, size_t len, struct sockaddr_t *remote) {

    return recv_from(fd, buf, len, 0, remote);
}


ssize_t network::recv_from(int fd, void *buf, size_t len) {

    return recv_from(fd, buf, len, 0, NULL);
}

int network::resolve(struct sockaddr_t *hostaddr, int family, std::string hostname)
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


int network::resolve(struct sockaddr_t *hostaddr, int family, std::string hostname, uint16_t port) {
    int ret;

    ret = resolve(hostaddr, family, hostname);
    if (ret < 0)
        return ret;

    lite_p2p::network::set_port(hostaddr, port);

    return 0;
}