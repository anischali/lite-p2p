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
    char addr_buf[INET6_ADDRSTRLEN];
    struct sockaddr_t saddr;

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next)
    {
        if (!strncmp(iface.c_str(), addr->ifa_name, std::min((int)iface.length(), IFNAMSIZ)))
        {
            memset(&saddr, 0x0, sizeof(saddr));
            saddr.sa_family = addr->ifa_addr->sa_family;

            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) {
                memcpy(&saddr.sa_addr, addr->ifa_addr, sizeof(struct sockaddr_in6));
                ip6.push_back(saddr);
            }

            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
                memcpy(&saddr.sa_addr, addr->ifa_addr, sizeof(struct sockaddr_in));
                ip = saddr;
            }

            if (addr->ifa_netmask && addr->ifa_netmask->sa_family == AF_INET) {
                memcpy(&saddr.sa_addr, addr->ifa_netmask, sizeof(struct sockaddr_in));
                netmask = saddr;
            }

            if (addr->ifa_ifu.ifu_broadaddr && addr->ifa_ifu.ifu_broadaddr->sa_family == AF_INET) {
                memcpy(&saddr.sa_addr, addr->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in));
                broadcast = saddr;
            }

        }
    }

    freeifaddrs(addrs);


}

network::network(const std::string __iface)
{
    int fd;
    struct ifreq req = {0};
    struct rtentry rt = {0};
    struct sockaddr_in *sin;

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
    std::string str;
    char buf[STR_INFO_SZ];
    char addr_buf[INET6_ADDRSTRLEN];

    memset(buf, 0x0, STR_INFO_SZ);
    memset(addr_buf, 0x0, INET6_ADDRSTRLEN);

    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*) &addr->sa_addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, addr_buf, sizeof(addr_buf));
        snprintf(buf, STR_INFO_SZ, "%s", &addr_buf[0]);
    }
    else if (addr->sa_family == AF_INET) {
       snprintf(buf, STR_INFO_SZ, "%s", inet_ntoa(((struct sockaddr_in *)&addr->sa_addr)->sin_addr));
    }

    str += buf;

    return str;
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
