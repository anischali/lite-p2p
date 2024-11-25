#include <vector>
#include <string>
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


std::vector<std::string>
network::net_interfaces(void)
{
    static std::vector<std::string> ifaces;
    struct ifaddrs *addrs;
    getifaddrs(&addrs);

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next)
    {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET)
        {
            ifaces.push_back(std::string(addr->ifa_name));
        }
    }

    freeifaddrs(addrs);

    return ifaces;
}


void network::ip_getinfo(void) {

    struct ifaddrs *addrs;
    getifaddrs(&addrs);
    std::string key;

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next)
    {
        if (!strncmp(iface.c_str(), addr->ifa_name, std::min((int)iface.length(), IFNAMSIZ)))
        {
            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) {
                ip6.push_back(((struct sockaddr_in6 *)addr->ifa_addr)->sin6_addr);
            }

            if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
                ip = ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr;
            }

            if (addr->ifa_netmask && addr->ifa_netmask->sa_family == AF_INET) {
                netmask = ((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr;
            }

            if (addr->ifa_ifu.ifu_broadaddr && addr->ifa_ifu.ifu_broadaddr->sa_family == AF_INET) {
                broadcast = ((struct sockaddr_in *)addr->ifa_ifu.ifu_broadaddr)->sin_addr.s_addr;
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

    gateway = ((struct sockaddr_in *)&rt.rt_gateway)->sin_addr.s_addr;

    ioctl(fd, SIOCGIFHWADDR, &req);
    memcpy(&mac[0], &req.ifr_hwaddr, ETH_ALEN);

    close(fd);
};

std::string network::to_string()
{
    #define STR_INFO_SZ 256
    std::string str_info;

    char buf[STR_INFO_SZ];
    char ip6_buf[STR_INFO_SZ/2];


    snprintf(buf, STR_INFO_SZ, "interface: %s\n", iface.c_str());
    str_info += buf;
    
    str_info += "mac: ";
    for (int i = 0; i <= ETH_ALEN - 1; ++i)
    {
        snprintf(buf, STR_INFO_SZ, "%02x%c", mac[i], i < ETH_ALEN - 1 ? ':' : '\n');
        str_info += buf;
    }

    snprintf(buf, STR_INFO_SZ, "inet: %s\n", inet_ntoa(in_addr{.s_addr = ip}));
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "netmask: %s\n", inet_ntoa(in_addr{.s_addr = netmask}));
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "broadcast: %s\n", inet_ntoa(in_addr{.s_addr = broadcast}));
    str_info += buf;

    for (auto &&a : ip6)
    {        
        memset(buf, 0x0, STR_INFO_SZ);
        inet_ntop(AF_INET6, &a, &ip6_buf[0], STR_INFO_SZ / 2);
        snprintf(buf, STR_INFO_SZ, "inet6: %s\n", ip6_buf);
        str_info += buf;
    }
    
    snprintf(buf, STR_INFO_SZ, "gateway: %s\n", inet_ntoa(in_addr{.s_addr = gateway}));
    str_info += buf;
    snprintf(buf, STR_INFO_SZ, "mtu: %d\n", mtu);
    str_info += buf;

    return str_info;
}
