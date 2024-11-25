#ifndef __LITE_NET_HPP__
#define __LITE_NET_HPP__
#include <vector>
#include <string>
#include <map>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#if __WIN32__ || __WIN64__
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include "winnet.h"
typedef uint32_t in_addr_t;
#else
#include <netinet/if_ether.h>
#endif

namespace lite_p2p
{
    class network
    {
    private:
        void ip_getinfo(void);

    public:
        std::vector<struct in6_addr> ip6;
        std::string iface;
        in_addr_t ip;
        in_addr_t netmask;
        in_addr_t gateway;
        in_addr_t broadcast;

        uint8_t mac[ETH_ALEN];
        int mtu;

        static std::vector<std::string> net_interfaces(void);
        network(const std::string __iface);
        std::string to_string(void);
        ~network() {}
    };
};
#endif