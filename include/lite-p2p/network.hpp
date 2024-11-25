#ifndef __LITE_NET_HPP__
#define __LITE_NET_HPP__
#include <vector>
#include <string>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <map>

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