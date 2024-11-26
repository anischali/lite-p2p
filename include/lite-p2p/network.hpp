#ifndef __LITE_NET_HPP__
#define __LITE_NET_HPP__
#include <vector>
#include <string>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <map>

struct sockaddr_t
{   
    int sa_family;
    union
    {
        struct sockaddr_in *addr_in;
        struct sockaddr_in6 *addr_in6;
    } sa_addr;
    struct sockaddr_storage s_addr;
};
namespace lite_p2p
{

    class network
    {

    private:
        void ip_getinfo(void);

    public:
        std::vector<struct sockaddr_t> ip6;
        std::string iface;
        struct sockaddr_t ip;
        struct sockaddr_t netmask;
        struct sockaddr_t gateway;
        struct sockaddr_t broadcast;

        uint8_t mac[ETH_ALEN];
        int mtu;

        static std::vector<std::string> network_interfaces(void);
        network(const std::string __iface);
        static std::string addr_to_string(struct sockaddr_t *addr);
        std::string to_string(void);
        ~network() {}
    };
};
#endif