#ifndef __LITE_NET_HPP__
#define __LITE_NET_HPP__
#include <vector>
#include <string>
#include <map>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <netinet/if_ether.h>

struct sockaddr_t
{   
    sa_family_t sa_family;
    union
    {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
    } sa_addr;
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
        static std::string addr_to_string(struct sockaddr_t *addr);
        static struct sockaddr_in * inet_address(struct sockaddr_t *addr);
        static struct sockaddr_in6 * inet6_address(struct sockaddr_t *addr);


        network(const std::string __iface);
        std::string to_string(void);
        ~network() {}
    };
};
#endif