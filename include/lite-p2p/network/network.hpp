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
        struct sockaddr_storage addr;
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
        static std::string addr_to_string(struct sockaddr_in *addr);
        static std::string addr_to_string(struct sockaddr_in6 *addr);

        static int string_to_addr(int family, std::string saddr, struct sockaddr_t *addr);
        static int string_to_addr(std::string saddr, struct sockaddr_in *addr);
        static int string_to_addr(std::string saddr, struct sockaddr_in6 *addr);

        static void set_address(int family, struct sockaddr_t *addr, struct sockaddr *__from);
        static void set_address(struct sockaddr_t *addr, struct sockaddr_in6 *__from);
        static void set_address(struct sockaddr_t *addr, struct sockaddr_in *__from);

        static void set_port(struct sockaddr_t *addr, uint16_t port);
        static uint16_t get_port(struct sockaddr_t *addr);
        
        static ssize_t send_to(int fd, void *buf, size_t len, struct sockaddr_t *remote);
        static ssize_t send_to(int fd, void *buf, size_t len, int flags, struct sockaddr_t *remote);

        static ssize_t recv_from(int fd, void *buf, size_t len, int flags, struct sockaddr_t *remote);
        static ssize_t recv_from(int fd, void *buf, size_t len, struct sockaddr_t *remote);
        static ssize_t recv_from(int fd, void *buf, size_t len);

        static struct sockaddr_in * inet_address(struct sockaddr_t *addr);
        static struct sockaddr_in6 * inet6_address(struct sockaddr_t *addr);
        
        static int resolve(struct sockaddr_t *hostaddr, int family, std::string hostname);
        static int resolve(struct sockaddr_t *hostaddr, int family, std::string hostname, uint16_t port);

        static int bind_socket(int fd, struct sockaddr_t *addr);
        static int connect_socket(int fd, struct sockaddr_t *addr);
        static int accept_socket(int fd, struct sockaddr_t *addr);
        static int listen_socket(int fd, int n);

        static void print_addr(struct sockaddr_t *a);


        network(const std::string __iface);
        std::string to_string(void);
        ~network() {}
    };
};
#endif