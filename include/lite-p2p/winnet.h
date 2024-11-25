#ifndef __WINNET_H__
#define __WINNET_H__
#include <stdint.h>
#include <winsock2.h>

#define ETH_ALEN 6
#define IFNAMSIZ 20

/* here is minimal subset of ifaddr API required for sockets & UDP
   providers */
struct ifaddrs {
	struct ifaddrs  *ifa_next;    /* Next item in list */
	char            *ifa_name;    /* Name of interface */
	unsigned int     ifa_flags;   /* Flags from SIOCGIFFLAGS */
	struct sockaddr *ifa_addr;    /* Address of interface */
	struct sockaddr *ifa_netmask; /* Netmask of interface */

	struct sockaddr_storage in_addrs;
	struct sockaddr_storage in_netmasks;

    union
    { 
        /* At most one of the following two is valid.  If the IFF_BROADCAST
        bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
        IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
        It is never the case that both these bits are set at once.  */
        struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
        struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
    } ifa_ifu;

	char		   ad_name[16];
	size_t		   speed;
};

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

#endif