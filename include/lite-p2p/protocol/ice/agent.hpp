#ifndef __ICE_AGENT_HPP__
#define __ICE_AGENT_HPP__
#include <vector>
#include <lite-p2p/network/network.hpp>

namespace lite_p2p::protocol::ice
{

    class agent
    {
    private:
        std::vector<struct sockaddr_t> addrs;
        std::vector<lite_p2p::network> ifaces_info;

        /* data */
    public:
        agent();
        ~agent();

        void gather_addrs(void);
        std::vector<struct sockaddr_t> get_addrs(void) {return addrs;};
    };
};
#endif