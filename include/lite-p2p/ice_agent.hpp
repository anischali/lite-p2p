#ifndef __ICE_AGENT_HPP__
#define __ICE_AGENT_HPP__
#include <vector>
#include <lite-p2p/network.hpp>

namespace lite_p2p
{

    class ice_agent
    {
    private:
        std::vector<struct sockaddr_t> addrs;
        std::vector<lite_p2p::network> ifaces_info;

        /* data */
    public:
        ice_agent();
        ~ice_agent();

        void gather_addrs(void);
        std::vector<struct sockaddr_t> get_addrs(void) {return addrs;};
    };
};
#endif