#include "lite-p2p/ice_agent.hpp"

using namespace lite_p2p;

ice_agent::ice_agent()
{
}

ice_agent::~ice_agent()
{
}


void ice_agent::gather_addrs(void) {
    std::vector<std::string> ifaces = network::network_interfaces();

    for (auto &&ifc : ifaces) {
        lite_p2p::network iface(ifc);

        ifaces_info.push_back(iface);
        
        addrs.push_back(iface.ip);
        for (auto &&ip6 : iface.ip6) {
            addrs.push_back(ip6);
        }
    }
}