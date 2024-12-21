#include <set>
#include "lite-p2p/protocol/ice/agent.hpp"

using namespace lite_p2p::protocol::ice;

agent::agent()
{
}

agent::~agent()
{
}


void agent::gather_addrs(void) {
    std::vector<std::string> ifaces = network::network_interfaces();

    for (auto &&ifc : ifaces) {

        lite_p2p::network iface(ifc);

        addrs.push_back(iface.ip);
        for (auto &&ip6 : iface.ip6) {
            addrs.push_back(ip6);
        }
        
        ifaces_info.push_back(iface);
    }
}