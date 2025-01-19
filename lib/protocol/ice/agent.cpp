#include <set>
#include <lite-p2p/protocol/ice/agent.hpp>
#include <lite-p2p/network/socket.hpp>

using namespace lite_p2p::protocol::ice;

struct ice_candidate {
    int type;
    struct sockaddr_t bind_addr;
    struct sockaddr_t addr;
    struct stun_session_t *session;
};

agent::agent(base_socket *s) : sock{s}
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

void agent::gather_candidates(std::vector<struct stun_session_t> s_stuns) {

    gather_addrs();

    // foreach stun/turn and each interface gather addresses
    // try direct first and then try turn sessions.
}

void agent::send_candidates(struct sockaddr_t *remote) {
    
}