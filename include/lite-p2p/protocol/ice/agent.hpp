#ifndef __ICE_AGENT_HPP__
#define __ICE_AGENT_HPP__
#include <vector>
#include <lite-p2p/network/network.hpp>
#include <lite-p2p/network/socket.hpp>
namespace lite_p2p::protocol::ice
{

    class agent
    {
    private:
        base_socket *sock;
        std::vector<struct sockaddr_t> addrs;
        std::vector<lite_p2p::network> ifaces_info;

        /* data */
    public:
        agent(base_socket *s);
        ~agent();

        void gather_addrs(void);
        void gather_candidates(std::vector<struct stun_session_t> s_stuns);
        void send_candidates(struct sockaddr_t *remote);
        std::vector<struct sockaddr_t> get_addrs(void) {return addrs;};
    };
};
#endif