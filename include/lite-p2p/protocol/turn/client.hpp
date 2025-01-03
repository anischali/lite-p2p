#ifndef __TURN_CLIENT_HPP__
#define __TURN_CLIENT_HPP__
#include "lite-p2p/protocol/stun/client.hpp"

namespace lite_p2p::protocol::turn
{

    class client : public lite_p2p::protocol::stun::client
    {
    private:

    public:
        client(base_socket *s, struct stun_session_t *sess);
        ~client() {};

        int allocate_request();
        int create_permission_request(struct sockaddr_t *peer);
        int refresh_request(uint32_t lifetime);
        int send_request_data(struct sockaddr_t *peer, std::vector<uint8_t> &buf);
        int bind_channel_request(struct sockaddr_t *peer, uint32_t chanel_id);
        int send_channel(struct sockaddr_t *peer, uint32_t channel_id, std::vector<uint8_t> &buf);

        struct sockaddr_t *stun_get_relayed_addr(struct sockaddr_t *stun_server);
    };
};
#endif