#ifndef __TURN_CLIENT_HPP__
#define __TURN_CLIENT_HPP__
#include "stun_client.hpp"

namespace lite_p2p
{

    class turn_client : public stun_client
    {
    private:
        int _socket;

    public:
        turn_client(int sock_fd);
        ~turn_client() {};

        int allocate_request(struct stun_session_t *session);
        int create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer);
        int bind_channel_request(int session_id, int peer_id, int channel_id);
        struct sockaddr_t *stun_get_relayed_addr(struct sockaddr_t *stun_server);
    };
};
#endif