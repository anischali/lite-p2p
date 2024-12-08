#ifndef __TURN_CLIENT_HPP__
#define __TURN_CLIENT_HPP__
#include "stun_client.hpp"

namespace lite_p2p
{

    class turn_client : public stun_client
    {
    private:

    public:
        turn_client(int sock_fd);
        ~turn_client() {};

        int allocate_request(struct stun_session_t *session);
        int create_permission_request(struct stun_session_t *session, struct sockaddr_t *peer);
        int refresh_request(struct stun_session_t *session, uint32_t lifetime);
        int send_request_data(struct stun_session_t *session, struct sockaddr_t *peer, std::vector<uint8_t> &buf);
        int bind_channel_request(struct stun_session_t *session, struct sockaddr_t *peer, uint32_t chanel_id);
        int send_channel(struct stun_session_t *session, struct sockaddr_t *peer, uint32_t channel_id, std::vector<uint8_t> &buf);

        struct sockaddr_t *stun_get_relayed_addr(struct sockaddr_t *stun_server);
    };
};
#endif