#ifndef __TURN_CLIENT_HPP__
#define __TURN_CLIENT_HPP__
#include "stun_client.hpp"

namespace lite_p2p
{

    class turn_client : stun_client
    {
    private:
        /* data */
    public:
        turn_client();
        ~turn_client();

        int allocate_request(const char *turn_hostname, short turn_port, int family);
        int create_channel_request(int session_id);
        int bind_channel_request(int session_id, int peer_id, int channel_id);
    };
};
#endif