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
    };
};
#endif