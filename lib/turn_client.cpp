#include <map>
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/stun_attrs.hpp"
#include "lite-p2p/crypto.hpp"

using namespace lite_p2p;

turn_client::turn_client(int sock_fd) : stun_client(sock_fd) {}


int turn_client::allocate_request(struct sockaddr_t *stun_server) {
    struct stun_packet_t packet(STUN_ALLOCATE);
    struct stun_attr_t attr = {0};
    uint8_t *attrs = &packet.attributes[0];
    int ret, len = 0;
    struct stun_session_t *session;

    session = stun_session_get(stun_server);
    if (!session)
        return -ENONET;
    
    ret = request(stun_server, &packet);
    if (ret < 0)
        return ret;

    attrs = &packet.attributes[0];
    len = std::min((uint16_t)ntohs(packet.msg_len), (uint16_t)sizeof(packet.attributes));

    for (int i = 0; i < len; i += (4 + attr.length))
    {
        attr = STUN_ATTR_H(&attrs[i], &attrs[i + 2], &attrs[i + 5]);
        switch (attr.type)
        {
        case STUN_ATTR_ERR_CODE:

            break;
        case STUN_ATTR_NONCE:

            break;
        
        default:
            break;
        }
    }

    return 0;
}