#ifndef __STUN_CLIENT_HPP__
#define __STUN_CLIENT_HPP__
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>





struct __attribute__((packed)) stun_request_t {
    stun_request_t() {
        memset(attributes, 0x0, sizeof(attributes));
        for (int i = 0; i < sizeof(transaction_id); ++i) {
            transaction_id[i] = rand() % 256;
            if (i < 9) {
                if (i == 4)
                    attributes[4 + i] = ':';
                else
                {
                    uint8_t c;
                    do {
                        c = (uint8_t)(rand() % ('z' - 'A' + 1) + 'A');
                    } while(c > 'Z' && c < 'a');

                    attributes[4 + i] = c;
                }
            }   
        }

        *(uint16_t *)&attributes[0] = htons(0x6);
        *(uint16_t *)&attributes[2] = htons(9);
    }

    const uint16_t msg_type = htons(0x1);
    const uint16_t msg_len = htons(16);
    const uint32_t magic_cookie = htonl(0x2112A442);
    uint8_t transaction_id[12];
    uint8_t attributes[16];
};

struct __attribute__((packed)) stun_response_t {
    uint16_t msg_type = htons(0x1);
    uint16_t msg_len = htons(0x0);
    uint32_t magic_cookie = htonl(0x2112A442);
    uint8_t transaction_id[12];
    uint8_t attributes[1000];
};

class stun_client
{
private:
    int _socket;

public:
    struct sockaddr_in ext_ip;
    struct sockaddr_in stun_server;

    stun_client(int socket_fd);
    ~stun_client();

    int stun_request(struct sockaddr_in stun_server);
    int stun_request(const char *stun_hostname, short stun_port);
};

#endif