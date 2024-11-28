#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/cleanup.hpp"
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/turn_client.hpp"
#include "lite-p2p/peer_connection.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/ice_agent.hpp"



void visichat_listener(void *args) {
    int ret;
    static char buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args; 
    struct sockaddr_t s_addr;

    printf("receiver thread start [OK]\n");

    while(true) {
        ret = lite_p2p::network::recv_from(conn->sock_fd, buf, 512, &s_addr);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", &buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&s_addr).c_str(), lite_p2p::network::get_port(&s_addr), buf);
    }
}

void visichat_sender(void *args) {
    int cnt = 0;
    char c = 0;
    static char buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args;

    printf("sender thread start [OK]\n");

    while(true) {
        printf("\r> ");
        while((c = getc(stdin)) != '\n') {
            buf[cnt] = c;
            cnt = ((cnt + 1) % sizeof(buf));
        }

        if (cnt <= 0)
            continue;

        lite_p2p::network::send_to(conn->sock_fd, buf, cnt, &conn->remote);
        cnt = 0;

        if (!strncmp("exit", &buf[0], 4)) {
            sleep(1);
            exit(0);
            printf("sender thread stop [OK]\n");
            return;
        }
    }
}



//stun:stun.l.google.com 19302
//34.203.251.243 3478
//TCP
//stun.sipnet.net:3478
//stun.sipnet.ru:3478
//stun.stunprotocol.org:3478
// Authentificated:
//stun.l.google.com:19302
//stun.l.google.com:5349
//stun1.l.google.com:3478
//stun1.l.google.com:5349
//2001:4860:4864:5:8000::1 19302
int main(int argc, char *argv[]) {

    if (argc < 5) {
        printf("wrong arguments number !\n");
        exit(0);
    }

    lite_p2p::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM})); 
    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    lite_p2p::peer_connection conn(family, atoi(argv[4]));
    lite_p2p::turn_client turn(conn.sock_fd);

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer_connection *c = (lite_p2p::peer_connection *)ctx;

        c->~peer_connection();
    });

    __at_exit.at_exit_cleanup_add(&turn, [](void *ctx){
        lite_p2p::turn_client *c = (lite_p2p::turn_client *)ctx;

        c->~turn_client();
    });

    int ret = turn.allocate_request(argv[2], atoi(argv[3]), family);
    if (ret < 0)
        exit(ret);

    //printf("external ip: %s\n", lite_p2p::network::addr_to_string(&turn).c_str());
    lite_p2p::network::string_to_addr(family, argv[6], &conn.remote);
    lite_p2p::network::set_port(&conn.remote, atoi(argv[5]));

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), lite_p2p::network::get_port(&conn.local));

    std::thread recver(visichat_listener, &conn);
    std::thread sender(visichat_sender, &conn);

    auto thread_cleanup = [](void *ctx) {
        std::thread *t = (std::thread *)ctx;
        pthread_cancel(t->native_handle());
    };

    __at_exit.at_exit_cleanup_add(&sender, thread_cleanup);
    __at_exit.at_exit_cleanup_add(&recver, thread_cleanup);

    recver.join();
    sender.join();

    return 0;
}