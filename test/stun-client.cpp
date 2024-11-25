#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/cleanup.hpp"
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/peer_connection.hpp"
#include "lite-p2p/network.hpp"



void visichat_listener(void *args) {
    int ret;
    static char buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args; 
    socklen_t len = sizeof(conn->remote);
    struct sockaddr_in s_addr;

    printf("receiver thread start [OK]\n");

    while(true) {
        ret = recvfrom(conn->sock_fd, buf, 512, 0, (struct sockaddr *)&s_addr, &len);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", &buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", inet_ntoa(s_addr.sin_addr), ntohs(s_addr.sin_port), buf);
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

        sendto(conn->sock_fd, buf, cnt, 0, (struct sockaddr *)&conn->remote, sizeof(conn->remote));
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
int main(int argc, char *argv[]) {

    lite_p2p::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM}));

    if (argc < 4) {
        printf("wrong arguments number !\n");
        exit(0);
    }

    srand(time(NULL));
    lite_p2p::peer_connection conn(AF_INET6, atoi(argv[3]));
    lite_p2p::stun_client stun(conn.sock_fd);

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer_connection *c = (lite_p2p::peer_connection *)ctx;

        c->~peer_connection();
    });

    __at_exit.at_exit_cleanup_add(&stun, [](void *ctx){
        lite_p2p::stun_client *c = (lite_p2p::stun_client *)ctx;

        c->~stun_client();
    });

    int ret = stun.request(argv[1], atoi(argv[2]));
    printf("STUN: %s [%d:%d]\n", inet_ntoa(stun.ext_ip.sin_addr), stun.ext_ip.sin_family, ntohs(stun.ext_ip.sin_port));
    if (ret < 0) {
        conn.~peer_connection();
        return ret;
    }

    conn.remote.ipv4_addr.sin_addr.s_addr = stun.ext_ip.sin_addr.s_addr;//htonl(inet_network("192.168.0.10"));
    conn.remote.ipv4_addr.sin_family = AF_INET;
    conn.remote.ipv4_addr.sin_port = htons(atoi(argv[4]));

    printf("bind: %s [%d]\n", inet_ntoa(conn.local.ipv4_addr.sin_addr), ntohs(conn.local.ipv4_addr.sin_port));

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