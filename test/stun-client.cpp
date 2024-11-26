#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/cleanup.hpp"
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/peer_connection.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/ice_agent.hpp"



void visichat_listener(void *args) {
    int ret;
    static char buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args; 
    socklen_t len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 s_addr;

    printf("receiver thread start [OK]\n");

    while(true) {
        ret = recvfrom(conn->sock_fd, buf, 512, 0, (struct sockaddr *)&s_addr, &len);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", &buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&s_addr).c_str(), ntohs(s_addr.sin6_port), buf);
    }
}

void visichat_sender(void *args) {
    int cnt = 0;
    char c = 0;
    static char buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args;
    struct sockaddr_in6 *remote = lite_p2p::network::inet6_address(&conn->remote);

    printf("sender thread start [OK]\n");

    while(true) {
        printf("\r> ");
        while((c = getc(stdin)) != '\n') {
            buf[cnt] = c;
            cnt = ((cnt + 1) % sizeof(buf));
        }

        if (cnt <= 0)
            continue;

        sendto(conn->sock_fd, buf, cnt, 0, (struct sockaddr *)remote, sizeof(*remote));
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

    lite_p2p::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM})); 
    struct sockaddr_in6 *remote, *local;

    lite_p2p::ice_agent ice;

    ice.gather_addrs();

    auto addrs = ice.get_addrs();

    for (auto &&addr : addrs) {
        std::cout << lite_p2p::network::addr_to_string(&addr) << std::endl;
    }

    
    if (argc < 4) {
        printf("wrong arguments number !\n");
        exit(0);
    }

    srand(time(NULL));
    lite_p2p::peer_connection conn(AF_INET6, "::", atoi(argv[3]));
    lite_p2p::stun_client stun(conn.sock_fd);

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer_connection *c = (lite_p2p::peer_connection *)ctx;

        c->~peer_connection();
    });

    __at_exit.at_exit_cleanup_add(&stun, [](void *ctx){
        lite_p2p::stun_client *c = (lite_p2p::stun_client *)ctx;

        c->~stun_client();
    });

    int ret = stun.request(argv[1], atoi(argv[2]), AF_INET6);
    printf("external ip: %s\n", lite_p2p::network::addr_to_string(&stun.ext_ip).c_str());
    if (ret < 0)
        exit(ret);

    remote = lite_p2p::network::inet6_address(&conn.remote);
    remote->sin6_addr = lite_p2p::network::inet6_address(&stun.ext_ip)->sin6_addr;//htonl(inet_network("192.168.0.10"));
    remote->sin6_family = AF_INET6;
    remote->sin6_port = htons(atoi(argv[4]));

    local = lite_p2p::network::inet6_address(&conn.local);

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), ntohs(local->sin6_port));

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