#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/cleanup.hpp"
#include "lite-p2p/lib_common.hpp"
#include "lite-p2p/stun_client.hpp"
#include "lite-p2p/peer_connection.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/ice_agent.hpp"
#if __has_include("./servers.hpp")
#include "./servers.hpp"
#else
std::map<std::string, struct stun_server_t> servers = {
    {
        "freestun", 
        {
            .type = STUN_SERV_TYPE_STUN_TURN,
            .port = 3478,
            .url = "turn:freestun.net",
            .username = "free",
            .credential = "free",
            .realm = "freestun.net",
            .support_ipv6 = false,
        }
    }
};
#endif


void visichat_listener(void *args) {
    int ret;
    static uint8_t buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args; 
    conn->fd = conn->sock_fd;
    struct sockaddr_t s_addr = {
        .sa_family = conn->family,
    };
    
    printf("receiver thread start [OK]\n");

    if (conn->protocol == IPPROTO_TCP) {
        conn->fd = -1;
        while (conn->fd < 0) {
            lite_p2p::network::listen_socket(conn->sock_fd, 1);
            conn->fd = lite_p2p::network::accept_socket(conn->sock_fd, &s_addr);
        }
    }

    while(true) {
        ret = conn->recv(buf, sizeof(buf), &s_addr);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", (char *)&buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&s_addr).c_str(), lite_p2p::network::get_port(&s_addr), (const char *)buf);
    }
}

void visichat_sender(void *args) {
    int cnt = 0;
    uint8_t c = 0;
    static uint8_t buf[512];
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args;

    if (conn->protocol == IPPROTO_TCP) {
        int ret = lite_p2p::network::connect_socket(conn->sock_fd, &conn->remote);
        if (ret < 0) {
            ret = errno;
            printf("%d - %s\n", ret, strerror(ret));
        }
    }

    printf("sender thread start [OK]\n");

    while(true) {
        printf("\r> ");
        while((c = getc(stdin)) != '\n') {
            buf[cnt] = c;
            cnt = ((cnt + 1) % sizeof(buf));
        }

        if (cnt <= 0)
            continue;

        buf[cnt] = 0;
        cnt = conn->send(buf, cnt);
        if (cnt < 0)
            printf("error sending data\n");

        cnt = 0;

        if (!strncmp("exit", (char *)&buf[0], 4)) {
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
    int ret;
    lite_p2p::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM})); 
    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    lite_p2p::peer_connection conn(family, argv[3], atoi(argv[4]));

    lite_p2p::stun_client stun(conn.sock_fd);
    struct stun_server_t srv = servers[argv[2]];
    struct stun_session_t s_stun = {
        .user = srv.username,
        .software = "lite-p2p v 1.0",
        .realm = srv.realm,
        .key_algo = SHA_ALGO_MD5,
        .password_algo = SHA_ALGO_CLEAR,
        .hmac_algo = SHA_ALGO_SHA1,
        .lifetime = (uint32_t)atoi(argv[5]),
        .protocol = IPPROTO_UDP,
        .family = family == AF_INET6 ? INET_IPV6 : INET_IPV4,
        .lt_cred_mech = true,
    };
    
    session_config c;

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer_connection *c = (lite_p2p::peer_connection *)ctx;

        c->~peer_connection();
    });

    __at_exit.at_exit_cleanup_add(&stun, [](void *ctx){
        lite_p2p::stun_client *c = (lite_p2p::stun_client *)ctx;

        c->~stun_client();
    });

    lite_p2p::network::resolve(&s_stun.server, family, srv.url, srv.port);
    
    c.stun_register_session(&s_stun);

    ret = stun.bind_request(&s_stun);
    if (ret < 0) {
        printf("request failed with: %d\n", ret);
        exit(-1);
    }
    
    printf("external ip: %s [%d]\n", lite_p2p::network::addr_to_string(&s_stun.mapped_addr).c_str(), lite_p2p::network::get_port(&s_stun.mapped_addr));
    lite_p2p::network::string_to_addr(family, parse("remote ip"), &conn.remote);
    lite_p2p::network::set_port(&conn.remote, atoi(parse("port").c_str()));

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), lite_p2p::network::get_port(&conn.local));
    printf("remote: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.remote).c_str(), lite_p2p::network::get_port(&conn.remote));
    conn.connection_type = PEER_DIRECT_CONNECTION;

    std::thread recver(visichat_listener, &conn);
    std::thread sender(visichat_sender, &conn);

    auto thread_cleanup = [](void *ctx) {
        std::thread *t = (std::thread *)ctx;
#if defined(__ANDROID__)
        t->~thread();
#else
        pthread_cancel(t->native_handle());
#endif
    };

    __at_exit.at_exit_cleanup_add(&recver, thread_cleanup);
    __at_exit.at_exit_cleanup_add(&sender, thread_cleanup);

    recver.join();
    sender.join();

    return 0;
}