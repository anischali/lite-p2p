#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/common/common.hpp"
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/peer/connection.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/protocol/ice/agent.hpp"
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
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args; 
    struct lite_p2p::base_socket *s = nullptr;
    struct sockaddr_t s_addr = {
        .sa_family = conn->sock->family,
    };
    
    printf("receiver thread start [OK]\n");

    if (conn->sock->protocol == IPPROTO_TCP) {
        while (!s) {
            conn->sock->listen(1);
            s = conn->sock->accept(&s_addr);
        }
    }
     else
    {
        s = conn->sock;
    }

    while(true) {
        ret = conn->recv(s, buf, sizeof(buf), &s_addr);
        if (ret <= 0 || buf[0] == 0)
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
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;

    if (conn->sock->protocol == IPPROTO_TCP) {
        int ret = conn->sock->connect(&conn->remote);
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

void visichat_keepalive(void *args) {
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;
    
    while(true) {
        conn->send(NULL, 0);
        
        sleep(30);
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
void usage(const char *prog) {
    printf("%s: <protocol> <server_name> <lan-ip> <lport>\n", prog);
    exit(0);
}

int main(int argc, char *argv[]) {

    if (argc < 5) {
        usage(argv[0]);
    }
    int ret;
    lite_p2p::common::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM})); 
    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    lite_p2p::peer::connection conn(family, argv[3], atoi(argv[4]));

    lite_p2p::protocol::stun::client stun(conn.socket_fd());
    struct stun_server_t srv = servers[argv[2]];
    struct stun_session_t s_stun = {
        .user = srv.username,
        .software = "lite-p2p v 1.0",
        .realm = srv.realm,
        .key_algo = SHA_ALGO_MD5,
        .password_algo = SHA_ALGO_CLEAR,
        .hmac_algo = SHA_ALGO_SHA1,
        .protocol = IPPROTO_UDP,
        .family = family == AF_INET6 ? INET_IPV6 : INET_IPV4,
        .lt_cred_mech = true,
    };
    
    session_config c;

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer::connection *c = (lite_p2p::peer::connection *)ctx;

        c->~connection();
    });

    __at_exit.at_exit_cleanup_add(&stun, [](void *ctx){
        lite_p2p::protocol::stun::client *c = (lite_p2p::protocol::stun::client *)ctx;

        c->~client();
    });

    lite_p2p::network::resolve(&s_stun.server, family, srv.url, srv.port);
    
    c.stun_register_session(&s_stun);

    ret = stun.bind_request(&s_stun);
    if (ret < 0) {
        printf("request failed with: %d\n", ret);
        exit(-1);
    }
    
    printf("external ip: %s [%d]\n", lite_p2p::network::addr_to_string(&s_stun.mapped_addr).c_str(), lite_p2p::network::get_port(&s_stun.mapped_addr));
    lite_p2p::network::string_to_addr(family, lite_p2p::common::parse("remote ip"), &conn.remote);
    lite_p2p::network::set_port(&conn.remote, atoi(lite_p2p::common::parse("port").c_str()));

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), lite_p2p::network::get_port(&conn.local));
    printf("remote: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.remote).c_str(), lite_p2p::network::get_port(&conn.remote));
    conn.connection_type = PEER_DIRECT_CONNECTION;

    std::thread recver(visichat_listener, &conn);
    std::thread sender(visichat_sender, &conn);
    std::thread keepalive(visichat_keepalive, &conn);


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
    __at_exit.at_exit_cleanup_add(&keepalive, thread_cleanup);

    recver.join();
    sender.join();

    return 0;
}