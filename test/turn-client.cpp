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
#include "lite-p2p/stun_session.hpp"



void visichat_listener(void *args) {
    int ret;
    static std::vector<uint8_t> buf(512);
    lite_p2p::peer_connection *conn = (lite_p2p::peer_connection *)args; 
    struct sockaddr_t s_addr;

    printf("receiver thread start [OK]\n");

    while(true) {
        ret = conn->recv(buf, &s_addr);
        if (ret < 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", (char *)&buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&s_addr).c_str(), lite_p2p::network::get_port(&s_addr), (const char *)buf.data());
    }
}

void visichat_sender(void *args) {
    int cnt = 0;
    uint8_t c = 0;
    static std::vector<uint8_t> buf(512);
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

        conn->send(buf);
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

    if (argc < 9) {
        printf("wrong arguments number !\n");
        exit(0);
    }

    lite_p2p::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM})); 
    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    lite_p2p::peer_connection conn(family, argv[4], atoi(argv[5]));
    lite_p2p::turn_client turn(conn.sock_fd);
    struct stun_session_t s_turn = {
        .user = "free",
        .software = "lite-p2p v 1.0",
        .realm = "freestun.net",
        .key_algo = SHA_ALGO_MD5,
        .password_algo = SHA_ALGO_CLEAR,
        .hmac_algo = SHA_ALGO_SHA1,
        .lifetime = (uint32_t)atoi(argv[8]),
        .protocol = IPPROTO_UDP,
        .family = family == AF_INET6 ? INET_IPV6 : INET_IPV4,
        .lt_cred_mech = true,
    };
    /*
    struct stun_session_t s_turn = {
        .user = "visi",
        .software = "lite-p2p v 1.0",
        .realm = "visibog.org",
        .key_algo = SHA_ALGO_MD5,
        .password_algo = SHA_ALGO_CLEAR,
        .hmac_algo = SHA_ALGO_SHA1,
        .lifetime = 60,
        .protocol = IPPROTO_UDP,
        .family = family == AF_INET6 ? INET_IPV6 : INET_IPV4,
        .lt_cred_mech = true,
    };*/
    session_config c;

    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx){
        lite_p2p::peer_connection *c = (lite_p2p::peer_connection *)ctx;

        c->~peer_connection();
    });

    __at_exit.at_exit_cleanup_add(&turn, [](void *ctx){
        lite_p2p::turn_client *c = (lite_p2p::turn_client *)ctx;

        c->~turn_client();
    });

    lite_p2p::network::resolve(&s_turn.server, family, argv[2], atoi(argv[3]));

    c.stun_generate_key(&s_turn, "free");

    print_hexbuf("key", s_turn.key);

    c.stun_register_session(&s_turn);

    conn.connection_type = PEER_RELAYED_CONNECTION;
    conn.session = &s_turn;
    conn.relay = &turn;

    lite_p2p::network::string_to_addr(family, argv[6], &conn.remote);
    lite_p2p::network::set_port(&conn.remote, atoi(argv[7]));

    int ret = turn.allocate_request(&s_turn);
    if (ret < 0) {
        printf("request failed with: %d\n", ret);
        exit(-1);
    }
    
    ret = turn.create_permission_request(&s_turn, &conn.remote);
    //ret = turn.bind_channel_request(&s_turn, &conn.remote, htons(rand_int(0x4000,0x4FFF)));
    //ret = turn.refresh_request(&s_turn, s_turn.lifetime);
    //ret = turn.send_request_data(&s_turn, &conn.remote, s_buf);

    printf("mapped addr: %s:%d relayed addr: %s:%d\n", 
        lite_p2p::network::addr_to_string(&s_turn.mapped_addr).c_str(), 
        lite_p2p::network::get_port(&s_turn.mapped_addr),
        lite_p2p::network::addr_to_string(&s_turn.relayed_addr).c_str(), 
        lite_p2p::network::get_port(&s_turn.relayed_addr));
    

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), lite_p2p::network::get_port(&conn.local));
    printf("peer: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.remote).c_str(), lite_p2p::network::get_port(&conn.remote));

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

    __at_exit.at_exit_cleanup_add(&sender, thread_cleanup);
    __at_exit.at_exit_cleanup_add(&recver, thread_cleanup);

    recver.join();
    sender.join();

    return 0;
}