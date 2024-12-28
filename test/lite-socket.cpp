#include <iostream>
#include <thread>
#include <cstdlib>
#include <time.h>
#include "lite-p2p/common/common.hpp"
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/peer/connection.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/network/socket.hpp"
#include "lite-p2p/protocol/ice/agent.hpp"

void visichat_listener(void *args)
{
    int ret;
    static uint8_t buf[512];
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;

    if (conn->sock->protocol == IPPROTO_TCP)
    {
        if (conn->type == PEER_CON_TCP_SERVER)
        {
            while (!conn->new_sock)
            {
                conn->sock->listen(1);
                conn->new_sock = conn->sock->accept(&conn->remote);
            }
        }
    }
    else
    {
        if (conn->sock->is_secure())
        {
            if (conn->type == PEER_CON_TCP_SERVER)
                conn->new_sock = conn->sock->accept(&conn->remote);
        }
        else
        {
            conn->new_sock = conn->sock;
        }
    }

    while (!conn->new_sock)
    {
        continue;
    }

    printf("receiver thread start [OK]\n");

    while (true)
    {
        ret = conn->recv(conn->new_sock, buf, sizeof(buf), &conn->remote);
        if (ret <= 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", (char *)&buf[0], 4))
            continue;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&conn->remote).c_str(), lite_p2p::network::get_port(&conn->remote), (const char *)buf);
    }
}

void visichat_sender(void *args)
{
    int cnt = 0, ret;
    uint8_t c = 0;
    static uint8_t buf[512];
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;

    if (conn->sock->protocol == IPPROTO_TCP)
    {
        if (conn->type == PEER_CON_TCP_CLIENT)
        {
            ret = -1;
            do
            {
                sleep(2);
                ret = conn->sock->connect(&conn->remote);
                if (ret < 0)
                {
                    ret = errno;
                    printf("%d - %s\n", ret, strerror(ret));
                }

            } while (ret != 0);

            conn->new_sock = conn->sock;
        }
    }
    else
    {
        if (conn->sock->is_secure())
        {
            if (conn->type == PEER_CON_TCP_CLIENT)
            {
                ret = -1;
                do
                {
                    sleep(2);
                    ret = conn->sock->connect(&conn->remote);
                    if (ret < 0)
                    {
                        ret = errno;
                        printf("%d - %s\n", ret, strerror(ret));
                    }
                } while (ret != 0);
            }
            
            conn->new_sock = conn->sock;
        }
        else
        {
            conn->new_sock = conn->sock;
        }

    }

    while (!conn->new_sock)
    {
        continue;
    }

    printf("sender thread start [OK]\n");

    while (true)
    {
        printf("\r> ");
        while ((c = getc(stdin)) != '\n')
        {
            buf[cnt] = c;
            cnt = ((cnt + 1) % sizeof(buf));
        }

        if (cnt <= 0)
            continue;

        buf[cnt] = 0;
        cnt = conn->send(conn->new_sock, buf, cnt);
        if (cnt < 0)
            printf("error sending data\n");

        cnt = 0;

        if (!strncmp("exit", (char *)&buf[0], 4))
        {
            sleep(1);
            exit(0);
            printf("sender thread stop [OK]\n");
            return;
        }
    }
}

void usage(const char *prog)
{
    printf("%s: <ip_protocol> <type> <listen_ip> <local_port> <remote_ip> <remote_port> <server|client>\n", prog);
    exit(0);
}

int main(int argc, char *argv[])
{

    if (argc < 8)
    {
        usage(argv[0]);
    }

    lite_p2p::common::at_exit_cleanup __at_exit(std::vector<int>({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM}));
    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    int type = !strncmp(argv[2], "tcp", 3) ? SOCK_STREAM : SOCK_DGRAM;
    int con_type = !strncmp(argv[7], "client", 6) ? PEER_CON_TCP_CLIENT : PEER_CON_TCP_SERVER;
    // lite_p2p::peer::connection conn(family, argv[3], atoi(argv[4]), type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);

    struct crypto_pkey_ctx_t ctx(EVP_PKEY_ED448);
    EVP_PKEY *p_keys = lite_p2p::crypto::crypto_generate_keypair(&ctx, "");
    lite_p2p::s_socket s(family, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP, p_keys, TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305);
    lite_p2p::peer::connection conn(&s, argv[3], atoi(argv[4]));

    conn.type = con_type;
    __at_exit.at_exit_cleanup_add(&conn, [](void *ctx)
                                  {
        lite_p2p::peer::connection *c = (lite_p2p::peer::connection *)ctx;

        c->~connection(); });

    lite_p2p::network::string_to_addr(family, argv[5], &conn.remote);
    lite_p2p::network::set_port(&conn.remote, atoi(argv[6]));

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.local).c_str(), lite_p2p::network::get_port(&conn.local));
    printf("remote: %s [%d]\n", lite_p2p::network::addr_to_string(&conn.remote).c_str(), lite_p2p::network::get_port(&conn.remote));
    conn.connection_type = PEER_DIRECT_CONNECTION;

    std::thread recver(visichat_listener, &conn);
    std::thread sender(visichat_sender, &conn);

    auto thread_cleanup = [](void *ctx)
    {
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