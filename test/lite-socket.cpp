#include <iostream>
#include <thread>
#include <cstdlib>
#include <atomic>
#include <time.h>
#include "lite-p2p/common/common.hpp"
#include "lite-p2p/protocol/stun/client.hpp"
#include "lite-p2p/peer/connection.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/network/socket.hpp"
#include "lite-p2p/protocol/ice/agent.hpp"

std::atomic<bool> terminate = false;

void visichat_listener(void *args)
{
    int ret;
    uint8_t buf[512];
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;
    bool accepted = false;
    lite_p2p::base_socket *s = NULL;

    memset(buf, 0x0, sizeof(buf));

    if ((conn->sock->type & SOCK_STREAM) != 0 || conn->sock->is_secure())
    {
        if (conn->type == PEER_CON_TCP_SERVER)
        {
            while (!accepted)
            {
                if ((conn->sock->type & SOCK_STREAM) != 0)
                    conn->sock->listen(1);
                
                s = conn->sock->accept(&conn->remote);
                accepted = s != NULL;
            }

            conn->new_sock = s;
        }
    }
    else
    {
        s = conn->new_sock = conn->sock;
    }

    while (!conn->new_sock && !terminate.load())
        sleep(1);

    printf("receiver thread start [OK]\n");

    while (!terminate.load())
    {
        ret = conn->recv(conn->new_sock, buf, sizeof(buf), &conn->remote);
        if (ret <= 0 || buf[0] == 0)
            continue;

        buf[ret] = 0;

        if (!strncmp("exit", (char *)&buf[0], 4))
            return;

        fprintf(stdout, "[%s:%d]: %s\n\r> ", lite_p2p::network::addr_to_string(&conn->remote).c_str(), lite_p2p::network::get_port(&conn->remote), (const char *)buf);
    }
}

void visichat_sender(void *args)
{
    int cnt = 0, ret;
    uint8_t c = 0;
    uint8_t buf[512];
    lite_p2p::peer::connection *conn = (lite_p2p::peer::connection *)args;
    bool connected = false;

    memset(buf, 0x0, sizeof(buf));

    if ((conn->sock->type & SOCK_STREAM) != 0 || conn->sock->is_secure())
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
        connected = true;
    }
    else
    {
        conn->new_sock = conn->sock;
        connected = true;
    }

    while (!connected || !conn->new_sock)
        sleep(1);

    printf("sender thread start [OK]\n");

    while (!terminate.load())
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
            terminate = true;
        }
    }
}

void usage(const char *prog)
{
    printf("%s: <ip_protocol> <type> <listen_ip> <local_port> <remote_ip> <remote_port> <server|client>\n", prog);
    exit(0);
}

// based on s_server of openssl.

int lite_generate_stateless_cookie(SSL *ssl, uint8_t *cookie, size_t *len)
{
    void *ctx = SSL_get_app_data(ssl);
    struct tls_context_t *tls;
    std::vector<uint8_t> s_cookie, t_cookie;
    BIO_ADDR *peer = NULL, *lpeer = NULL;
    size_t length = 0;
    uint16_t port;

    if (!ctx)
        return 0;

    tls = (struct tls_context_t *)ctx;

    if (!tls->cookie_initialized)
    {
        tls->cookie_secret = lite_p2p::crypto::crypto_random_bytes(128);
        tls->cookie_initialized = true;
    }

    if (SSL_is_dtls(ssl))
    {
        lpeer = peer = BIO_ADDR_new();
        if (!peer)
            return 0;

        (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), peer);
    }

    if (!BIO_ADDR_rawaddress(peer, NULL, &length))
    {
        BIO_ADDR_free(lpeer);
        return 0;
    }

    port = BIO_ADDR_rawport(peer);
    length += sizeof(port);

    s_cookie.resize(length);

    memcpy(s_cookie.data(), &port, sizeof(port));
    BIO_ADDR_rawaddress(peer, s_cookie.data() + sizeof(port), NULL);

    struct crypto_mac_ctx_t hmac_sha1(SN_hmac, "", SN_sha1, tls->cookie_secret);
    t_cookie = lite_p2p::crypto::crypto_mac_sign(&hmac_sha1, s_cookie);

    memcpy(cookie, t_cookie.data(), t_cookie.size());
    *len = t_cookie.size();

    BIO_ADDR_free(lpeer);

    return 0;
}

int lite_generate_cookie(SSL *ssl, uint8_t *cookie, uint32_t *len)
{
    return lite_generate_stateless_cookie(ssl, cookie, (size_t *)&len);
}

int lite_verify_stateless_cookie(SSL *ssl, const uint8_t *cookie, size_t len)
{
    void *ctx = SSL_get_app_data(ssl);
    struct tls_context_t *tls;
    unsigned char v_cookie[EVP_MAX_MD_SIZE];
    size_t length;

    if (!ctx)
        return 0;

    tls = (struct tls_context_t *)ctx;

    if (tls->cookie_initialized && lite_generate_stateless_cookie(ssl, v_cookie, &length) && len == length && memcmp(v_cookie, cookie, length) == 0)
        return 1;

    return 0;
}

int lite_verify_cookie(SSL *ssl, const uint8_t *cookie, uint32_t len)
{
    return lite_verify_stateless_cookie(ssl, cookie, len);
}

void ssl_info_callback(const SSL *ssl, int where, int ret)
{
    if (ret == 0)
    {
        fprintf(stderr, "SSL_info_callback: error occurred\n");
        return;
    }

    const char *str = SSL_state_string_long(ssl);
    fprintf(stderr, "SSL_info_callback: state=%s\n", str);
}

int ssl_peer_verify(int ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

static struct tls_ops_t __attribute_maybe_unused__ lite_tls_ops = {
    .ssl_peer_verify = ssl_peer_verify,
    .ssl_info = ssl_info_callback,
    .generate_cookie = lite_generate_cookie,
    .verify_cookie = lite_verify_cookie,
    .generate_stateless_cookie = lite_generate_stateless_cookie,
    .verify_stateless_cookie = lite_verify_stateless_cookie,
};

int main(int argc, char *argv[])
{

    if (argc < 8)
    {
        usage(argv[0]);
    }

    srand(time(NULL));
    int family = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    int type = !strncmp(argv[2], "tcp", 3) ? SOCK_STREAM : SOCK_DGRAM;
    int con_type = !strncmp(argv[7], "client", 6) ? PEER_CON_TCP_CLIENT : PEER_CON_TCP_SERVER;
    // lite_p2p::peer::connection *conn = new lite_p2p::peer::connection(family, argv[3], atoi(argv[4]), type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
    lite_p2p::common::at_exit_cleanup __at_exit({SIGABRT, SIGHUP, SIGINT, SIGQUIT, SIGTERM});

    struct crypto_pkey_ctx_t ctx(EVP_PKEY_RSA);
    EVP_PKEY *p_keys = lite_p2p::crypto::crypto_generate_keypair(&ctx, "");
    struct tls_config_t cfg = {
        .keys = p_keys,
        .x509_expiration = 86400L,
        .timeout = 5,
        .verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, //| SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        .min_version = TLS1_2_VERSION,
        .ciphers = TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        .ops = &lite_tls_ops
    };
    lite_p2p::tsocket *s = new lite_p2p::tsocket(family, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP, &cfg);
    lite_p2p::peer::connection *conn = new lite_p2p::peer::connection(s, argv[3], atoi(argv[4]));
    conn->connection_type = PEER_DIRECT_CONNECTION;
    conn->type = con_type;
    lite_p2p::network::string_to_addr(family, argv[5], &conn->remote);
    lite_p2p::network::set_port(&conn->remote, atoi(argv[6]));

    printf("bind: %s [%d]\n", lite_p2p::network::addr_to_string(&conn->local).c_str(), lite_p2p::network::get_port(&conn->local));
    printf("remote: %s [%d]\n", lite_p2p::network::addr_to_string(&conn->remote).c_str(), lite_p2p::network::get_port(&conn->remote));

    __at_exit.at_exit_cleanup_add(p_keys, [](void *a)
                                  {
        EVP_PKEY *p = (EVP_PKEY *)a;
        if (!p)
            return;

        EVP_PKEY_free(p); });

    __at_exit.at_exit_cleanup_add(s, [](void *a)
                                  {
        lite_p2p::tsocket *s = (lite_p2p::tsocket *)a;

        if (!s)
            return;

        delete s; });

    __at_exit.at_exit_cleanup_add(conn, [](void *c)
                                  {
        lite_p2p::peer::connection *cn = (lite_p2p::peer::connection *)c;
        
        if (!cn)
            return;

        delete cn; });

    std::thread sender(visichat_sender, conn);
    std::thread recver(visichat_listener, conn);

    auto th_cleanup = [](void *ctx)
    {
        terminate = true;
    };

    __at_exit.at_exit_cleanup_add(&sender, th_cleanup);
    __at_exit.at_exit_cleanup_add(&recver, th_cleanup);

    sender.join();
    recver.join();

    return 0;
}