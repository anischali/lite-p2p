#include <lite-p2p/network/socket.hpp>
#include <fcntl.h>

using namespace lite_p2p;

void SSL_info_callback(const SSL *ssl, int where, int ret)
{
    if (ret == 0)
    {
        fprintf(stderr, "SSL_info_callback: error occurred\n");
        return;
    }

    const char *str = SSL_state_string_long(ssl);
    fprintf(stderr, "SSL_info_callback: state=%s\n", str);
}

static inline const SSL_METHOD *ssl_method(int protocol)
{
    return (protocol == IPPROTO_UDP) ? DTLS_method() : TLS_method();
}

int tsocket::tsocket_ssl_init()
{
    int ret;
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    if (!tls.method)
        return -ENOENT;

    tls.ctx = SSL_CTX_new(tls.method);
    if (!tls.ctx)
        return -ENOMEM;

    ret = SSL_CTX_set_cipher_list(tls.ctx, config->ciphers.c_str());
    if (ret <= 0)
        goto err_out;

    ret = SSL_CTX_use_PrivateKey(tls.ctx, config->keys);
    if (ret <= 0)
        goto err_out;

    ret = SSL_CTX_use_certificate(tls.ctx, config->x509);
    if (ret <= 0)
        goto err_out;

    return 0;

err_out:
    SSL_CTX_free(tls.ctx);
    tls.ctx = NULL;
    return ret;
}

int tsocket::tsocket_ssl_dgram(struct sockaddr_t *addr, bool listen)
{
    struct timeval timeout = {60, 0};
    int ret;

    if (!tls.ctx)
        return -ENOENT;

    tls.session = SSL_new(tls.ctx);
    if (!tls.session)
        return -ENOMEM;

    SSL_set_app_data(tls.session, &tls);

    tls.bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!tls.bio)
        goto err_sll;

    SSL_set_bio(tls.session, tls.bio, tls.bio);
    BIO_set_fd(SSL_get_rbio(tls.session), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr->sa_addr);
    BIO_ctrl(tls.bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    if (listen)
    {
        if (config && config->ops && config->ops->generate_cookie)
            SSL_CTX_set_cookie_generate_cb(tls.ctx, config->ops->generate_cookie);

        if (config && config->ops && config->ops->verify_cookie)
            SSL_CTX_set_cookie_verify_cb(tls.ctx, config->ops->verify_cookie);

        ret = SSL_accept(tls.session);
        if (ret <= 0)
            goto err_bio;

        // SSL_CTX_set_options(tls.ctx, SSL_OP_COOKIE_EXCHANGE);
        // SSL_set_accept_state(tls.session);
        // DTLSv1_listen(tls.session, NULL);
        // if (!SSL_is_init_finished(tls.session)) {
        //     do {
        //         ret = SSL_do_handshake(tls.session);
        //     } while (ret <= 0);
        // }

        // BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_GET_PEER, 0, &peer_addr);
    }
    else
    {
        SSL_connect(tls.session);
        do
        {
            ret = SSL_do_handshake(tls.session);
        } while (ret <= 0);
    }
    return 0;

err_bio:
    BIO_free(tls.bio);
    tls.bio = NULL;

err_sll:
    SSL_free(tls.session);
    tls.session = NULL;
    return ret;
}

int tsocket::tsocket_ssl_accept()
{
    int ret;

    if (!tls.ctx)
        return -ENOENT;

    tls.session = SSL_new(tls.ctx);
    if (!tls.session)
        return -ENOMEM;

    SSL_set_fd(tls.session, fd);
    ret = SSL_accept(tls.session);
    if (ret <= 0)
        goto err_ssl;

    return 0;

err_ssl:
    SSL_free(tls.session);
    tls.session = NULL;

    return ret;
}

int tsocket::tsocket_ssl_connect()
{
    X509 *server_cert;
    int ret;

    if (!tls.ctx)
        return -ENOENT;

    tls.session = SSL_new(tls.ctx);
    if (!tls.session)
        throw std::runtime_error("failed to create ssl session");

    ret = SSL_set_fd(tls.session, fd);
    if (ret <= 0)
        goto err_ssl;

    ret = SSL_connect(tls.session);
    if (ret <= 0)
        goto err_ssl;

    server_cert = SSL_get_peer_certificate(tls.session);
    if (!server_cert)
        goto err_ssl;

    if (config->ops && config->ops->ssl_peer_validate)
    {
        ret = config->ops->ssl_peer_validate(server_cert);
        if (ret < 0)
            goto err_ssl;
    }

    return 0;

err_ssl:
    SSL_free(tls.session);
    tls.session = NULL;

    return ret;
}

void tsocket::tsocket_ssl_cleanup() {
    if (tls.session)
    {
        if (SSL_get_shutdown(tls.session) != 0)
            SSL_shutdown(tls.session);
        
        SSL_free(tls.session);
        tls.session = NULL;

        if (tls.bio)
        {
            BIO_free(tls.bio);
            tls.bio = NULL;
        }            
    }

    if (tls.ctx)
    {
        SSL_CTX_free(tls.ctx);
        tls.ctx = NULL;
    }

    if (config->x509_auto_generate && config->x509 != NULL)
    {
        lite_p2p::crypto::crypto_free_x509(&config->x509);
        config->x509 = NULL;
    }
}

tsocket::tsocket(sa_family_t _family, int _type, int _protocol, struct tls_config_t *cfg) : base_socket(_family, _type, _protocol),
                                                                                            config{cfg}
{
    try
    {
        tls.cfg = cfg;
        tls.method = ssl_method(protocol);
        if (!config->x509)
        {
            config->x509_auto_generate = true;
            config->x509 = lite_p2p::crypto::crypto_pkey_to_x509(config->keys, config->x509_info, config->x509_expiration); // until tomorrow
            if (!config->x509)
                throw std::runtime_error("failed to generate certificate from key");
        }

        if (tsocket_ssl_init() < 0)
            throw std::runtime_error("failed to create ssl context");
    }
    catch (const std::exception &e)
    {
        tsocket_ssl_cleanup();
    }
}

tsocket::tsocket(int _fd, struct tls_config_t *cfg) : base_socket(_fd),
                                                      config{cfg}
{
    try
    {
        tls.cfg = cfg;
        tls.method = ssl_method(protocol);
        if (tsocket_ssl_init() < 0)
            throw std::runtime_error("failed to create ssl context");
    }
    catch (const std::exception &e)
    {
        tsocket_ssl_cleanup();
    }
}

tsocket::~tsocket()
{
    tsocket_ssl_cleanup();
}

int tsocket::bind(struct sockaddr_t *addr)
{
    return lite_p2p::network::bind_socket(fd, addr);
}

int tsocket::connect(struct sockaddr_t *addr)
{
    int ret;
        
    ret = lite_p2p::network::connect_socket(fd, addr);
    if (ret < 0)
        return ret;

    if (type == SOCK_STREAM)
    {
        ret = tsocket_ssl_connect();
        if (ret < 0)
            return ret;
    }
    else
    {
        return tsocket_ssl_dgram(addr, false);
    }

    return 0;
}

int tsocket::listen(int n)
{
    return network::listen_socket(fd, n);
}

base_socket *tsocket::accept(struct sockaddr_t *addr)
{
    int ret;

    if (type == SOCK_STREAM)
    {
        int nfd = lite_p2p::network::accept_socket(fd, addr);
        if (nfd <= 0)
            return NULL;

        auto s = new tsocket(nfd, config);

        ret = s->tsocket_ssl_accept();
        if (ret < 0)
            return NULL;

        return s;
    }
    else
    {
        auto s = new tsocket(fd, config);
        ret = s->tsocket_ssl_dgram(addr, true);
        if (ret < 0)
            return NULL;

        return s;
    }

    return NULL;
}

size_t tsocket::send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr)
{
    if (!tls.session)
        return -ENOENT;

    return send(buf, len);
}

size_t tsocket::send(void *buf, size_t len)
{
    if (!tls.session)
        return -ENOENT;

    return SSL_write(tls.session, buf, len);
}

size_t tsocket::recv_from(void *buf, size_t len, int flags, struct sockaddr_t *addr)
{
    if (!tls.session)
        return -EINVAL;

    return recv(buf, len);
}

size_t tsocket::recv(void *buf, size_t len)
{
    if (!tls.session)
        return -EINVAL;

    return SSL_read(tls.session, buf, len);
}

void tsocket::tsocket_set_ssl_ops(struct tls_ops_t *ops)
{
    if (config)
    {
        config->ops = ops;
        if (!config->ops && !config->ops->ssl_info)
            SSL_CTX_set_info_callback(tls.ctx, config->ops->ssl_info);
    }
}