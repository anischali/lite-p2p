#include <lite-p2p/network/socket.hpp>

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

    tls.ctx = SSL_CTX_new(tls.method);
    if (!tls.ctx)
        throw std::runtime_error("failed to create ssl context");

    ret = SSL_CTX_set_cipher_list(tls.ctx, config->ciphers.c_str());
    if (ret <= 0)
        throw std::runtime_error("failed to set cipher list");

    ret = SSL_CTX_use_PrivateKey(tls.ctx, config->keys);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given private key");

    ret = SSL_CTX_use_certificate(tls.ctx, config->x509);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given certificate key");

    return 0;
}

int tsocket::tsocket_ssl_dgram(bool listen)
{
    struct timeval timeout = {5, 0};
    BIO *bio;

    try
    {
        tls.session = SSL_new(tls.ctx);
        if (!tls.session)
            throw std::runtime_error("failed to create ssl session");

        bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!bio)
            throw std::runtime_error("failed to create bio for ssl session");

        // BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &timeout);

        SSL_set_bio(tls.session, bio, bio);
        if (listen)
        {
            SSL_set_accept_state(tls.session);
            if (!SSL_is_init_finished(tls.session))
                ;
            SSL_do_handshake(tls.session);
        }
        else
        {
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
            SSL_set_connect_state(tls.session);
            SSL_do_handshake(tls.session);
        }
    }
    catch (std::exception &e)
    {
        return -EINVAL;
    }

    return 0;
}

int tsocket::tsocket_ssl_accept()
{
    int ret;
    try
    {
        tls.session = SSL_new(tls.ctx);
        if (!tls.session)
            throw std::runtime_error("failed to create ssl session");

        SSL_set_fd(tls.session, fd);
        ret = SSL_accept(tls.session);
        if (ret <= 0)
            throw std::runtime_error("failed to accept ssl");
    }
    catch (std::exception &e)
    {
        return -EINVAL;
    }

    return 0;
}

int tsocket::tsocket_ssl_connect()
{
    int ret;
    try
    {
        tls.session = SSL_new(tls.ctx);
        if (!tls.session)
            throw std::runtime_error("failed to create ssl session");

        // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ret = SSL_set_fd(tls.session, fd);
        if (ret <= 0)
        {
            ret = SSL_get_error(tls.session, ret);
            throw std::runtime_error("failed to associate socket to session");
        }

        ret = SSL_connect(tls.session);
        if (ret <= 0)
        {
            ret = SSL_get_error(tls.session, ret);
            throw std::runtime_error("failed to accept ssl");
        }

        X509 *server_cert = SSL_get_peer_certificate(tls.session);
        if (!server_cert)
            throw std::runtime_error("failed to get peer certificate");

        if (config->ops && config->ops->ssl_peer_validate)
        {
            ret = config->ops->ssl_peer_validate(server_cert);
            if (ret < 0)
                throw std::runtime_error("failed to validate peer certificate");
        }
    }
    catch (std::exception &e)
    {
        return -(ret);
    }

    return 0;
}

tsocket::tsocket(sa_family_t _family, int _type, int _protocol, struct tls_config_t *cfg) : base_socket(_family, _type, _protocol),
                                                                                             config{cfg}
{
    try
    {
        tls.method = ssl_method(protocol);
        if (!config->x509)
        {
            config->x509_auto_generate = true;
            config->x509 = lite_p2p::crypto::crypto_pkey_to_x509(config->keys, config->x509_info, config->x509_expiration); // until tomorrow
            if (!config->x509)
                throw std::runtime_error("failed to generate certificate from key");
        }

        tsocket_ssl_init();
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

tsocket::tsocket(int _fd, struct tls_config_t *cfg) : base_socket(_fd),
                                                       config{cfg}
{
    try
    {
        tls.method = ssl_method(protocol);
        tsocket_ssl_init();
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

tsocket::~tsocket()
{
    SSL_shutdown(tls.session);
    SSL_free(tls.session);
    SSL_CTX_free(tls.ctx);
    
    if (config->x509_auto_generate)
        lite_p2p::crypto::crypto_free_x509(&config->x509);
    
    close(fd);
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
        return tsocket_ssl_dgram(false);
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
            return nullptr;

        auto s = new tsocket(nfd, config);

        ret = s->tsocket_ssl_accept();
        if (ret < 0)
            return nullptr;

        return s;
    }
    else
    {
        ret = tsocket_ssl_dgram(true);
        if (ret < 0)
            return nullptr;

        return this;
    }

    return nullptr;
}

size_t tsocket::send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr)
{
    if (!tls.session)
    {
        connect(addr);
    }

    return send(buf, len);
}

size_t tsocket::send(void *buf, size_t len)
{
    return SSL_write(tls.session, buf, len);
}

size_t tsocket::recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote)
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