#include <lite-p2p/network/socket.hpp>
#include <lite-p2p/common/common.hpp>
#include <openssl/err.h>

using namespace lite_p2p;

static inline const SSL_METHOD *ssl_method(int type)
{
    return ((type & SOCK_DGRAM) != 0) ? DTLS_method() : TLS_method();
}

#define ssl_err(s, c) printf("%s\n", ERR_error_string(SSL_get_error(s, c), NULL));

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

    SSL_CTX_set_app_data(tls.ctx, &tls);

    if (config->ciphers.length() > 0)
    {
        ret = SSL_CTX_set_ciphersuites(tls.ctx, config->ciphers.c_str());
        if (ret <= 0)
            goto err_out;
    }

    ret = SSL_CTX_use_PrivateKey(tls.ctx, config->keys);
    if (ret <= 0)
        goto err_out;

    ret = SSL_CTX_use_certificate(tls.ctx, config->x509);
    if (ret <= 0)
        goto err_out;

    if (config->min_version != 0)
    {
        SSL_CTX_set_min_proto_version(tls.ctx, config->min_version);
    }

    if (config->max_version != 0)
    {
        SSL_CTX_set_max_proto_version(tls.ctx, config->min_version);
    }

    SSL_CTX_set_session_cache_mode(tls.ctx, config->cache_mode);

    ret = SSL_CTX_set_session_id_context(tls.ctx, (const uint8_t *)&tls.ctx_id, sizeof(int));
    if (ret <= 0)
        goto err_out;

    SSL_CTX_set_read_ahead(tls.ctx, 1);

    tsocket_set_ssl_ops(config->ops);
    return 0;

err_out:
    SSL_CTX_free(tls.ctx);
    tls.ctx = NULL;
    return ret;
}

int tsocket::tsocket_ssl_accept(struct sockaddr_t *addr, long int timeout_s)
{
    int ret, retry = 25;
    struct timeval tv = {.tv_sec = timeout_s};

    if (!tls.ctx)
        return -ENOENT;

    tls.session = SSL_new(tls.ctx);
    if (!tls.session)
        return -ENOMEM;

    SSL_set_app_data(tls.session, &tls);

    SSL_set_accept_state(tls.session);

    if (config->ops && config->ops->msg_callback)
        SSL_set_msg_callback(tls.session, config->ops->msg_callback);

    if ((type & SOCK_STREAM) != 0)
    {
        ret = SSL_set_fd(tls.session, fd);
        if (ret <= 0)
            goto err_ssl;
    }

    if ((type & SOCK_DGRAM) != 0)
    {
        tls.bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!tls.bio)
            goto err_ssl;

        SSL_set_bio(tls.session, tls.bio, tls.bio);

        if (timeout_s != 0)
        {
            BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv);
            BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv);
        }

        if (config->mtu_discover)
            BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

        if (protocol != IPPROTO_SCTP)
            SSL_set_options(tls.session, SSL_OP_COOKIE_EXCHANGE);
        
        memset(&addr->sa_addr, 0, sizeof(addr->sa_addr));
        do
        {
            ret = (config->stateless) ? SSL_stateless(tls.session) : DTLSv1_listen(tls.session, (BIO_ADDR *)&addr->sa_addr);
            if (ret < 0)
            {
                ssl_err(tls.session, ret);
                goto err_ssl;
            }

            if (!ret)
                ssl_err(tls.session, ret);

        } while (ret <= 0 && retry-- > 0);

        if (ret <= 0)
            goto err_ssl;
        
        BIO_ctrl_set_connected(SSL_get_rbio(tls.session), &addr->sa_addr.addr);
    }

    ret = SSL_accept(tls.session);
    if (ret <= 0)
        goto err_ssl;

    return 0;

err_ssl:
    if (tls.session)
    {
        ret = SSL_shutdown(tls.session);
        if (!ret)
            ret = SSL_shutdown(tls.session);

        SSL_free(tls.session);
        tls.session = NULL;
    }

    return ret;
}

int tsocket::tsocket_ssl_connect(struct sockaddr_t *addr, long int timeout_s)
{
    timeval tv = {.tv_sec = timeout_s};
    X509 *server_cert;
    int ret;

    if (!tls.ctx)
        return -ENOENT;

    tls.session = SSL_new(tls.ctx);
    if (!tls.session)
        throw std::runtime_error("failed to create ssl session");

    SSL_set_app_data(tls.session, &tls);

    SSL_set_connect_state(tls.session);

    if (config->ops && config->ops->msg_callback)
        SSL_set_msg_callback(tls.session, config->ops->msg_callback);

    if (type == SOCK_DGRAM)
    {
        tls.bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (!tls.bio)
            goto err_ssl;

        SSL_set_bio(tls.session, tls.bio, tls.bio);
        BIO_set_fd(SSL_get_rbio(tls.session), fd, BIO_NOCLOSE);
        BIO_ctrl(SSL_get_rbio(tls.session), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr->sa_addr.addr);

        if (timeout_s != 0)
        {
            BIO_ctrl(tls.bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv);
            BIO_ctrl(tls.bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv);
        }
    }

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
            goto err_srv;
    }

    X509_free(server_cert);

    return 0;

err_srv:
    X509_free(server_cert);
err_ssl:
    if (tls.session)
    {
        ret = SSL_shutdown(tls.session);
        if (!ret)
            ret = SSL_shutdown(tls.session);

        SSL_free(tls.session);
        tls.session = NULL;
    }

    return ret;
}

void tsocket::tsocket_ssl_cleanup()
{
    int ret;

    if (tls.session)
    {
        ret = SSL_shutdown(tls.session);
        if (!ret)
            SSL_shutdown(tls.session);

        SSL_free(tls.session);
        tls.session = NULL;
    }

    if (tls.ctx)
    {
        SSL_CTX_free(tls.ctx);
        tls.ctx = NULL;
    }

    if (config)
    {
        if (config->x509_auto_generate && config->x509)
        {
            lite_p2p::crypto::crypto_free_x509(config->x509);
            config->x509 = NULL;
        }
        delete config;
        config = NULL;
    }
}

tsocket::tsocket(sa_family_t _family, int _type, int _protocol, struct tls_config_t *cfg) : base_socket(_family, _type, _protocol)
{
    try
    {
        config = new struct tls_config_t(*cfg);
        tls.cfg = config;

        tls.method = ssl_method(type);
        if (!config->x509)
        {
            config->x509_auto_generate = true;
            config->x509 = lite_p2p::crypto::crypto_pkey_to_x509(config->keys, config->x509_info, config->x509_expiration);
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

tsocket::tsocket(int _fd, struct tls_config_t *cfg) : base_socket(_fd)
{
    try
    {
        config = new struct tls_config_t(*cfg);

        config->x509_auto_generate = false;
        if (!config->x509)
        {
            config->x509_auto_generate = true;
            config->x509 = lite_p2p::crypto::crypto_pkey_to_x509(config->keys, config->x509_info, config->x509_expiration);
            if (!config->x509)
                throw std::runtime_error("failed to generate certificate from key");
        }

        tls.cfg = config;
        tls.method = ssl_method(type);
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

    ret = tsocket_ssl_connect(addr, config->timeout);
    if (ret < 0)
        return ret;

    return 0;
}

int tsocket::listen(int n)
{
    return network::listen_socket(fd, n);
}

base_socket *tsocket::accept(struct sockaddr_t *addr)
{
    int ret, nfd;
    const int enable = 1;
    struct sockaddr_t bind_addr;
    tsocket *s;

    if (type == SOCK_STREAM)
    {
        nfd = lite_p2p::network::accept_socket(fd, addr);
        if (nfd <= 0)
            return NULL;

        s = new tsocket(nfd, config);
        if (!s)
            return NULL;
    }
    else
    {
        nfd = socket(addr->sa_family, SOCK_DGRAM, 0);
        if (nfd < 0)
            return NULL;

        s = new tsocket(nfd, config);
        if (!s)
            return NULL;

        s->set_sockopt(SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        s->set_sockopt(SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

        ret = lite_p2p::network::get_sockname(fd, &bind_addr);
        if (ret < 0)
            goto err_nsock;

        ret = lite_p2p::network::bind_socket(nfd, &bind_addr);
        if (ret < 0)
            goto err_nsock;   
    }

    if (!s)
        return NULL;

    ret = s->tsocket_ssl_accept(addr, config->timeout);
    if (ret < 0)
        goto err_nsock;

    return s;

err_nsock:
    delete s;
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
    if (config && ops)
    {
        config->ops = ops;
        if (config->ops && config->ops->ssl_info)
            SSL_CTX_set_info_callback(tls.ctx, config->ops->ssl_info);

        if (config->ops && config->ops->generate_cookie)
            SSL_CTX_set_cookie_generate_cb(tls.ctx, config->ops->generate_cookie);

        if (config->ops && config->ops->verify_cookie)
            SSL_CTX_set_cookie_verify_cb(tls.ctx, config->ops->verify_cookie);

        if (config->ops && config->ops->generate_stateless_cookie)
            SSL_CTX_set_stateless_cookie_generate_cb(tls.ctx, config->ops->generate_stateless_cookie);

        if (config->ops && config->ops->verify_stateless_cookie)
            SSL_CTX_set_stateless_cookie_verify_cb(tls.ctx, config->ops->verify_stateless_cookie);

        if (config->ops && config->ops->ssl_peer_verify && config->verify_mode != 0)
            SSL_CTX_set_verify(tls.ctx, config->verify_mode, config->ops->ssl_peer_verify);
    }
}