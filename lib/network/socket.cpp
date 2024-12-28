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

static inline const SSL_METHOD *ssl_method_by_type(int type)
{

    return (type == SOCK_DGRAM) ? DTLS_method() : nullptr;
}

int s_socket::s_socket_ssl_init()
{
    int ret;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(method);
    if (!ctx)
        throw std::runtime_error("failed to create ssl context");

    SSL_CTX_set_info_callback(ctx, SSL_info_callback);

    ret = SSL_CTX_set_cipher_list(ctx, tls_cipher.c_str());
    if (ret <= 0)
        throw std::runtime_error("failed to set cipher list");

    ret = SSL_CTX_use_PrivateKey(ctx, keys);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given private key");

    ret = SSL_CTX_use_certificate(ctx, x509);
    if (ret <= 0)
        throw std::runtime_error("failed to use the given certificate key");

    return 0;
}

int s_socket::s_socket_ssl_accept()
{
    int ret;
    try
    {
        session = SSL_new(ctx);
        if (!session)
            throw std::runtime_error("failed to create ssl session");

        SSL_set_fd(session, fd);
        ret = SSL_accept(session);
        if (ret <= 0)
            throw std::runtime_error("failed to accept ssl");
    }
    catch (std::exception &e)
    {
        return -EINVAL;
    }

    return 0;
}

int s_socket::s_socket_ssl_connect()
{
    int ret;
    try
    {
        session = SSL_new(ctx);
        if (!session)
            throw std::runtime_error("failed to create ssl session");

        // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        ret = SSL_set_fd(session, fd);
        if (ret <= 0)
        {
            ret = SSL_get_error(session, ret);
            throw std::runtime_error("failed to associate socket to session");
        }

        ret = SSL_connect(session);
        if (ret <= 0)
        {
            ret = SSL_get_error(session, ret);
            throw std::runtime_error("failed to accept ssl");
        }

        X509 *server_cert = SSL_get_peer_certificate(session);
        if (!server_cert)
            throw std::runtime_error("failed to get peer certificate");

        if (ssl_peer_certificate_check)
        {
            ret = ssl_peer_certificate_check(server_cert);
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

s_socket::s_socket(sa_family_t _family, int _type, int _protocol, EVP_PKEY *pkey, const SSL_METHOD *_method, std::string cipher) : base_socket(_family, _type, _protocol),
                                                                                                                                   keys{pkey}, method{_method}, tls_cipher{cipher}
{
    try
    {
        if (method)
        {
            x509 = lite_p2p::crypto::crypto_pkey_to_x509(keys, x509_info, 86400L); // until tomorrow
            if (!x509)
                throw std::runtime_error("failed to generate certificate from key");

            s_socket_ssl_init();
        }
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

s_socket::s_socket(sa_family_t _family, int _type, int _protocol, EVP_PKEY *pkey, const SSL_METHOD *_method, std::string cipher, X509 *cert) : base_socket(_family, _type, _protocol),
                                                                                                                                               keys{pkey}, method{_method}, tls_cipher{cipher}, x509{cert}
{
    try
    {
        if (method)
        {
            s_socket_ssl_init();
        }
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

s_socket::s_socket(int _fd, EVP_PKEY *pkey, const SSL_METHOD *_method, std::string cipher, X509 *cert) : base_socket(_fd),
                                                                                                         keys{pkey}, method{_method}, tls_cipher{cipher}, x509{cert}
{
    try
    {
        if (method)
        {
            s_socket_ssl_init();
        }
    }
    catch (const std::exception &e)
    {
        throw e;
    }
}

s_socket::~s_socket()
{
    SSL_shutdown(session);
    SSL_free(session);
    SSL_CTX_free(ctx);
    lite_p2p::crypto::crypto_free_x509(&x509);
    close(fd);
}

int s_socket::bind(struct sockaddr_t *addr)
{
    return lite_p2p::network::bind_socket(fd, addr);
}

int s_socket::connect(struct sockaddr_t *addr)
{
    int ret;

    ret = lite_p2p::network::connect_socket(fd, addr);
    if (ret < 0)
        return ret;

    ret = s_socket_ssl_connect();
    if (ret < 0)
        return ret;

    return 0;
}

int s_socket::listen(int n)
{
    return network::listen_socket(fd, n);
}

base_socket *s_socket::accept(struct sockaddr_t *addr)
{
    int ret;
    int nfd = lite_p2p::network::accept_socket(fd, addr);
    if (nfd <= 0)
        return nullptr;

    auto s = new s_socket(nfd, keys, TLS_method(), tls_cipher, x509);

    ret = s->s_socket_ssl_accept();
    if (ret < 0)
        return nullptr;

    return s;
}

size_t s_socket::send_to(void *buf, size_t len, int flags, struct sockaddr_t *addr)
{
    if (!session)
    {
        connect(addr);
    }

    return send(buf, len);
}

size_t s_socket::send(void *buf, size_t len)
{
    return SSL_write(session, buf, len);
}

size_t s_socket::recv_from(void *buf, size_t len, int flags, struct sockaddr_t *remote)
{
    if (!session)
    {
        connect(remote);
    }

    return recv(buf, len);
}

size_t s_socket::recv(void *buf, size_t len)
{
    return SSL_read(session, buf, len);
}