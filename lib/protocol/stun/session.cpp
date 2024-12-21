#include <lite-p2p/protocol/stun/session.hpp>
#include <lite-p2p/protocol/stun/client.hpp>


using namespace lite_p2p;
using namespace lite_p2p::protocol::stun;

const std::vector<struct algo_type_t> algos = {
            ALGO_TYPE(SHA_ALGO_MD5, EVP_md5(), htons(STUN_PASSWD_ALG_MD5), "md5", 16),
            ALGO_TYPE(SHA_ALGO_SHA1, EVP_sha1(), htons(STUN_PASSWD_ALG_SHA256), "sha1", 20),
            ALGO_TYPE(SHA_ALGO_SHA256, EVP_sha256(), htons(STUN_PASSWD_ALG_SHA256), "sha256", 32),
            ALGO_TYPE(SHA_ALGO_SHA384, EVP_sha384(), htons(STUN_PASSWD_ALG_SHA256), "sha384", 48),
            ALGO_TYPE(SHA_ALGO_SHA512, EVP_sha512(), htons(STUN_PASSWD_ALG_SHA256), "sha512", 64),
};

struct stun_session_t *session_config::stun_session_get(struct sockaddr_t *addr)
{
    std::string s_sha, s_tmp = lite_p2p::network::addr_to_string(addr) + ":" +
                               std::to_string(lite_p2p::network::get_port(addr)) + ":" +
                               std::to_string(addr->sa_family);

    s_sha = lite_p2p::crypto::crypto_base64_encode(lite_p2p::crypto::checksum(SHA_ALGO(sha1), s_tmp));

    if (auto s = session_db.find(s_sha); s != session_db.end())
    {
        return s->second;
    }

    return nullptr;
}


void session_config::stun_generate_key(struct stun_session_t *session, std::string password)
{
    const struct algo_type_t *alg;
    std::string s_key = session->lt_cred_mech ? (session->user + ":" + session->realm + ":" + password) : password;

    if (session->password_algo == SHA_ALGO_CLEAR) {
        alg = &algos[session->key_algo];
        session->key = lite_p2p::crypto::checksum(alg->ossl_alg, s_key);
    }

    if (session->algorithms.size() == 0) {
        session->algorithms.push_back(algos[SHA_ALGO_MD5].stun_alg);
        session->algorithms.push_back(algos[SHA_ALGO_SHA256].stun_alg);
    }
}

void session_config::stun_register_session(struct stun_session_t *session)
{

    std::string s_sha, s_tmp = network::addr_to_string(&session->server) + ":" +
                               std::to_string(network::get_port(&session->server)) + ":" +
                               std::to_string(session->server.sa_family);

    s_sha = lite_p2p::crypto::crypto_base64_encode(lite_p2p::crypto::checksum(SHA_ALGO(sha1), s_tmp));
    session_db[s_sha] = session;
}