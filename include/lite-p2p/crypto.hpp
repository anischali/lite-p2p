#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SHA_ALGO(alg) EVP_##alg()

struct crypto_mac_ctx_t {

    crypto_mac_ctx_t(std::vector<uint8_t> _key) {
        algorithm = "hmac";
        key = _key;

        params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)"", 0);
        params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *)"sha256", 0);
        params[2] = OSSL_PARAM_construct_end();        
    };

    crypto_mac_ctx_t(std::string _algorithm,
                    std::string _cipher,
                    std::string _digest,
                    std::vector<uint8_t> _key) {
        algorithm = _algorithm;
        key = _key;

        params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)_cipher.c_str(), 0);
        params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *)_digest.c_str(), 0);
        params[2] = OSSL_PARAM_construct_end();
    };

    std::string algorithm;
    size_t size;
    OSSL_PARAM params[3];
    std::vector<uint8_t> key;
};

namespace lite_p2p {

    class crypto {
    public:
        static std::string crypto_base64_encode(std::vector<uint8_t> buf);
        static std::vector<uint8_t> crypto_base64_decode(std::string &str);

        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::string &s);
        static struct crypto_mac_ctx_t * crypto_mac_new(const char *algorithm, const char *_cipher,
                                const char *_digest, std::vector<uint8_t> &_key); 
        static void crypto_mac_free(crypto_mac_ctx_t *ctx);
        static std::vector<uint8_t> crypto_mac_sign(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf);
        static bool crypto_mac_verify(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf, std::vector<uint8_t> &digest);

        static std::vector<uint8_t> crypto_random_password(int bits);
    };

};


#endif