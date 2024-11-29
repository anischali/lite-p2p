#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <string>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <vector>

#define SHA_ALGO(alg) EVP_##alg()

struct ossl_hmac_ctx_t {

    ossl_hmac_ctx_t(const uint8_t *_key,
                    size_t key_len){
        key = _key;
        keylen = key_len;

        params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)cipher, 0);
        params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
        params[2] = OSSL_PARAM_construct_end();        
    };

    ossl_hmac_ctx_t(const char *_algorithm,
                    const char *_cipher,
                    const char *_digest,
                    const uint8_t *_key,
                    size_t key_len) {
        algorithm = _algorithm;
        cipher = _cipher;
        digest = _digest;
        key = _key;
        keylen = key_len;

        params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)cipher, 0);
        params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *)digest, 0);
        params[2] = OSSL_PARAM_construct_end();
    };

    const char *algorithm;
    const char *cipher;
    const char *digest;
    OSSL_PARAM params[3];
    const uint8_t *key;
    size_t keylen;

    EVP_MAC *mac; 
    EVP_MAC_CTX *ctx;
};

namespace lite_p2p {

    class crypto {
    public:

        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> hmac_compute_buffer(const EVP_MD *algorithm, 
                        std::vector<uint8_t> &buf, std::vector<uint8_t> &key);
    };

};


#endif