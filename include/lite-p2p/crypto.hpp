#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <string>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SHA_ALGO(alg) EVP_##alg()
namespace lite_p2p {


    class crypto {
    public:

        static int checksum(const EVP_MD *algorithm, uint8_t *buf, size_t buf_len, uint8_t *out_buf);
        static int compute_buf_hmac(const char *alg_params[3], const uint8_t *key, 
                size_t key_len, uint8_t *buf, size_t len, uint8_t *outbuf);
    };

};


#endif