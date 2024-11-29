#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define SHA_ALGO(alg) EVP_##alg()
namespace lite_p2p {


    class crypto {
    public:

        static int checksum(const EVP_MD *algorithm, uint8_t *buf, size_t buf_len, uint8_t *out_buf);
        
        static int hmac_sha256(uint8_t *buf, size_t buf_len, uint8_t *key, size_t key_len, uint8_t *out_buf, size_t *out_len);
        static int hmac_sha1(uint8_t *buf, size_t buf_len, uint8_t *key, size_t key_len, uint8_t *out_buf, size_t *out_len);



    };

};


#endif