#include "lite-p2p/crypto.hpp"
#include <cerrno>


using namespace lite_p2p;

int crypto::sha256(uint8_t *buf, size_t len, uint8_t *out_hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;
    uint32_t out_len = 0;

    if (!ctx)
        return -ENOMEM;
    
    ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (!ret)
        return -errno;

    ret = EVP_DigestUpdate(ctx, buf, len);
    if (!ret)
        return -errno;

    ret = EVP_DigestFinal_ex(ctx, out_hash, &out_len);
    if (!ret)
        return -errno;

    return (int)out_len;
}


int crypto::sha1(uint8_t *buf, size_t len, uint8_t *key) {


    return 0;
}