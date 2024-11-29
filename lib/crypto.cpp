#include "lite-p2p/crypto.hpp"
#include <cerrno>


using namespace lite_p2p;

int crypto::checksum(const EVP_MD *algorithm, uint8_t *buf, size_t len, uint8_t *out_buf) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;
    uint32_t out_len = 0;

    if (!ctx)
        return -ENOMEM;
    
    ret = EVP_DigestInit_ex(ctx, algorithm, NULL);
    if (!ret)
        goto out_err;

    ret = EVP_DigestUpdate(ctx, buf, len);
    if (!ret)
        goto out_err;

    ret = EVP_DigestFinal_ex(ctx, out_buf, &out_len);
    if (!ret)
        goto out_err;

    EVP_MD_CTX_free(ctx);

    return (int)out_len;

out_err:
    EVP_MD_CTX_free(ctx);
    return -EINVAL;
}