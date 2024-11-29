#include "lite-p2p/crypto.hpp"
#include <cerrno>


using namespace lite_p2p;

std::vector<uint8_t> crypto::checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint32_t out_len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> digest(out_len);
    int ret;

    if (!ctx)
        return digest;
    
    ret = EVP_DigestInit_ex(ctx, algorithm, NULL);
    if (!ret)
        goto out_err;

    ret = EVP_DigestUpdate(ctx, buf.data(), buf.size());
    if (!ret)
        goto out_err;

    ret = EVP_DigestFinal_ex(ctx, digest.data(), &out_len);
    if (!ret)
        goto out_err;

    EVP_MD_CTX_free(ctx);

    digest.resize(out_len);

    return digest;

out_err:
    EVP_MD_CTX_free(ctx);

    return {};
}

#define goto_print(msg, label) {\
    printf("%s\n", msg); \
    goto label; \
}

std::vector<uint8_t> crypto::hmac_compute_buffer(const EVP_MD *algorithm, std::vector<uint8_t> &buf, 
                        std::vector<uint8_t> &key) {

    return {};
}