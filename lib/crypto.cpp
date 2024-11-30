#include "lite-p2p/crypto.hpp"
#include <cerrno>
#include <cstdlib>


using namespace lite_p2p;

std::vector<uint8_t> crypto::checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint32_t out_len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> digest(out_len);
    int ret;

    if (!ctx)
        return {};
    
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

struct crypto_mac_ctx_t * crypto::crypto_mac_new(const char *algorithm, const char *_cipher,
                                const char *_digest, std::vector<uint8_t> &_key) {
    struct crypto_mac_ctx_t *ctx = new crypto_mac_ctx_t(algorithm, _cipher, _digest, _key);
    
    if (!ctx)
        return NULL;
    
    return ctx;
}


void crypto::crypto_mac_free(crypto_mac_ctx_t *ctx) {
    
    if (!ctx)
        return;

    delete ctx;
}

std::vector<uint8_t> crypto::crypto_mac_sign(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf) {
    std::vector<uint8_t> digest;
    EVP_MAC_CTX *evp_ctx = NULL;
    EVP_MAC *mac = NULL;
    size_t len = 0;
    int ret;

    mac = EVP_MAC_fetch(NULL, ctx->algorithm, NULL);
    if (!mac)
        return {};

    evp_ctx = EVP_MAC_CTX_new(mac);
    if (!evp_ctx)
        goto clean_mac;


    ret = EVP_MAC_init(evp_ctx, ctx->key.data(), ctx->key.size(), ctx->params);
    if (!ret)
        goto clean_ctx;
    
    ret = EVP_MAC_update(evp_ctx, buf.data(), buf.size());
    if (!ret)
        goto clean_ctx;
    
    ret = EVP_MAC_final(evp_ctx, NULL, &len, 0);
    if (!ret)
        goto clean_ctx;
    
    digest.resize(len);
    ret = EVP_MAC_final(evp_ctx, digest.data(), &len, len);
    if (!ret)
        goto clean_ctx;

    EVP_MAC_CTX_free(evp_ctx);
    EVP_MAC_free(mac);

    return digest;

clean_ctx:
    EVP_MAC_CTX_free(evp_ctx);
clean_mac:
    EVP_MAC_free(mac);

    return {};
}