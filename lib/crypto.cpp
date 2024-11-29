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

#define goto_print(msg, label) {\
    printf("%s\n", msg); \
    goto label; \
}

int crypto::compute_buf_hmac(const char *alg_params[3], const uint8_t *key, 
                size_t key_len, uint8_t *buf, size_t len, uint8_t *outbuf) {
    int ret;
    size_t out_len = 0, i;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[3];
    
    mac = EVP_MAC_fetch(NULL, alg_params[0], NULL);
    if (!mac)
        return -ENOMEM;

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx)
        goto_print("ctx failed", clean_mac);

    params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)alg_params[1], 0);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *)alg_params[2], 0);
    params[2] = OSSL_PARAM_construct_end();

    ret = EVP_MAC_init(ctx, key, key_len, &params[0]);
    if (!ret)
        goto_print("init ctx failed", clean_context);

    for (i = 0; i < len; ++i) {
        ret = EVP_MAC_update(ctx, &buf[i], 1);
        if (!ret)
            goto_print("hmac update", clean_context);
    }

    ret = EVP_MAC_final(ctx, outbuf, &out_len, 4096);
    if (!ret)
        goto_print("hmac final", clean_context);


    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return out_len;

clean_context:
    EVP_MAC_CTX_free(ctx);
clean_mac:
    EVP_MAC_free(mac);

    return -EINVAL;
}