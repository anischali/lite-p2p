#include "lite-p2p/crypto.hpp"
#include <openssl/rand.h>
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
    
    ret = EVP_DigestInit(ctx, algorithm);
    if (!ret)
        goto out_err;

    ret = EVP_DigestUpdate(ctx, buf.data(), buf.size());
    if (!ret)
        goto out_err;

    ret = EVP_DigestFinal(ctx, digest.data(), &out_len);
    if (!ret)
        goto out_err;

    EVP_MD_CTX_free(ctx);

    digest.resize(out_len);

    return digest;

out_err:
    EVP_MD_CTX_free(ctx);

    return {};
}


std::vector<uint8_t> crypto::checksum(const EVP_MD *algorithm, std::string &s) {

    std::vector<uint8_t> buf(s.begin(), s.end());

    return checksum(algorithm, buf);
}


std::vector<uint8_t> crypto::crypto_random_password(int bits) {
    int ret;
    size_t byte_len = (bits / 8);
    std::vector<uint8_t> pass(byte_len);

    ret = RAND_bytes(pass.data(), byte_len);
    if (!ret)
        return {};

    return pass;
}


std::string crypto::crypto_base64_encode(std::vector<uint8_t> buf) {

    return crypto::crypto_base64_encode(buf.data(), buf.size());
}

std::string crypto::crypto_base64_encode(uint8_t *buf, size_t s_len) {
    EVP_ENCODE_CTX *ctx;
    auto b64_size = [](int len) {
        int d_len = 4 * (len / 3 + 2) + 1;
        if (len % 3) {
            d_len += 4 - (len % 4);
        }

        return d_len;
    };
    int ret, len = b64_size(s_len);
    std::vector<uint8_t> out(len);    

    ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
        return "";

    EVP_EncodeInit(ctx);
    
    ret = EVP_EncodeUpdate(ctx, out.data(), &len, buf, s_len);
    if (ret < 0)
        goto clean_ctx;

    EVP_EncodeFinal(ctx, out.data(), &len);
    EVP_ENCODE_CTX_free(ctx);
    out.resize(len);

    return std::string(out.begin(), out.end());

clean_ctx:
    EVP_ENCODE_CTX_free(ctx);
    return "";
}


std::vector<uint8_t> crypto::crypto_base64_decode(std::string &str) {

    return crypto::crypto_base64_decode(str.c_str(), str.length());
}

std::vector<uint8_t> crypto::crypto_base64_decode(const char *str, size_t s_len) {
    EVP_ENCODE_CTX *ctx;
    std::vector<uint8_t> out((int)(s_len * 3 / 4));    
    int ret, len;
    
    ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
        return {};

    EVP_DecodeInit(ctx);
    
    ret = EVP_DecodeUpdate(ctx, out.data(), &len, (uint8_t *)str, s_len);
    if (ret < 0)
        goto clean_ctx;

    out.resize(len);
    EVP_DecodeFinal(ctx, out.data() + len, &len);
    EVP_ENCODE_CTX_free(ctx);

    return out;

clean_ctx:
    EVP_ENCODE_CTX_free(ctx);
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

    mac = EVP_MAC_fetch(NULL, ctx->algorithm.c_str(), NULL);
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


bool crypto::crypto_mac_verify(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf, std::vector<uint8_t> &digest) {
    std::vector<uint8_t> tmp;

    tmp = crypto_mac_sign(ctx, buf);

    return ((digest.size() == tmp.size()) && !CRYPTO_memcmp(digest.data(), tmp.data(), digest.size()));
}