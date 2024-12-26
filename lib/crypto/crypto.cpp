#include "lite-p2p/crypto/crypto.hpp"
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <cerrno>
#include <cstdlib>
#include <iostream>

using namespace lite_p2p;

std::vector<uint8_t> crypto::xof_checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf, int bits) {
    EVP_MD_CTX *ctx;
    uint32_t o_len = (uint32_t)(bits / 8);
    std::vector<uint8_t> digest(o_len);
    OSSL_PARAM params[3];
    int ret, xof = 1;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return {};
    
    ret = EVP_DigestInit(ctx, algorithm);
    if (!ret)
        goto out_err;

    params[0] = OSSL_PARAM_construct_uint32(OSSL_DIGEST_PARAM_XOFLEN, &o_len);
    params[1] = OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOF, &xof);
    params[2] = OSSL_PARAM_construct_end();

    ret = EVP_MD_CTX_set_params(ctx, params);
    if (ret <= 0)
        goto out_err;
    

    ret = EVP_DigestUpdate(ctx, buf.data(), buf.size());
    if (!ret)
        goto out_err;

    
    ret = EVP_DigestFinalXOF(ctx, digest.data(), bits / 8);
    if (!ret)
        goto out_err;

    EVP_MD_CTX_free(ctx);

    digest.resize(o_len);

    return digest;

out_err:
    EVP_MD_CTX_free(ctx);

    return {};
}


std::vector<uint8_t> crypto::xof_checksum(const EVP_MD *algorithm, std::string &s, int bits) {
    std::vector<uint8_t> buf(s.begin(), s.end());

    return xof_checksum(algorithm, buf, bits);
}


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


std::vector<uint8_t> crypto::crypto_random_bytes(int bits) {
    int ret;
    size_t byte_len = (bits / 8);
    std::vector<uint8_t> pass(byte_len);

    ret = RAND_bytes(pass.data(), byte_len);
    if (!ret)
        return {};

    return pass;
}


std::vector<uint8_t> crypto::crypto_random_password(int bits) {
    return crypto_random_bytes(bits);
}

std::string crypto::crypto_base64_encode(std::vector<uint8_t> buf) {

    return crypto::crypto_base64_encode(buf.data(), buf.size());
}

std::string crypto::crypto_base64_encode(uint8_t *buf, size_t s_len) {
    EVP_ENCODE_CTX *ctx;
    int ret, len = EVP_ENCODE_LENGTH(s_len), o_len = 0, remaining;
    std::vector<uint8_t> out(len);
    uint8_t *o_ptr = out.data(), *i_ptr = buf;

    ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
        return "";

    EVP_EncodeInit(ctx);
    
    do {
        remaining = std::min(48, (int)s_len);
        ret = EVP_EncodeUpdate(ctx, o_ptr, &len, i_ptr, remaining);
        if (ret < 0)
            goto clean_ctx;

        o_ptr += len;
        i_ptr += remaining;
        s_len -= remaining;
        o_len += len;

    } while(s_len > 0);

    
    EVP_EncodeFinal(ctx, o_ptr, &len);
    o_len += len;
    EVP_ENCODE_CTX_free(ctx);
    out.resize(o_len);

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
    std::vector<uint8_t> out(EVP_DECODE_LENGTH(s_len));    
    int ret, len = 0, remaining = 0, o_len = 0;
    uint8_t *i_ptr = (uint8_t *)str, *o_ptr = out.data();

    ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
        return {};

    EVP_DecodeInit(ctx);
    
    do {
        remaining = std::min(65, (int)s_len);
        ret = EVP_DecodeUpdate(ctx, o_ptr, &len, i_ptr, remaining);
        if (ret < 0)
            goto clean_ctx;

        o_ptr += len;
        i_ptr += remaining;
        s_len -= remaining;
        o_len += len;

    } while(s_len > 0);

    EVP_DecodeFinal(ctx, o_ptr, &len);
    o_len += len;
    out.resize(o_len);
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


    ret = EVP_MAC_init(evp_ctx, ctx->key.data(), ctx->key.size(), ossl_build_params(ctx->params).data());
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

EVP_PKEY * crypto::crypto_generate_keypair(struct crypto_pkey_ctx_t *ctx, std::string password) {
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *evp_ctx = nullptr;
    int ret = -1;

    evp_ctx = EVP_PKEY_CTX_new_id(ctx->id, nullptr);
    if (!evp_ctx)
        return nullptr;

    ret = EVP_PKEY_keygen_init(evp_ctx);
    if (ret <= 0)
        goto clean_ctx;
    
    ret = EVP_PKEY_CTX_set_params(evp_ctx, ossl_build_params(ctx->params).data());
    if (ret <= 0)
        goto clean_ctx;

    ret = EVP_PKEY_keygen(evp_ctx, &pkey);
    if (ret <= 0)
        goto clean_ctx;
    
    EVP_PKEY_CTX_free(evp_ctx);


#if defined(DEBUG)
    printf("Print parameters:\n");
    EVP_PKEY_print_params_fp(stdout, pkey, 2, NULL);
    printf("Print the private key:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    printf("Print the public key:\n");
    PEM_write_PUBKEY(stdout, pkey);
#endif    

    return pkey;

clean_ctx:
    EVP_PKEY_CTX_free(evp_ctx);

    return nullptr;
}


void crypto::crypto_free_keypair(EVP_PKEY **pkey) {
    
    if (*pkey) {
        EVP_PKEY_free(*pkey);
        *pkey = nullptr;
    }
};

std::vector<uint8_t> crypto::crypto_kdf_derive(
    struct crypto_kdf_ctx_t *ctx, std::vector<uint8_t> password, 
    std::vector<uint8_t> salt, int nbits) {
    std::vector<uint8_t> digest(nbits / 8);
    EVP_KDF_CTX *evp_ctx = NULL;
    EVP_KDF *kdf = NULL;
    struct ossl_param_t param;
    int ret;

    param = {
        .ossl_type = ossl_octet_string, 
        .size = password.size(), 
        .str_val = (char *)password.data()
    };
    ctx->params[OSSL_KDF_PARAM_PASSWORD] = param;
    
    if (salt.size() > 0) {
        param = {
            .ossl_type = ossl_octet_string, 
            .size = salt.size(), 
            .str_val = (char *)salt.data()
        };
        ctx->params[OSSL_KDF_PARAM_SALT] = param;
    }

    kdf = EVP_KDF_fetch(NULL, ctx->algorithm.c_str(), NULL);
    if (!kdf)
        return {};

    evp_ctx = EVP_KDF_CTX_new(kdf);
    if (!evp_ctx)
        goto clean_kdf;
    
    ret = EVP_KDF_derive(evp_ctx, digest.data(), digest.size(), 
                        ossl_build_params(ctx->params).data());
    if (ret <= 0)
        goto clean_ctx;

    EVP_KDF_CTX_free(evp_ctx);
    EVP_KDF_free(kdf);

    return digest;

clean_ctx:
    EVP_KDF_CTX_free(evp_ctx);
clean_kdf:
    EVP_KDF_free(kdf);

    return {};
}


std::vector<uint8_t> crypto::crypto_kdf_derive(
    struct crypto_kdf_ctx_t *ctx, 
    std::vector<uint8_t> password, 
    int nbits) {
    return crypto_kdf_derive(ctx, password, {}, nbits);
}

std::vector<uint8_t> crypto::crypto_asm_encrypt(EVP_PKEY *pkey, std::vector<uint8_t> &buf) {
    EVP_PKEY_CTX *evp_ctx = nullptr;
    std::vector<uint8_t> enc_msg;
    size_t o_len = 0;
    int ret;

    evp_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!evp_ctx)
        return {};
    
    ret = EVP_PKEY_encrypt_init(evp_ctx);
    if (ret <= 0)
        goto clean_ctx;

    ret = EVP_PKEY_encrypt(evp_ctx, nullptr, &o_len, buf.data(), buf.size());
    if (ret <= 0)
        goto clean_ctx;
    
    enc_msg.resize(o_len);
    ret = EVP_PKEY_encrypt(evp_ctx, enc_msg.data(), &o_len, buf.data(), buf.size());
    if (ret <= 0)
        goto clean_ctx;

    EVP_PKEY_CTX_free(evp_ctx);

    return enc_msg;

clean_ctx:
    EVP_PKEY_CTX_free(evp_ctx);

    return {};
}

std::vector<uint8_t> crypto::crypto_asm_decrypt(EVP_PKEY *pkey, std::vector<uint8_t> &enc_buf) {
    EVP_PKEY_CTX *evp_ctx = nullptr;
    std::vector<uint8_t> msg(enc_buf.size());
    size_t o_len = 0;
    int ret;

    if (!enc_buf.size() || !pkey)
        return {};

    evp_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!evp_ctx)
        return {};
    
    ret = EVP_PKEY_decrypt_init(evp_ctx);
    if (ret <= 0)
        goto clean_ctx;

    ret = EVP_PKEY_decrypt(evp_ctx, nullptr, &o_len, enc_buf.data(), enc_buf.size());
    if (ret <= 0)
        goto clean_ctx;
    
    ret = EVP_PKEY_decrypt(evp_ctx, msg.data(), &o_len, enc_buf.data(), enc_buf.size());
    if (ret <= 0)
        goto clean_ctx;

    msg.resize(o_len);

    EVP_PKEY_CTX_free(evp_ctx);

    return msg;

clean_ctx:
    EVP_PKEY_CTX_free(evp_ctx);

    return {};
}


std::vector<uint8_t> crypto::crypto_sym_encrypt(struct crypto_cipher_ctx_t *ctx, std::vector<uint8_t> &buf) {
    EVP_CIPHER_CTX *cp_ctx = nullptr;
    std::vector<uint8_t> enc_msg(buf.size());
    int o_len = 0, remaining, s_len = buf.size(), len = 0;
    uint8_t *o_ptr = enc_msg.data(), *i_ptr = buf.data();
    int ret;

    if (!ctx || !buf.size() || !ctx->key.size())
        return {};

    cp_ctx = EVP_CIPHER_CTX_new();
    if (!cp_ctx)
        return {};

    if (ctx->params.size() > 1) {
        ret = EVP_EncryptInit_ex2(cp_ctx, ctx->cipher_type, ctx->key.data(), 
                ctx->iv.data(), ossl_build_params(ctx->params).data());
        if (ret <= 0)
            goto clean_ctx;
    }
    else {
        ret = EVP_EncryptInit(cp_ctx, ctx->cipher_type, ctx->key.data(), ctx->iv.data());
        if (ret <= 0)
            goto clean_ctx;
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(cp_ctx) == (int)ctx->key.size());
    if (ctx->iv.size()) {
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(cp_ctx) == (int)ctx->iv.size());
    }

    do {
        remaining = std::min(1024, s_len);
        ret = EVP_EncryptUpdate(cp_ctx, o_ptr, &len, i_ptr, remaining);
        if (ret < 0)
            goto clean_ctx;

        o_len += len;
        o_ptr += len;
        i_ptr += remaining;
        s_len -= remaining;

        if (o_len >= (int)enc_msg.size())
            enc_msg.resize(o_len * 2);

    } while(s_len > 0);

    EVP_EncryptFinal(cp_ctx, o_ptr + o_len, &len);
    o_len += len;
    enc_msg.resize(o_len);
    EVP_CIPHER_CTX_free(cp_ctx);

    return enc_msg;

clean_ctx:
    EVP_CIPHER_CTX_free(cp_ctx);

    return {};
}

std::vector<uint8_t> crypto::crypto_sym_decrypt(struct crypto_cipher_ctx_t *ctx, std::vector<uint8_t> &enc_buf) {
    EVP_CIPHER_CTX *cp_ctx = nullptr;
    std::vector<uint8_t> msg(enc_buf.size());
    int o_len = 0, s_len = enc_buf.size(), remaining, len;
    uint8_t *o_ptr = msg.data(), *i_ptr = enc_buf.data();
    int ret;

    if (!ctx || !enc_buf.size() || !ctx->key.size())
        return {};

    cp_ctx = EVP_CIPHER_CTX_new();
    if (!cp_ctx)
        return {};

    if (ctx->params.size() > 1) {
        ret = EVP_DecryptInit_ex2(cp_ctx, ctx->cipher_type, ctx->key.data(), 
                ctx->iv.data(), ossl_build_params(ctx->params).data());
        if (ret <= 0)
            goto clean_ctx;
    }
    else {
        ret = EVP_DecryptInit(cp_ctx, ctx->cipher_type, ctx->key.data(), ctx->iv.data());
        if (ret <= 0)
            goto clean_ctx;
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(cp_ctx) == (int)ctx->key.size());
    if (ctx->iv.size()) {
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(cp_ctx) == (int)ctx->iv.size());
    }

     do {
        remaining = std::min(1024, s_len);
        ret = EVP_DecryptUpdate(cp_ctx, o_ptr, &len, i_ptr, remaining);
        if (ret < 0)
            goto clean_ctx;

        o_ptr += len;
        o_len += len;
        i_ptr += remaining;
        s_len -= remaining;

        if (o_len >= (int)msg.size())
            msg.resize(o_len * 2);

    } while(s_len > 0);

    EVP_DecryptFinal(cp_ctx, o_ptr + o_len, &len);
    o_len += len;
    msg.resize(o_len);
    EVP_CIPHER_CTX_free(cp_ctx);

    return msg;

clean_ctx:
    EVP_CIPHER_CTX_free(cp_ctx);

    return {};
}

std::vector<uint8_t> crypto::crypto_asm_sign(const EVP_MD *algo, EVP_PKEY *pkey, std::vector<uint8_t> &buf) {
    EVP_MD_CTX *md_ctx = nullptr;
    std::vector<uint8_t> sign_msg;
    size_t o_len = 0;
    int ret;

    if (!pkey || !buf.size())
        return {};

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        goto clean_algo;

    ret = EVP_DigestSignInit(md_ctx, nullptr, algo, nullptr, pkey);
    if (ret <= 0)
        goto clean_algo;


    ret = EVP_DigestSign(md_ctx, nullptr, &o_len, buf.data(), buf.size());
    if (ret <= 0)
        goto clean_algo;
    
    sign_msg.resize(o_len);
    ret = EVP_DigestSign(md_ctx, sign_msg.data(), &o_len, buf.data(), buf.size());
    if (ret <= 0)
        goto clean_algo;

    EVP_MD_CTX_free(md_ctx);

    return sign_msg;

clean_algo:
    EVP_MD_CTX_free(md_ctx);

    return {};
}

bool crypto::crypto_asm_verify_sign(const EVP_MD *algo, EVP_PKEY *pkey, std::vector<uint8_t> &buf, std::vector<uint8_t> &sign) {
    EVP_MD_CTX *md_ctx = nullptr;
    int ret;

    if (!sign.size() || !buf.size() || !pkey)
        return false;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        return {};
    
    ret = EVP_DigestVerifyInit(md_ctx, nullptr, algo, nullptr, pkey);
    if (ret <= 0)
        goto clean_ctx;

    ret = EVP_DigestVerify(md_ctx, sign.data(), sign.size(), buf.data(), buf.size());
    if (ret <= 0)
        goto clean_ctx;

    

    EVP_MD_CTX_free(md_ctx);

    return true;

clean_ctx:
    EVP_MD_CTX_free(md_ctx);

    return false;
}