#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifndef ANDROID
#include <openssl/thread.h>
#endif

#define SHA_ALGO(alg) EVP_##alg()

enum ossl_params_type
{
    ossl_utf8_string = 0,
    ossl_octet_string,
    ossl_octet_ptr,
    ossl_numeric_int,
    ossl_numeric_int32,
    ossl_numeric_uint32,
    ossl_numeric_int64,
    ossl_numeric_uint64,
};
struct ossl_param_t
{

    enum ossl_params_type ossl_type;
    size_t size;
    union {
        char *str_val;
        int int_val;
    };
};

static inline std::vector<OSSL_PARAM> ossl_build_params(std::map<std::string, struct ossl_param_t> mparams)
{
    std::vector<OSSL_PARAM> params;

    for (auto &&p : mparams)
    {
        switch (p.second.ossl_type)
        {
        case ossl_utf8_string:
            params.push_back(OSSL_PARAM_construct_utf8_string(p.first.c_str(), (char *)p.second.str_val, p.second.size));
            break;
        case ossl_octet_string:
            params.push_back(OSSL_PARAM_construct_octet_string(p.first.c_str(), (char *)p.second.str_val, p.second.size));
            break;
        case ossl_numeric_int:
        case ossl_numeric_int32:
        case ossl_numeric_uint32:
        case ossl_numeric_int64:
        case ossl_numeric_uint64:
            params.push_back(OSSL_PARAM_construct_int(p.first.c_str(), &p.second.int_val));
            break;

        default:
            break;
        }
    }
    params.push_back(OSSL_PARAM_construct_end());

    return params;
}

struct crypto_mac_ctx_t
{

    crypto_mac_ctx_t(std::string _algorithm,
                     std::vector<uint8_t> _key,
                     std::map<std::string, struct ossl_param_t> mparams)
    {
        algorithm = _algorithm;
        key = _key;
        params = mparams;
    };

    crypto_mac_ctx_t(std::vector<uint8_t> _key) : crypto_mac_ctx_t("hmac", _key,
    {
        {OSSL_MAC_PARAM_CIPHER, {.ossl_type = ossl_utf8_string, .size = 0, .str_val = nullptr}},
        {OSSL_MAC_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha256), .str_val = (char *)std::string(SN_sha256).c_str()}}
    }) {};

    crypto_mac_ctx_t(std::string _algorithm,
                     std::string _cipher,
                     std::string _digest,
                     std::vector<uint8_t> _key) : crypto_mac_ctx_t(_algorithm, _key,
    {
        { OSSL_MAC_PARAM_CIPHER, {.ossl_type = ossl_utf8_string, .size = _cipher.length(), .str_val = (char *)_cipher.c_str() }},
        { OSSL_MAC_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = _digest.length(), .str_val = (char *)_digest.c_str() }}
    }){

    };

    std::string algorithm;
    size_t size;
    std::map<std::string, struct ossl_param_t> params;
    std::vector<uint8_t> key;
};

struct crypto_kdf_ctx_t
{
    crypto_kdf_ctx_t() : crypto_kdf_ctx_t("PKCS12KDF",
    {
        { OSSL_KDF_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha256), .str_val = (char *)std::string(SN_sha256).c_str()}},
        { OSSL_KDF_PARAM_ITER, {.ossl_type = ossl_numeric_uint64, .int_val = 65000}},
    }) {};

    crypto_kdf_ctx_t(std::string _algorithm,
                     std::map<std::string, struct ossl_param_t> mparams)
    {
        algorithm = _algorithm;
        params = mparams;

#ifndef ANDROID
        if (auto k = mparams.find(OSSL_KDF_PARAM_THREADS); k != mparams.end())
        {
            if (k->second.int_val > 1)
            {
                OSSL_set_max_threads(NULL, k->second.int_val);
            }
        }
#endif
    };

    std::string algorithm;
    std::map<std::string, struct ossl_param_t> params;
};

struct crypto_pkey_ctx_t
{
    const std::map<int, std::map<std::string, struct ossl_param_t>> default_params = {
        { 
            EVP_PKEY_RSA,  
            {
                { OSSL_PKEY_PARAM_RSA_BITS, {.ossl_type = ossl_numeric_int, .int_val = 1024}},
                { OSSL_PKEY_PARAM_RSA_PRIMES, {.ossl_type = ossl_numeric_int, .int_val = 3}},
            }
        },
        { 
            EVP_PKEY_ED25519, {
                {OSSL_PKEY_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha512_256), .str_val = (char *)std::string(SN_sha512_256).c_str()}}
            }
        },
        { 
            EVP_PKEY_X25519, {
                {OSSL_PKEY_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha512_256), .str_val = (char *)std::string(SN_sha512_256).c_str()}}
            }
        },
        {
            EVP_PKEY_ED448, {
                {OSSL_PKEY_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha512_256), .str_val = (char *)std::string(SN_shake256).c_str()}}
            }
        },
        {
            EVP_PKEY_X448, {
                {OSSL_PKEY_PARAM_DIGEST, {.ossl_type = ossl_utf8_string, .size = sizeof(SN_sha512_256), .str_val = (char *)std::string(SN_shake256).c_str()}}
            }
        }
    };

    crypto_pkey_ctx_t() : crypto_pkey_ctx_t(EVP_PKEY_ED25519,
    {
        { OSSL_PKEY_PARAM_RSA_BITS, {.ossl_type = ossl_numeric_int, .int_val = 1024}},
        { OSSL_PKEY_PARAM_RSA_PRIMES, {.ossl_type = ossl_numeric_int, .int_val = 3}},
    }) {};

    crypto_pkey_ctx_t(int _id, std::map<std::string, struct ossl_param_t> mparams)
    {
        id = _id;
        params = mparams;
    };

    crypto_pkey_ctx_t(int _id) {
        id = _id;

        if (auto p = default_params.find(_id); p != default_params.end()) 
            params = p->second;
    };

    int id;
    std::map<std::string, struct ossl_param_t> params;
};

struct crypto_cipher_ctx_t {
    const EVP_CIPHER *cipher_type;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::map<std::string, struct ossl_param_t> params;
    int block_len = 16;
};

namespace lite_p2p
{

    class crypto
    {
    public:
        static EVP_PKEY * crypto_generate_keypair(struct crypto_pkey_ctx_t *ctx, std::string password);
        static void crypto_free_keypair(EVP_PKEY **pkey);
        static std::vector<uint8_t> crypto_kdf_derive(struct crypto_kdf_ctx_t *ctx, std::vector<uint8_t> password, int nbits);
        static std::vector<uint8_t> crypto_kdf_derive(struct crypto_kdf_ctx_t *ctx, std::vector<uint8_t> password, std::vector<uint8_t> salt, int nbits);

        static std::vector<uint8_t> crypto_asm_encrypt(EVP_PKEY *pkey, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> crypto_asm_decrypt(EVP_PKEY *pkey, std::vector<uint8_t> &enc_buf);

        static std::vector<uint8_t> crypto_sym_encrypt(struct crypto_cipher_ctx_t *ctx, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> crypto_sym_decrypt(struct crypto_cipher_ctx_t *ctx, std::vector<uint8_t> &enc_buf);

        static std::vector<uint8_t> crypto_asm_sign(const EVP_MD *algo, EVP_PKEY *pkey, std::vector<uint8_t> &buf);
        static bool crypto_asm_verify_sign(const EVP_MD *algo, EVP_PKEY *pkey, std::vector<uint8_t> &buf, std::vector<uint8_t> &sign);

        static std::string crypto_base64_encode(std::vector<uint8_t> buf);
        static std::string crypto_base64_encode(uint8_t *buf, size_t len);

        static std::vector<uint8_t> crypto_base64_decode(std::string &str);
        static std::vector<uint8_t> crypto_base64_decode(const char *str, size_t len);

        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::string &s);
        static std::vector<uint8_t> xof_checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf, int bits);
        static std::vector<uint8_t> xof_checksum(const EVP_MD *algorithm, std::string &s, int bits);

        static struct crypto_mac_ctx_t *crypto_mac_new(const char *algorithm, const char *_cipher,
                                                       const char *_digest, std::vector<uint8_t> &_key);
        static void crypto_mac_free(crypto_mac_ctx_t *ctx);
        static std::vector<uint8_t> crypto_mac_sign(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf);
        static bool crypto_mac_verify(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf, std::vector<uint8_t> &digest);

        static std::vector<uint8_t> crypto_random_password(int bits);
        static std::vector<uint8_t> crypto_random_bytes(int bits);
    };

};

#endif