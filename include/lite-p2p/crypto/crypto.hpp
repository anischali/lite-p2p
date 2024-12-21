#ifndef __CRYPTO_HPP__
#define __CRYPTO_HPP__
#include <string>
#include <vector>
#include <map>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SHA_ALGO(alg) EVP_##alg()


enum ossl_params_type {
    ossl_utf8_string = 0,
    ossl_octet_string,
    ossl_octet_ptr,
    ossl_numeric_int32,
    ossl_numeric_uint32,
    ossl_numeric_int64,
    ossl_numeric_uint64,
};
struct ossl_param_t {

    enum ossl_params_type ossl_type;
    union {
        const char *str_val;
        long int_val;
        double double_val;
    };
};


static inline std::vector<OSSL_PARAM> ossl_build_params(std::map<std::string, struct ossl_param_t> mparams) {
    std::vector<OSSL_PARAM> params;

    for (auto &&p : mparams) {
            switch (p.second.ossl_type)
            {
            case ossl_utf8_string:
                params.push_back(OSSL_PARAM_construct_utf8_string(p.first.c_str(), (char *)p.second.str_val, 0));
                break;
            case ossl_octet_string:
                params.push_back(OSSL_PARAM_construct_octet_string(p.first.c_str(), (char *)p.second.str_val, 0));
                break;
            case ossl_numeric_int32:
                params.push_back(OSSL_PARAM_construct_int32(p.first.c_str(), (int32_t *)&p.second.int_val));
                break;
            case ossl_numeric_uint32:
                params.push_back(OSSL_PARAM_construct_uint32(p.first.c_str(), (uint32_t *)&p.second.int_val));
                break;
            case ossl_numeric_int64:
                params.push_back(OSSL_PARAM_construct_int64(p.first.c_str(), (int64_t *)&p.second.int_val));
                break;
            case ossl_numeric_uint64:
                params.push_back(OSSL_PARAM_construct_uint64(p.first.c_str(), (uint64_t *)&p.second.int_val));
                break;
            
            default:
                break;
            }
        }
        params.push_back(OSSL_PARAM_construct_end());

        return params;
}

struct crypto_mac_ctx_t {

    crypto_mac_ctx_t(std::string _algorithm, 
            std::vector<uint8_t> _key, 
            std::map<std::string, struct ossl_param_t> mparams) {
        
        algorithm = _algorithm;
        key = _key;

        params = ossl_build_params(mparams);
    };

    crypto_mac_ctx_t(std::vector<uint8_t> _key) : crypto_mac_ctx_t("hmac", _key, 
    {
        {"cipher", {.ossl_type = ossl_utf8_string, .str_val = ""}},
        {"digest", {.ossl_type = ossl_utf8_string, .str_val = "sha256"}}
    }) {};

    crypto_mac_ctx_t(std::string _algorithm,
                    std::string _cipher,
                    std::string _digest,
                    std::vector<uint8_t> _key) : crypto_mac_ctx_t(_algorithm, _key, 
    {
        {"cipher", {.ossl_type = ossl_utf8_string, .str_val = _cipher.c_str()}},
        {"digest", {.ossl_type = ossl_utf8_string, .str_val = _digest.c_str()}}
    }) {};
                    
    std::string algorithm;
    size_t size;
    std::vector<OSSL_PARAM> params;
    std::vector<uint8_t> key;
};


struct crypto_kdf_ctx_t {

    crypto_kdf_ctx_t() :  crypto_kdf_ctx_t("hmac",
    {
        {"cipher", { .ossl_type = ossl_utf8_string, .str_val = ""}},
        {"digest", { .ossl_type = ossl_utf8_string, .str_val = "sha256"}}
    }) {};

    crypto_kdf_ctx_t(std::string _algorithm,
                    std::map<std::string, struct ossl_param_t> mparams) {
        algorithm = _algorithm;

        params = ossl_build_params(mparams);
    };

    std::string algorithm;
    std::vector<OSSL_PARAM> params;
};

namespace lite_p2p {

    class crypto {
    public:

        static std::vector<uint8_t> crypto_generate_keypair(int alg_id, std::string &password);
        static std::vector<uint8_t> crypto_pbkdf_derive(std::string &password, std::vector<uint8_t> &salt, std::vector<uint8_t> &digest);

        static std::string crypto_base64_encode(std::vector<uint8_t> buf);
        static std::string crypto_base64_encode(uint8_t *buf, size_t len);

        static std::vector<uint8_t> crypto_base64_decode(std::string &str);
        static std::vector<uint8_t> crypto_base64_decode(const char *str, size_t len);

        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::vector<uint8_t> &buf);
        static std::vector<uint8_t> checksum(const EVP_MD *algorithm, std::string &s);
        static struct crypto_mac_ctx_t * crypto_mac_new(const char *algorithm, const char *_cipher,
                                const char *_digest, std::vector<uint8_t> &_key); 
        static void crypto_mac_free(crypto_mac_ctx_t *ctx);
        static std::vector<uint8_t> crypto_mac_sign(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf);
        static bool crypto_mac_verify(struct crypto_mac_ctx_t *ctx, std::vector<uint8_t> &buf, std::vector<uint8_t> &digest);

        static std::vector<uint8_t> crypto_random_password(int bits);
        static std::vector<uint8_t> crypto_random_bytes(int bits);
    };

};


#endif