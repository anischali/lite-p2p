#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "lite-p2p/crypto.hpp"

void print_hexbuf(const char *label, uint8_t *buf, int len) {

    printf("%s (%d): ", label, len);
    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}

#include <cstring>
enum _SHATYPE {
  SHATYPE_ERROR = -1,
  SHATYPE_DEFAULT = 0,
  SHATYPE_SHA1 = SHATYPE_DEFAULT,
  SHATYPE_SHA256,
  SHATYPE_SHA384,
  SHATYPE_SHA512
};
typedef uint8_t hmackey_t[64];
bool stun_produce_integrity_key_str(const uint8_t *uname, const uint8_t *realm, const uint8_t *upwd, hmackey_t key, int shatype) {
  bool ret;

  size_t ulen = strlen((const char *)uname);
  size_t rlen = strlen((const char *)realm);
  size_t plen = strlen((const char *)upwd);
  size_t sz = ulen + 1 + rlen + 1 + plen + 1 + 10;
  size_t strl = ulen + 1 + rlen + 1 + plen;
  uint8_t *str = (uint8_t *)malloc(sz + 1);

  strncpy((char *)str, (const char *)uname, sz);
  str[ulen] = ':';
  strncpy((char *)str + ulen + 1, (const char *)realm, sz - ulen - 1);
  str[ulen + 1 + rlen] = ':';
  strncpy((char *)str + ulen + 1 + rlen + 1, (const char *)upwd, sz - ulen - 1 - rlen - 1);
  str[strl] = 0;
    printf("pass: %s\n", str);
  if (shatype == SHATYPE_SHA256) {
#if !defined(OPENSSL_NO_SHA256) && defined(SHA256_DIGEST_LENGTH)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unsigned int keylen = 0;
    EVP_MD_CTX ctx;
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, str, strl);
    EVP_DigestFinal(&ctx, key, &keylen);
    EVP_MD_CTX_cleanup(&ctx);
#else
    unsigned int keylen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, str, strl);
    EVP_DigestFinal(ctx, key, &keylen);
    EVP_MD_CTX_free(ctx);
#endif
    ret = true;
#else
    fprintf(stderr, "SHA256 is not supported\n");
    ret = false;
#endif
  } else if (shatype == SHATYPE_SHA384) {
#if !defined(OPENSSL_NO_SHA384) && defined(SHA384_DIGEST_LENGTH)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unsigned int keylen = 0;
    EVP_MD_CTX ctx;
    EVP_DigestInit(&ctx, EVP_sha384());
    EVP_DigestUpdate(&ctx, str, strl);
    EVP_DigestFinal(&ctx, key, &keylen);
    EVP_MD_CTX_cleanup(&ctx);
#else
    unsigned int keylen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha384());
    EVP_DigestUpdate(ctx, str, strl);
    EVP_DigestFinal(ctx, key, &keylen);
    EVP_MD_CTX_free(ctx);
#endif
    ret = true;
#else
    fprintf(stderr, "SHA384 is not supported\n");
    ret = false;
#endif
  } else if (shatype == SHATYPE_SHA512) {
#if !defined(OPENSSL_NO_SHA512) && defined(SHA512_DIGEST_LENGTH)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unsigned int keylen = 0;
    EVP_MD_CTX ctx;
    EVP_DigestInit(&ctx, EVP_sha512());
    EVP_DigestUpdate(&ctx, str, strl);
    EVP_DigestFinal(&ctx, key, &keylen);
    EVP_MD_CTX_cleanup(&ctx);
#else
    unsigned int keylen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha512());
    EVP_DigestUpdate(ctx, str, strl);
    EVP_DigestFinal(ctx, key, &keylen);
    EVP_MD_CTX_free(ctx);
#endif
    ret = true;
#else
    fprintf(stderr, "SHA512 is not supported\n");
    ret = false;
#endif
  } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unsigned int keylen = 0;
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
#if defined EVP_MD_CTX_FLAG_NON_FIPS_ALLOW && !defined(LIBRESSL_VERSION_NUMBER)
    if (FIPS_mode()) {
      EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif // defined EVP_MD_CTX_FLAG_NON_FIPS_ALLOW && !defined(LIBRESSL_VERSION_NUMBER)
    EVP_DigestInit_ex(&ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(&ctx, str, strl);
    EVP_DigestFinal(&ctx, key, &keylen);
    EVP_MD_CTX_cleanup(&ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
    unsigned int keylen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (EVP_default_properties_is_fips_enabled(NULL)) {
      EVP_default_properties_enable_fips(NULL, 0);
    }
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, str, strl);
    EVP_DigestFinal(ctx, key, &keylen);
    EVP_MD_CTX_free(ctx);
#else // OPENSSL_VERSION_NUMBER >= 0x10100000L && OPENSSL_VERSION_NUMBER < 0x30000000L
    unsigned int keylen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#if defined EVP_MD_CTX_FLAG_NON_FIPS_ALLOW && !defined(LIBRESSL_VERSION_NUMBER)
    if (FIPS_mode()) {
      EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, str, strl);
    EVP_DigestFinal(ctx, key, &keylen);
    EVP_MD_CTX_free(ctx);
#endif // OPENSSL_VERSION_NUMBER < 0X10100000L
    ret = true;
  }

  free(str);

  return ret;
}


int main(int argc, char *argv[]) {
    std::vector<uint8_t> hash, sign;
    std::string str(argv[1]);
    std::vector<uint8_t> data;

    data.assign(str.begin(), str.end());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha256), data); // echo -n "test" | sha256sum
    print_hexbuf("sha256", hash.data(), hash.size());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha1), data); // echo -n "test" | sha1sum
    print_hexbuf("sha1", hash.data(), hash.size());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(md5), data); // echo -n "test" | md5sum
    print_hexbuf("md5", hash.data(), hash.size());

    std::string pass("pass123");
    std::vector<uint8_t> key(pass.begin(), pass.end());

    struct crypto_mac_ctx_t ctx_hmacsha256("hmac", "", "sha256", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha256, data); // echo -n "test" | sha256hmac -K "pass123" -h sha256
    print_hexbuf("hmacsha256", sign.data(), sign.size());
    
    std::string b64 = lite_p2p::crypto::crypto_base64_encode(sign); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("%s\n", b64.c_str());
    std::vector<uint8_t> rb64 = lite_p2p::crypto::crypto_base64_decode(b64);
    print_hexbuf("hmacsha1 - b64", rb64.data(), rb64.size());
    
    struct crypto_mac_ctx_t ctx_hmacsha1("hmac", "", "sha1", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha1, data); // echo -n "test" | sha256hmac -K "pass123" -h sha1
    print_hexbuf("hmacsha1", sign.data(), sign.size());


    bool valid = lite_p2p::crypto::crypto_mac_verify(&ctx_hmacsha1, data, sign);

    print_hexbuf("hmacsha1 - verify", (uint8_t *)&valid, 1);

    std::vector<uint8_t> vpass = lite_p2p::crypto::crypto_random_password(128);
    print_hexbuf("password", (uint8_t *)vpass.data(), vpass.size());

    std::string b64_pass = lite_p2p::crypto::crypto_base64_encode(vpass); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("%s\n", b64_pass.c_str());
    std::vector<uint8_t> rpass = lite_p2p::crypto::crypto_base64_decode(b64_pass);
    print_hexbuf("pass-decode", rpass.data(), rpass.size());

    hmackey_t shkey;
    stun_produce_integrity_key_str((const uint8_t *)"visi", (const uint8_t *)"visibog.org", (const uint8_t *)"Z6OjD52Q4rZqgGmmCXE3xA==", shkey, SHATYPE_SHA256);
    print_hexbuf("sha256", shkey, sizeof(shkey));
    stun_produce_integrity_key_str((const uint8_t *)"visi", (const uint8_t *)"visibog.org", (const uint8_t *)"Z6OjD52Q4rZqgGmmCXE3xA==", shkey, SHATYPE_SHA1);
    print_hexbuf("sha1", shkey, sizeof(shkey));



    return 0;
}