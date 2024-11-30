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

    
    struct crypto_mac_ctx_t ctx_hmacsha1("hmac", "", "sha1", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha1, data); // echo -n "test" | sha256hmac -K "pass123" -h sha1
    print_hexbuf("hmacsha1", sign.data(), sign.size());

    return 0;
}