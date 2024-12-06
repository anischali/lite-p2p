#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "lite-p2p/crypto.hpp"
#include "lite-p2p/lib_common.hpp"

int main(int argc, char *argv[]) {
    std::vector<uint8_t> hash, sign;
    std::string str(argv[1]);
    std::vector<uint8_t> data;

    data.assign(str.begin(), str.end());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha256), data); // echo -n "test" | sha256sum
    print_hexbuf("sha256", hash);

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha1), data); // echo -n "test" | sha1sum
    print_hexbuf("sha1", hash);

    hash = lite_p2p::crypto::checksum(SHA_ALGO(md5), data); // echo -n "test" | md5sum
    print_hexbuf("md5", hash);

    std::string pass("pass123");
    std::vector<uint8_t> key(pass.begin(), pass.end());

    struct crypto_mac_ctx_t ctx_hmacsha256("hmac", "", "sha256", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha256, data); // echo -n "test" | sha256hmac -K "pass123" -h sha256
    print_hexbuf("hmacsha256", sign);
    
    std::string b64 = lite_p2p::crypto::crypto_base64_encode(sign); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("%s\n", b64.c_str());
    std::vector<uint8_t> rb64 = lite_p2p::crypto::crypto_base64_decode(b64);
    print_hexbuf("hmacsha1 - b64", rb64);
    
    struct crypto_mac_ctx_t ctx_hmacsha1("hmac", "", "sha1", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha1, data); // echo -n "test" | sha256hmac -K "pass123" -h sha1
    print_hexbuf("hmacsha1", sign);


    bool valid = lite_p2p::crypto::crypto_mac_verify(&ctx_hmacsha1, data, sign);

    printf("hmacsha1 - verify: %d\n", valid);

    std::vector<uint8_t> vpass = lite_p2p::crypto::crypto_random_password(128);
    print_hexbuf("password", vpass);

    std::string b64_pass = lite_p2p::crypto::crypto_base64_encode(vpass); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("%s\n", b64_pass.c_str());
    std::vector<uint8_t> rpass = lite_p2p::crypto::crypto_base64_decode(b64_pass);
    print_hexbuf("pass-decode", rpass);


    return 0;
}