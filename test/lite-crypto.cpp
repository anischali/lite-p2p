#include <iostream>
#include <cstdlib>
#include <cstring>
#include "lite-p2p/crypto.hpp"

void print_hexbuf(const char *label, uint8_t *buf, int len) {

    printf("%s: ", label);
    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}


int main(int argc, char *argv[]) {
    int ret;
    uint8_t hash[EVP_MAX_MD_SIZE];

    memset(hash, 0x0, EVP_MAX_MD_SIZE);
    ret = lite_p2p::crypto::checksum(SHA_ALGO(sha256), (uint8_t *)argv[1], strlen(argv[1]), hash);
    print_hexbuf("sha256", hash, ret);


    memset(hash, 0x0, EVP_MAX_MD_SIZE);
    ret = lite_p2p::crypto::checksum(SHA_ALGO(sha1), (uint8_t *)argv[1], strlen(argv[1]), hash);
    print_hexbuf("sha1", hash, ret);

    memset(hash, 0x0, EVP_MAX_MD_SIZE);
    ret = lite_p2p::crypto::checksum(SHA_ALGO(md5), (uint8_t *)argv[1], strlen(argv[1]), hash);
    print_hexbuf("md5", hash, ret);

    return 0;
}