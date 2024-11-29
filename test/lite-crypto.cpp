#include <iostream>
#include <cstdlib>
#include <cstring>
#include "lite-p2p/crypto.hpp"

void print_hexbuf(uint8_t *buf, int len) {

    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }

    printf("\n");
}


int main(int argc, char *argv[]) {
    int ret;
    uint8_t hash[EVP_MAX_MD_SIZE];

    memset(hash, 0x0, EVP_MAX_MD_SIZE);
    ret = lite_p2p::crypto::sha256((uint8_t *)argv[1], strlen(argv[1]), hash);
    print_hexbuf(hash, ret);


    memset(hash, 0x0, EVP_MAX_MD_SIZE);
    ret = lite_p2p::crypto::sha1((uint8_t *)argv[1], strlen(argv[1]), hash);
    print_hexbuf(hash, ret);

    return 0;
}