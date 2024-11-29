#include <iostream>
#include <cstdlib>
#include <cstring>
#include "lite-p2p/crypto.hpp"




int main(int argc, char *argv[]) {
    int ret;
    uint8_t hash[EVP_MAX_MD_SIZE];

    ret = lite_p2p::crypto::sha256((uint8_t *)argv[1], strlen(argv[1]), hash);

    for (int i = 0; i < ret; ++i) {
        printf("%02x", hash[i]);
    }

    printf("\n");
    return 0;
}