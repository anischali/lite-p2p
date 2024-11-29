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
    std::vector<uint8_t> hash;
    
    std::string str(argv[1]);
    std::vector<uint8_t> data;

    data.assign(str.begin(), str.end());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha256), data);
    print_hexbuf("sha256", hash.data(), hash.size());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha1), data);
    print_hexbuf("sha1", hash.data(), hash.size());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(md5), data);
    print_hexbuf("md5", hash.data(), hash.size());

    return 0;
}