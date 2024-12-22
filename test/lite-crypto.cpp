#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include "lite-p2p/crypto/crypto.hpp"
#include "lite-p2p/common/common.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/types/types.hpp"
#include "lite-p2p/types/btree.hpp"
#include "lite-p2p/protocol/dht/kademlia.hpp"



int main(int argc, char *argv[]) {
    std::vector<uint8_t> hash, sign;
    std::string str(argv[1]);
    std::vector<uint8_t> data;

    data.assign(str.begin(), str.end());

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha256), data); // echo -n "test" | sha256sum
    lite_p2p::common::print_hexbuf("sha256", hash);

    hash = lite_p2p::crypto::checksum(SHA_ALGO(sha1), data); // echo -n "test" | sha1sum
    lite_p2p::common::print_hexbuf("sha1", hash);

    hash = lite_p2p::crypto::checksum(SHA_ALGO(md5), data); // echo -n "test" | md5sum
    lite_p2p::common::print_hexbuf("md5", hash);

    std::string pass("pass123");
    std::vector<uint8_t> key(pass.begin(), pass.end());

    struct crypto_mac_ctx_t ctx_hmacsha256("hmac", "", "sha256", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha256, data); // echo -n "test" | sha256hmac -K "pass123" -h sha256
    lite_p2p::common::print_hexbuf("hmacsha256", sign);
    
    std::string b64 = lite_p2p::crypto::crypto_base64_encode(sign); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("base64: %s\n", b64.c_str());
    std::vector<uint8_t> rb64 = lite_p2p::crypto::crypto_base64_decode(b64);
    lite_p2p::common::print_hexbuf("hmacsha1 - b64", rb64);
    
    struct crypto_mac_ctx_t ctx_hmacsha1("hmac", "", "sha1", key);
    sign = lite_p2p::crypto::crypto_mac_sign(&ctx_hmacsha1, data); // echo -n "test" | sha256hmac -K "pass123" -h sha1
    lite_p2p::common::print_hexbuf("hmacsha1", sign);


    bool valid = lite_p2p::crypto::crypto_mac_verify(&ctx_hmacsha1, data, sign);

    printf("hmacsha1 - verify: %d\n", valid);

    std::vector<uint8_t> vpass = lite_p2p::crypto::crypto_random_password(256);
    lite_p2p::common::print_hexbuf("password", vpass);

    std::string b64_pass = lite_p2p::crypto::crypto_base64_encode(vpass); // echo -n b33283b4055e919f700f08f65328c75ec87938d5d22b17520df5ad7532908ed9 | xxd -r -p | base64
    printf("%s\n", b64_pass.c_str());
    std::vector<uint8_t> rpass = lite_p2p::crypto::crypto_base64_decode(b64_pass);
    lite_p2p::common::print_hexbuf("pass-decode", rpass);

    //int fd = open(argv[2], O_RDONLY);
    //size_t size = lseek(fd, 0, SEEK_END);
    //lseek(fd, 0, SEEK_SET);
    //std::vector<uint8_t> file_buf(size);

    //read(fd, file_buf.data(), size);
    //printf("size: %ld\n", size);

    //std::string b64_file = lite_p2p::crypto::crypto_base64_encode(file_buf);
    //printf("file-b64: %s\n", b64_file.c_str());
    //close(fd);

    //auto before_b64 = lite_p2p::crypto::crypto_base64_decode(b64_file);
    //int fd2 = open(argv[3], O_WRONLY | O_CREAT, 0666);
    //write(fd2, before_b64.data(), before_b64.size());
    //printf("size: %ld\n", before_b64.size());

    //sync();

    //close(fd2);

    lite_p2p::peer::peer_info<lite_p2p::types::lpint256_t> curr;
    lite_p2p::peer::peer_info<lite_p2p::types::lpint256_t> rem;

    lite_p2p::protocol::dht::kademlia<lite_p2p::types::lpint256_t> dht(curr.key);

    dht.add_peer(curr);
    dht.add_peer(rem);

    auto pi = dht.get_peer_info(rem.key);

    printf("key: %s|%s\n", rem.key.to_string().c_str(), pi->key.to_string().c_str());

    dht.~kademlia();


    lite_p2p::types::lpint8_t v1, v2, v3;

    v1 = lite_p2p::crypto::crypto_random_bytes(8);
    v2 = lite_p2p::crypto::crypto_random_bytes(8);
    v3 = v1 ^ v2;

    printf("%s = %s ^ %s\n", v3.to_string().c_str(), v1.to_string().c_str(), v2.to_string().c_str());

    struct crypto_kdf_ctx_t ctx;
    vpass = {1,2,3,5,6,7,3,2,1};
    std::vector<uint8_t> salt = {0x3e, 0xa1, 0x2f, 0xb2, 0x1d, 0xca, 0xc9, 0xd7, 0x77, 0xb9, 0x9b, 0x52, 0x05, 0x51, 0xa0, 0x78, 0x80, 0x3f, 0x8b, 0x46, 0x3b, 0x2e, 0x4a, 0xdf, 0xdc, 0x18, 0xfc, 0x7c, 0x65, 0xb5, 0xda, 0x8f};
    lite_p2p::common::print_hexbuf("salt", salt);
    auto der = lite_p2p::crypto::crypto_kdf_derive(&ctx, vpass, salt, 2048);
    printf("b64 hmac pswd: %s\n", lite_p2p::crypto::crypto_base64_encode(der).c_str());
    lite_p2p::common::print_hexbuf("kdf", vpass);
    lite_p2p::common::print_hexbuf("kdf", der);

    return 0;
}