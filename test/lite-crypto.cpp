#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include "lite-p2p/crypto.hpp"
#include "lite-p2p/lib_common.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/litetypes.hpp"
#include "lite-p2p/btree.hpp"
#include "lite-p2p/kademlia_dht.hpp"



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
    printf("base64: %s\n", b64.c_str());
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

    int fd = open(argv[2], O_RDONLY);
    size_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    std::vector<uint8_t> file_buf(size);

    read(fd, file_buf.data(), size);
    printf("size: %ld\n", size);

    std::string b64_file = lite_p2p::crypto::crypto_base64_encode(file_buf);
    printf("file-b64: %s\n", b64_file.c_str());
    close(fd);

    auto before_b64 = lite_p2p::crypto::crypto_base64_decode(b64_file);
    int fd2 = open(argv[3], O_WRONLY | O_CREAT, 0666);
    write(fd2, before_b64.data(), before_b64.size());
    printf("size: %ld\n", before_b64.size());

    sync();

    close(fd2);

    lite_p2p::btree<lite_p2p::lpint256_t> bt;

    struct dht_peer_t {
        lite_p2p::lpint256_t key = lite_p2p::lpint256_t(lite_p2p::crypto::crypto_random_bytes(256));
        struct sockaddr_t addr;
        lite_p2p::btree_node_t node = { .leaf = true };
    };

    struct dht_peer_t curr;
    struct dht_peer_t rem;


    lite_p2p::lpint256_t ds = curr.key ^ curr.key;
    ds = curr.key ^ curr.key;
    bt.btree_insert_key(&curr.node, ds);
    ds = curr.key ^ rem.key;
    bt.btree_insert_key(&rem.node, ds);

    auto node = bt.btree_find_node(ds);
    if (node) {
        auto nval = container_of(node, struct dht_peer_t, node);
        if (nval) {
            printf("key found (%s|%s)\n", rem.key.to_string().c_str(), nval->key.to_string().c_str());
        }
    }


    lite_p2p::lpint256_t vs;
    for (size_t i = 0; i < ds.bits(); ++i) {
        int j = (255 - i);
        int vbit = ds.at(j);
        printf("bit at: %d [%d:%d]\n", (int)i, vbit, (int)((ds[j / 8] >> (j % 8)) & 1) != 0);

        vs.set_bit(j, vbit);
    }

    auto shb = lite_p2p::crypto::checksum(EVP_sha256(), before_b64);

    lite_p2p::lpint256_t p = shb;

    printf("key (%s)\n", p.to_string().c_str());

    print_hexbuf("key sha", shb);

    bt.print();

    bt.~btree();

    lite_p2p::kademlia_dht<lite_p2p::lpint256_t> dht(curr.key);

    dht.~kademlia_dht();

    return 0;
}