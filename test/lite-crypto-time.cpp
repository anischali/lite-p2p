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
#include <chrono>
#include <openssl/thread.h>

#define MAX_TEST_LOOP 1000

struct algo_stat_t {
    std::string algo;
    int64_t ms_enc_duration;
    int64_t ms_dec_duration;
    int key_size;
};

std::vector<struct algo_stat_t> stats;


void cipher_stats(std::string label, std::vector<struct algo_stat_t> stats) {
    int cnt = 1;
    printf("%s:\n", label.c_str());
    for (auto&& algo : stats) {
       printf("%d - measure cipher: %s {key size: %d bits} [ encryption time: %ld ms - decryption time: %ld ms ]\n", cnt++, algo.algo.c_str(), algo.key_size, algo.ms_enc_duration, algo.ms_dec_duration);
    }

}

void encrypt_decrypt_measure(std::string algo, std::string filename, std::vector<uint8_t> key, std::vector<uint8_t> iv)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(nullptr, algo.c_str(), nullptr);
    int64_t dec = 0, enc = 0;
    std::vector<uint8_t> file_buf, menc, other;

    if (!cipher)
        return;

    struct crypto_cipher_ctx_t c_ctx = {
        .cipher_type = cipher,
        .key = key,
        .iv = iv,
        .block_len = !strncmp(algo.c_str(), "ChaCha20", 8) ? 64 : 16
    };

    file_buf = lite_p2p::common::read_file(filename);
    lite_p2p::types::lpint160_t sha_orig = lite_p2p::crypto::checksum(EVP_sha1(), file_buf);
    
    for (int i = 0; i < MAX_TEST_LOOP; ++i) {
        auto start_enc = std::chrono::high_resolution_clock::now();
        menc = lite_p2p::crypto::crypto_sym_encrypt(&c_ctx, file_buf);
        auto stop_enc = std::chrono::high_resolution_clock::now();
        auto duration_enc = std::chrono::duration_cast<std::chrono::microseconds>(stop_enc - start_enc);
        enc += duration_enc.count();
    }

    enc /= MAX_TEST_LOOP;

    for (int i = 0; i < MAX_TEST_LOOP; ++i) {
        auto start_dec = std::chrono::high_resolution_clock::now();
        other = lite_p2p::crypto::crypto_sym_decrypt(&c_ctx, menc);
        auto stop_dec = std::chrono::high_resolution_clock::now();
        auto duration_dec = std::chrono::duration_cast<std::chrono::microseconds>(stop_dec - start_dec);
        dec += duration_dec.count();
    }

    dec /= MAX_TEST_LOOP;
    
    lite_p2p::types::lpint160_t sha_new = lite_p2p::crypto::checksum(EVP_sha1(), other);
    
    if (sha_orig != sha_new) {
        printf("valid: %s %d\n", algo.c_str(), (sha_orig == sha_new));
        lite_p2p::common::write_file(other, algo.c_str(), false);
    }
    else
    {
        stats.push_back({
            .algo = algo,
            .ms_enc_duration = enc,
            .ms_dec_duration = dec,
            .key_size = (int)key.size() * 8,
        });
    }

    EVP_CIPHER_free(cipher);
}

int main(int argc, const char *argv[])
{
    encrypt_decrypt_measure(SN_aes_128_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(96));         // 128-bit key
    encrypt_decrypt_measure(SN_aes_192_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(96));         // 192-bit key
    encrypt_decrypt_measure(SN_aes_256_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96));         // 256-bit key
    encrypt_decrypt_measure(SN_aria_128_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(96)); // 128-bit key, GCM mode
    encrypt_decrypt_measure(SN_aria_192_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(96)); // 192-bit key, GCM mode
    encrypt_decrypt_measure(SN_aria_256_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, GCM mode
    encrypt_decrypt_measure(SN_camellia_128_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(96)); // 128-bit key, GCM mode
    encrypt_decrypt_measure(SN_camellia_192_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(96)); // 192-bit key, GCM mode
    encrypt_decrypt_measure(SN_camellia_256_gcm, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, GCM mode
    encrypt_decrypt_measure(SN_chacha20_poly1305, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96));  // 256-bit key
    encrypt_decrypt_measure(SN_aes_128_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128));         // 128-bit key
    encrypt_decrypt_measure(SN_aes_192_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128));         // 192-bit key
    encrypt_decrypt_measure(SN_aes_256_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128));         // 256-bit key
    encrypt_decrypt_measure(SN_aes_128_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128));         // 128-bit key
    encrypt_decrypt_measure(SN_aes_192_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128));         // 192-bit key
    encrypt_decrypt_measure(SN_aes_256_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(0));         // 256-bit key
    encrypt_decrypt_measure(SN_aes_128_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(0));         // 128-bit key
    encrypt_decrypt_measure(SN_aes_192_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(0));         // 192-bit key
    encrypt_decrypt_measure(SN_aes_256_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(0));         // 256-bit key
    encrypt_decrypt_measure(SN_rc4, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128));                // 128-bit key
    encrypt_decrypt_measure(SN_chacha20, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128));           // 256-bit key
    encrypt_decrypt_measure(SN_aria_128_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128)); // 128-bit key, CBC mode
    encrypt_decrypt_measure(SN_aria_192_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128)); // 192-bit key, CBC mode
    encrypt_decrypt_measure(SN_aria_256_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128)); // 256-bit key, CBC mode
    encrypt_decrypt_measure(SN_aria_128_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128)); // 128-bit key, CTR mode
    encrypt_decrypt_measure(SN_aria_192_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128)); // 192-bit key, CTR mode
    encrypt_decrypt_measure(SN_aria_256_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128)); // 256-bit key, CTR mode
    encrypt_decrypt_measure(SN_aria_128_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(0)); // 128-bit key, ECB mode
    encrypt_decrypt_measure(SN_aria_192_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(0)); // 192-bit key, ECB mode
    encrypt_decrypt_measure(SN_aria_256_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(0)); // 256-bit key, ECB mode
    encrypt_decrypt_measure(SN_camellia_128_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128)); // 128-bit key, CBC mode
    encrypt_decrypt_measure(SN_camellia_192_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128)); // 192-bit key, CBC mode
    encrypt_decrypt_measure(SN_camellia_256_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128)); // 256-bit key, CBC mode
    encrypt_decrypt_measure(SN_camellia_128_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128)); // 128-bit key, CTR mode
    encrypt_decrypt_measure(SN_camellia_192_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128)); // 192-bit key, CTR mode
    encrypt_decrypt_measure(SN_camellia_256_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128)); // 256-bit key, CTR mode
    encrypt_decrypt_measure(SN_camellia_128_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(0)); // 128-bit key, ECB mode
    encrypt_decrypt_measure(SN_camellia_192_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(0)); // 192-bit key, ECB mode
    encrypt_decrypt_measure(SN_camellia_256_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(0)); // 256-bit key, ECB mode
    encrypt_decrypt_measure(SN_camellia_128_ccm, argv[1], lite_p2p::crypto::crypto_random_bytes(128), lite_p2p::crypto::crypto_random_bytes(128)); // 128-bit key, CCM mode
    encrypt_decrypt_measure(SN_camellia_192_ccm, argv[1], lite_p2p::crypto::crypto_random_bytes(192), lite_p2p::crypto::crypto_random_bytes(128)); // 192-bit key, CCM mode
    encrypt_decrypt_measure(SN_camellia_256_ccm, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(128)); // 256-bit key, CCM mode
    encrypt_decrypt_measure(SN_kuznyechik_cbc, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, CBC mode
    encrypt_decrypt_measure(SN_kuznyechik_kexp15, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, GCM mode
    encrypt_decrypt_measure(SN_kuznyechik_ctr, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, CTR mode
    encrypt_decrypt_measure(SN_kuznyechik_ecb, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, ECB mode
    encrypt_decrypt_measure(SN_kuznyechik_cfb, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, ECB mode
    encrypt_decrypt_measure(SN_kuznyechik_ctr_acpkm, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, CCM mode
    encrypt_decrypt_measure(SN_kuznyechik_ctr_acpkm_omac, argv[1], lite_p2p::crypto::crypto_random_bytes(256), lite_p2p::crypto::crypto_random_bytes(96)); // 256-bit key, OCB mode


    std::sort(stats.begin(), stats.end(), [](struct algo_stat_t a, struct algo_stat_t b){
        return (a.ms_dec_duration + a.ms_enc_duration) < (b.ms_dec_duration + b.ms_enc_duration);
    });
    cipher_stats("encryption speed", stats);
}