#ifndef __KADEMLIA_DHT_HPP__
#define __KADEMLIA_DHT_HPP__
#include <array>
#include "lite-p2p/btree.hpp"
#include "lite-p2p/litetypes.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/crypto.hpp"
#include "lite-p2p/list_head.hpp"

namespace lite_p2p
{
    template <typename T> class kademlia_peer {
        public:
            kademlia_peer(T s_key) {
                key = s_key;
            };

            kademlia_peer() {
                key = lite_p2p::crypto::crypto_random_bytes(sizeof(T) * 8);
            };

        T key;
        struct sockaddr_t addr;
        struct timeval last_seen;
        int status;
    };

    template <typename T> class kademlia_bucket {
        public:
            constexpr static size_t bucket_size = sizeof(T) * 8;
            std::array<kademlia_peer<T>, bucket_size> peers;
            struct btree_node_t node = { .leaf = true };
    };

    template <typename T> class kademlia_dht
    {
    private:
        T self_key;
        struct btree<T> kad_tree;

    public:
        kademlia_dht(T skey);
        ~kademlia_dht();

        void start();
        void stop();

        struct sockaddr_t get_peer_address(T key);
        btree_node_t *find_closest_node(T key);
    };
}

#endif
