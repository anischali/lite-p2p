#ifndef __KADEMLIA_DHT_HPP__
#define __KADEMLIA_DHT_HPP__
#include <array>
#include "lite-p2p/btree.hpp"
#include "lite-p2p/litetypes.hpp"
#include "lite-p2p/network.hpp"
#include "lite-p2p/crypto.hpp"
#include "lite-p2p/list_head.hpp"
#include "lite-p2p/peer_connection.hpp"

namespace lite_p2p
{
    template <typename T> class kademlia_bucket {
        public:
            constexpr static size_t bucket_size = sizeof(T) * 8;
            std::array<lite_peer<T>, bucket_size> peers;
            struct btree_node_t node = { .leaf = true };
    };

    template <typename T> class kademlia_dht
    {
    private:
        T self_key;
        struct btree<T> kad_tree;

    public:
        kademlia_dht(T skey) : self_key{skey} {}
        ~kademlia_dht() { kad_tree.~btree(); }

        btree_node_t * find_closest_node(T key) {
            T s_key = key ^ self_key;
    
            return kad_tree.btree_find_node(s_key);
        }

        void start();
        void stop();

        struct sockaddr_t get_peer_address(T key);
    };
}

#endif
