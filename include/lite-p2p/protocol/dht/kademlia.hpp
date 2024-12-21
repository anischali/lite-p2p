#ifndef __KADEMLIA_DHT_HPP__
#define __KADEMLIA_DHT_HPP__
#include <array>
#include "lite-p2p/types/btree.hpp"
#include "lite-p2p/types/types.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/crypto/crypto.hpp"
#include "lite-p2p/types/list_head.hpp"
#include "lite-p2p/peer/connection.hpp"

namespace lite_p2p::protocol::dht
{
    template <typename T> class kademlia_bucket {
        public:
            constexpr static size_t bucket_size = sizeof(T) * 8;
            std::array<peer::peer_info<T>, bucket_size> peers;
            struct lite_p2p::types::btree_node_t node = { .leaf = true };
    };

    template <typename T> class kademlia
    {
    private:
        T self_key;
        struct lite_p2p::types::btree<T> kad_tree;

    public:
        kademlia(T skey) : self_key{skey} {}
        ~kademlia() { kad_tree.~btree(); }

        lite_p2p::types::btree_node_t * find_closest_node(T key) {
            T s_key = key ^ self_key;
    
            return kad_tree.btree_find_node(s_key);
        }

        void start();
        void stop();

        struct sockaddr_t get_peer_address(T key);
    };
}

#endif
