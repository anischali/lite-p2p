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
    template <typename T>
    class kademlia_bucket
    {
    public:
        constexpr static size_t bucket_size = sizeof(T) * 8;
        std::vector<lite_p2p::peer::peer_info<T>> peers;
        struct lite_p2p::types::btree_node_t node = {.leaf = true};
    };

    template <typename T>
    class kademlia
    {
    private:
        T self_key;
        struct lite_p2p::types::btree<T> kad_tree;

    public:
        kademlia(T skey) : self_key{skey} {}
        ~kademlia()
        {

            kad_tree.btree_callback_on_leaf([](lite_p2p::types::btree_node_t **n)
            {
                lite_p2p::protocol::dht::kademlia_bucket<T> *bucket = nullptr;

                if (!(*n))
                    return;

                if ((*n)->leaf) {    
                    bucket = container_of(*n, lite_p2p::protocol::dht::kademlia_bucket<T>, node);
                    if (bucket != nullptr) {
                        bucket->peers.~vector();
                        free(bucket);
                        bucket = nullptr;
                    }
                }
            });

            kad_tree.~btree();
        }

        lite_p2p::types::btree_node_t *find_closest_node(T key)
        {
            lite_p2p::types::btree_node_t *node = nullptr;
            T s_key = key ^ self_key;

            node = kad_tree.btree_find_node(s_key);
            if (node)
                return node;

            return node;
        }

        void add_peer(lite_p2p::peer::peer_info<T> &info)
        {
            T s_key;
            lite_p2p::protocol::dht::kademlia_bucket<T> *bucket = nullptr;
            lite_p2p::types::btree_node_t *n = find_closest_node(info.key);

            if (!n)
            {
                bucket = (lite_p2p::protocol::dht::kademlia_bucket<T> *)calloc(1, sizeof(lite_p2p::protocol::dht::kademlia_bucket<T>));
                bucket->node.leaf = true;
                s_key = self_key ^ info.key;
                kad_tree.btree_insert_key(&bucket->node, s_key);
            }
            else
            {
                bucket = container_of(n, lite_p2p::protocol::dht::kademlia_bucket<T>, node);
                if (!bucket)
                {
                    bucket = (lite_p2p::protocol::dht::kademlia_bucket<T> *)calloc(1, sizeof(lite_p2p::protocol::dht::kademlia_bucket<T>));
                    bucket->node.leaf = true;
                    s_key = self_key ^ info.key;
                    kad_tree.btree_insert_key(&bucket->node, s_key);
                }
            }

            bucket->peers.emplace_back(info);
        }

        lite_p2p::peer::peer_info<T> *get_peer_info(T key)
        {
            lite_p2p::types::btree_node_t *n = find_closest_node(key);
            lite_p2p::protocol::dht::kademlia_bucket<T> *bucket = nullptr;

            if (!n)
                return nullptr;

            bucket = container_of(n, lite_p2p::protocol::dht::kademlia_bucket<T>, node);
            if (!bucket)
            {
                std::throw_with_nested("kadmelia bucket not found!");
            }

            auto pi = std::find_if(bucket->peers.begin(),
                                   bucket->peers.end(), [&](const lite_p2p::peer::peer_info<T> &v) -> bool
                                   { 
                    printf("%s\n", key.to_string().c_str());
                    return  key == v.key; });

            if (pi != bucket->peers.end())
            {
                return &(*pi);
            }

            return nullptr;
        }
    };
}

#endif
