#ifndef __KADEMLIA_DHT_HPP__
#define __KADEMLIA_DHT_HPP__
#include <array>
#include "lite-p2p/types/btree.hpp"
#include "lite-p2p/types/types.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/crypto/crypto.hpp"
#include "lite-p2p/types/list_head.hpp"
#include "lite-p2p/peer/connection.hpp"

using namespace lite_p2p::types;
using namespace lite_p2p::peer;
using namespace lite_p2p::protocol;

namespace lite_p2p::protocol::dht
{
    template <typename T>
    class kademlia_bucket
    {
    public:
        size_t bucket_size = sizeof(T) * 8;
        std::vector<peer_info<T>> peers;
        struct btree_node_t node;
    };
    template <typename T>
    class kademlia
    {
    private:
        base_socket *sock;
        T self_key;
        btree<T> *kad_tree = new btree<T>();
        std::vector<kademlia_bucket<T> *> kbuckets; 

    public:
        kademlia(T skey) : self_key{skey} {}
        kademlia(base_socket *s, T skey) : sock{s}, self_key{skey} {}
        ~kademlia()
        {
            if (!kad_tree)
                return;

            delete kad_tree;
            kad_tree = NULL;

            for (auto &&b : kbuckets) {
                if (b) {
                    delete b;
                    b = NULL;
                }
            }
        }

        btree_node_t *find_closest_node(T key)
        {
            T s_key = key ^ self_key;

            return kad_tree->btree_find_node(s_key);
        }

        void add_peer(peer_info<T> &info)
        {
            T s_key;
            kademlia_bucket<T> *bucket = NULL;
            btree_node_t *n = find_closest_node(info.key);

            if (!n)
            {
                bucket = new kademlia_bucket<T>();
                if (!bucket)
                    return;

                kbuckets.push_back(bucket);
                bucket->node.leaf = true;
                s_key = self_key ^ info.key;
                kad_tree->btree_insert_key(&bucket->node, s_key);
            }
            else
            {
                bucket = container_of(n, kademlia_bucket<T>, node);
                if (!bucket)
                {
                    bucket = new kademlia_bucket<T>();
                    if (!bucket)
                        return;

                    kbuckets.push_back(bucket);
                    bucket->node.leaf = true;
                    s_key = self_key ^ info.key;
                    kad_tree->btree_insert_key(&bucket->node, s_key);
                }
            }

            bucket->peers.emplace_back(info);
        }

        peer_info<T> *get_peer_info(T key)
        {
            btree_node_t *n = find_closest_node(key);
            kademlia_bucket<T> *bucket = NULL;

            if (!n)
                return NULL;

            bucket = container_of(n, kademlia_bucket<T>, node);
            if (!bucket)
            {
                std::throw_with_nested("kadmelia bucket not found!");
            }

            auto pi = std::find_if(bucket->peers.begin(),
                                   bucket->peers.end(), [&](const peer_info<T> &v) -> bool
                                   { 
                    return  key == v.key; });

            if (pi != bucket->peers.end())
            {
                return &(*pi);
            }

            return NULL;
        }
    };
}

#endif
