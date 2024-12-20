#include "lite-p2p/kademlia_dht.hpp"

using namespace lite_p2p;

template class kademlia_dht<lite_p2p::lpint8_t>;
template class kademlia_dht<lite_p2p::lpint16_t>;
template class kademlia_dht<lite_p2p::lpint24_t>;
template class kademlia_dht<lite_p2p::lpint32_t>;
template class kademlia_dht<lite_p2p::lpint64_t>;
template class kademlia_dht<lite_p2p::lpint128_t>;
template class kademlia_dht<lite_p2p::lpint256_t>;
template class kademlia_dht<lite_p2p::lpint512_t>;
template class kademlia_dht<lite_p2p::lpint1024_t>;
template class kademlia_dht<lite_p2p::lpint2048_t>;
template class kademlia_dht<lite_p2p::lpint4096_t>;


template <typename T>
kademlia_dht<T>::kademlia_dht(T skey) : self_key{skey} {}

template <typename T>
kademlia_dht<T>::~kademlia_dht() {
    kad_tree.~btree();
}

template <typename T>
btree_node_t * kademlia_dht<T>::find_closest_node(T key) {

    T s_key = key ^ self_key;
    
    return kad_tree.btree_find_node(s_key);
}
