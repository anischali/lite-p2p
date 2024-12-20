#ifndef __BTREE_HPP__
#define __BTREE_HPP__
#include "list_head.hpp"
#include <stdint.h>
#include <errno.h>
#include "litetypes.hpp"

namespace lite_p2p
{
    struct btree_node_t
    {
        bool leaf = false;
        struct btree_node_t *children[2] = {nullptr, nullptr};
    };
    
    template <typename T>
    class btree
    {

    private:
        size_t depth = sizeof(T) * 8;
        struct btree_node_t *root = nullptr;

    public:
        btree();
        ~btree();
        
        struct btree_node_t *get_root() {return root;};
        int btree_insert_key(struct btree_node_t *node, T key);
        struct btree_node_t *btree_find_node(T key);
        void print();
    };
};
#endif