#ifndef __BTREE_HPP__
#define __BTREE_HPP__
#include "list_head.hpp"
#include <stdint.h>
#include <errno.h>
#include "litetypes.hpp"
extern "C"
{
    struct btree_node_t;
    struct btree_node_t
    {
        bool leaf = false;
        struct btree_node_t *children[2] = {nullptr, nullptr};
    };

    struct btree_t
    {
        int depth = 0;
        struct btree_node_t *root = nullptr;
    };

#define node_value(node, type, member) container_of(node, type, member)

    static inline int insert_node(struct btree_node_t *btree, struct btree_node_t *node, int val)
    {

        if (!btree)
            return -ENONET;

        val = !!val;
        if (btree->children[val])
            return -EALREADY;

        btree->children[val] = node;

        return 0;
    }

    static inline int allocate_node(struct btree_node_t **node)
    {
        struct btree_node_t *n; 
        
        if (!node)
            return -EINVAL;
        
        n = (struct btree_node_t *)std::calloc(1, sizeof(struct btree_node_t));
        if (!n)
            return -ENOMEM;

        *node = n;
        return 0;
    }

    static inline int btree_insert_value_u256(struct btree_t *btree, struct btree_node_t *node, uint256_t v)
    {
        struct btree_node_t *bt;
        if (!btree->root)
        {
            if ((allocate_node(&btree->root)) != 0)
                return -ENOMEM;
        }

        bt = btree->root;
        for (size_t i = 0; i < v.bits() - 1 && bt; ++i)
        {
            int vbit = v.at(i);
            if (!bt->children[vbit])
            {
                if ((allocate_node(&bt->children[vbit])) != 0)
                    return -ENOMEM;
            }

            bt = bt->children[vbit];
        }

        bt->children[v.at(v.bits() - 1)] = node;

        return 0;
    }

    static inline void btree_print(struct btree_node_t *bt)
    {

        if (bt->leaf)
            printf("leaf\n");

        if (!bt)
            return;

        if (bt->children[0])
            btree_print(bt->children[0]);

        if (bt->children[1])
            btree_print(bt->children[1]);
    }

    static inline void btree_free(struct btree_node_t *bt)
    {
        struct btree_node_t *c1, *c2;
        c1 = bt->children[0];
        c2 = bt->children[1];

        if (bt->leaf || !bt)
            return;

        if (c1)
            btree_free(c1);

        if (c2)
            btree_free(c2);

        free(bt);
    }
};
#endif