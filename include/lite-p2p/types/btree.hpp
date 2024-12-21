#ifndef __BTREE_HPP__
#define __BTREE_HPP__
#include "list_head.hpp"
#include <stdint.h>
#include <errno.h>
#include "lite-p2p/types/types.hpp"

namespace lite_p2p::types
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
        struct btree_node_t *root = nullptr;
        size_t depth = sizeof(T) * 8;

        static inline int allocate_node(struct btree_node_t **node)
        {
            struct btree_node_t *n;

            if (!node)
                return -EINVAL;

            n = (struct btree_node_t *)std::calloc(1, sizeof(btree_node_t));
            if (!n)
                return -ENOMEM;

            *node = n;
            return 0;
        }

        static inline void btree_free(struct btree_node_t *bt, int depth)
        {
            struct btree_node_t *c1 = nullptr, *c2 = nullptr;
            
            if (!bt || depth == 0)
                return;

            c1 = bt->children[0];
            c2 = bt->children[1];
            --depth;
          
            if (c1)
                btree_free(c1, depth);

            if (c2)
                btree_free(c2, depth);

            
            if (bt) {
                free(bt);
                bt = nullptr;
            }
            
        }

        static inline void btree_print(struct btree_node_t *bt)
        {

            if (!bt)
                return;

            if (bt->leaf)
                printf("leaf\n");
            
            if (bt->children[0])
                btree_print(bt->children[0]);

            if (bt->children[1])
                btree_print(bt->children[1]);
        }

        static inline void btree_callback_on_leaf(btree_node_t *bt, void (*exec_callback)(btree_node_t **node)) {
            
            if (!bt)
                return;
        
            if (bt->leaf && exec_callback) {
                exec_callback(&bt);
                return;
            }

            if (bt->children[0])
                btree_callback_on_leaf(bt->children[0], exec_callback);

            if (bt->children[1])
                btree_callback_on_leaf(bt->children[1], exec_callback);
        }

        
        static inline void btree_node_callback(btree_node_t *bt, void (*exec_callback)(lite_p2p::types::btree_node_t **node)) {
            
            if (!bt)
                return;
        
            if (bt->children[0])
                btree_node_callback(bt->children[0], exec_callback);

            if (bt->children[1])
                btree_node_callback(bt->children[1], exec_callback);
            
            exec_callback(&bt);
        }

    public:
        btree() {}
        ~btree()
        {
            btree_free(root, depth);
            root = nullptr;
        }

        int btree_insert_key(struct btree_node_t *node, T key)
        {
            struct btree_node_t *bt;
            size_t vsize = (sizeof(T) * 8);

            if (!root)
            {
                if ((allocate_node(&root)) != 0)
                    return -ENOMEM;
            }

            bt = root;
            for (size_t i = 0; i < vsize - 1 && bt; ++i)
            {
                int vbit = key.at(i);
                if (!bt->children[vbit])
                {
                    if ((allocate_node(&bt->children[vbit])) != 0)
                        return -ENOMEM;
                }

                bt = bt->children[vbit];
            }

            bt->children[key.at(vsize - 1)] = node;

            return 0;
        }

        struct btree_node_t *btree_find_node(T key)
        {
            struct btree_node_t *bt;
            size_t vsize = (sizeof(T) * 8);

            bt = root;
            if (!bt)
                return nullptr;

            for (size_t i = 0; i < vsize - 1 && bt; ++i)
            {
                int vbit = key.at(i);
                if (!bt->children[vbit])
                {
                    return nullptr;
                }

                bt = bt->children[vbit];
            }

            return bt->children[key.at(vsize - 1)];
        }

        void print()
        {
            btree_print(root);
        }

        void btree_callback_on_leaf(void (*exec_callback)(btree_node_t **node)) {
            
            btree_callback_on_leaf(root, exec_callback);
        }

        void btree_node_callback(void (*exec_callback)(lite_p2p::types::btree_node_t **node)) {
            
            btree_node_callback(root, exec_callback);
        }

        struct btree_node_t *get_root() { return root; };
    };
};
#endif