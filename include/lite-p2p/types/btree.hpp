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
        struct btree_node_t *children[2] = {NULL, NULL};
    };

    template <typename T>
    class btree
    {

    private:
        struct btree_node_t *root = NULL;

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

        static inline void btree_free(struct btree_node_t *bt)
        {
            if (!bt || bt->leaf) {
                return;
            }

            if (bt->children[0])
                btree_free(bt->children[0]);
            
            if (bt->children[1])
                btree_free(bt->children[1]);

            if (bt) {
                free(bt);
                bt = NULL;
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
        btree() {
            allocate_node(&root);
        };
        ~btree()
        {
            if (!root)
                return;

            btree_free(root);
            root = NULL;
        }

        int btree_insert_key(struct btree_node_t *node, T key)
        {
            struct btree_node_t *bt;
            ssize_t vsize = (sizeof(T) * 8) - 1;

            if (!root)
            {
                if ((allocate_node(&root)) != 0)
                    return -ENOMEM;
            }

            //while(!key.at(vsize--) && vsize);

            bt = root;
            for (ssize_t i = vsize; i > 0 && bt; --i)
            {
                int vbit = !!key.at(i);
                if (!bt->children[vbit])
                {
                    if ((allocate_node(&bt->children[vbit])) != 0)
                        return -ENOMEM;
                }

                bt = bt->children[vbit];
            }

            bt->children[!!key.at(0)] = node;

            return 0;
        }

        struct btree_node_t *btree_find_node(T key)
        {
            struct btree_node_t *bt;
            ssize_t vsize = (sizeof(T) * 8) - 1;

            bt = root;
            if (!bt)
                return NULL;

            //while(!key.at(vsize--) && vsize);

            for (ssize_t i = vsize; i > 0 && bt; --i)
            {
                int vbit = !!key.at(i);
                if (!bt->children[vbit])
                {
                    return NULL;
                }

                bt = bt->children[vbit];
            }

            return bt->children[!!key.at(0)];
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