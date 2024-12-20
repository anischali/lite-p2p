#include "lite-p2p/btree.hpp"

using namespace lite_p2p;


template class btree<lite_p2p::lpint8_t>;
template class btree<lite_p2p::lpint16_t>;
template class btree<lite_p2p::lpint24_t>;
template class btree<lite_p2p::lpint32_t>;
template class btree<lite_p2p::lpint64_t>;
template class btree<lite_p2p::lpint128_t>;
template class btree<lite_p2p::lpint256_t>;
template class btree<lite_p2p::lpint512_t>;
template class btree<lite_p2p::lpint1024_t>;
template class btree<lite_p2p::lpint2048_t>;
template class btree<lite_p2p::lpint4096_t>;


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
    struct btree_node_t *c1, *c2;
    if (!bt || bt->leaf)
        return;

    c1 = bt->children[0];
    c2 = bt->children[1];

    if (c1)
        btree_free(c1);

    if (c2)
        btree_free(c2);

    free(bt);
    bt = nullptr;
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

template <typename T> btree<T>::btree() {}

template <typename T> btree<T>::~btree()
{
    btree_free(root);
    root = nullptr;
}

template <typename T>
int btree<T>::btree_insert_key(struct btree_node_t *node, T v)
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
        int vbit = v.at(i);
        if (!bt->children[vbit])
        {
            if ((allocate_node(&bt->children[vbit])) != 0)
                return -ENOMEM;
        }

        bt = bt->children[vbit];
    }

    bt->children[v.at(vsize - 1)] = node;

    return 0;
}


template <typename T>
void btree<T>::print() {
    btree_print(root);
}