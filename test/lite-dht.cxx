#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include "lite-p2p/crypto/crypto.hpp"
#include "lite-p2p/common/common.hpp"
#include "lite-p2p/network/network.hpp"
#include "lite-p2p/types/types.hpp"
#include "lite-p2p/types/btree.hpp"
#include "lite-p2p/protocol/dht/kademlia.hpp"

using namespace lite_p2p::peer;
using namespace lite_p2p::types;
using namespace lite_p2p::protocol::dht;

peer_info<lite_p2p::types::lpint256_t> remotes[100];

int main(int argc, char *argv[]) {
    srand(time(NULL));

    peer_info<lpint256_t> curr;
    auto dht = new kademlia<lpint256_t>(curr.key);

    dht->add_peer(curr);

    for (auto &&r : remotes) {
        r.key.set_bit(lite_p2p::common::rand_int(226, 256), 0);
        r.key.set_bit(lite_p2p::common::rand_int(32, 255), 0);
        r.key.set_bit(lite_p2p::common::rand_int(32, 255), 0);
        r.key.set_bit(lite_p2p::common::rand_int(32, 255), 0);
        dht->add_peer(r);
    }

    auto pi = dht->get_peer_info(remotes[7].key);

    printf("key: %s|%s\n", remotes[7].key.to_string().c_str(), pi->key.to_string().c_str());

    delete dht;

    return 0;
}