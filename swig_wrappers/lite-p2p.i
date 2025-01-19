%module lite_p2p
%{
#include <lite-p2p/types/types.hpp>
#include <lite-p2p/types/list_head.hpp>
#include <lite-p2p/types/btree.hpp>
#include <lite-p2p/common/common.hpp>
#include <lite-p2p/crypto/crypto.hpp>
#include <lite-p2p/network/network.hpp>
#include <lite-p2p/network/socket.hpp>
#include <lite-p2p/peer/connection.hpp>
#include <lite-p2p/protocol/dht/kademlia.hpp>
#include <lite-p2p/protocol/ice/agent.hpp>
#include <lite-p2p/protocol/stun/attrs.hpp>
#include <lite-p2p/protocol/stun/client.hpp>
#include <lite-p2p/protocol/stun/session.hpp>
#include <lite-p2p/protocol/turn/client.hpp>
%}


%include <lite-p2p/types/types.hpp>
%include <lite-p2p/types/list_head.hpp>
%include <lite-p2p/types/btree.hpp>
%include <lite-p2p/common/common.hpp>
%include <lite-p2p/crypto/crypto.hpp>
%include <lite-p2p/network/network.hpp>
%include <lite-p2p/network/socket.hpp>
%include <lite-p2p/peer/connection.hpp>
%include <lite-p2p/protocol/dht/kademlia.hpp>
%include <lite-p2p/protocol/ice/agent.hpp>
%include <lite-p2p/protocol/stun/attrs.hpp>
%include <lite-p2p/protocol/stun/client.hpp>
%include <lite-p2p/protocol/stun/session.hpp>
%include <lite-p2p/protocol/turn/client.hpp>