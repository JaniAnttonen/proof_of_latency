
//! Demonstrates how to perform Kademlia queries on the IPFS network.
//!
//! You can pass as parameter a base58 peer ID to search for. If you don't pass any parameter, a
//! peer ID will be generated randomly.

use async_std::task;
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{GetClosestPeersError, Kademlia, KademliaConfig, KademliaEvent};
use libp2p::{build_development_transport, identity, PeerId, Swarm};
use std::{env, error::Error, time::Duration};

pub struct P2P {
    pub identity: identity::Keypair,
    transport: 
}

impl P2P {
    pub fn create() -> P2P { 
          // Create a random key for ourselves.
          let local_key = identity::Keypair::generate_ed25519();
          let local_peer_id = PeerId::from(local_key.public());

          // Set up a an encrypted DNS-enabled TCP Transport over the Mplex protocol
          let transport = build_development_transport(local_key)?;

          return P2P{identity: local_key, transport: transport};
    }
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let p2p_instance = P2P::create();

    // Create a swarm to manage peers and events.
    let mut swarm = {
        // Create a Kademlia behaviour.
        let mut cfg = KademliaConfig::default();

        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        let store = MemoryStore::new(local_peer_id.clone());
        let mut behaviour = Kademlia::with_config(local_peer_id.clone(), store, cfg);

        // The only address that currently works.
        behaviour.add_address(
          &"QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ".parse()?,
          "/ip4/104.131.131.82/tcp/4001".parse()?,
        );

        Swarm::new(transport, behaviour, local_peer_id)
    };

    // Order Kademlia to search for a peer.
    let to_search: PeerId = if let Some(peer_id) = env::args().nth(1) {
        peer_id.parse()?
    } else {
        identity::Keypair::generate_ed25519().public().into()
    };

    println!("Searching for the closest peers to {:?}", to_search);
    swarm.get_closest_peers(to_search);

    // Kick it off!
    task::block_on(async move {
    loop {
      let event = swarm.next().await;
      if let KademliaEvent::GetClosestPeersResult(result) = event {
        match result {
          Ok(ok) => {
            if !ok.peers.is_empty() {
              println!("Query finished with closest peers: {:#?}", ok.peers)
            } else {
              // The example is considered failed as there
              // should always be at least 1 reachable peer.
              println!("Query finished with no closest peers.")
            }
          }
          Err(GetClosestPeersError::Timeout { peers, .. }) => {
            if !peers.is_empty() {
              println!("Query timed out with closest peers: {:#?}", peers)
            } else {
              // The example is considered failed as there
              // should always be at least 1 reachable peer.
              println!("Query timed out with no closest peers.");
            }
          }
        };

        break;
      }
    }

    Ok(())
    })
}
