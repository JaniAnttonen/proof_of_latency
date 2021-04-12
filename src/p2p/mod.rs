use async_std::task;
use futures::prelude::*;
use libp2p::{
    mdns::{Mdns, MdnsEvent},
    NetworkBehaviour, Swarm,
};
use std::{
    error::Error,
    task::{Context, Poll},
};

pub mod identity;
pub mod protocol;

// We create a custom network behaviour that combines floodsub and mDNS.
// In the future, we want to improve libp2p to make this easier to do.
// Use the derive to generate delegating NetworkBehaviour impl and require the
// NetworkBehaviourEventProcess implementations below.
#[derive(NetworkBehaviour)]
struct PoLBehavior {
    pol: protocol::PoL,
    mdns: Mdns,

    // Struct fields which do not implement NetworkBehaviour need to be ignored
    #[behaviour(ignore)]
    #[allow(dead_code)]
    ignored_member: bool,
}

pub fn run_p2p() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");

    // create a random peerid.
    let (id_keys, peer_id) = identity::create_identity();
    println!("Local peer id: {:?}", peer_id);

    // create a transport.
    let transport = libp2p::build_development_transport(id_keys)?;

    // create a PoL network behaviour.
    let pol_behavior = protocol::PoL::new(protocol::PoLConfig::new());

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let mdns = task::block_on(Mdns::new())?;
        let mut behavior = PoLBehavior {
            pol: pol_behavior,
            mdns,
            ignored_member: false,
        };
        Swarm::new(transport, behavior, peer_id)
    };

    // Tell the swarm to listen on all interfaces and a random, OS-assigned
    // port.
    Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut listening = false;
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| loop {
        match swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(event)) => println!("{:?}", event),
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => {
                if !listening {
                    for addr in Swarm::listeners(&swarm) {
                        println!("Listening on {}", addr);
                        listening = true;
                    }
                }
                return Poll::Pending;
            }
        }
    }));

    Ok(())
}
