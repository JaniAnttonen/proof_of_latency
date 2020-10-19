use libp2p::{identity::Keypair, PeerId};

pub fn create_identity() -> (Keypair, PeerId) {
    let local_key: Keypair = Keypair::generate_ed25519();
    let local_peer_id: PeerId = PeerId::from(local_key.public());
    (local_key, local_peer_id)
}
