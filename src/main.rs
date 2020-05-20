use proof_of_latency::ProofOfLatency;
pub mod vdf;
//pub mod p2p;

// rsa_mod = N, root = g
fn main() {
    let pol = ProofOfLatency::new("beep boop beep");
    pol.run();
    //p2p::run().unwrap();
}
