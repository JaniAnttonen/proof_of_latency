#[macro_use]
extern crate log;
use proof_of_latency::ProofOfLatency;
use ramp::Int;
use std::str::FromStr;

pub mod vdf;

fn main() {
    let mut pol = ProofOfLatency::new();

    let divider = Int::from_str(proof_of_latency::RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let root = vdf::util::hash("beep boop beep", &divider);

    pol.set_params(divider, root, 50000);

    pol.start();

    info!("{:?}", pol);
    //p2p::run().unwrap();
}
