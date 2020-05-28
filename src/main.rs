#[macro_use]
extern crate log;
use proof_of_latency::{vdf, ProofOfLatency};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    let mut pol = ProofOfLatency::default();

    let divider = Int::from_str(proof_of_latency::RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let prime1 = Generator::new_prime(128);
    let prime2 = Generator::new_prime(128);
    let diffiehellman = prime1 * prime2;
    let root_hashed = vdf::util::hash(&diffiehellman.to_string(), &divider);

    pol.start(divider.clone(), root_hashed.clone(), usize::MAX);
    let verifiers_vdf = vdf::VDF::new(divider, root_hashed, 20000);

    //pol.estimate_upper_bound(5000);

    let (_, receiver) = verifiers_vdf.run_vdf_worker();
    if let Ok(res) = receiver.recv() {
        if let Ok(proof) = res {
            pol.receive(proof);
        }
    }

    info!("{:?}", pol);
    //p2p::run().unwrap();
}
