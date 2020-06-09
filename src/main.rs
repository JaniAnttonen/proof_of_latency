#[macro_use]
extern crate log;
use proof_of_latency::{vdf, ProofOfLatency};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    let mut pol = ProofOfLatency::default();
    debug!("Proof of latency instance created");

    let modulus = Int::from_str(proof_of_latency::RSA_2048).unwrap();
    debug!("RSA modulus formed!");

    let prime1 = Generator::new_uint(128);
    let prime2 = Generator::new_uint(128);
    let diffiehellman = prime1 * prime2;
    debug!("Key exchange done!");

    let base = vdf::util::hash(&diffiehellman.to_string(), &modulus);
    debug!("Variables created");

    let verifiers_vdf = vdf::VDF::new(modulus.clone(), base.clone(), 30);
    debug!("Verifier's VDF created");

    pol.start(modulus.clone(), base.clone(), usize::MAX);
    debug!("Proof of Latency calculation started");

    let (_, receiver) = verifiers_vdf.run_vdf_worker();
    debug!("Verifier's VDF worker running");

    if let Ok(res) = receiver.recv() {
        debug!("Got the proof from verifier!");
        if let Ok(proof) = res {
            pol.receive(proof);
        }
    }

    debug!("{:?}", pol);
    //p2p::run().unwrap();
}
