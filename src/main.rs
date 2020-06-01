#[macro_use]
extern crate log;
use proof_of_latency::{vdf, ProofOfLatency};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    let mut pol = ProofOfLatency::default();

    let modulus = Int::from_str(proof_of_latency::RSA_2048).unwrap();

    let prime1 = Generator::new_prime(128);
    let prime2 = Generator::new_prime(128);
    let diffiehellman = prime1 * prime2;
    let base = vdf::util::hash(&diffiehellman.to_string(), &modulus);

    pol.start(modulus.clone(), base.clone(), usize::MAX);
    let verifiers_vdf = vdf::VDF::new(modulus, base, 30);

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
