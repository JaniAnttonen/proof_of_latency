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

    let prime = Generator::new_uint(128);
    debug!("Key exchange done!");

    let base = vdf::util::hash(&prime.to_string(), &modulus);
    debug!("Variables created");

    let verifiers_vdf = vdf::VDF::new(modulus.clone(), base.clone(), 1028);
    debug!("Verifier's VDF created");

    pol.start(modulus.clone(), base.clone(), u32::MAX);
    debug!("Proof of Latency calculation started");

    let (_, receiver) = verifiers_vdf.run_vdf_worker();
    debug!("Verifier's VDF worker running");

    if let Ok(res) = receiver.recv() {
        debug!("Got the proof from verifier!");
        if let Ok(proof) = res {
            pol.receive(proof);
        }
    }

    let proofs_correct =
        pol.prover_result.unwrap().verify() && pol.verifier_result.unwrap().verify();

    if proofs_correct {
        debug!("Proofs correct!");
    } else {
        error!("Either the prover's or verifier's proof was not correct!");
    }
    //p2p::run().unwrap();
}
