#[macro_use]
extern crate log;
use proof_of_latency::{p2p, vdf, ProofOfLatency};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    p2p::run();

    let mut pol = ProofOfLatency::default();
    debug!("Proof of latency instance created");

    let modulus = Int::from_str(proof_of_latency::RSA_2048).unwrap();
    debug!("RSA modulus formed!");

    let prime = Generator::new_safe_prime(32);
    debug!("Key exchange done!");

    let base = vdf::util::hash(&prime.to_string(), &modulus);
    debug!("Variables created");

    let verifiers_vdf = vdf::VDF::new(modulus.clone(), base.clone(), 128);
    debug!("Verifier's VDF created");

    pol.start(modulus, base, u32::MAX);
    debug!("Proof of Latency calculation started");

    let (_, receiver) = verifiers_vdf.run_vdf_worker();
    debug!("Verifier's VDF worker running");

    if let Ok(res) = receiver.recv() {
        debug!("Got the proof from verifier!");
        if let Ok(proof) = res {
            pol.receive(proof);
        }
    }

    let ver_proof_correct = pol.verifier_result.unwrap().verify();
    let pro_proof_correct = pol.prover_result.unwrap().verify();

    if ver_proof_correct {
        info!("Verifier proof correct!");
    } else {
        error!("Verifier proof incorrect!");
    }

    if pro_proof_correct {
        info!("Prover proof correct!");
    } else {
        error!("Prover proof incorrect!");
    }
}
