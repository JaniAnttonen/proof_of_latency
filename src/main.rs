#[macro_use]
extern crate log;
use proof_of_latency::{p2p, vdf, PoLRole, ProofOfLatency};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    // p2p::run();

    let mut pol = ProofOfLatency::default();
    debug!("Proof of latency instance created");

    //let ver_proof_correct = pol.verifier_result.unwrap().verify();
    //let pro_proof_correct = pol.prover_result.unwrap().verify();

    //if ver_proof_correct {
    //    info!("Verifier proof correct!");
    //} else {
    //    error!("Verifier proof incorrect!");
    //}

    //if pro_proof_correct {
    //    info!("Prover proof correct!");
    //} else {
    //    error!("Prover proof incorrect!");
    //}
}
