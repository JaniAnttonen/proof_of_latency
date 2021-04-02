#[macro_use]
extern crate log;
use proof_of_latency::p2p;
use proof_of_latency::{PoLMessage, PoLRole, ProofOfLatency, RSA_2048};
use ramp::Int;
use ramp_primes::Generator;
use std::str::FromStr;

fn main() {
    env_logger::init();

    let p2p_result = p2p::run_p2p();
    debug!("{:?}", p2p_result);

    let modulus = Int::from_str(RSA_2048).unwrap();
    let mut pol =
        ProofOfLatency::default().init(modulus, 150000, String::from(""));
    let (input, output) = pol.open_io();
    debug!("Proof of latency instance created");

    match pol.start(PoLRole::Prover) {
        Ok(_) => info!("PoL state machine started"),
        Err(_) => error!("Couldn't start the PoL state machine"),
    }

    if let Ok(message) = output.recv() {
        match message {
            PoLMessage::GeneratorPart { num } => {
                info!("Generator part received: {:?}", num)
            }
            _ => error!("Wrong message received"),
        }
    } else {
        error!("Channel closed!")
    }

    let cap = Generator::new_safe_prime(128);
    let generator_part = Generator::new_uint(128);
    match input.send(PoLMessage::GeneratorPartAndCap {
        generator_part,
        cap,
    }) {
        Ok(_) => info!("Received g2, l2"),
        Err(_) => error!("Channel closed!"),
    }

    if let Ok(message) = output.recv() {
        match message {
            PoLMessage::VDFProofAndCap { proof, cap: _ } => {
                if proof.verify() {
                    info!("VDF ready!")
                } else {
                    error!("Our VDF proof was not correct!")
                }
            }
            _ => error!("Wrong message received"),
        }
    } else {
        error!("Channel closed!");
    }
}
