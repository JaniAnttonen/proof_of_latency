use ramp::Int;
use std::str::FromStr;
use std::{thread, time};

use proof_of_latency::{RSA_2048, ProofOfLatency};
pub mod vdf;
//pub mod p2p;

// rsa_mod = N, root = g
fn main() {
    // This parameter just needs to provide a group of unknown order, thus a large RSA number is
    // required. N in the paper.
    let rsa_mod = Int::from_str(RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let root = vdf::util::hash(&"Beep boop beep".to_string(), &rsa_mod);

    // Create VDF, estimate upper bound for 5 seconds
    let our_vdf = vdf::VDF::new(rsa_mod, root).estimate_upper_bound(5000);

    // OH YES, it's a random prime that gets used in the proof and verification. This has to be
    // sent from another peer and this actually is the thing that ends the calculation and
    // facilitates the proof.
    let cap: u64 = vdf::util::get_prime();

    // Run the VDF, returning connection channels to push to and receive data from
    let (vdf_worker, worker_output) = our_vdf.run_vdf_worker();

    // Sleep for 300 milliseconds to simulate latency overseas
    let sleep_time = time::Duration::from_millis(300);
    thread::sleep(sleep_time);

    // Send received signature from the other peer, "capping off" the VDF
    if vdf_worker.send(cap).is_err() {
        println!(
            "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
        );
    };

    // Wait for response from VDF worker
    let success = match worker_output.recv() {
        Ok(res) => match res {
            Ok(proof) => {
                println!("VDF ran for {:?} times!\nThe output being {:?}",
                proof.output.iterations, proof.output.result);
                if proof.verify() {
                    println!("The VDF is correct!");
                }
                else {
                    println!("The VDF couldn't be verified!");
                }
                true
            },
            Err(_) => false,
        },
        Err(err) => {
            println!("Error when receiving response from VDF worker: {:?}", err);
            false
        }
    };

    if !success {
        println!("The VDF is not correct, there was a problem generating the proof");
    };

    //p2p::run().unwrap();
}
