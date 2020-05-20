use ramp::Int;
use std::str::FromStr;
use std::{thread, time};

mod vdf;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

pub enum STATE {}

// rsa_mod = N, root = g
pub struct ProofOfLatency {
    pub rsa_mod: Int,
    pub root: Int,
    vdf: vdf::VDF,
    pub our_proof: Option<vdf::VDFProof>,
    pub their_proof: Option<vdf::VDFProof>,
}

impl ProofOfLatency {
    pub fn new(secret: &str) -> ProofOfLatency {
        let rsa_mod = Int::from_str(RSA_2048).unwrap();

        // Security parameter, g in the paper. This needs to be replaced with a key that's decided
        // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
        // repeatedly for T times. Used to verify that the calculations started here. That's why the
        // setup needs to generate a random starting point that couldn't have been forged beforehand.
        let root = vdf::util::hash(secret, &rsa_mod);

        let our_vdf = vdf::VDF::new(rsa_mod.clone(), root.clone()).estimate_upper_bound(5000);

        ProofOfLatency {
            rsa_mod,
            root,
            vdf: our_vdf,
            our_proof: Option::default(),
            their_proof: Option::default(),
        }
    }
    pub fn run(mut self) {
        // OH YES, it's a random prime that gets used in the proof and verification. This has to be
        // sent from another peer and this actually is the thing that ends the calculation and
        // facilitates the proof.
        let cap: u64 = vdf::util::get_prime();

        // Run the VDF, returning connection channels to push to and receive data from
        let (vdf_worker, worker_output) = self.vdf.run_vdf_worker();

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
                    println!(
                        "VDF ran for {:?} times!\nThe output being {:?}",
                        proof.output.iterations, proof.output.result
                    );
                    if proof.verify() {
                        println!("The VDF is correct!");
                        self.our_proof = Some(proof);
                    } else {
                        println!("The VDF couldn't be verified!");
                    }
                    true
                }
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
    }
}
