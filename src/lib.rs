use env_logger;
use ramp::Int;
use std::error::Error;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time};

mod vdf;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

pub enum STATE {}

// divider = N, root = g
pub struct ProofOfLatency {
    pub divider: Option<Int>,
    pub root: Option<Int>,
    pub lower_bound: Option<u128>,
    vdf: Option<vdf::VDF>,
    capper: Option<Sender<u64>>,
    receiver: Option<Receiver<Result<vdf::VDFProof, vdf::InvalidCapError>>>,
    pub prover_result: Option<vdf::VDFProof>,
    pub verifier_result: Option<vdf::VDFProof>,
}

impl ProofOfLatency {
    pub fn new() -> ProofOfLatency {
        ProofOfLatency {
            divider: None,
            root: None,
            lower_bound: None,
            vdf: None,
            capper: None,
            receiver: None,
            prover_result: None,
            verifier_result: None,
        }
    }

    pub fn set_params(mut self, divider: Int, root: Int, lower_bound: u128) {
        self.divider = Some(divider);
        self.root = Some(root);
        self.lower_bound = Some(lower_bound);
        self.vdf = Some(vdf::VDF::new(divider.clone(), root.clone()));
    }

    /// TODO: Add a Result<> as a return type, with an error VDFStartError
    pub fn start(mut self) {
        // OH YES, it's a random prime that gets used in the proof and verification. This has to be
        // sent from another peer and this actually is the thing that ends the calculation and
        // facilitates the proof.
        let cap: u64 = vdf::util::get_prime();

        // Run the VDF, returning connection channels to push to and receive data from
        let (capper, receiver) = self.vdf.unwrap().run_vdf_worker();

        // TODO: THIS IS STUPID, HAVE CAPPER AND RECEIVER BE ATTRIBUTES OF THE VDF, OTHERWISE THEIR
        // LIFETIME IS WAAAAY TOO LONG!
        self.capper = Some(capper);
        self.receiver = Some(receiver);
    }

    pub fn receive(mut self, their_proof: vdf::VDFProof) -> Option<error::Error> {
        // Send received signature from the other peer, "capping off" the VDF
        if self.capper.unwrap().send(their_proof.cap).is_err() {
            println!(
                "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
            );
        };

        // Wait for response from VDF worker
        let success = match self.receiver.unwrap().recv() {
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
    }
}
