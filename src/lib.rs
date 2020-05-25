#[macro_use]
extern crate log;
use ramp::Int;
use std::sync::mpsc::{Receiver, Sender};

mod vdf;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

pub enum STATE {}

// divider = N, root = g
#[derive(Debug)]
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

impl Default for ProofOfLatency {
    fn default() -> Self {
        Self {
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
}

impl ProofOfLatency {
    pub fn set_params(&mut self, divider: Int, root: Int, lower_bound: u128) {
        let root_hashed = vdf::util::hash(&root.to_string(), &divider);
        self.vdf = Some(vdf::VDF::new(
            divider.clone(),
            root_hashed.clone(),
            lower_bound,
        ));
        self.divider = Some(divider);
        self.root = Some(root_hashed);
        self.lower_bound = Some(lower_bound);
    }

    /// TODO: Add a Result<> as a return type, with an error VDFStartError
    pub fn start(&mut self) {
        // OH YES, it's a random prime that gets used in the proof and verification. This has to be
        // sent from another peer and this actually is the thing that ends the calculation and
        // facilitates the proof.
        //let cap: u64 = vdf::util::get_prime();

        let (capper, receiver) = self.vdf.clone().unwrap().run_vdf_worker();

        self.capper = Some(capper);
        self.receiver = Some(receiver);
    }

    pub fn receive(mut self, their_proof: vdf::VDFProof) {
        if their_proof.verify() {
            // Send received signature from the other peer, "capping off" the VDF
            if self.capper.unwrap().send(their_proof.cap).is_err() {
                debug!(
                    "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
                );
            };

            // Wait for response from VDF worker
            if let Ok(res) = self.receiver.unwrap().recv() {
                if let Ok(proof) = res {
                    debug!(
                        "VDF ran for {:?} times!\nThe output being {:?}",
                        proof.output.iterations, proof.output.result
                    );
                    if proof.verify() {
                        info!("The VDF is correct!");
                        self.prover_result = Some(proof);
                        self.verifier_result = Some(their_proof);
                    } else {
                        error!("The VDF couldn't be verified!");
                    }
                } else {
                    error!("Error when receiving response from VDF worker");
                }
            }
        }
    }
}
