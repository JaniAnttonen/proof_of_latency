#[macro_use]
extern crate log;

use ramp::Int;
use std::sync::mpsc::{Receiver, Sender};

pub mod vdf;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

pub enum STATE {}

// modulus = N, base = g
#[derive(Debug)]
pub struct ProofOfLatency {
    pub modulus: Option<Int>,
    pub base: Option<Int>,
    pub upper_bound: Option<usize>,
    capper: Option<Sender<Int>>,
    receiver: Option<Receiver<Result<vdf::VDFProof, vdf::InvalidCapError>>>,
    pub prover_result: Option<vdf::VDFProof>,
    pub verifier_result: Option<vdf::VDFProof>,
}

impl Default for ProofOfLatency {
    fn default() -> Self {
        Self {
            modulus: None,
            base: None,
            upper_bound: None,
            capper: None,
            receiver: None,
            prover_result: None,
            verifier_result: None,
        }
    }
}

impl ProofOfLatency {
    pub fn start(&mut self, modulus: Int, base: Int, upper_bound: usize) {
        self.modulus = Some(modulus.clone());
        self.base = Some(base.clone());
        self.upper_bound = Some(upper_bound);

        let prover_vdf = vdf::VDF::new(modulus, base, upper_bound);
        let (capper, receiver) = prover_vdf.run_vdf_worker();
        self.capper = Some(capper);
        self.receiver = Some(receiver);
    }

    pub fn receive(&mut self, their_proof: vdf::VDFProof) {
        // Send received signature from the other peer, "capping off" the VDF
        if self
            .capper
            .as_ref()
            .unwrap()
            .send(their_proof.cap.clone())
            .is_err()
        {
            debug!(
                "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
            );
        };

        // Wait for response from VDF worker
        loop {
            if let Ok(res) = self.receiver.as_ref().unwrap().try_recv() {
                if let Ok(proof) = res {
                    debug!(
                        "VDF ran for {:?} times!\nThe output being {:?}",
                        proof.output.iterations, proof.output.result
                    );

                    let iter_prover: usize = proof.output.iterations;
                    let iter_verifier: usize = their_proof.output.iterations;
                    let difference: Int = if iter_prover > iter_verifier {
                        Int::from(iter_prover - iter_verifier)
                    } else {
                        Int::from(iter_verifier - iter_prover)
                    };
                    info!(
                        "Both proofs are correct! Latency between peers was {:?} iterations.",
                        difference
                    );

                    self.prover_result = Some(proof);
                    self.verifier_result = Some(their_proof);

                    break;
                } else {
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramp_primes::Generator;
    use std::str::FromStr;

    #[test]
    fn start_modifies_self() {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let prime1 = Generator::new_prime(128);
        let prime2 = Generator::new_prime(128);
        let diffiehellman = prime1 * prime2;

        let mut pol = ProofOfLatency::default();

        let pol2 = ProofOfLatency::default();
        pol.start(modulus, diffiehellman, usize::MAX);

        assert!(pol.capper.is_some());
        assert!(pol2.capper.is_none());
        assert!(pol.receiver.is_some());
        assert!(pol2.receiver.is_none());
    }

    #[test]
    fn is_deterministic() {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let prime1 = Generator::new_prime(128);
        let prime2 = Generator::new_prime(128);
        let diffiehellman = prime1 * prime2;
        let root_hashed = vdf::util::hash(&diffiehellman.to_string(), &modulus);

        let mut pol = ProofOfLatency::default();
        pol.start(modulus.clone(), root_hashed.clone(), 100);
        let verifiers_vdf = vdf::VDF::new(modulus, root_hashed, 100);

        let (_, receiver) = verifiers_vdf.run_vdf_worker();
        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                pol.receive(proof);
            }
        }

        assert!(pol.prover_result.is_some());
        assert!(pol.verifier_result.is_some());
        assert_eq!(
            pol.verifier_result.unwrap().output,
            pol.prover_result.unwrap().output
        );
    }
}
