use ramp::Int;
use ramp_primes::Generator;
use ramp_primes::Verification;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time};

pub mod util;

/// InvalidCapError is returned when a non-prime cap is received in the vdf_worker
#[derive(Debug)]
pub struct InvalidCapError;

impl fmt::Display for InvalidCapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid cap value encountered!")
    }
}

impl Error for InvalidCapError {
    fn description(&self) -> &str {
        "Invalid cap value encountered!"
    }
}

/// The end result of the VDF which we still need to prove
#[derive(Debug, Clone)]
pub struct VDFResult {
    pub result: Int,
    pub iterations: usize,
}

/// Traits that make calculating differences between VDFResults easier
impl Ord for VDFResult {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iterations.cmp(&other.iterations)
    }
}

impl PartialOrd for VDFResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VDFResult {
    fn eq(&self, other: &Self) -> bool {
        self.result == other.result && self.iterations == other.iterations
    }
}

impl Eq for VDFResult {}

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug, Clone)]
pub struct VDFProof {
    pub modulus: Int,
    pub root: Int,
    pub output: VDFResult,
    pub cap: Int,
    pub proof: Int,
}

impl PartialEq for VDFProof {
    fn eq(&self, other: &Self) -> bool {
        self.output == other.output
            && self.proof == other.proof
            && self.modulus == other.modulus
            && self.root == other.root
            && self.cap == other.cap
    }
}

impl VDFProof {
    /// A public function that a receiver can use to verify the correctness of the VDFProof
    pub fn verify(&self) -> bool {
        // Check first that the result isn't larger than the RSA base
        if self.proof > self.modulus {
            return false;
        }
        let r = Int::from(self.output.iterations).pow_mod(&Int::from(2), &self.cap);
        self.output.result
            == (self.proof.pow_mod(&self.cap, &self.modulus)
                * self.root.pow_mod(&Int::from(r), &self.modulus))
                % &self.modulus
    }

    pub fn validate(&self) -> bool {
        self.modulus.gcd(&self.root) == 1 && self.modulus.gcd(&self.cap) == 1
    }

    /// Helper function for calculating the difference in iterations between two VDFProofs
    pub fn abs_difference(&self, other: &VDFProof) -> usize {
        if self.output > other.output {
            self.output.iterations - other.output.iterations
        } else {
            other.output.iterations - self.output.iterations
        }
    }
}

/// VDF is an options struct for calculating VDFProofs
#[derive(Debug, Clone)]
pub struct VDF {
    pub modulus: Int,
    pub root: Int,
    pub upper_bound: usize,
    pub cap: Int,
}

impl VDF {
    /// VDF builder with default options. Can be chained with estimate_upper_bound
    pub fn new(modulus: Int, root: Int, upper_bound: usize) -> Self {
        assert!(modulus.gcd(&root) == 1);
        Self {
            modulus,
            root,
            upper_bound,
            cap: Int::zero(),
        }
    }

    /// Estimates the maximum number of sequential calculations that can fit in the fiven ms_bound
    /// millisecond threshold.
    pub fn estimate_upper_bound(mut self, ms_bound: u64) {
        let cap: Int = Generator::new_prime(128);
        let (capper, receiver) = self.clone().run_vdf_worker();

        let sleep_time = time::Duration::from_millis(ms_bound);
        thread::sleep(sleep_time);
        capper.send(cap).unwrap();

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                self.upper_bound = proof.output.iterations;
            }
        }
    }

    /// Returns a VDFProof based on a VDFResult
    fn generate_proof(&self, result: VDFResult, cap: Int) -> VDFProof {
        let mut proof = Int::one();
        let mut r = Int::one();
        let mut b: Int;

        for _ in 0..result.iterations {
            b = 2 * &r / &cap;
            r = (2 * &r) % &cap;
            proof =
                proof.pow_mod(&Int::from(2), &self.modulus) * self.root.pow_mod(&b, &self.modulus);
            proof %= &self.modulus;
        }

        VDFProof {
            modulus: self.modulus.clone(),
            root: self.root.clone(),
            output: result,
            cap,
            proof,
        }
    }

    /// A worker that does the actual calculation in a VDF. Returns a VDFProof based on initial
    /// parameters in the VDF.
    pub fn run_vdf_worker(self) -> (Sender<Int>, Receiver<Result<VDFProof, InvalidCapError>>) {
        let (caller_sender, worker_receiver) = channel();
        let (worker_sender, caller_receiver) = channel();

        thread::spawn(move || {
            let mut result = self.root.clone();
            let mut iterations: usize = 0;
            loop {
                result = result.pow_mod(&Int::from(2), &self.modulus);
                iterations += 1;

                if iterations == self.upper_bound || iterations == usize::MAX {
                    // Upper bound reached, stops iteration and calculates the proof
                    debug!("Upper bound of {:?} reached, generating proof.", iterations);

                    // Copy pregenerated cap
                    let mut self_cap: Int = self.cap.clone();

                    // Check if default, check for primality if else
                    if self_cap == 0 {
                        self_cap = Generator::new_prime(128);
                    } else if !Verification::verify_prime(self_cap.clone()) {
                        if worker_sender.send(Err(InvalidCapError)).is_err() {
                            error!("Self-generated cap was not a prime! Check the implementation!");
                        }
                        break;
                    }

                    // Generate the VDF proof
                    let proof = self.generate_proof(VDFResult { result, iterations }, self_cap);

                    // Send proof to caller
                    if worker_sender.send(Ok(proof)).is_err() {
                        error!("Failed to send the proof to caller!");
                    }

                    break;
                } else {
                    // Try receiving a cap from caller on each iteration
                    let cap = worker_receiver.try_recv();
                    if !cap.is_err() {
                        let received_cap: Int = cap.unwrap();
                        // Cap received
                        info!("Received the cap {:?}, generating proof.", received_cap);

                        // Check for primality
                        if Verification::verify_prime(received_cap.clone()) {
                            // Generate proof on given cap
                            let proof =
                                self.generate_proof(VDFResult { result, iterations }, received_cap);
                            debug!("Proof generated! {:?}", proof);
                            // Send proof to caller
                            if worker_sender.send(Ok(proof)).is_err() {
                                error!("Failed to send the proof to caller!");
                            }
                        } else {
                            error!("Received cap was not a prime!");
                            // Received cap was not a prime, send error to caller
                            if worker_sender.send(Err(InvalidCapError)).is_err() {
                                error!("Error sending InvalidCapError to caller!");
                            }
                        }
                        break;
                    } else {
                        continue;
                    }
                }
            }
        });

        (caller_sender, caller_receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn is_deterministic() {
        let modulus = Int::from_str("251697").unwrap();
        let prime1 = Int::from(util::get_prime());
        let prime2 = Int::from(util::get_prime());
        let diffiehellman = prime1 * prime2;
        let root_hashed = util::hash(&diffiehellman.to_string(), &modulus);

        let verifiers_vdf = VDF::new(modulus.clone(), root_hashed.clone(), 100);
        let provers_vdf = VDF::new(modulus, root_hashed, 100);

        let (_, receiver) = verifiers_vdf.run_vdf_worker();
        let (_, receiver2) = provers_vdf.run_vdf_worker();

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                assert!(proof.verify());
            }
        }

        if let Ok(res) = receiver2.recv() {
            if let Ok(proof) = res {
                assert!(proof.verify());
            }
        }

        // assert!(prover_result.is_some());
        // assert!(pol.verifier_result.is_some());
        // assert_eq!(
        //     pol.verifier_result.unwrap().output,
        //     pol.prover_result.unwrap().output
        // );
    }
}
