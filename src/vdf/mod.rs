use primal::is_prime;
use ramp::Int;
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
#[derive(Debug)]
pub struct VDFResult {
    pub result: Int,
    pub iterations: u128,
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
        self.iterations == other.iterations
    }
}

impl Eq for VDFResult {}

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug)]
pub struct VDFProof {
    pub rsa_mod: Int,
    pub seed: Int,
    pub output: VDFResult,
    pub cap: u64,
    pub proof: Int,
}

impl VDFProof {
    /// A public function that a receiver can use to verify the correctness of the VDFProof
    pub fn verify(&self) -> bool {
        let cap_int: Int = Int::from(self.cap);
        // Check first that the result isn't larger than the RSA base
        if self.proof > self.rsa_mod {
            return false;
        }
        let r = util::pow_mod(2, self.output.iterations, self.cap.into());
        self.output.result
            == (self.proof.pow_mod(&cap_int, &self.rsa_mod)
                * self.seed.pow_mod(&Int::from(r), &self.rsa_mod))
                % &self.rsa_mod
    }

    /// Helper function for calculating the difference in iterations between two VDFProofs
    pub fn abs_difference(&self, other: VDFProof) -> u128 {
        let ours_is_larger = self.output > other.output;
        if ours_is_larger {
            self.output.iterations - other.output.iterations
        } else {
            other.output.iterations - self.output.iterations
        }
    }
}

/// VDF is an options struct for calculating VDFProofs
#[derive(Debug, Clone)]
pub struct VDF {
    pub rsa_mod: Int,
    pub seed: Int,
    pub upper_bound: u128,
    pub cap: u64,
    capper: Option<Sender<u64>>,
    receiver: Option<Receiver<Result<VDFProof, InvalidCapError>>>, 
}

impl VDF {
    /// VDF builder with default options. Can be chained with estimate_upper_bound
    pub fn new(rsa_mod: Int, seed: Int) -> VDF {
        VDF {
            rsa_mod,
            seed,
            upper_bound: 0,
            cap: 0,
            capper: None,
            receiver: None,
        }
    }

    /// Estimates the maximum number of sequential calculations that can fit in the fiven ms_bound
    /// millisecond threshold.
    pub fn estimate_upper_bound(mut self, ms_bound: u64) -> Self {
        let cap: u64 = util::get_prime();
        let (vdf_worker, worker_output) = self.clone().run_vdf_worker();

        let sleep_time = time::Duration::from_millis(ms_bound);
        thread::sleep(sleep_time);
        vdf_worker.send(cap).unwrap();

        if let Ok(res) = worker_output.recv() {
            if let Ok(proof) = res {
                println!("VDF ran for {:?} times!", proof.output.iterations);
                println!("The output being {:?}", proof.output.result);
                self.upper_bound = proof.output.iterations;
            } else {
                self.upper_bound = 500000;
            }
        } else {
            self.upper_bound = 500000;
        }

        self
    }

    /// Returns a VDFProof based on a VDFResult
    fn generate_proof(&self, result: VDFResult, cap: u64) -> VDFProof {
        let mut proof = Int::one();
        let mut r = Int::one();
        let mut b: Int;

        let cap_int: Int = Int::from(cap);
        for _ in 0..result.iterations {
            b = 2 * &r / &cap_int;
            r = (2 * &r) % &cap_int;
            proof =
                proof.pow_mod(&Int::from(2), &self.rsa_mod) * self.seed.pow_mod(&b, &self.rsa_mod);
            proof %= &self.rsa_mod;
        }

        VDFProof {
            rsa_mod: self.rsa_mod.clone(),
            seed: self.seed.clone(),
            output: result,
            cap,
            proof,
        }
    }

    /// A worker that does the actual calculation in a VDF. Returns a VDFProof based on initial
    /// parameters in the VDF.
    pub fn run_vdf_worker(self) -> (Sender<u64>, Receiver<Result<VDFProof, InvalidCapError>>) {
        let (tx, rx) = channel();
        let (res_channel, receiver) = channel();

        thread::spawn(move || {
            let mut result = self.seed.clone();
            let mut iterations: u128 = 0;
            loop {
                result = result.pow_mod(&Int::from(2), &self.rsa_mod);
                iterations += 1;

                if iterations == self.upper_bound {
                    // Upper bound reached, stops iteration and calculates the proof
                    println!("Upper bound of {:?} reached, generating proof.", iterations);

                    // Copy pregenerated cap
                    let mut self_cap: u64 = self.cap;

                    // Check if default, check for primality if else
                    if self_cap == 0 {
                        self_cap = util::get_prime();
                    } else if !is_prime(self_cap) {
                        if res_channel.send(Err(InvalidCapError)).is_err() {
                            println!(
                                "Self-generated cap was not a prime! Check the implementation!"
                            );
                        }
                        break;
                    }

                    // Generate the VDF proof
                    let proof = self.generate_proof(VDFResult { result, iterations }, self_cap);

                    // Send proof to caller
                    if res_channel.send(Ok(proof)).is_err() {
                        println!("Failed to send the proof to caller!");
                    }
                    break;
                } else {
                    // Try receiving a cap from caller on each iteration
                    let cap = rx.try_recv();

                    match cap {
                        Ok(cap) => {
                            // Cap received
                            println!("Received the cap {:?}, generating proof.", cap);

                            // Check for primality
                            if !is_prime(cap) {
                                // Generate proof on given cap
                                let proof =
                                    self.generate_proof(VDFResult { result, iterations }, cap);

                                // Send proof to caller
                                if res_channel.send(Ok(proof)).is_err() {
                                    println!("Failed to send the proof to caller!");
                                }
                            } else {
                                // Received cap was not a prime, send error to caller
                                if res_channel.send(Err(InvalidCapError)).is_err() {
                                    println!("Received cap was not a prime!");
                                }
                            }
                            break;
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }
            }
        });

        (tx, receiver)
    }
}
