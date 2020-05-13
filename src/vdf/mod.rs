use primal::is_prime;
use ramp::Int;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time};

pub mod util;

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

#[derive(Debug)]
pub struct VDFResult {
    pub result: Int,
    pub iterations: u128,
}

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

#[derive(Debug)]
pub struct VDFProof {
    pub rsa_mod: Int,
    pub seed: Int,
    pub output: VDFResult,
    pub cap: u64,
    pub proof: Int,
}

impl VDFProof {
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
    pub fn abs_difference(&self, other: VDFProof) -> u128 {
        let ours_is_larger = self.output > other.output;
        if ours_is_larger {
            self.output.iterations - other.output.iterations
        } else {
            other.output.iterations - self.output.iterations
        }
    }
}

#[derive(Debug, Clone)]
pub struct VDF {
    pub rsa_mod: Int,
    pub seed: Int,
    pub upper_bound: u128,
    pub cap: u64,
}

impl VDF {
    pub fn new(rsa_mod: Int, seed: Int) -> VDF {
        VDF {
            rsa_mod,
            seed,
            upper_bound: 0,
            cap: 0,
        }
    }
    pub fn estimate_upper_bound(self, ms_bound: u64) -> VDF {
        let cap: u64 = util::get_prime();
        let (vdf_worker, worker_output) = self.clone().run_vdf_worker();

        let sleep_time = time::Duration::from_millis(ms_bound);
        thread::sleep(sleep_time);
        vdf_worker.send(cap).unwrap();
        let response = worker_output.recv().unwrap().unwrap();

        let mut vdf: VDF = self;
        vdf.upper_bound = response.output.iterations;
        vdf
    }
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
                    println!("Cap wasn't received until upper bound of {:?} was reached, generating proof of already calculated work", iterations);

                    // Check if the cap is prime
                    let mut self_cap: u64 = self.cap;
                    if self_cap == 0 {
                        self_cap = util::get_prime();
                    } else if !is_prime(self_cap) {
                        println!("{:?}", self_cap);
                        res_channel.send(Err(InvalidCapError));
                        break;
                    }
                    println!("FSAFSHA");
                    println!("{:?}", self_cap);
                    let proof = self.generate_proof(VDFResult { result, iterations }, self_cap);
                    res_channel.send(Ok(proof));
                    break;
                }

                let cap = rx.try_recv();

                match cap {
                    Ok(cap) => {
                        println!(
                            "Received the cap for the VDF! Generating proof with {:?}",
                            cap
                        );
                        let proof = self.generate_proof(VDFResult { result, iterations }, cap);
                        res_channel.send(Ok(proof));
                        break;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        });

        (tx, receiver)
    }
}
