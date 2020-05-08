use std::sync::mpsc::{Sender, channel, Receiver};
use std::{thread, time};
use std::error::Error;
use std::fmt;
use ramp::Int;

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

pub struct VDFResult {
    result: Int,
    iterations: u128,
}

pub struct VDFProof {
    rsa_mod: Int,
    seed: Int,
    output: VDFResult,
    cap: u128,
    proof: Int,
}
    
pub struct ProofOfLatency {
    rsa_mod: Int,
    seed: Int,
    upper_bound: u128, 
}

impl VDFProof {
    pub fn verify(&self) -> bool {
        let cap_int: Int = Int::from(self.cap);
        // Check first that the result isn't larger than the RSA base
        if self.proof > self.rsa_mod {
            return false;
        } 
        let r = util::pow_mod(2, self.output.iterations, self.cap);
        self.output.result == (self.proof.pow_mod(&Int::from(cap_int), &self.rsa_mod) * self.seed.pow_mod(&Int::from(r), &self.rsa_mod)) % &self.rsa_mod
    }
}

impl ProofOfLatency {
    fn generate_proof(&self, result: VDFResult, cap: u128) -> VDFProof {
        let mut proof = Int::one();
        let mut r = Int::one();
        let mut b: Int;

        let cap_int: Int = Int::from(cap);
        for _ in 0..result.iterations {
            b = 2 * &r / &cap_int;
            r = (2 * &r) % &cap_int;
            proof = proof.pow_mod(&Int::from(2), &self.rsa_mod) * self.seed.pow_mod(&b, &self.rsa_mod);
            proof %= &self.rsa_mod;
        }

        return VDFProof{rsa_mod: self.rsa_mod.clone(), seed: self.seed.clone(), output: result, cap, proof};
    }

    pub fn run_vdf_worker(self) -> (Sender<u128>, Receiver<Result<VDFProof, InvalidCapError>>) {
        let (tx, rx) = channel();
        let (res_channel, receiver) = channel();

        thread::spawn(move || {
            let mut result = self.seed.clone();
            let mut iterations: u128 = 0;
            loop {
                result = result.pow_mod(&Int::from(2), &self.rsa_mod);
                iterations += 1;

                if iterations == self.upper_bound {
                    println!("Cap wasn't received until upper bound was reached, generating proof of already calculated work");
                    let self_cap = get_prime(); 
                    let proof = self.generate_proof(VDFResult{result, iterations}, self_cap);
                    res_channel.send(Ok(proof));
                    break;
                }

                let cap = rx.try_recv();
                match cap {
                    Ok(cap) => {
                        println!("Received the cap for the VDF! Generating proof with {:?}", cap);
                        let proof = self.generate_proof(VDFResult{result, iterations}, cap);
                        res_channel.send(Ok(proof));
                        break;
                    },
                    Err(_) => {
                        continue;
                    }
                }
            }
        });

        (tx, receiver)
    }
}

