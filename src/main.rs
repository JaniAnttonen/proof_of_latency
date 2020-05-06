use std::str::FromStr;
use std::sync::mpsc::{Sender, channel, Receiver};
use std::{thread, time};
use std::error::Error;
use std::fmt;
use ramp::Int;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use primality::{is_prime, pow_mod};

pub const RSA_2048: &str = "135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563";


// rsa_mod = N, seed = g
fn main() {
    // This parameter just needs to provide a group of unknown order, thus a large RSA number is
    // required. N in the paper.
    let rsa_mod = Int::from_str(RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let seed = hash(&format!("Beep boop beep"), &rsa_mod);

    let proof_of_latency = ProofOfLatency{rsa_mod, seed, upper_bound: 6537892};
    
    // OH YES, it's a random prime that gets used in the proof and verification. This has to be
    // sent from another peer and this actually is the thing that ends the calculation and
    // facilitates the proof.
    let cap = get_prime();

    // Run the VDF, returning connection channels to push to and receive data from
    let (vdf_worker, worker_output) = proof_of_latency.run_vdf_worker();

    // Sleep for 300 milliseconds to simulate latency overseas
    let sleep_time = time::Duration::from_millis(300);
    thread::sleep(sleep_time);

    // Send received signature from the other peer, "capping off" the 
    vdf_worker.send(cap).unwrap();

    // Wait for response from VDF worker
    let response = worker_output.recv().unwrap().unwrap();
   
    println!("VDF ran for {:?} times!", response.output.iterations);
    println!("The output being {:?}", response.output.result);

    // Verify the proof
    let is_ok = response.verify();

    match is_ok {
        true => println!("The VDF is correct!"),
        false => println!("The VDF couldn't be verified!"),
    }
}

#[derive(Debug)]
struct InvalidCapError;

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

struct VDFResult {
    result: Int,
    iterations: u128,
}

struct VDFProof {
    rsa_mod: Int,
    seed: Int,
    output: VDFResult,
    cap: u128,
    proof: Int,
}
    
struct ProofOfLatency {
    rsa_mod: Int,
    seed: Int,
    upper_bound: u128, 
}

impl VDFProof {
    fn verify(&self) -> bool {
        let cap_int: Int = Int::from(self.cap);
        // Check first that the result isn't larger than the RSA base
        if self.proof > self.rsa_mod {
            return false;
        } 
        let r = pow_mod(2, self.output.iterations, self.cap);
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

    fn run_vdf_worker(self) -> (Sender<u128>, Receiver<Result<VDFProof, InvalidCapError>>) {
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
                    Err(cap) => {
                        println!("Whoops, i panicked, because {:?}", cap);
                        res_channel.send(Err(InvalidCapError));
                        break;
                    }
                }
            }
        });

        (tx, receiver)
    }
}


pub mod primality;

pub fn hash(s: &str, rsa_mod: &Int) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * rsa_mod.bit_length() / 512 + 1) {
        let mut hasher = Sha3_512::new();
        hasher.input(format!("{}{}", s, i).as_bytes());
        let arr = hasher.result();
        for x in arr.into_iter() {
            ans = (ans << 8) + Int::from(x);
        }
    }
    ans % rsa_mod
}

pub fn get_prime() -> u128 {
    let mut rng = rand::thread_rng();
    let mut l: u128;
    loop {
        l = rng.next_u64().into();
        println!("{:?}", l);
        if is_prime(l.into(), 10) {
            break;
        }
    }
    l
}

