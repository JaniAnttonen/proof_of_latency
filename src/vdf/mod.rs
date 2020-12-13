use ramp::Int;
use ramp_primes::Generator;
use ramp_primes::Verification;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{thread, time};

pub mod util;

/// InvalidCapError is returned when a non-prime cap is received in the
/// vdf_worker
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
#[derive(Debug, Clone, Default)]
pub struct VDFResult {
    pub result: Int,
    pub iterations: u32,
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
#[derive(Debug, Clone, Default)]
pub struct VDFProof {
    pub modulus: Int,
    pub base: Int,
    pub output: VDFResult,
    pub cap: Int,
    pub proof: Int,
}

impl PartialEq for VDFProof {
    fn eq(&self, other: &Self) -> bool {
        self.output == other.output
            && self.proof == other.proof
            && self.modulus == other.modulus
            && self.base == other.base
            && self.cap == other.cap
    }
}

impl VDFProof {
    /// Returns a VDFProof based on a VDFResult
    pub fn new(
        modulus: &Int,
        base: &Int,
        result: &VDFResult,
        cap: &Int,
    ) -> Self {
        let mut proof = Int::one();
        let mut r = Int::one();
        let mut b: Int;
        let two: &Int = &Int::from(2);

        for _ in 0..result.iterations {
            b = two * &r / cap;
            r = (two * &r) % cap;
            proof = proof.pow_mod(two, modulus) * base.pow_mod(&b, modulus);
            proof %= modulus;
        }

        debug!(
            "Proof generated, final state: r: {:?}, proof: {:?}",
            r, proof
        );

        VDFProof {
            modulus: modulus.clone(),
            base: base.clone(),
            output: result.clone(),
            cap: cap.clone(),
            proof,
        }
    }

    /// A public function that a receiver can use to verify the correctness of
    /// the VDFProof
    pub fn verify(&self) -> bool {
        // Check first that the result isn't larger than the RSA base
        if self.proof > self.modulus {
            return false;
        }
        //self.validate();
        let r =
            Int::from(2).pow_mod(&Int::from(self.output.iterations), &self.cap);
        self.output.result
            == (self.proof.pow_mod(&self.cap, &self.modulus)
                * self.base.pow_mod(&r, &self.modulus))
                % &self.modulus
    }

    pub fn validate(&self) -> bool {
        self.modulus.gcd(&self.base) == 1 && self.modulus.gcd(&self.cap) == 1
    }

    /// Helper function for calculating the difference in iterations between two
    /// VDFProofs
    pub fn abs_difference(&self, other: &VDFProof) -> u32 {
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
    pub base: Int,
    pub upper_bound: u32,
    pub cap: Int,
}

pub fn iter_vdf(result: Int, modulus: &Int, to_power: &Int) -> Int {
    result.pow_mod(to_power, modulus)
}

impl VDF {
    /// VDF builder with default options. Can be chained with
    /// estimate_upper_bound
    pub fn new(modulus: Int, base: Int, upper_bound: u32) -> Self {
        Self {
            modulus,
            base,
            upper_bound,
            cap: Int::zero(),
        }
    }

    /// Add a precomputed cap to the VDF
    pub fn with_cap(mut self, cap: Int) -> Self {
        self.cap = cap;
        self
    }

    /// Validates that cap is not below upper bound and is prime.
    fn validate_cap(&self, cap: &Int, upper_bound: u32) -> bool {
        Verification::verify_prime(cap.clone())
            && cap.bit_length() < upper_bound
    }

    /// Estimates the maximum number of sequential calculations that can fit in
    /// the fiven ms_bound millisecond threshold.
    pub fn estimate_upper_bound(mut self, ms_bound: u64) -> Self {
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
        self
    }

    /// A worker that does the actual calculation in a VDF. Returns a VDFProof
    /// based on initial parameters in the VDF.
    pub fn run_vdf_worker(
        self,
    ) -> (Sender<Int>, Receiver<Result<VDFProof, InvalidCapError>>) {
        let (caller_sender, worker_receiver): (Sender<Int>, Receiver<Int>) =
            channel();
        let (worker_sender, caller_receiver) = channel();

        thread::spawn(move || {
            let mut result = self.base.clone();
            let two = Int::from(2);
            let mut iterations: u32 = 0;
            loop {
                result = iter_vdf(result, &self.modulus, &two);
                iterations += 1;

                if iterations == self.upper_bound || iterations == u32::MAX {
                    // Upper bound reached, stops iteration and calculates the
                    // proof
                    debug!(
                        "Upper bound of {:?} reached, generating proof.",
                        iterations
                    );

                    // Copy pregenerated cap
                    let mut self_cap: Int = self.cap.clone();

                    // Check if default, check for primality if else
                    if self_cap == 0 {
                        self_cap = Generator::new_safe_prime(128);
                        debug!("Cap generated: {:?}", self_cap);
                    } else if !self.validate_cap(&self_cap, iterations) {
                        if worker_sender.send(Err(InvalidCapError)).is_err() {
                            error!("Predefined cap was not a prime or its length is below upper_bound! Check the implementation!");
                        }
                        break;
                    }

                    // Generate the VDF proof
                    let vdf_result = VDFResult { result, iterations };
                    let proof = VDFProof::new(
                        &self.modulus,
                        &self.base,
                        &vdf_result,
                        &self_cap,
                    );
                    debug!("Proof generated! {:?}", proof);

                    // Send proof to caller
                    if worker_sender.send(Ok(proof)).is_err() {
                        error!("Failed to send the proof to caller!");
                    }

                    break;
                } else {
                    // Try receiving a cap from the other participant on each
                    // iteration
                    if let Ok(cap) = worker_receiver.try_recv() {
                        // Cap received
                        debug!("Received the cap {:?}, generating proof.", cap);

                        // Check for primality
                        if self.validate_cap(&cap, iterations) {
                            // Generate the VDF proof
                            let vdf_result = VDFResult { result, iterations };
                            let proof = VDFProof::new(
                                &self.modulus,
                                &self.base,
                                &vdf_result,
                                &cap,
                            );
                            debug!("Proof generated! {:?}", proof);

                            // Send proof to caller
                            if worker_sender.send(Ok(proof)).is_err() {
                                error!("Failed to send the proof to caller!");
                            }
                        } else {
                            error!("Received cap was not a prime!");
                            // Received cap was not a prime, send error to
                            // caller
                            if worker_sender.send(Err(InvalidCapError)).is_err()
                            {
                                error!(
                                    "Error sending InvalidCapError to caller!"
                                );
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
    use proptest::prelude::*;
    use std::str::FromStr;

    const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

    #[test]
    fn is_deterministic() {
        let modulus = Int::from_str("91").unwrap();
        let prime = Generator::new_safe_prime(128);
        let root_hashed = util::hash(&prime.to_string(), &modulus);

        // Create two VDFs with same inputs to check if they end up in the same
        // result
        let cap = Int::from(7);
        let verifiers_vdf = VDF::new(modulus.clone(), root_hashed.clone(), 32)
            .with_cap(cap.clone());
        let provers_vdf = VDF::new(modulus, root_hashed, 32).with_cap(cap);

        let (_, receiver) = verifiers_vdf.run_vdf_worker();
        let (_, receiver2) = provers_vdf.run_vdf_worker();

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                println!("{:?}", proof);
                assert!(proof.verify());

                let our_proof = proof;

                if let Ok(res2) = receiver2.recv() {
                    if let Ok(proof2) = res2 {
                        assert!(proof2.verify());
                        let their_proof = proof2;
                        assert_eq!(our_proof, their_proof);
                    }
                }
            }
        }
    }

    #[test]
    fn vdf_iter_should_be_correct() {
        let modulus = Int::from(17);
        let base = Int::from(11);
        let two = Int::from(2);
        let cap = Int::from(7);
        let mut result = base.clone();

        result = iter_vdf(result, &modulus, &two);
        assert_eq!(result, two);

        result = iter_vdf(result, &modulus, &two);
        assert_eq!(result, Int::from(4));

        result = iter_vdf(result, &modulus, &two);
        assert_eq!(result, Int::from(16));

        // result = iter_vdf(result, &modulus, &two);
        // assert_eq!(result, Int::from(1));

        let proof = VDFProof::new(
            &modulus,
            &base,
            &VDFResult {
                iterations: 3,
                result,
            },
            &cap,
        );
        println!("{:?}", proof);
        assert!(proof.verify());
    }

    #[test]
    fn proof_generation_should_be_same_between_predetermined_and_received_input(
    ) {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let hashablings2 = &"ghsalkghsakhgaligheliah<lifehf esipf";
        let root_hashed = util::hash(&hashablings2.to_string(), &modulus);

        let cap = Generator::new_safe_prime(16);
        let vdf = VDF::new(modulus.clone(), root_hashed.clone(), u32::MAX);

        let (capper, receiver) = vdf.run_vdf_worker();

        thread::sleep(time::Duration::from_millis(10));

        let mut first_proof = VDFProof::default();

        let cap_error = capper.send(cap.clone()).is_err();
        assert!(!cap_error);

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                assert!(proof.proof != 1);
                first_proof = proof;
            }
        }

        let vdf2 =
            VDF::new(modulus, root_hashed, first_proof.output.iterations)
                .with_cap(first_proof.cap.clone());

        let (_, receiver2) = vdf2.run_vdf_worker();

        if let Ok(res2) = receiver2.recv() {
            if let Ok(proof2) = res2 {
                assert_eq!(proof2, first_proof);
                //assert!(first_proof.verify());
                //assert!(proof2.verify());
                println!("Proof1: {:?}, Proof2: {:?}", first_proof, proof2);
            }
        }
    }

    // proptest! {
    //     #[test]
    //     fn works_with_any_prime_integer_as_cap(t in 1u32..32) {
    //         let cap_bit_length: usize = 16;
    //         let cap_bit_length_u32: u32 = 16;
    //         prop_assume!(t > cap_bit_length_u32);

    //         let rsa_int: Int = Int::from_str(RSA_2048).unwrap();
    //         let root_hashed =
    // util::hash(&Generator::new_safe_prime(8).to_string(), &rsa_int);
    //         let cap: Int = Generator::new_safe_prime(cap_bit_length);

    //         let vdf = VDF::new(rsa_int, root_hashed, t).with_cap(cap);
    //         let (_, receiver) = vdf.run_vdf_worker();

    //         if let Ok(res) = receiver.recv() {
    //             if let Ok(proof) = res {
    //                 println!("Proof {:?}", proof);
    //                 assert!(proof.verify());
    //             }
    //         }
    //     }
    // }
}
