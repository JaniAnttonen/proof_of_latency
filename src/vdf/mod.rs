use ramp::Int;
use ramp_primes::Generator;
use ramp_primes::Verification;
use rayon::iter::ParallelBridge;
use rayon::prelude::ParallelIterator;
// use serde::ser::SerializeStruct;
// use serde::{Deserialize, Serialize, Serializer};
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

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ProofIterable {
    pub pi: Int,
    pub r: Int,
    pub b: Int,
    pub i: u32,
}

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VDFProof {
    pub modulus: Int,
    pub generator: Int,
    pub output: VDFResult,
    pub cap: Int,
    pub iterable: ProofIterable,
    two: Int,
}

impl Iterator for VDFProof {
    type Item = ProofIterable;
    fn next(&mut self) -> Option<ProofIterable> {
        self.iterable.b = &self.two * &self.iterable.r / &self.cap;
        self.iterable.r = (&self.two * &self.iterable.r) % &self.cap;
        self.iterable.pi = self.iterable.pi.pow_mod(&self.two, &self.modulus)
            * self.generator.pow_mod(&self.iterable.b, &self.modulus);
        self.iterable.pi %= &self.modulus;
        self.iterable.i += 1;
        if self.iterable.i < self.output.iterations {
            Some(self.iterable.clone())
        } else {
            None
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.output.iterations as usize > usize::MAX {
            (0, None)
        } else {
            (0, Some(self.output.iterations as usize))
        }
    }
}

impl VDFProof {
    /// Returns a VDFProof based on a VDFResult
    pub fn new(
        modulus: &Int,
        generator: &Int,
        result: &VDFResult,
        cap: &Int,
    ) -> Self {
        VDFProof {
            modulus: modulus.clone(),
            generator: generator.clone(),
            output: result.clone(),
            cap: cap.clone(),
            iterable: ProofIterable {
                pi: Int::from(1),
                r: Int::from(1),
                b: Int::zero(),
                i: 0,
            },
            two: Int::from(2),
        }
    }

    // pub fn to_iter(&self) -> rayon::iter::IterBridge<VDFProof> {
    //     self.clone().into_iter()
    // }

    pub fn calculate(&mut self) -> Option<VDFProof> {
        match self.last() {
            Some(proof) => {
                self.iterable = proof;
                Some(self.clone())
            }
            None => None,
        }
    }

    /// A public function that a receiver can use to verify the correctness of
    /// the VDFProof
    pub fn verify(&self) -> bool {
        // Check first that the proof belongs in the RSA group
        if self.iterable.pi > self.modulus {
            return false;
        }
        let r =
            Int::from(2).pow_mod(&Int::from(self.output.iterations), &self.cap);
        self.output.result
            == (self.iterable.pi.pow_mod(&self.cap, &self.modulus)
                * self.generator.pow_mod(&r, &self.modulus))
                % &self.modulus
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
    pub generator: Int,
    pub upper_bound: u32,
    pub cap: Int,
    pub result: VDFResult,
    two: Int,
}

impl Iterator for VDF {
    type Item = VDFResult;
    fn next(&mut self) -> Option<VDFResult> {
        self.result.iterations += 1;
        if self.result.iterations <= self.upper_bound {
            self.result.result =
                self.result.result.pow_mod(&self.two, &self.modulus);
            Some(self.result.clone())
        } else {
            None
        }
    }
}

fn calculate_and_send_proof(
    modulus: &Int,
    generator: &Int,
    result: &VDFResult,
    cap: &Int,
    worker_sender: &Sender<Result<VDFProof, InvalidCapError>>,
) {
    let proof = VDFProof::new(modulus, generator, result, cap).calculate();

    match proof {
        None => error!("Failed to generate a proof!"),
        Some(success) => {
            debug!("Proof generated! {:#?}", success);

            // Send proof to caller
            if worker_sender.send(Ok(success)).is_err() {
                error!("Failed to send the proof to caller!");
            }
        }
    }
}

impl VDF {
    /// VDF builder with default options. Can be chained with
    /// estimate_upper_bound
    pub fn new(modulus: Int, generator: Int, upper_bound: u32) -> Self {
        Self {
            modulus,
            generator: generator.clone(),
            upper_bound,
            cap: Int::zero(),
            result: VDFResult {
                result: generator,
                iterations: 0,
            },
            two: Int::from(2),
        }
    }

    /// Add a precomputed cap to the VDF
    pub fn with_cap(mut self, cap: Int) -> Self {
        self.cap = cap;
        self
    }

    /// Validates that cap is prime.
    fn validate_cap(&self, cap: &Int) -> bool {
        Verification::verify_prime(cap.clone())
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
        mut self,
    ) -> (Sender<Int>, Receiver<Result<VDFProof, InvalidCapError>>) {
        let (caller_sender, worker_receiver): (Sender<Int>, Receiver<Int>) =
            channel();
        let (worker_sender, caller_receiver) = channel();

        thread::spawn(move || loop {
            match self.next() {
                None => {
                    // Upper bound reached, stops iteration
                    // and calculates the proof
                    debug!(
                        "Upper bound of {:?} reached, generating proof.",
                        self.result.iterations
                    );

                    // Copy pregenerated cap
                    let mut self_cap: Int = self.cap.clone();

                    // Check if default, check for primality if else
                    if self_cap == Int::zero() {
                        self_cap = Generator::new_safe_prime(128);
                        debug!("Cap generated: {:?}", self_cap);
                    } else if !self.validate_cap(&self_cap) {
                        if worker_sender.send(Err(InvalidCapError)).is_err() {
                            error!("Cap not correct!");
                        }
                        break;
                    }

                    calculate_and_send_proof(
                        &self.modulus,
                        &self.generator,
                        &self.result,
                        &self_cap,
                        &worker_sender,
                    );

                    break;
                }
                Some(result) => {
                    // Try receiving a cap from the other participant on each
                    // iteration
                    if let Ok(cap) = worker_receiver.try_recv() {
                        // Cap received
                        debug!("Received the cap {:?}, generating proof.", cap);

                        // Check for primality
                        if self.validate_cap(&cap) {
                            calculate_and_send_proof(
                                &self.modulus,
                                &self.generator,
                                &result,
                                &cap,
                                &worker_sender,
                            );
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
                println!("{:#?}", proof);
                assert!(proof.verify());

                let our_proof = proof;

                if let Ok(res2) = receiver2.recv() {
                    if let Ok(proof2) = res2 {
                        assert!(proof2.verify());
                        println!("{:#?}", proof2);
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
        let generator = Int::from(11);
        let two = Int::from(2);
        let cap = Int::from(7);
        let mut vdf = VDF::new(modulus, generator, 0);

        vdf.next();
        assert_eq!(vdf.result.result, two);

        vdf.next();
        assert_eq!(vdf.result.result, Int::from(4));

        vdf.next();
        assert_eq!(vdf.result.result, Int::from(16));

        let proof =
            VDFProof::new(&vdf.modulus, &vdf.generator, &vdf.result, &cap);

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

        let cap_error = capper.send(cap).is_err();
        assert!(!cap_error);

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                assert!(proof.iterable.pi != 1);
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
                assert!(first_proof.verify());
                assert!(proof2.verify());
                println!("Proof1: {:#?}, Proof2: {:#?}", first_proof, proof2);
            }
        }
    }
}
