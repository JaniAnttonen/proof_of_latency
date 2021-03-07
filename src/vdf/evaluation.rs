use crossbeam::channel::unbounded;
use crossbeam::channel::{Receiver, Sender};
use ramp::Int;
use ramp_primes::Generator;
use ramp_primes::Verification;
use std::cmp::Ordering;
use std::time::Instant;
use std::{thread, time};

use crate::vdf;

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

/// VDF is an options struct for calculating VDFProofs
#[derive(Debug, Clone)]
pub struct VDF {
    pub modulus: Int,
    pub generator: Int,
    pub upper_bound: u32,
    pub cap: Int,
    pub result: VDFResult,
    two: Int,
    pub proof_type: vdf::proof::ProofType,
    proof_nudger: Option<Sender<bool>>,
    proof_receiver: Option<Receiver<vdf::proof::VDFProof>>,
}

impl Iterator for VDF {
    type Item = VDFResult;
    fn next(&mut self) -> Option<VDFResult> {
        if self.result.iterations < self.upper_bound {
            self.result.iterations += 1;
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
    worker_sender: &Sender<Result<vdf::proof::VDFProof, vdf::InvalidCapError>>,
) {
    let proof = vdf::proof::VDFProof::new(
        modulus,
        generator,
        result,
        cap,
        &vdf::proof::ProofType::Sequential,
    )
    .calculate();

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
    pub fn new(
        modulus: Int,
        generator: Int,
        upper_bound: u32,
        proof_type: vdf::proof::ProofType,
    ) -> Self {
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
            proof_type,
            proof_nudger: None,
            proof_receiver: None,
        }
    }

    /// Add a precomputed cap to the VDF
    pub fn with_cap(mut self, cap: Int) -> Self {
        let (proof_nudger, proof_receiver): (
            Option<Sender<bool>>,
            Option<Receiver<vdf::proof::VDFProof>>,
        ) = match self.proof_type {
            vdf::proof::ProofType::Sequential => (None, None),
            vdf::proof::ProofType::Parallel => {
                if self.cap.gt(&Int::zero()) {
                    let mut proof = vdf::proof::VDFProof::new(
                        &self.modulus,
                        &self.generator,
                        &self.result,
                        &self.cap,
                        &self.proof_type,
                    );
                    let (nudger, receiver) = proof.calculate_parallel();
                    (Some(nudger), Some(receiver))
                } else {
                    (None, None)
                }
            }
        };
        self.proof_nudger = proof_nudger;
        self.proof_receiver = proof_receiver;
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
    ) -> (
        Sender<Int>,
        Receiver<Result<vdf::proof::VDFProof, vdf::InvalidCapError>>,
    ) {
        let (caller_sender, worker_receiver): (Sender<Int>, Receiver<Int>) =
            unbounded();
        let (worker_sender, caller_receiver) = unbounded();

        let timer = Instant::now();
        thread::spawn(move || loop {
            if let Some(nudger) = self.proof_nudger.as_ref() {
                if nudger.send(true).is_err() {
                    break;
                }
            }

            match self.next() {
                None => {
                    // Upper bound reached, stops iteration
                    // and calculates the proof
                    debug!(
                        "Upper bound of {:?} reached in {:?} milliseconds, generating proof.",
                        self.result.iterations, timer.elapsed().as_millis()
                    );

                    // Copy pregenerated cap
                    let mut self_cap: Int = self.cap.clone();

                    // Check if default, check for primality if else
                    if self_cap == Int::zero() {
                        self_cap = Generator::new_safe_prime(128);
                        debug!("Cap generated: {:?}", self_cap);
                    } else if !self.validate_cap(&self_cap) {
                        if worker_sender
                            .send(Err(vdf::InvalidCapError))
                            .is_err()
                        {
                            error!("Cap not correct!");
                        }
                        break;
                    }

                    match self.proof_receiver {
                        None => calculate_and_send_proof(
                            &self.modulus,
                            &self.generator,
                            &self.result,
                            &self_cap,
                            &worker_sender,
                        ),
                        Some(receiver) => {
                            match receiver.recv() {
                                Ok(proof) => {
                                    if worker_sender.send(Ok(proof)).is_err() {
                                        error!("Couldn't send proof to worker listener!");
                                    }
                                }
                                Err(_) => {
                                    error!("Error with parallel proof calculation!");
                                }
                            }
                        }
                    }

                    break;
                }
                Some(result) => {
                    self.result = result;
                    // Try receiving a cap from the other participant on
                    // each iteration
                    if let Ok(cap) = worker_receiver.try_recv() {
                        // Cap received
                        debug!("Received the cap {:?} after {:?} milliseconds, generating proof.", cap, timer.elapsed().as_millis());

                        // Check for primality
                        if self.validate_cap(&cap) {
                            match self.proof_receiver {
                                None => calculate_and_send_proof(
                                    &self.modulus,
                                    &self.generator,
                                    &self.result,
                                    &cap,
                                    &worker_sender,
                                ),
                                Some(receiver) => match receiver.recv() {
                                    Ok(proof) => {
                                        if worker_sender
                                            .send(Ok(proof))
                                            .is_err()
                                        {
                                            error!("Couldn't send proof to worker listener!");
                                        }
                                    }
                                    Err(_) => {
                                        error!("Error with parallel proof calculation!");
                                    }
                                },
                            }
                        } else {
                            error!("Received cap was not a prime!");
                            // Received cap was not a prime, send error to
                            // caller
                            if worker_sender
                                .send(Err(vdf::InvalidCapError))
                                .is_err()
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
