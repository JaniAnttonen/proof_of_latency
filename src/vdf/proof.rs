use crate::vdf::evaluation;
use crossbeam::channel::unbounded;
use crossbeam::channel::{Receiver, Sender};
use ramp::Int;
use rayon::prelude::*;
use std::convert::TryFrom;
use std::thread;
use std::time::Instant;

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VDFProof {
    pub modulus: Int,
    pub generator: Int,
    pub output: evaluation::VDFResult,
    pub cap: Int,
    pub pi: Int,
    pub proof_type: ProofType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofType {
    Sequential,
    Parallel,
}

impl Default for ProofType {
    fn default() -> Self {
        ProofType::Sequential
    }
}

impl VDFProof {
    /// Returns a VDFProof based on a VDFResult
    pub fn new(
        modulus: &Int,
        generator: &Int,
        result: &evaluation::VDFResult,
        cap: &Int,
        proof_type: ProofType,
    ) -> Self {
        VDFProof {
            modulus: modulus.clone(),
            generator: generator.clone(),
            output: result.clone(),
            cap: cap.clone(),
            pi: Int::zero(),
            proof_type: proof_type,
        }
    }

    /// Parallel proof calculator. This should be nudged in parallel to the
    /// evaluator, in the end generating a proof on a false nudge value. Cap
    /// must be defined before VDF evaluation.
    pub fn calculate_parallel(&mut self) -> (Sender<bool>, Receiver<VDFProof>) {
        let (nudger, nudge_listener): (Sender<bool>, Receiver<bool>) =
            unbounded();
        let (sender, output): (Sender<VDFProof>, Receiver<VDFProof>) =
            unbounded();

        let mut self_clone = self.clone();
        thread::spawn(move || {
            let two = &Int::from(2);
            let cap = &self_clone.cap;
            let mut r = &Int::from(1);
            let mut b: Int;
            let mut pi = Int::from(1);
            loop {
                if let Ok(nudge) = nudge_listener.recv() {
                    match nudge {
                        true => {
                            // calculate next proof
                            r = r * two % cap;
                            b = two * r / cap;
                            pi = pi.pow_mod(two, &self_clone.modulus)
                                * self_clone
                                    .generator
                                    .pow_mod(&b, &self_clone.modulus)
                                % &self_clone.modulus;
                        }
                        false => {
                            self_clone.pi = pi.clone();
                            sender.send(self_clone.clone());
                        }
                    }
                } else {
                    return;
                }
            }
        });

        (nudger, output)
    }

    pub fn calculate(&mut self) -> Option<VDFProof> {
        let timer = Instant::now();
        match usize::try_from(self.output.iterations) {
            Err(_) => {
                error!("Using PoL on a platform with no u32 support!");
                None
            }
            Ok(iter) => {
                match iter {
                    0 => None,
                    _ => {
                        let two = &Int::from(2);
                        let cap = &self.cap;
                        let mut r: Vec<Int> = Vec::with_capacity(iter);
                        r.push(Int::from(1));

                        // Calculate r values
                        (0..iter)
                            .skip(1)
                            .for_each(|i| r.push(&r[i - 1] * two % cap));

                        // Construct a parallel iterator for values of b
                        let b = r.into_par_iter().map(|r| two * r / cap);
                        let pi_y: Vec<Int> = b
                            .into_par_iter()
                            .map(|b| self.generator.pow_mod(&b, &self.modulus))
                            .collect();

                        debug!(
                            "Calculating all pi_y has taken {:?} milliseconds",
                            timer.elapsed().as_millis()
                        );
                        // Up until this point this could be calculated in
                        // parallel to the VDF itself

                        let pi_last = |mut pi: Int| {
                            for y in pi_y {
                                pi = pi.pow_mod(two, &self.modulus) * y
                                    % &self.modulus;
                            }
                            pi
                        };
                        let pi = pi_last(Int::from(1));

                        debug!(
                            "Proof generation took {:?} milliseconds",
                            timer.elapsed().as_millis()
                        );

                        if pi != self.pi {
                            self.pi = pi;
                            Some(self.clone())
                        } else {
                            None
                        }
                    }
                }
            }
        }
    }

    /// A public function that a receiver can use to verify the correctness of
    /// the VDFProof
    pub fn verify(&self) -> bool {
        // Check first that the proof belongs in the RSA group
        if self.pi > self.modulus {
            return false;
        }
        let r =
            Int::from(2).pow_mod(&Int::from(self.output.iterations), &self.cap);
        self.output.result
            == (self.pi.pow_mod(&self.cap, &self.modulus)
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
