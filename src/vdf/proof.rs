use crate::vdf::evaluation;
use crossbeam::channel::unbounded;
use crossbeam::channel::{Receiver, Sender};
use lazy_static::lazy_static;
use ramp::Int;
use rayon::prelude::*;
use rkyv::{Archive, Deserialize, Serialize};
use std::convert::TryFrom;
use std::thread;
use std::time::Instant;

lazy_static! {
    static ref TWO: Int = Int::from_str_radix("2", 10).unwrap();
}

#[derive(
    Archive, Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq,
)]
pub struct DeserializableVDFProof {
    pub modulus: String,
    pub generator: String,
    pub output: evaluation::DeserializableVDFResult,
    pub cap: String,
    pub pi: String,
    pub proof_type: ProofType,
}

impl DeserializableVDFProof {
    pub fn serialize(&self) -> VDFProof {
        VDFProof {
            modulus: Int::from_str_radix(&self.modulus, 10).unwrap(),
            generator: Int::from_str_radix(&self.generator, 10).unwrap(),
            output: self.output.serialize(),
            cap: Int::from_str_radix(&self.cap, 10).unwrap(),
            pi: Int::from_str_radix(&self.pi, 10).unwrap(),
            proof_type: self.proof_type.clone(),
        }
    }
    pub fn verify(&self) -> bool {
        self.serialize().verify()
    }
}

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

#[derive(Archive, Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
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
        proof_type: &ProofType,
    ) -> Self {
        Self {
            modulus: modulus.clone(),
            generator: generator.clone(),
            output: result.clone(),
            cap: cap.clone(),
            pi: Int::zero(),
            proof_type: proof_type.clone(),
        }
    }

    pub fn deserialize(&self) -> DeserializableVDFProof {
        DeserializableVDFProof {
            modulus: self.modulus.to_str_radix(10, false),
            generator: self.generator.to_str_radix(10, false),
            output: self.output.deserialize(),
            cap: self.cap.to_str_radix(10, false),
            pi: self.pi.to_str_radix(10, false),
            proof_type: self.proof_type.clone(),
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
            let mut r: Int = Int::from(1);
            let mut b: Int;
            let modulus: &Int = &self_clone.modulus;
            let generator: &Int = &self_clone.generator;
            let cap: &Int = &self_clone.cap;
            let mut pi = Int::from(1);

            while let Ok(nudge) = nudge_listener.recv() {
                match nudge {
                    true => {
                        // calculate next proof
                        b = &*TWO * &r / cap;
                        pi = pi.pow_mod(&*TWO, modulus)
                            * generator.pow_mod(&b, modulus)
                            % modulus;
                        r = r * &*TWO % cap;
                        continue;
                    }
                    false => {
                        break;
                    }
                }
            }

            debug!("Nudger received false, sending current proof");
            self_clone.pi = pi;
            if sender.send(self_clone).is_err() {
                error!("Couldn't send parallelly calculated VDF proof to the evaluator!");
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
                        let cap = &self.cap;
                        let mut r: Vec<Int> = Vec::with_capacity(iter);
                        r.push(Int::from(1));

                        // Calculate r values
                        (0..iter)
                            .skip(1)
                            .for_each(|i| r.push(&r[i - 1] * &*TWO % cap));

                        // Construct a parallel iterator for values of b
                        let b = r.into_par_iter().map(|r| &*TWO * r / cap);
                        let pi_y: Vec<Int> = b
                            .into_par_iter()
                            .map(|b| self.generator.pow_mod(&b, &self.modulus))
                            .collect();

                        debug!(
                            "Calculating all pi_y has taken {:?} milliseconds",
                            timer.elapsed().as_millis()
                        );

                        let pi_last = |mut pi: Int| {
                            for y in pi_y {
                                pi = pi.pow_mod(&*TWO, &self.modulus) * y
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
        let r = TWO.pow_mod(&Int::from(self.output.iterations), &self.cap);
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
