use crate::vdf::evaluation;
use ramp::Int;
use rayon::prelude::*;
use std::convert::TryFrom;

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VDFProof {
    pub modulus: Int,
    pub generator: Int,
    pub output: evaluation::VDFResult,
    pub cap: Int,
    pub pi: Int,
}

impl VDFProof {
    /// Returns a VDFProof based on a VDFResult
    pub fn new(
        modulus: &Int,
        generator: &Int,
        result: &evaluation::VDFResult,
        cap: &Int,
    ) -> Self {
        // TODO: Add functional calculation here, no need to store the _final
        // state_ in the proof itself (r, b, i, two)
        // Create a separate function for iterating over vec![pi: Int, r: Int,
        // b: Int], use rayon's enumerate() Or even vec![pi: Int, rb:
        // vec![r: Int, b: Int]]?

        VDFProof {
            modulus: modulus.clone(),
            generator: generator.clone(),
            output: result.clone(),
            cap: cap.clone(),
            pi: Int::zero(),
        }
    }

    pub fn calculate(&mut self) -> Option<VDFProof> {
        let iterations = usize::try_from(self.output.iterations).unwrap();
        match iterations {
            0 => None,
            _ => {
                let two = &Int::from(2);
                let cap = &self.cap;
                let mut r: Vec<Int> = Vec::with_capacity(iterations);
                r.push(Int::from(1));

                // Calculate r values
                (0..iterations)
                    .skip(1)
                    .for_each(|i| r.push(&r[i - 1] * two % cap));

                // Construct a parallel iterator for values of b
                let b = r.into_par_iter().map(|r| two * r / cap);
                let pi_y: Vec<Int> = b
                    .map(|b| self.generator.pow_mod(&b, &self.modulus))
                    .collect();

                let pi_last = |mut pi: Int| {
                    for y in pi_y {
                        pi = pi.pow_mod(two, &self.modulus) * y % &self.modulus;
                    }
                    pi
                };
                let pi = pi_last(Int::from(1));

                if pi != self.pi {
                    self.pi = pi;
                    Some(self.clone())
                } else {
                    None
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
