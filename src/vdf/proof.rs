use ramp::Int;

use crate::vdf::evaluation;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ProofIterable {
    pub pi: Int,
    pub r: Int,
    pub b: Int,
    pub i: u32,
}

/// Proof of an already calculated VDF that gets passed around between peers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VDFProof {
    pub modulus: Int,
    pub generator: Int,
    pub output: evaluation::VDFResult,
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
        match self.iterable.i <= self.output.iterations {
            true => Some(self.iterable.clone()),
            false => None,
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
        result: &evaluation::VDFResult,
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
