use crate::rsa::{UnmatchingModulusError, RSA};
use crate::vdf::util::hash_to_prime;
use ramp::Int;

#[derive(Debug, Clone)]
pub struct ProofOfExponentiation {
    previous: RSA,
    exponent: Int,
    current: RSA,
    proof: RSA,
}

impl ProofOfExponentiation {
    pub fn new(previous: RSA, exponent: Int, current: RSA) -> Self {
        let unique_prime = hash_to_prime(
            &(&previous.as_int() + &exponent + &current.as_int())
                .to_str_radix(10, false),
            &current.get_modulus(),
        );
        let witness = &exponent / &unique_prime;
        let proof = previous.pow(&witness);
        Self {
            previous,
            exponent,
            current,
            proof,
        }
    }
    pub fn verify(self) -> bool {
        let unique_prime = hash_to_prime(
            &(&self.previous.as_int()
                + &self.exponent
                + &self.current.as_int())
                .to_str_radix(10, false),
            &self.current.get_modulus(),
        );
        let r = &self.exponent % &unique_prime;
        let w = self.proof.pow(&unique_prime) * self.previous.pow(&r);
        w == self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::RSA;
    use proptest::prelude::*;
    use ramp::Int;

    proptest! {
        #[test]
        fn poe_proptest(m in 0u16..u16::MAX, g in 0u16..u16::MAX, e in 0u16..u16::MAX) {
            let modulus = Int::from(m);
            let generator =
                &RSA::new(Int::from(g), modulus.clone());
            let exponent = Int::from(e);
            let current = RSA::new(generator.pow(&exponent).as_int(), modulus.clone());
            let proof =
                ProofOfExponentiation::new(generator.clone(), exponent, current);
            assert!(proof.verify());
        }
    }

    #[test]
    fn poe_test() {
        let modulus = &Int::from_str_radix("133769", 10).unwrap();
        let generator = &RSA::new(
            Int::from_str_radix("120420", 10).unwrap(),
            modulus.clone(),
        );
        let exponent = Int::from_str_radix("47", 10).unwrap();
        let current =
            RSA::new(generator.pow(&exponent).as_int(), modulus.clone());
        let proof =
            ProofOfExponentiation::new(generator.clone(), exponent, current);
        assert!(proof.verify());
    }
}
