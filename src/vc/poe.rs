use crate::vdf::util::hash_to_prime;
use ramp::Int;

#[derive(Debug, Clone)]
pub struct ProofOfExponentiation(Int, Int);

impl ProofOfExponentiation {
    pub fn new(
        previous: &Int,
        exponent: &Int,
        current: &Int,
        modulus: &Int,
    ) -> Self {
        let unique_prime = hash_to_prime(
            &(previous + exponent + current).to_str_radix(10, false),
            modulus,
        );
        let witness = exponent / unique_prime;
        let proof = previous.pow_mod(&witness, modulus);
        Self(proof, modulus.clone())
    }
    pub fn verify(
        &self,
        previous: &Int,
        exponent: &Int,
        current: &Int,
    ) -> bool {
        let unique_prime = hash_to_prime(
            &(previous + exponent + current).to_str_radix(10, false),
            &self.1,
        );
        let r = exponent % &unique_prime;
        let w = &self.0.pow_mod(&unique_prime, &self.1)
            * previous.pow_mod(&r, &self.1);
        &w == current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::RSA_2048;
    use ramp::Int;

    #[test]
    fn poe_test() {
        let modulus = &*RSA_2048;
        let generator =
            &Int::from_str_radix("78905317890531857319", 10).unwrap();
        let exponent = &Int::from_str_radix("10", 10).unwrap();
        let current = &generator.pow_mod(exponent, modulus);
        let proof =
            ProofOfExponentiation::new(generator, exponent, current, modulus);
        assert!(proof.verify(generator, exponent, current));
    }
}
