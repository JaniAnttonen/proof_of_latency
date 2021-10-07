extern crate blake3;
use blake3::Hash;
use ramp::Int;
use ramp_primes::Verification;
use std::str;

/// Hashes the input with blake3 and converts to a (Big)Int
pub fn hash_to_int(s: &str, bit_length: u32) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * bit_length / 512 + 1) {
        let hash: Hash = blake3::hash(format!("{}{}", s, i).as_bytes());
        for x in hash.as_bytes().iter() {
            ans = (ans << 8) + Int::from(*x);
        }
    }
    ans
}

/// Deterministically hashes the input string s to be a member of the
/// multiplicative group of modulo mod.
pub fn hash_to_mod(s: &str, modulus: &Int) -> Int {
    let ans = hash_to_int(s, modulus.bit_length());
    ans % modulus
}

/// A hash function that deterministically hashes the input to a prime number
pub fn hash_to_prime(s: &str, lower_bound: &Int) -> Int {
    let n = lower_bound.bit_length();
    let mut result = hash_to_int(s, n);

    loop {
        result.set_bit(0, true);
        result.set_bit(n - 1, true);
        if Verification::verify_prime(result.clone()) && &result > lower_bound {
            break;
        } else {
            result = hash_to_int(&Int::to_str_radix(&result, 10, false), n);
            continue;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RSA_2048;
    use proptest::prelude::*;
    use ramp::Int;
    use ramp_primes::Verification;

    proptest! {
        #[test]
        fn output_is_in_group(modulus in 0u32..u32::MAX) {
            let mod_int: Int = Int::from(modulus);
            let test_string = "ASDFJKJÖGAGLELJ";
            let output: Int = hash_to_mod(test_string, &mod_int);
            assert!(output > Int::zero());
            assert!(output < mod_int);
        }
    }

    #[test]
    fn hash_to_prime_produces_unique_primes_that_are_larger_than_mod() {
        let modulus = Int::from_str_radix(RSA_2048, 10).unwrap();
        let input1 = "fhaehkuhalfehan";
        let input2 = "hgkrusfejs";

        // Test that the prime hasher produces primes larger than modulus
        let prime1 = hash_to_prime(input1, &modulus);
        assert!(Verification::verify_prime(prime1.clone()));
        assert!(prime1 > modulus);

        // Test that the prime hasher produces deterministic output
        let prime2 = hash_to_prime(input1, &modulus);
        assert!(prime1 == prime2);

        // Test that the prime hasher produces unique output
        let prime3 = hash_to_prime(input2, &modulus);
        assert!(prime3 != prime1);
    }
}
