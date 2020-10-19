extern crate blake3;
use blake3::Hash;
use ramp::Int;

/// Deterministically hashes the input string s to be a member of the
/// multiplicative group of modulo mod.
pub fn hash(s: &str, modulus: &Int) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * modulus.bit_length() / 512 + 1) {
        let hash: Hash = blake3::hash(format!("{}{}", s, i).as_bytes());
        for x in hash.as_bytes().into_iter() {
            ans = (ans << 8) + Int::from(*x);
        }
    }
    ans % modulus
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn output_is_in_group(modulus in 0u32..u32::MAX) {
            let mod_int: Int = Int::from(modulus);
            let test_string = "ASDFJKJÖGAGLELJ";
            let output: Int = hash(test_string, &mod_int);
            assert!(output > Int::zero());
            assert!(output < mod_int);
        }
    }
}
