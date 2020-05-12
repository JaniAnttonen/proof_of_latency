use ramp::Int;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use primal;

/// Modular exponentiation
pub fn pow_mod(b: u128, e: u128, n: u128) -> u128 {
    if n == 1 {
        return 0;
    }
    let mut result = 1;
    let mut base = b % n;
    let mut exp = e;
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % n;
        }
        exp >>= 1;
        base = (base * base) % n;
    }
    result
}

pub fn hash(s: &str, rsa_mod: &Int) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * rsa_mod.bit_length() / 512 + 1) {
        let mut hasher = Sha3_512::new();
        hasher.input(format!("{}{}", s, i).as_bytes());
        let arr = hasher.result();
        for x in arr.into_iter() {
            ans = (ans << 8) + Int::from(x);
        }
    }
    ans % rsa_mod
}


pub fn get_prime() -> u64 {
    let mut rng = rand::thread_rng();
    let mut l: u64;
    loop {
        l = rng.next_u64().into();
        if primal::is_prime(l) {
            break;
        }
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pow_mod_works() {
        assert_eq!(pow_mod(2, 5, 10), 2);
    }
}
