use ramp::Int;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use rand::Rng;

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

/// Miller-Rabin primality testing
pub fn is_prime(n: u128, r: usize) -> bool {
    let mut rng = rand::thread_rng();

    if n % 2 == 0 {
        return false;
    }

    let mut r = 0;
    let mut d = n - 1;
    while d % 2 == 0 {
        r += 1;
        d /= 2;
    }
    'rounds: for _i in 0..r {
        let a = rng.gen_range(2, n - 2);
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue 'rounds;
        } else {
            for _ in 0..r - 1 {
                x = (x * x) % n;
                if x == n - 1 {
                    continue 'rounds;
                }
            }
            return false;
        }
    }
    true
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


pub fn get_prime() -> u128 {
    let mut rng = rand::thread_rng();
    let mut l: u128;
    loop {
        l = rng.next_u64().into();
        if is_prime(l.into(), 10) {
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

    #[test]
    fn primality_works() {
        for i in 5..100 {
            if is_prime(i, 10) {
                println!("{}",i);
            }
        }
    }
}
