use ramp::Int;
use sha3::{Digest, Sha3_512};

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
