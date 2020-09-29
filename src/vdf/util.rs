extern crate blake3;
use blake3::Hash;
use ramp::Int;

/// Deterministically hashes the input string s to be a member of the
/// multiplicative group of modulo rsa_mod.
pub fn hash(s: &str, rsa_mod: &Int) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * rsa_mod.bit_length() / 512 + 1) {
        let hash: Hash = blake3::hash(format!("{}{}", s, i).as_bytes());
        for x in hash.as_bytes().into_iter() {
            ans = (ans << 8) + Int::from(*x);
        }
    }
    ans % rsa_mod
}
