use lazy_static::lazy_static;
use ramp::Int;
use std::cmp::Ordering;

pub const RSA_2048_STR: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

lazy_static! {
    pub static ref TWO: Int = Int::from_str_radix("2", 10).unwrap();
    pub static ref RSA_2048: Int =
        Int::from_str_radix(RSA_2048_STR, 10).unwrap();
}

#[derive(Debug, Clone, Eq)]
pub struct RSA(Int, Int);

impl Ord for RSA {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for RSA {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RSA {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Default for RSA {
    fn default() -> Self {
        RSA(TWO.clone(), RSA_2048.clone())
    }
}

impl RSA {
    pub fn new(generator: Int, modulus: Int) -> Self {
        Self(generator, modulus)
    }
    pub fn next_square(&self) -> Self {
        let next = self.0.pow_mod(&TWO, &self.1);
        Self(next, self.1.clone())
    }
    pub fn pow(&self, power: &Int) -> Self {
        let next = self.0.pow_mod(power, &self.1);
        Self(next, self.1.clone())
    }
    pub fn current(&self) -> Int {
        self.0.clone()
    }
    pub fn deserialize(&self) -> String {
        self.0.to_str_radix(10, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramp::Int;

    #[test]
    fn rsa_squaring() {
        let generator =
            Int::from_str_radix("78905317890531857319", 10).unwrap();
        let rsa = RSA(generator, RSA_2048.clone());
        let next = rsa.next_square();
        assert!(rsa != next);
    }

    #[test]
    fn rsa_pow() {
        let generator =
            Int::from_str_radix("97556298743265743962543", 10).unwrap();
        let rsa = RSA(generator, RSA_2048.clone());
        let power = Int::from_str_radix("77698319831", 10).unwrap();
        let next = rsa.pow(&power);
        assert!(rsa != next);
    }
}
