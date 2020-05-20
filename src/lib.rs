use ramp::Int;
use std::str::FromStr;
mod vdf;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

pub enum STATE {}

// rsa_mod = N, root = g
pub struct ProofOfLatency {
    pub rsa_mod: Int,
    pub root: Int,
}

impl ProofOfLatency {
    pub fn new(secret: &str) -> ProofOfLatency {
        let rsa_mod = Int::from_str(RSA_2048).unwrap();

        // Security parameter, g in the paper. This needs to be replaced with a key that's decided
        // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
        // repeatedly for T times. Used to verify that the calculations started here. That's why the
        // setup needs to generate a random starting point that couldn't have been forged beforehand.
        let root = vdf::util::hash(secret, &rsa_mod);
        ProofOfLatency { rsa_mod, root }
    }
}
