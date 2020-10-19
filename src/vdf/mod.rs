use std::error::Error;
use std::fmt;

pub mod evaluation;
pub mod proof;
pub mod util;

/// InvalidCapError is returned when a non-prime cap is received in the
/// vdf_worker
#[derive(Debug)]
pub struct InvalidCapError;

impl fmt::Display for InvalidCapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid cap value encountered!")
    }
}

impl Error for InvalidCapError {
    fn description(&self) -> &str {
        "Invalid cap value encountered!"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramp::Int;
    use ramp_primes::Generator;
    use std::str::FromStr;
    use std::{thread, time};

    const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

    #[test]
    fn is_deterministic() {
        let modulus = Int::from_str("91").unwrap();
        let prime = Generator::new_safe_prime(128);
        let root_hashed = util::hash(&prime.to_string(), &modulus);

        // Create two VDFs with same inputs to check if they end up in the same
        // result
        let cap = Int::from(7);
        let verifiers_vdf =
            evaluation::VDF::new(modulus.clone(), root_hashed.clone(), 32)
                .with_cap(cap.clone());
        let provers_vdf =
            evaluation::VDF::new(modulus, root_hashed, 32).with_cap(cap);

        let (_, receiver) = verifiers_vdf.run_vdf_worker();
        let (_, receiver2) = provers_vdf.run_vdf_worker();

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                println!("{:#?}", proof);
                assert!(proof.verify());

                let our_proof = proof;

                if let Ok(res2) = receiver2.recv() {
                    if let Ok(proof2) = res2 {
                        assert!(proof2.verify());
                        println!("{:#?}", proof2);
                        let their_proof = proof2;
                        assert_eq!(our_proof, their_proof);
                    }
                }
            }
        }
    }

    #[test]
    fn vdf_iter_should_be_correct() {
        let modulus = Int::from(17);
        let generator = Int::from(11);
        let two = Int::from(2);
        let cap = Int::from(7);
        let mut vdf = evaluation::VDF::new(modulus, generator, 0);

        vdf.next();
        assert_eq!(vdf.result.result, two);

        vdf.next();
        assert_eq!(vdf.result.result, Int::from(4));

        vdf.next();
        assert_eq!(vdf.result.result, Int::from(16));

        let proof = proof::VDFProof::new(
            &vdf.modulus,
            &vdf.generator,
            &vdf.result,
            &cap,
        );

        assert!(proof.verify());
    }

    #[test]
    fn proof_generation_should_be_same_between_predetermined_and_received_input(
    ) {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let hashablings2 = &"ghsalkghsakhgaligheliah<lifehf esipf";
        let root_hashed = util::hash(&hashablings2.to_string(), &modulus);

        let cap = Generator::new_safe_prime(16);
        let vdf = evaluation::VDF::new(
            modulus.clone(),
            root_hashed.clone(),
            u32::MAX,
        );

        let (capper, receiver) = vdf.run_vdf_worker();

        thread::sleep(time::Duration::from_millis(10));

        let mut first_proof = proof::VDFProof::default();

        let cap_error = capper.send(cap).is_err();
        assert!(!cap_error);

        if let Ok(res) = receiver.recv() {
            if let Ok(proof) = res {
                assert!(proof.iterable.pi != 1);
                first_proof = proof;
            }
        }

        let vdf2 = evaluation::VDF::new(
            modulus,
            root_hashed,
            first_proof.output.iterations,
        )
        .with_cap(first_proof.cap.clone());

        let (_, receiver2) = vdf2.run_vdf_worker();

        if let Ok(res2) = receiver2.recv() {
            if let Ok(proof2) = res2 {
                assert_eq!(proof2, first_proof);
                assert!(first_proof.verify());
                assert!(proof2.verify());
                println!("Proof1: {:#?}, Proof2: {:#?}", first_proof, proof2);
            }
        }
    }
}
