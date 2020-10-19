#[macro_use]
extern crate log;
extern crate sm;

use ramp::Int;
use ramp_primes::Generator;
use std::error::Error;
use std::fmt;

use std::sync::mpsc::{channel, Receiver, Sender};

// Internal imports
pub mod p2p;
pub mod vdf;
use vdf::evaluation::VDF;
use vdf::proof::VDFProof;
use vdf::InvalidCapError;

// RSA-2048, copied from Wikipedia
pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

use sm::sm;

// State machine macro for handling the protocol state
sm!(
  PoL {
      InitialStates { Prover, Verifier }

      // Both the Prover and the Verifier start by creating a part of the generator
      CreateGeneratorPart {
          Prover => Sending
          Verifier => Waiting
      }

      // Prover sends the created generator part to the Verifier
      SendGeneratorPart {
          Sending => Waiting
      }

      // Verifier receives the generator part created by the Prover, starts its VDF, and sends back a generator part with the cap
      SendGeneratorPartAndCap {
          Waiting => EvaluatingAndWaiting
      }

      // Prover receives the generator part and the cap from the Verifier, starts evaluating until predefined difficulty T is reached
      ReceiveGeneratorPartAndCap {
          Waiting => Evaluating
      }

      // Evaluation end state for both the Prover and the Verifier, triggering proof generation
      EndEvaluation {
          Evaluating => Sending
          EvaluatingAndWaiting => Generating
      }

      // Prover sends the VDF proof with a cap to the Verifier
      GenerateProverProof {
          Sending => ProofReady
      }

      // Verifier has created its own proof, and combines the two VDF proofs into a proof of latency.
      GenerateVerifierProof {
          Generating => ProofReady
      }
  }
);

use crate::PoL::*;

/// All possible messages that are passed between the prover and the verifier in
/// calculating a Proof of Latency
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoLMessage {
    GeneratorPart { num: Int },

    Cap { num: Int },

    GeneratorPartAndCap { generatorPart: Int, cap: Int },

    VDFProof { proof: VDFProof },

    SignedVDFProof { proof: VDFProof, signature: String },

    Error { reason: String },
}

/// PoLStartError is thrown when Proof of Latency is started before all
/// prequisites are met.
#[derive(Debug)]
pub struct PoLStartError;

impl fmt::Display for PoLStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I/O not defined yet, trying to start a Proof of Latency without new()?")
    }
}

impl Error for PoLStartError {
    fn description(&self) -> &str {
        "I/O not defined yet, trying to start a Proof of Latency without new()?"
    }
}

/// Struct that keeps the needed variables in memory during the state machine
/// execution modulus = N, generator = g
#[derive(Debug)]
pub struct ProofOfLatency {
    pub modulus: Option<Int>,
    pub generator: Option<Int>,
    pub upper_bound: Option<u32>,
    VDFCapper: Option<Sender<Int>>,
    VDFResultChannel: Option<Receiver<Result<VDFProof, InvalidCapError>>>,
    pub prover_result: Option<VDFProof>,
    pub verifier_result: Option<VDFProof>,
    pub input: Option<Sender<PoLMessage>>,
    userInputListener: Option<Receiver<PoLMessage>>,
    pub output: Option<Receiver<PoLMessage>>,
    userOutputSender: Option<Sender<PoLMessage>>,
}

impl Default for ProofOfLatency {
    fn default() -> Self {
        Self {
            modulus: None,
            generator: None,
            upper_bound: None,
            VDFCapper: None,
            VDFResultChannel: None,
            prover_result: None,
            verifier_result: None,
            output: None,
            userInputListener: None,
            input: None,
            userOutputSender: None,
        }
    }
}

impl ProofOfLatency {
    pub fn new(&mut self, modulus: Int, upper_bound: u32) -> Self {
        self.modulus = Some(modulus.clone());
        self.generator = None;
        self.upper_bound = Some(upper_bound);
        let (input, listener): (Sender<PoLMessage>, Receiver<PoLMessage>) =
            channel();
        let (sender, output): (Sender<PoLMessage>, Receiver<PoLMessage>) =
            channel();
        self.input = Some(input);
        self.userInputListener = Some(listener);
        self.output = Some(output);
        self.userOutputSender = Some(sender);
        *self
    }

    fn abort(&mut self, reason: &str) {
        self.userOutputSender.unwrap().send(PoLMessage::Error {
            reason: String::from(reason),
        });
    }

    pub fn start(
        &mut self,
        modulus: Int,
        generator: Int,
        upper_bound: u32,
    ) -> Result<(), PoLStartError> {
        if self.output.is_none() | self.input.is_none() {
            Err(PoLStartError)
        }
        let mut sm = Machine::new(Prover).as_enum();
        let prover_vdf = VDF::new(modulus, generator, upper_bound);

        loop {
            sm = match sm {
                // PROVER: Create g1 + l1
                Variant::InitialProver(m) => {
                    self.generator = Some(Generator::new_uint(64));
                    m.transition(CreateGeneratorPart).as_enum()
                }
                // VERIFIER: Create g2 + l2
                Variant::InitialVerifier(m) => {
                    self.generator = Some(Generator::new_uint(64));
                    m.transition(CreateGeneratorPart).as_enum()
                }
                // PROVER: Send g1
                Variant::SendingByCreateGeneratorPart(m) => {
                    match self.userOutputSender {
                        Some(sender) => {
                            sender.send(PoLMessage::GeneratorPart {
                                num: self.generator.unwrap(),
                            });
                            m.transition(SendGeneratorPart).as_enum()
                        }
                        None => continue,
                    }
                }
                // VERIFIER: Receive g1, Start VDF, Send g2 + l2
                Variant::WaitingByCreateGeneratorPart(m) => {
                    // Receive g1
                    match self.userInputListener {
                        Some(input) => {
                            if let Ok(message) = input.recv() {
                                match message {
                                    PoLMessage::GeneratorPart { num } => {
                                        let sumStr: String =
                                            (self.generator.unwrap() + num)
                                                .to_str_radix(16, true);
                                        let hash: Int = vdf::util::hash(
                                            &sumStr,
                                            &self.modulus.unwrap(),
                                        );
                                    }
                                    _ => {
                                        self.abort("Expected PoLMessage::GeneratorPart, received something else");
                                        break;
                                    }
                                }
                            } else {
                                self.abort("Could not receive input");
                                break;
                            }
                        }
                        None => continue,
                    }

                    // Start VDF

                    // Send g2 + l2
                    match self.userOutputSender {
                        Some(sender) => {
                            sender.send(PoLMessage::GeneratorPart {
                                num: self.generator.unwrap(),
                            });
                        }
                        None => {
                            self.abort("Cannot send to user, aborting");
                            break;
                        }
                    }

                    // Transition the state machine
                    m.transition(SendGeneratorPartAndCap).as_enum()
                }
            }
        }

        let (capper, receiver) = prover_vdf.run_vdf_worker();
        self.VDFCapper = Some(capper);
        self.VDFResultChannel = Some(receiver);
    }

    pub fn receive(&mut self, their_proof: VDFProof) {
        // Send received signature from the other peer, "capping off" the VDF
        if self
            .VDFCapper
            .as_ref()
            .unwrap()
            .send(their_proof.cap.clone())
            .is_err()
        {
            debug!(
                "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
            );
        };

        // Wait for response from VDF worker
        loop {
            if let Ok(res) = self.receiver.as_ref().unwrap().try_recv() {
                if let Ok(proof) = res {
                    debug!(
                        "VDF ran for {:?} times!\nThe output being {:?}",
                        proof.output.iterations, proof.output.result
                    );

                    let iter_prover: u32 = proof.output.iterations;
                    let iter_verifier: u32 = their_proof.output.iterations;
                    let difference: Int = if iter_prover > iter_verifier {
                        Int::from(iter_prover - iter_verifier)
                    } else {
                        Int::from(iter_verifier - iter_prover)
                    };
                    info!(
                        "Both proofs are correct! Latency between peers was {:?} iterations.",
                        difference
                    );

                    self.prover_result = Some(proof);
                    self.verifier_result = Some(their_proof);

                    break;
                } else {
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ramp_primes::Generator;
    use std::str::FromStr;

    #[test]
    fn start_modifies_self() {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let prime = Generator::new_prime(128);
        let mut pol = ProofOfLatency::default();

        let pol2 = ProofOfLatency::default();
        pol.start(modulus, prime, u32::MAX);

        assert!(pol.capper.is_some());
        assert!(pol2.capper.is_none());
        assert!(pol.receiver.is_some());
        assert!(pol2.receiver.is_none());
    }
}
