#[macro_use]
extern crate log;
extern crate sm;

use ramp::Int;
use ramp_primes::Generator;
use std::error::Error;
use std::fmt;

use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

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
      CreateGeneratorPartAndCap {
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

      // Prover receives the generator part and the  cap from the Verifier, starts evaluating until predefined difficulty T is reached
      ReceiveGeneratorPartAndCap {
          Waiting => Evaluating
      }

      // Evaluation end state for the Prover, triggering proof generation
      EndProverEvaluation {
          Evaluating => Waiting
      }

      // Verifier creates a signed Proof of Latency, sends it to Prover for verification and signing
      EndVerifierEvaluation {
          EvaluatingAndWaiting => Waiting
      }

      // Prover signs the Verifier's VDF, sending back the fully signed Proof of Latency
      SignVerifierVDF {
          Waiting => ProofReady
      }

      // Verifier receives the fully signed Proof of Latency.
      ReceiveProofOfLatency {
          Waiting => ProofReady
      }
  }
);

use crate::PoL::*;

/// Proof of Latency roles – Prover / Verifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoLRole {
    Prover,
    Verifier,
}

/// All possible messages that are passed between the prover and the verifier in
/// calculating a Proof of Latency
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoLMessage {
    GeneratorPart {
        num: Int,
    },

    Cap {
        num: Int,
    },

    GeneratorPartAndCap {
        generator_part: Int,
        cap: Int,
    },

    VDFProof {
        proof: VDFProof,
    },

    VDFProofAndCap {
        proof: VDFProof,
        cap: Int,
    },

    ProofOfLatency {
        prover: VDFProof,
        verifier: VDFProof,
        prover_pub_key: String,
        verifier_pub_key: String,
        prover_signature: String,
        verifier_signature: String,
    },

    Error {
        reason: String,
    },
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
    // Starting parameters
    pub modulus: Option<Int>,
    pub generator: Option<Int>,
    pub upper_bound: Option<u32>,
    pub pubkey: Option<String>,
    // Channels for discussing with the VDF
    vdf_capper: Option<Sender<Int>>,
    vdf_result_channel: Option<Receiver<Result<VDFProof, InvalidCapError>>>,
    // User I/O
    pub input: Option<Sender<PoLMessage>>,
    user_input_listener: Option<Receiver<PoLMessage>>,
    pub output: Option<Receiver<PoLMessage>>,
    user_output_sender: Option<Sender<PoLMessage>>,
    // VDF Proofs
    pub prover_result: Option<VDFProof>,
    pub verifier_result: Option<VDFProof>,
}

impl Default for ProofOfLatency {
    fn default() -> Self {
        Self {
            modulus: None,
            generator: None,
            upper_bound: None,
            pubkey: None,
            vdf_capper: None,
            vdf_result_channel: None,
            prover_result: None,
            verifier_result: None,
            output: None,
            user_input_listener: None,
            input: None,
            user_output_sender: None,
        }
    }
}

impl ProofOfLatency {
    pub fn new(
        mut self,
        modulus: Int,
        upper_bound: u32,
        pubkey: String,
    ) -> Self {
        self.modulus = Some(modulus.clone());
        self.generator = None;
        self.upper_bound = Some(upper_bound);
        self.pubkey = Some(pubkey);
        let (input, listener): (Sender<PoLMessage>, Receiver<PoLMessage>) =
            channel();
        let (sender, output): (Sender<PoLMessage>, Receiver<PoLMessage>) =
            channel();
        self.input = Some(input);
        self.user_input_listener = Some(listener);
        self.output = Some(output);
        self.user_output_sender = Some(sender);
        self
    }

    fn abort(&self, reason: &str) {
        match self.user_output_sender.as_ref() {
            Some(sender) => {
                match sender.send(
                    PoLMessage::Error {
                        reason: String::from(reason),
                    },
                ) {
                    Ok(result) => debug!("{:?}", result),
                    Err(_err) => warn!("Couldn't send PoL abort message back to user, check implementation!")
                }
            },
            None => error!("This shouldn't happen, the state machine implementation has a bug.")
        }
    }

    fn combine_generator_parts(&self, our: &Int, other: &Int) -> Int {
        let sum_str: String = (our + other).to_str_radix(16, true);
        vdf::util::hash(&sum_str, &self.modulus.as_ref().unwrap())
    }

    pub fn start(&mut self, role: PoLRole) -> Result<bool, PoLStartError> {
        // Check if all channels are defined
        if self.output.is_none() {
            return Err(PoLStartError);
        }

        // Unwrap the user I/O
        let user_input: &Receiver<PoLMessage> =
            self.user_input_listener.as_ref().unwrap();
        let user_output: &Sender<PoLMessage> =
            self.user_output_sender.as_ref().unwrap();

        // Start a new state machine
        let mut sm = match role {
            PoLRole::Prover => Machine::new(Prover).as_enum(),
            PoLRole::Verifier => Machine::new(Verifier).as_enum(),
        };

        // Create the sendable cap and generator part
        let mut sendable_cap = Int::zero();
        let mut our_generator_part = Int::zero();
        let bit_depth = 64;

        loop {
            sm = match sm {
                // PROVER: Create g1 + l1
                Variant::InitialProver(m) => {
                    sendable_cap = Generator::new_prime(bit_depth);
                    our_generator_part = Generator::new_uint(bit_depth);
                    m.transition(CreateGeneratorPartAndCap).as_enum()
                }
                // VERIFIER: Create g2 + l2
                Variant::InitialVerifier(m) => {
                    sendable_cap = Generator::new_prime(bit_depth);
                    our_generator_part = Generator::new_uint(bit_depth);
                    m.transition(CreateGeneratorPartAndCap).as_enum()
                }
                // PROVER: Send g1
                Variant::SendingByCreateGeneratorPartAndCap(m) => {
                    match user_output.send(PoLMessage::GeneratorPart {
                        num: our_generator_part.clone(),
                    }) {
                        Ok(_) => m.transition(SendGeneratorPart).as_enum(),
                        Err(_) => break,
                    }
                }
                // VERIFIER: Receive g1, Start VDF, Send g2 + l2
                Variant::WaitingByCreateGeneratorPartAndCap(m) => {
                    // Construct the VDF
                    let mut verif_vdf = VDF::new(
                        self.modulus.as_ref().unwrap().clone(),
                        Int::zero(),
                        self.upper_bound.as_ref().unwrap().clone(),
                    );
                    // Receive g1, construct hash(g1+g2)
                    if let Ok(message) = user_input.recv() {
                        match message {
                            PoLMessage::GeneratorPart { num } => {
                                verif_vdf.generator = self
                                    .combine_generator_parts(
                                        &our_generator_part,
                                        &num,
                                    );
                            }
                            _ => {
                                self.abort("WaitingByCreateGeneratorPart: Expected PoLMessage::GeneratorPart, received something else");
                                break;
                            }
                        }
                    } else {
                        self.abort("WaitingByCreateGeneratorPart: Could not receive input");
                        break;
                    }

                    // Start VDF
                    let (capper, receiver) = verif_vdf.run_vdf_worker();
                    self.vdf_capper = Some(capper);
                    self.vdf_result_channel = Some(receiver);

                    // Send g2 + l2
                    match user_output.send(PoLMessage::GeneratorPartAndCap {
                        generator_part: our_generator_part.clone(),
                        cap: sendable_cap.clone(),
                    }) {
                        Ok(_) => {
                            m.transition(SendGeneratorPartAndCap).as_enum()
                        }
                        Err(_) => break,
                    }
                }
                // PROVER: Receive g2 and l2, Start VDF
                Variant::WaitingBySendGeneratorPart(m) => {
                    // Construct the VDF
                    let mut prover_vdf = VDF::new(
                        self.modulus.as_ref().unwrap().clone(),
                        Int::zero(),
                        self.upper_bound.as_ref().unwrap().clone(),
                    );

                    if let Ok(message) = user_input.recv() {
                        match message {
                            PoLMessage::GeneratorPartAndCap {
                                generator_part,
                                cap,
                            } => {
                                prover_vdf.generator = self
                                    .combine_generator_parts(
                                        &our_generator_part,
                                        &generator_part,
                                    );
                                prover_vdf.cap = cap;
                            }
                            _ => {
                                self.abort("WaitingBySendGeneratorPart: Expected PoLMessage::GeneratorPartAndCap, received something else");
                                break;
                            }
                        }
                    } else {
                        self.abort("WaitingBySendGeneratorPart: Could not receive input");
                        break;
                    }

                    let (_, receiver) = prover_vdf.run_vdf_worker();
                    self.vdf_result_channel = Some(receiver);

                    // Transition the state machine
                    m.transition(ReceiveGeneratorPartAndCap).as_enum()
                }
                // PROVER: Wait for the VDF to finish and generate a proof
                // with the gap given by the verifier, send verifier the
                // VDFProof and the cap generated at start.
                Variant::EvaluatingByReceiveGeneratorPartAndCap(m) => {
                    if let Ok(proof) =
                        self.vdf_result_channel.as_ref().unwrap().recv()
                    {
                        match user_output.send(PoLMessage::VDFProofAndCap {
                            proof: proof.unwrap(),
                            cap: sendable_cap.clone(),
                        }) {
                            Ok(_) => {
                                m.transition(EndProverEvaluation).as_enum()
                            }
                            Err(_) => break,
                        }
                    } else {
                        self.abort("EvaluatingByReceiveGeneratorPartAndCap: Error received from VDF, check negotiated VDF parameters like the received cap, modulus and the generator.");
                        break;
                    }
                }
                // VERIFIER: Receive VDFProof + l1, construct Proof of
                // Latency and send it to the user to sign and send to
                // Prover
                Variant::EvaluatingAndWaitingBySendGeneratorPartAndCap(m) => {
                    if let Ok(message) = user_input.recv() {
                        match message {
                            PoLMessage::VDFProofAndCap { proof, cap } => {
                                // Stop our VDF with cap l1
                                match self.receive(proof, cap) {
                                    (Some(our_proof), Some(their_proof)) => {
                                        self.verifier_result = Some(our_proof);
                                        self.prover_result = Some(their_proof);
                                    }
                                    _ => {
                                        self.abort("EvaluatingAndWaitingBySendGeneratorPartAndCap: either the verifier or prover VDF proof was incorrect!");
                                        break;
                                    }
                                }
                            }
                            _ => {
                                self.abort("EvaluatingAndWaitingBySendGeneratorPartAndCap: Expected PoLMessage::VDFProofAndCap, received something else");
                                break;
                            }
                        }
                    } else {
                        self.abort("EvaluatingAndWaitingBySendGeneratorPartAndCap: Could not receive input");
                        break;
                    }

                    match user_output.send(PoLMessage::ProofOfLatency {
                        verifier: self
                            .verifier_result
                            .as_ref()
                            .unwrap()
                            .clone(),
                        prover: self.prover_result.as_ref().unwrap().clone(),
                        verifier_pub_key: self.pubkey.clone().unwrap(),
                        prover_pub_key: String::from(""),
                        verifier_signature: String::from(""),
                        prover_signature: String::from(""),
                    }) {
                        Ok(_) => m.transition(EndVerifierEvaluation).as_enum(),
                        Err(_) => break,
                    }
                }
                // PROVER: Receive Proof of Latency from Verifier, check
                // that it is correct and has a signature, and send back to
                // Verifier with a signature
                Variant::WaitingByEndProverEvaluation(m) => {
                    if let Ok(message) = user_input.recv() {
                        match message {
                            PoLMessage::ProofOfLatency {
                                prover,
                                verifier,
                                prover_pub_key,
                                verifier_pub_key,
                                prover_signature,
                                verifier_signature,
                            } => {
                                if verifier_pub_key != String::from("")
                                    && verifier_signature != String::from("")
                                {
                                    match user_output.send(
                                        PoLMessage::ProofOfLatency {
                                            verifier,
                                            prover,
                                            verifier_pub_key,
                                            prover_pub_key,
                                            verifier_signature,
                                            prover_signature,
                                        },
                                    ) {
                                        Ok(_) => m
                                            .transition(SignVerifierVDF)
                                            .as_enum(),
                                        Err(_) => break,
                                    }
                                } else {
                                    break;
                                }
                            }
                            _ => {
                                self.abort("WaitingByEndProverEvaluation: Expected PoLMessage::ProofOfLatency, received something else");
                                break;
                            }
                        }
                    } else {
                        self.abort("WaitingByEndProverEvaluation: Could not receive input");
                        break;
                    }
                }
                // VERIFIER: Receive a ready Proof of Latency from Prover,
                // make it available to the network
                Variant::WaitingByEndVerifierEvaluation(m) => {
                    m.transition(ReceiveProofOfLatency).as_enum()
                }
                // PROVER: Make proof available to the network
                Variant::ProofReadyBySignVerifierVDF(_) => {
                    break;
                }
                // VERIFIER: Make proof available to the network
                Variant::ProofReadyByReceiveProofOfLatency(_) => {
                    break;
                }
            }
        }

        Ok(true)
    }

    pub fn receive(
        &self,
        their_proof: VDFProof,
        cap: Int,
    ) -> (Option<VDFProof>, Option<VDFProof>) {
        // Send received signature from the other peer, "capping off" the VDF
        if self.vdf_capper.as_ref().unwrap().send(cap).is_err() {
            debug!(
                "The VDF has stopped prematurely or it reached the upper bound! Waiting for proof..."
            );
        };

        // Wait for response from VDF worker
        if let Ok(res) = self.vdf_result_channel.as_ref().unwrap().recv() {
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

                if their_proof.verify() && proof.verify() {
                    info!(
                        "Both proofs are correct! Latency between peers was {:?} iterations.",
                        difference
                    );

                    return (Some(proof), Some(their_proof));
                }
            }
        }
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use ramp_primes::Generator;
    use std::str::FromStr;

    #[test]
    fn new_assigns_io_channels() {
        let modulus = Int::from_str(RSA_2048).unwrap();
        let pol =
            ProofOfLatency::default().new(modulus, u32::MAX, String::from(""));
        let pol2 = ProofOfLatency::default();

        assert!(pol.user_input_listener.is_some());
        assert!(pol2.user_input_listener.is_none());
    }
}
