#[macro_use]
extern crate log;

use proof_of_latency::vdf::util::hash_to_prime;
use proof_of_latency::{PoLMessage, PoLRole, ProofOfLatency, RSA_2048};
use ramp::Int;
use ramp_primes::Generator;
use std::time::Instant;
// use ockam::{Context, Result, Route, SecureChannel, TcpTransport, Vault, TCP};

// #[ockam::node]
fn main() {
    env_logger::init();

    //   // Initialize the TCP Transport.
    //   let tcp = TcpTransport::create(&ctx).await?;
    //
    //   // Create a TCP connection.
    //   tcp.connect("127.0.0.1:3000").await?;
    //
    //   let vault = Vault::create(&ctx).await?;
    //
    //   // Connect to a secure channel listener and perform a handshake.
    //   let channel = SecureChannel::create(
    //       &mut ctx,
    //       // route to the secure channel listener
    //       Route::new()
    //           .append_t(TCP, "127.0.0.1:4000") // responder node
    //           .append("secure_channel_listener"), // secure_channel_listener
    // on responder node,       &vault,
    //   )
    //       .await?;
    //
    //   // Send a message to the echoer worker via the channel.
    //   ctx.send(
    //       Route::new().append(channel.address()).append("echoer"),
    //       "Hello Ockam!".to_string(),
    //   )
    //       .await?;
    //
    //   // Wait to receive a reply and print it.
    //   let reply = ctx.receive::<String>().await?;
    //   println!("App Received: {}", reply); // should print "Hello Ockam!"

    let modulus = Int::from_str_radix(RSA_2048, 10).unwrap();

    let timer = Instant::now();
    let prime1 = hash_to_prime("asdfhjaefhliuefeaji", &modulus);
    debug!(
        "Prime {:?} calculated in {:?}ms",
        prime1,
        timer.elapsed().as_millis()
    );

    let mut pol = ProofOfLatency::default().init(modulus, 150000);
    let (input, output) = pol.open_io();
    debug!("Proof of latency instance created");

    match pol.start(PoLRole::Prover) {
        Ok(_) => info!("PoL state machine started"),
        Err(_) => error!("Couldn't start the PoL state machine"),
    }

    if let Ok(message) = output.recv() {
        match message {
            PoLMessage::GeneratorPart { num } => {
                info!("Generator part received: {:?}", num)
            }
            _ => error!("Wrong message received"),
        }
    } else {
        error!("Channel closed!")
    }

    let cap = Generator::new_safe_prime(128);
    let generator_part = Generator::new_uint(128);
    match input.send(PoLMessage::GeneratorPartAndCap {
        generator_part: generator_part.to_str_radix(10, false),
        cap: cap.to_str_radix(10, false),
    }) {
        Ok(_) => info!("Received g2, l2"),
        Err(_) => error!("Channel closed!"),
    }

    if let Ok(message) = output.recv() {
        match message {
            PoLMessage::VDFProofAndCap { proof, cap: _ } => {
                if proof.verify() {
                    info!("VDF ready!")
                } else {
                    error!("Our VDF proof was not correct!")
                }
            }
            _ => error!("Wrong message received"),
        }
    } else {
        error!("Channel closed!");
    }

    //   // Stop all workers, stop the node, cleanup and return.
    //   ctx.stop().await
}
