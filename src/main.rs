use ramp::Int;
use std::str::FromStr;
use std::{thread, time};

pub mod vdf;
//pub mod p2p;

pub const RSA_2048: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363725908514186546204357679842338718477444792073993423658482382428119816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461651572335077870774981712577246796292638635637328991215483143816789988504044536402352738195137863656439121201039712282120720357";

// rsa_mod = N, seed = g
fn main() {
    // This parameter just needs to provide a group of unknown order, thus a large RSA number is
    // required. N in the paper.
    let rsa_mod = Int::from_str(RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let seed = vdf::util::hash(&"Beep boop beep".to_string(), &rsa_mod);

    // Create VDF, estimate upper bound for 5 seconds
    let our_vdf = vdf::VDF::new(rsa_mod, seed).estimate_upper_bound(100);

    // OH YES, it's a random prime that gets used in the proof and verification. This has to be
    // sent from another peer and this actually is the thing that ends the calculation and
    // facilitates the proof.
    let cap: u64 = vdf::util::get_prime();

    // Run the VDF, returning connection channels to push to and receive data from
    let (vdf_worker, worker_output) = our_vdf.run_vdf_worker();

    // Sleep for 300 milliseconds to simulate latency overseas
    let sleep_time = time::Duration::from_millis(900);
    thread::sleep(sleep_time);

    // Send received signature from the other peer, "capping off" the
    vdf_worker.send(cap).unwrap();

    // Wait for response from VDF worker
    let response = worker_output.recv().unwrap().unwrap();

    println!("VDF ran for {:?} times!", response.output.iterations);
    println!("The output being {:?}", response.output.result);

    // Verify the proof
    let is_ok = response.verify();

    if is_ok {
        println!("The VDF is correct!")
    } else {
        println!("The VDF couldn't be verified!")
    }

    //p2p::run().unwrap();
}
