use ramp::Int;
use std::str::FromStr;
use std::{thread, time};

pub mod vdf;
//pub mod p2p;

pub const RSA_2048: &str =
    "2519590847565789349402718324004839857142928212620403202777713783604366202070
           7595556264018525880784406918290641249515082189298559149176184502808489120072
           8449926873928072877767359714183472702618963750149718246911650776133798590957
           0009733045974880842840179742910064245869181719511874612151517265463228221686
           9987549182422433637259085141865462043576798423387184774447920739934236584823
           8242811981638150106748104516603773060562016196762561338441436038339044149526
           3443219011465754445417842402092461651572335077870774981712577246796292638635
           6373289912154831438167899885040445364023527381951378636564391212010397122822
           120720357";

// rsa_mod = N, seed = g
fn main() {
    // This parameter just needs to provide a group of unknown order, thus a large RSA number is
    // required. N in the paper.
    let rsa_mod = Int::from_str(RSA_2048).unwrap();

    // Security parameter, g in the paper. This needs to be replaced with a key that's decided
    // between two peers with Diffie-Hellman. The starting point for the VDF that gets squared
    // repeatedly for T times. Used to verify that the calculations started here. That's why the
    // setup needs to generate a random starting point that couldn't have been forged beforehand.
    let seed = vdf::util::hash(&format!("Beep boop beep"), &rsa_mod);

    // Create VDF, estimate upper bound for 5 seconds
    let our_vdf = vdf::VDF::new(rsa_mod, seed).estimate_upper_bound(100);

    // OH YES, it's a random prime that gets used in the proof and verification. This has to be
    // sent from another peer and this actually is the thing that ends the calculation and
    // facilitates the proof.
    let cap: u64 = vdf::util::get_prime();

    // Run the VDF, returning connection channels to push to and receive data from
    let (vdf_worker, worker_output) = our_vdf.run_vdf_worker();

    // Sleep for 300 milliseconds to simulate latency overseas
    let sleep_time = time::Duration::from_millis(3000);
    thread::sleep(sleep_time);

    // Send received signature from the other peer, "capping off" the
    vdf_worker.send(cap).unwrap();

    // Wait for response from VDF worker
    let response = worker_output.recv().unwrap().unwrap();

    println!("VDF ran for {:?} times!", response.output.iterations);
    println!("The output being {:?}", response.output.result);

    // Verify the proof
    let is_ok = response.verify();

    match is_ok {
        true => println!("The VDF is correct!"),
        false => println!("The VDF couldn't be verified!"),
    }

    //p2p::run().unwrap();
}
