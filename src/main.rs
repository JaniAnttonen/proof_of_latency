use std::str::FromStr;
use std::sync::mpsc::{Sender, channel, Receiver};
use std::{thread, time};
use ramp::Int;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use primality::{is_prime, pow_mod};

// rsa_mod = N, seed = g
fn main() {
    // RSA Setup. TODO: Replace this with an interactive key setup between two peers
    let rsa_mod = Int::from_str("135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563").expect("Cannot read string");
    let seed = hash(&format!("Beep boop beep"), &rsa_mod);

    // TODO: Understand what this does
    let l = get_prime();

    // Run the VDF, returning connection channels to push to and receive data from
    let (vdf_worker, worker_output) = run_vdf_worker(seed.clone(), rsa_mod.clone());

    // Sleep for 300 milliseconds to simulate latency overseas
    let sleep_time = time::Duration::from_millis(300);
    thread::sleep(sleep_time);

    // Send received signature from the other peer, "capping off" the 
    vdf_worker.send(Msg::Cap(String::from("asd"))).unwrap();

    // Wait for response from VDF worker
    let response = worker_output.recv().unwrap();
   
    println!("VDF ran for {:?} times!", response.iterations);
    println!("The output being {:?}", response.result);

    // Generate the proof
    let proof = prove(&seed, &response.result, &Int::from(l), response.iterations, &rsa_mod);

    // Verify the proof
    let is_ok = verify(&proof, &seed, &response.result, l, response.iterations, &rsa_mod);
    match is_ok {
        true => println!("The VDF is correct!"),
        false => println!("The VDF couldn't be verified!"),
    }
}

enum Msg {
    Cap(String), 
}

struct VDFResponse {
    result: Int,
    iterations: u128,
}

fn run_vdf_worker(g: Int, rsa_mod: Int) -> (Sender<Msg>, Receiver<VDFResponse>) {
    let (tx, rx) = channel();
    let (res_channel, receiver) = channel();

    thread::spawn(move || {
        let mut ans = g.clone();
        let mut iterations: u128 = 0;
        loop {
            ans = ans.pow_mod(&Int::from(2), &rsa_mod);
            iterations += 1;
            let signal = rx.try_recv();
            match signal {
                Ok(Msg::Cap(sig)) => {
                    res_channel.send(VDFResponse{result: ans, iterations: iterations});
                    break;
                },
                Err(err) => continue,
                _ => continue
            }
        }
    });

    (tx, receiver)
}

pub mod primality;

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

pub fn prove(g: &Int, h: &Int, l: &Int, iterations: u128, rsa_mod: &Int) -> Int {
    let mut pi = Int::one();
    let mut r = Int::one();
    let mut b: Int;
    for _ in 0..iterations {
        b = 2 * &r / l;
        r = (2 * &r) % l;
        pi = pi.pow_mod(&Int::from(2), rsa_mod) * g.pow_mod(&b, rsa_mod);
        pi %= rsa_mod;
    }
    return pi;
}

pub fn get_prime() -> u64 {
    let mut rng = rand::thread_rng();
    let mut l: u64;
    loop {
        l = rng.next_u64();
        if is_prime(l.into(), 10) {
            break;
        }
    }
    l
}

pub fn verify(pi: &Int, g: &Int, h: &Int, l: u64, iterations: u128, rsa_mod: &Int) -> bool {
    if pi > rsa_mod {
        return false;
    }
    let r = pow_mod(2, iterations, l.into());
    *h == (pi.pow_mod(&Int::from(l), &rsa_mod) * g.pow_mod(&Int::from(r), &rsa_mod)) % rsa_mod
}

