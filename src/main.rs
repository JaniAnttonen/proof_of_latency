use std::str::FromStr;
use std::sync::mpsc::{Sender, channel, Receiver};
use std::{thread, time};
use ramp::Int;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use primality::{is_prime, pow_mod};

fn main() {
    let N = Int::from_str("135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563").expect("Cannot read string");
    
    let g = hash(&format!("VDFs are awesome"), &N);

    let l = get_prime();

    let (vdf_worker, worker_output) = run_vdf_worker(g.clone(), N.clone());

    let sleep_time = time::Duration::from_secs(5);
    thread::sleep(sleep_time);

    vdf_worker.send(Msg::Cap(String::from("asd")));

    let response = worker_output.recv().unwrap();
   
    println!("VDF ran for {:?} times!", response.iterations);
    // Generate the proof
    //let pi = prove(&g, &response.result, &Int::from(l), response.iterations, &N);

    // Verify the proof
    //let is_ok = verify(&pi, &g, &response.result, l, response.iterations, &N);
    // assert!(is_ok);
}

enum Msg {
    Cap(String), 
}

struct VDFResponse {
    result: Int,
    iterations: u128,
}

fn run_vdf_worker(g: Int, N: Int) -> (Sender<Msg>, Receiver<VDFResponse>) {
    let (tx, rx) = channel();
    let (res_channel, receiver) = channel();

    thread::spawn(move || {
        let mut ans = g.clone();
        let mut T: u128 = 1;
        loop {
            ans = ans.pow_mod(&Int::from(2), &N);
            T += 1;
            let signal = rx.try_recv();
            match signal {
                Ok(Msg::Cap(sig)) => {
                    res_channel.send(VDFResponse{result: ans, iterations: T});
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

pub fn hash(s: &str, N: &Int) -> Int {
    let mut ans = Int::zero();
    for i in 0..(2 * N.bit_length() / 512 + 1) {
        let mut hasher = Sha3_512::new();
        hasher.input(format!("{}{}", s, i).as_bytes());
        let arr = hasher.result();
        for x in arr.into_iter() {
            ans = (ans << 8) + Int::from(x);
        }
    }
    ans % N
}

pub fn prove(g: &Int, h: &Int, l: &Int, T: u128, N: &Int) -> Int {
    let mut pi = Int::one();
    let mut r = Int::one();
    let mut b: Int;
    for _ in 0..T {
        b = 2 * &r / l;
        r = (2 * &r) % l;
        pi = pi.pow_mod(&Int::from(2), N) * g.pow_mod(&b, N);
        pi %= N;
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

pub fn verify(pi: &Int, g: &Int, h: &Int, l: u64, T: u128, N: &Int) -> bool {
    if pi > N {
        return false;
    }
    let r = pow_mod(2, T, l.into());
    *h == (pi.pow_mod(&Int::from(l), &N) * g.pow_mod(&Int::from(r), &N)) % N
}

