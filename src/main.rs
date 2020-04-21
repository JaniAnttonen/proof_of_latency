use std::str::FromStr;
use std::io::BufRead;
use std::sync::mpsc::{Sender, channel};
use std::thread;
use ramp::Int;
use rand::Rng;
use rand_core::RngCore;
use sha3::{Digest, Sha3_512};
use primality::{is_prime, pow_mod};

fn main() {
    let num_bits: u16 = 2048;
    let worker = spawn_worker();

    let stdin = ::std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        worker.send(Msg::Echo(line)).unwrap();
    }

    let N = Int::from_str("135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563").expect("Cannot read string");
    let T = 100000;
    
    // Running the VDF
    let g = hash(&format!("VDFs are awesome"), &N);

    let res = vdf(&g, T, &N);
    // Sampling the prime
    let l = get_prime();
    // Generate the proof pi
    let pi = prove(&g, &res, &Int::from(l), T, &N);
    // Verify the proof
    let is_ok = verify(&pi, &g, &res, l, T, &N);
    assert!(is_ok);

}

enum Msg {
    Echo(String),
}

fn spawn_worker() -> Sender<Msg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        loop {
            let msg = rx.recv().unwrap();
            match msg {
                Msg::Echo(msg) => println!("{} love", msg),
            }
        }
    });
    tx
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

pub fn vdf(g: &Int, T: u128, N: &Int) -> Int {
    let mut ans = g.clone();
    for _ in 0..T {
        ans = ans.pow_mod(&Int::from(2), N);
    }
    ans
}

pub fn vdf_str(x: &str, T: u128, N: &str) -> String {
    let N_int = Int::from_str(N).unwrap();
    let g = hash(x, &N_int);
    let v = vdf(&g, T, &N_int);
    v.to_string()
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

