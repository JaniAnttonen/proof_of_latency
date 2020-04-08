extern crate vdf;
use std::sync::mpsc::channel;
use std::thread;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

fn main() {
    let (sender, receiver) = channel();
    let num_bits: u16 = 2048;
    let wesolowski_vdf = WesolowskiVDFParams(num_bits).new();

    thread::spawn(move || {
        sender.send(wesolowski_vdf.solve(b"\xaa", 10000)).unwrap();
    });

    println!("{:?}", receiver.recv().unwrap());
}
