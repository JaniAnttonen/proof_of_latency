extern crate vdf;
use vdf::{VDFParams, WesolowskiVDFParams, VDF};

fn main() {
    let num_bits: u16 = 2048;
    let wesolowski_vdf = WesolowskiVDFParams(num_bits).new();

    let solution = wesolowski_vdf.solve(b"\xaa", 10000).unwrap();
    println!("{:?}", solution);
}
