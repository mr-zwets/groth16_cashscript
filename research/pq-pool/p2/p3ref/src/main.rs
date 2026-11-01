//! Reads lines of 8 decimal u64 (each < p) on stdin; prints, per line, the 8 output lanes of
//! p3_goldilocks::default_goldilocks_poseidon2_8() (stock Plonky3 constants), as decimal.
use std::io::{BufRead, Write};

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;

fn main() {
    let p2 = p3_goldilocks::default_goldilocks_poseidon2_8();
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let v: Vec<u64> = line.split_whitespace().map(|t| t.parse().unwrap()).collect();
        if v.is_empty() {
            continue;
        }
        assert_eq!(v.len(), 8, "need 8 lanes");
        let x: [Goldilocks; 8] = core::array::from_fn(|i| {
            assert!(v[i] < Goldilocks::ORDER_U64, "lane >= p");
            Goldilocks::from_u64(v[i])
        });
        let y = p2.permute(x);
        let s: Vec<String> = y.iter().map(|e| e.as_canonical_u64().to_string()).collect();
        writeln!(out, "{}", s.join(" ")).unwrap();
    }
}
