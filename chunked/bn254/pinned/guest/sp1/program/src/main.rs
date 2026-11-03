//! Track 12 example guest (SP1 v5): ZK hash-lock vault. Reads (secret, instance id, outputs), checks
//! sha256(secret) == LOCK_HASH and commits PV = encode_pv(instance, outputs) as the raw public values.
//! The covenant pins this program's vkey (`vk.bytes32()`) and rebuilds PV from the spending transaction's outputs.
#![no_main]
sp1_zkvm::entrypoint!(main);
use sha2::{Digest, Sha256};

include!("../../../shared/pv.rs");

pub fn main() {
    let secret: Vec<u8> = sp1_zkvm::io::read();
    let instance: [u8; 32] = sp1_zkvm::io::read();
    let outputs: Vec<(u64, Vec<u8>)> = sp1_zkvm::io::read();
    assert_eq!(Sha256::digest(&secret).as_slice(), &LOCK_HASH[..], "wrong secret");
    // commit_slice: the public values ARE these bytes (no bincode framing), so sha256(public values) = sha256(PV)
    sp1_zkvm::io::commit_slice(&encode_pv(&instance, &outputs));
}
