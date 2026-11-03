//! Track 12 example guest (RISC Zero): ZK hash-lock vault. Reads (secret, instance id, outputs), checks
//! sha256(secret) == LOCK_HASH and commits the journal = PV = encode_pv(instance, outputs) (raw bytes).
//! The covenant pins this guest's image id and rebuilds the receipt claim digest from it and sha256(PV).
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

include!("../../../../shared/pv.rs");

fn main() {
    let secret: Vec<u8> = env::read();
    let instance: [u8; 32] = env::read();
    let outputs: Vec<(u64, Vec<u8>)> = env::read();
    assert_eq!(Sha256::digest(&secret).as_slice(), &LOCK_HASH[..], "wrong secret");
    env::commit_slice(&encode_pv(&instance, &outputs));
}
