//! Track 12 example host (SP1 v5).
//!   cargo run --release -- vkey                       print the programVKey to pin in the covenant
//!   cargo run --release -- prove <request.json> <proof.json>
//! Both refuse while guest/shared/pv.rs has the example LOCK_HASH, unless --regtest is given.
//! request.json (written by `node ../../../example.mjs request <secretHex> <statement.json> request.json`):
//!   {"secretHex": "..", "instanceId": "<32 B hex>", "outputs": [{"lockingHex": "..", "valueSatoshis": "200000"}, ..]}
//! proof.json: {"system": "sp1", "programVKey": "0x..", "publicValuesHex": "..", "proofHex": "<a4594c59 ‖ 8 words>"}
//! Groth16 on CPU: SP1_PROVER=cpu (the gnark wrap step runs in docker, or natively with sp1-sdk's `native-gnark`).
use serde::Deserialize;
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};

const ELF: &[u8] = include_elf!("bch-pinned-payout");

// The guest's LOCK_HASH (the same file the guest includes) and the PUBLIC example value: refuse to print a program id
// for, or prove with, the example build unless --regtest is given (anyone can prove for any outputs under it).
#[allow(dead_code)]
mod shared { include!("../../../shared/pv.rs"); }
// sha256("verifier.cash track12 example secret: REPLACE with >=128 random bits") = example-params.mjs EXAMPLE_LOCK_HASH
const EXAMPLE_LOCK_HASH: &str = "99a364f66b31c63e9f7413d84a752e065825a6befa6d026eed90070c8e7836bf";
fn refuse_example_lock_hash(regtest: bool) {
    if hex::encode(shared::LOCK_HASH) == EXAMPLE_LOCK_HASH && !regtest {
        eprintln!("refused: guest/shared/pv.rs still has the EXAMPLE LOCK_HASH (public secret): replace it with sha256 of YOUR \
                   secret (>= 128 random bits) and rebuild, or pass --regtest");
        std::process::exit(2);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Output { locking_hex: String, value_satoshis: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request { secret_hex: String, instance_id: String, outputs: Vec<Output> }

fn main() {
    sp1_sdk::utils::setup_logger();
    let all: Vec<String> = std::env::args().collect();
    let regtest = all.iter().any(|x| x == "--regtest");
    let args: Vec<String> = all.into_iter().filter(|x| x != "--regtest").collect();
    refuse_example_lock_hash(regtest);
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(ELF);
    if args.get(1).map(String::as_str) == Some("vkey") { println!("{}", vk.bytes32()); return; }
    assert!(args.len() == 4 && args[1] == "prove", "usage: vkey | prove <request.json> <proof.json>");
    let req: Request = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
    let instance: [u8; 32] = hex::decode(&req.instance_id).unwrap().try_into().expect("32-byte instance id");
    let outputs: Vec<(u64, Vec<u8>)> = req.outputs.iter()
        .map(|o| (o.value_satoshis.parse().unwrap(), hex::decode(&o.locking_hex).unwrap())).collect();
    let mut stdin = SP1Stdin::new();
    stdin.write(&hex::decode(&req.secret_hex).unwrap());
    stdin.write(&instance);
    stdin.write(&outputs);
    let proof = client.prove(&pk, &stdin).groth16().run().expect("proving failed");
    client.verify(&proof, &vk).expect("verification failed");
    let out = serde_json::json!({
        "system": "sp1", "programVKey": vk.bytes32(),
        "publicValuesHex": hex::encode(proof.public_values.as_slice()), "proofHex": hex::encode(proof.bytes()),
    });
    std::fs::write(&args[3], serde_json::to_string_pretty(&out).unwrap()).unwrap();
}
