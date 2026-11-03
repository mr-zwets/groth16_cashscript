//! Track 12 example host (SP1 v5).
//!   cargo run --release -- vkey                       print the programVKey to pin in the covenant
//!   cargo run --release -- prove <request.json> <proof.json>
//! request.json (written by `node ../../../example.mjs request sp1 ...`):
//!   {"secretHex": "..", "instanceId": "<32 B hex>", "outputs": [{"lockingHex": "..", "valueSatoshis": "200000"}, ..]}
//! proof.json: {"system": "sp1", "programVKey": "0x..", "publicValuesHex": "..", "proofHex": "<a4594c59 ‖ 8 words>"}
//! Groth16 on CPU: SP1_PROVER=cpu (the gnark wrap step runs in docker, or natively with sp1-sdk's `native-gnark`).
use serde::Deserialize;
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};

const ELF: &[u8] = include_elf!("bch-pinned-payout");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Output { locking_hex: String, value_satoshis: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request { secret_hex: String, instance_id: String, outputs: Vec<Output> }

fn main() {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = std::env::args().collect();
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
