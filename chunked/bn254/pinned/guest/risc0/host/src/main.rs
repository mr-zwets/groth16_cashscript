//! Track 12 example host (RISC Zero 3.0.x).
//!   cargo run --release -- imageid                   print the image id to pin in the covenant (key 'risc0-v3')
//!   cargo run --release -- prove <request.json> <proof.json>
//! proof.json: {"system": "risc0", "imageId": "..", "journalHex": "..", "sealHex": "<selector ‖ 8 words>"}
//! Groth16 on x86-64 Linux needs the risc0-groth16 prover component (rzup) or docker.
use methods::{PAYOUT_ELF, PAYOUT_ID};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, ProverOpts, VerifierContext};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Output { locking_hex: String, value_satoshis: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request { secret_hex: String, instance_id: String, outputs: Vec<Output> }

fn main() -> anyhow_free::Result {
    let args: Vec<String> = std::env::args().collect();
    let image_id = hex::encode(Digest::from(PAYOUT_ID).as_bytes());
    if args.get(1).map(String::as_str) == Some("imageid") { println!("{image_id}"); return Ok(()); }
    assert!(args.len() == 4 && args[1] == "prove", "usage: imageid | prove <request.json> <proof.json>");
    let req: Request = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
    let instance: [u8; 32] = hex::decode(&req.instance_id)?.try_into().expect("32-byte instance id");
    let outputs: Vec<(u64, Vec<u8>)> = req.outputs.iter()
        .map(|o| (o.value_satoshis.parse().unwrap(), hex::decode(&o.locking_hex).unwrap())).collect();
    let env = ExecutorEnv::builder()
        .write(&hex::decode(&req.secret_hex)?)?.write(&instance)?.write(&outputs)?.build()?;
    let receipt = default_prover()
        .prove_with_ctx(env, &VerifierContext::default(), PAYOUT_ELF, &ProverOpts::groth16())?.receipt;
    receipt.verify(PAYOUT_ID)?;
    let seal = risc0_ethereum_contracts::encode_seal(&receipt)?; // selector ‖ Groth16 proof, as the EVM verifier takes it
    let out = serde_json::json!({"system": "risc0", "imageId": image_id,
        "journalHex": hex::encode(&receipt.journal.bytes), "sealHex": hex::encode(seal)});
    std::fs::write(&args[3], serde_json::to_string_pretty(&out)?)?;
    Ok(())
}

// a minimal boxed-error Result so the host needs no extra error crate
mod anyhow_free { pub type Result = std::result::Result<(), Box<dyn std::error::Error>>; }
