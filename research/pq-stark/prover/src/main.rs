//! verifier.cash Track 5 prover: Plonky3 uni-stark (pinned commit) configured with SHA-256 over
//! Goldilocks, writing p3s-v1 proof vectors for the JS reference verifier and a CashVM verifier.
//!
//!   pq-stark-prover prove --air fib|mimc --log-n N --set NAME [--k K] [--zk] --out FILE.json
//!   pq-stark-prover check FILE.json...     (decode every proof in the file and run Plonky3's verifier)
//!   pq-stark-prover sets                   (print the parameter sets and Plonky3's security estimates)

mod airs;
mod cfg;
mod sets;
mod wire;

use std::time::Instant;

use airs::*;
use cfg::*;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, prove, verify};
use serde_json::{Value, json};
use wire::{Shape, decode, encode};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Shape that the verifier derives from the parameter set and the AIR (not from the proof).
fn shape_for(set: &FriSet, width: usize, num_chunks: usize, log_lde: usize) -> Shape {
    let d = set.ext;
    // fold schedule: one input height (all matrices share log_lde), greedy max arity
    let mut las = Vec::new();
    let mut h = log_lde;
    let fin = set.log_blowup + set.log_final_poly_len;
    while h > fin {
        let la = (h - fin).min(set.max_log_arity);
        las.push(la);
        h -= la;
    }
    let mut batch_widths = Vec::new();
    let rc = if set.zk { set.num_random_codewords } else { 0 };
    if set.zk {
        batch_widths.push(vec![d + rc]);
    }
    batch_widths.push(vec![width + rc]);
    batch_widths.push(vec![d + rc; num_chunks]);
    Shape {
        ext: d,
        width,
        opens_next: true,
        num_chunks,
        zk: set.zk,
        salt: if set.zk { set.salt } else { 0 },
        rc,
        digest: set.digest,
        log_arities: las,
        num_queries: set.num_queries,
        final_poly_len: 1 << set.log_final_poly_len,
        ood_pow: false,
        batch_pow: set.batch_pow_bits > 0,
        commit_pow: set.commit_pow_bits > 0,
        query_pow: set.query_pow_bits > 0,
        batch_widths,
    }
}

struct Run {
    proof_json: Value,
    prove_ms: u128,
    verify_ms: u128,
    transcript: Vec<Vec<u8>>,
}

macro_rules! with_cfg {
    ($set:expr, $seed:expr, |$c:ident| $body:expr) => {{
        let set: &FriSet = $set;
        match (set.ext, set.zk, if set.zk { set.salt } else { set.digest }) {
            (2, false, 32) => { let $c = make_cfg::<EF2>(set); $body }
            (3, false, 32) => { let $c = make_cfg::<EF3>(set); $body }
            (2, false, 25) => { let $c = make_tcfg::<EF2, 25>(set); $body }
            (3, false, 25) => { let $c = make_tcfg::<EF3, 25>(set); $body }
            (2, true, 4) => { let $c = make_hcfg::<EF2, 4>(set, $seed); $body }
            (3, true, 4) => { let $c = make_hcfg::<EF3, 4>(set, $seed); $body }
            (2, true, 2) => { let $c = make_hcfg::<EF2, 2>(set, $seed); $body }
            (3, true, 2) => { let $c = make_hcfg::<EF3, 2>(set, $seed); $body }
            _ => panic!("ext 2|3; zk: salt 2|4 (digest 32); plain: digest 32|25"),
        }
    }};
}

macro_rules! run_air {
    ($c:expr, $air:expr, $trace:expr, $pis:expr) => {{
        let t0 = Instant::now();
        let proof = prove($c, $air, $trace, $pis).expect("prove");
        let prove_ms = t0.elapsed().as_millis();
        tap_start();
        let t1 = Instant::now();
        verify($c, $air, &proof, $pis).expect("Plonky3 rejected its own proof");
        let verify_ms = t1.elapsed().as_millis();
        let transcript = tap_take();
        Run { proof_json: serde_json::to_value(&proof).unwrap(), prove_ms, verify_ms, transcript }
    }};
}

/// Decode `bytes` with `shape` and run Plonky3's verifier on it. Ok(()) = accepted.
macro_rules! check_bytes {
    ($c:expr, $air:expr, $bytes:expr, $shape:expr, $pis:expr) => {{
        match decode($bytes, $shape) {
            Err(e) => Err(format!("decode: {e}")),
            Ok(v) => match serde_json::from_value(v) {
                Err(e) => Err(format!("serde: {e}")),
                Ok(proof) => {
                    let proof: Proof<_> = proof;
                    // a malformed proof may make Plonky3 panic instead of returning Err; treat as reject
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        verify($c, $air, &proof, $pis)
                    }));
                    match r {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(format!("{e:?}")),
                        Err(_) => Err("panic".into()),
                    }
                }
            },
        }
    }};
}

/// tampered case = valid bytes + overwrite patches, then an optional insertion, then an optional truncation
fn apply_tamper(valid: &[u8], t: &Value) -> Vec<u8> {
    let mut b = valid.to_vec();
    for p in t["patch"].as_array().into_iter().flatten() {
        let at = p["at"].as_u64().unwrap() as usize;
        let h = unhex(p["hex"].as_str().unwrap());
        b[at..at + h.len()].copy_from_slice(&h);
    }
    if let Some(ins) = t.get("insert") {
        let at = ins["at"].as_u64().unwrap() as usize;
        let h = unhex(ins["hex"].as_str().unwrap());
        b.splice(at..at, h);
    }
    if let Some(n) = t.get("truncate") {
        b.truncate(n.as_u64().unwrap() as usize);
    }
    b
}

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).map(|i| args[i + 1].clone())
}

fn statement(air: &str, log_n: usize, k: u8) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let n = 1usize << log_n;
    match air {
        "fib" => fib_trace(k as u64, 1 + k as u64, n),
        "mimc" => mimc_trace(mimc_x_in(k), n),
        _ => panic!("air"),
    }
}

fn cmd_prove(args: &[String]) {
    use p3_field::PrimeField64;
    let air = arg(args, "--air").expect("--air");
    let log_n: usize = arg(args, "--log-n").expect("--log-n").parse().unwrap();
    let k: u8 = arg(args, "--k").map(|s| s.parse().unwrap()).unwrap_or(0);
    let mut set = sets::get(&arg(args, "--set").expect("--set"));
    // --zk: Plonky3's hiding PCS with its test defaults (4 random codewords, 4-element salts);
    // --zkmin: the smallest allowed (random codewords = extension degree, 2-element = 128-bit salts).
    // The hiding MMCS here uses full 32-byte digests.
    if args.iter().any(|a| a == "--zk" || a == "--zkmin") {
        set.zk = true;
        set.digest = 32;
        if args.iter().any(|a| a == "--zkmin") {
            set.num_random_codewords = set.ext;
            set.salt = 2;
            set.name.push_str("-zkmin");
        } else {
            set.name.push_str("-zk");
        }
    }
    let out = arg(args, "--out").expect("--out");
    let seed = 1000 + k as u64;
    let (trace, pis) = statement(&air, log_n, k);
    let width = trace.width;
    let run = with_cfg!(&set, seed, |c| {
        match air.as_str() {
            "fib" => run_air!(&c, &FibAir, trace, &pis),
            _ => run_air!(&c, &MimcAir::new(), trace, &pis),
        }
    });
    let p = &run.proof_json;
    if std::env::var("P3_RAW").is_ok() {
        std::fs::write(format!("{out}.raw.json"), serde_json::to_string(p).unwrap()).unwrap();
    }
    let num_chunks = p["opened_values"]["quotient_chunks"].as_array().unwrap().len();
    let degree_bits = p["degree_bits"].as_u64().unwrap() as usize;
    let log_lde = degree_bits + set.log_blowup;
    let shape = shape_for(&set, width, num_chunks, log_lde);
    let (bytes, sizes) = encode(p, &shape);
    // round trip through our format and Plonky3's verifier
    let back = with_cfg!(&set, seed, |c| {
        match air.as_str() {
            "fib" => check_bytes!(&c, &FibAir, &bytes, &shape, &pis),
            _ => check_bytes!(&c, &MimcAir::new(), &bytes, &shape, &pis),
        }
    });
    assert!(back.is_ok(), "round trip failed: {back:?}");
    let seps = match (set.ext, air.as_str()) {
        (2, "fib") => sets::separators::<EF2, _>(&FibAir, &set, &shape, degree_bits),
        (2, _) => sets::separators::<EF2, _>(&MimcAir::new(), &set, &shape, degree_bits),
        (_, "fib") => sets::separators::<EF3, _>(&FibAir, &set, &shape, degree_bits),
        _ => sets::separators::<EF3, _>(&MimcAir::new(), &set, &shape, degree_bits),
    };
    let estimates = sets::estimates(&set, &air, log_n);
    let pis_u: Vec<String> = pis.iter().map(|x| x.as_canonical_u64().to_string()).collect();
    let v = json!({
        "format": "p3s-v1",
        "plonky3_rev": sets::PLONKY3_REV,
        "air": air, "log_n": log_n, "k": k,
        "set": set, "shape": shape,
        "public_values": pis_u,
        "proof_hex": hex(&bytes),
        "sizes": sizes,
        "prove_ms": run.prove_ms, "rust_verify_ms": run.verify_ms,
        "rust_verify": "accepted",
        "plonky3_security_estimates": estimates,
        "debug_separators": seps,
        "transcript_hash_inputs": run.transcript.iter().map(|b| hex(b)).collect::<Vec<_>>(),
    });
    std::fs::write(&out, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    eprintln!(
        "{out}: {} {} n=2^{log_n} set={} bytes={} prove={}ms verify={}ms chunks={num_chunks} folds={:?}",
        air, k, set.name, bytes.len(), run.prove_ms, run.verify_ms, shape.log_arities
    );
}

/// check FILE...: decode proof_hex and every tampered[i].proof_hex, run Plonky3's verifier,
/// compare with the expected verdicts; print one line per case and a JSON summary.
fn cmd_check(args: &[String]) {
    let mut bad = 0;
    let mut results = Vec::new();
    for f in args {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let set: FriSet = sets::from_json(&v["set"]);
        let shape: Shape = sets::shape_from_json(&v["shape"]);
        let air = v["air"].as_str().unwrap().to_string();
        let seed = 1000 + v["k"].as_u64().unwrap();
        let mut cases = vec![(
            "valid".to_string(),
            v["proof_hex"].as_str().unwrap().to_string(),
            v["public_values"].clone(),
            true,
        )];
        if let Some(t) = v["tampered"].as_array() {
            for c in t {
                cases.push((
                    c["name"].as_str().unwrap().to_string(),
                    hex(&apply_tamper(&unhex(v["proof_hex"].as_str().unwrap()), c)),
                    c.get("public_values").cloned().unwrap_or(v["public_values"].clone()),
                    false,
                ));
            }
        }
        for (name, ph, pv, expect) in cases {
            use p3_field::PrimeCharacteristicRing;
            let pis: Vec<Val> =
                pv.as_array().unwrap().iter().map(|x| Val::from_u64(x.as_str().unwrap().parse().unwrap())).collect();
            let bytes = unhex(&ph);
            let r = with_cfg!(&set, seed, |c| {
                match air.as_str() {
                    "fib" => check_bytes!(&c, &FibAir, &bytes, &shape, &pis),
                    _ => check_bytes!(&c, &MimcAir::new(), &bytes, &shape, &pis),
                }
            });
            let ok = r.is_ok() == expect;
            if !ok {
                bad += 1;
            }
            println!(
                "{} {f} {name}: {}{}",
                if ok { "ok  " } else { "FAIL" },
                if r.is_ok() { "ACCEPT".to_string() } else { "REJECT".to_string() },
                r.err().map(|e| format!(" ({})", &e[..e.len().min(110)])).unwrap_or_default()
            );
            results.push(json!({"file": f, "case": name, "ok": ok}));
        }
    }
    eprintln!("rust check: {} cases, {} unexpected", results.len(), bad);
    if bad > 0 {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") => cmd_prove(&args[2..]),
        Some("check") => cmd_check(&args[2..]),
        Some("sets") => sets::print_sets(),
        Some("estimate") => {
            // estimate SET AIR LOGN [--zk]
            let mut s = sets::get(&args[2]);
            s.zk = args.iter().any(|a| a == "--zk");
            println!("{}", sets::estimates(&s, &args[3], args[4].parse().unwrap()));
        }
        _ => {
            eprintln!("usage: prove|check|sets");
            std::process::exit(2);
        }
    }
}
