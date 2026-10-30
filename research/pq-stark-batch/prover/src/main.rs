//! verifier.cash Track 8 (S1) prover: Plonky3 p3-batch-stark at the pinned commit, configured with
//! SHA-256 over Goldilocks and the cubic trinomial extension, writing p3b-v1 vectors (FORMAT.md).
//!
//!   pq-stark-batch-prover prove --case NAME --set SET [--shift N|auto] [--seed K] [--sweep] --out F.json
//!   pq-stark-batch-prover check F.json...      decode every proof (and tampered case) and run verify_batch
//!   pq-stark-batch-prover accept --set SET [--shift N|auto] --outdir DIR [--sweep]
//!                                              all five DESIGN-T8 S1 cases; exit 1 on any failure
//!   pq-stark-batch-prover sets                 print the parameter sets
//!
//! Every vector is checked by decoding its bytes back into Plonky3's `BatchProof` and running
//! Plonky3's own `verify_batch` on the decoded proof, with the transcript hash inputs recorded.

mod airs;
mod cfg;
mod dag;
mod shape;
mod wire;

use std::time::Instant;

use airs::*;
use cfg::*;
use p3_air::BaseAir;
use p3_batch_stark::{BatchProof, ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use serde_json::{Value, json};
use wire::{Shape, decode, encode};

pub const PLONKY3_REV: &str = "0d803737b681774186cd283b1fd2d8e493655c82";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().position(|a| a == k).map(|i| args[i + 1].clone())
}

macro_rules! with_cfg {
    ($set:expr, $seed:expr, |$c:ident| $body:expr) => {{
        let set: &Params = $set;
        match (set.zk, set.salt) {
            (false, _) => { let $c = make_cfg(set); $body }
            (true, 2) => { let $c = make_hcfg::<2>(set, $seed); $body }
            (true, 4) => { let $c = make_hcfg::<4>(set, $seed); $body }
            _ => panic!("zk salt must be 2 or 4"),
        }
    }};
}

/// Smallest shift that puts every trace on a legal FRI height: log LDE > log_final + log_blowup
/// (strict), i.e. log n + zk > log_final_poly_len.
/// Under ZK also the hiding budget n >= 2 (D * points + Q) per matrix (DESIGN-T8 section 2.4), taken
/// with 2 opening points.
fn auto_shift(s: &Params, logs: &[usize]) -> usize {
    let mut need = s.log_final_poly_len + 1 - (s.zk as usize).min(s.log_final_poly_len + 1);
    if s.zk {
        let budget = 2 * (D * 2 + s.num_queries);
        need = need.max(budget.next_power_of_two().trailing_zeros() as usize);
    }
    need.saturating_sub(*logs.iter().min().unwrap())
}

/// Verifying-key side of a run: AIRs, heights, common data. `common` is rebuilt from the same
/// config (the hiding MMCS salts the preprocessed commitment from the seeded RNG).
struct Vk {
    shape: Shape,
    pre_commitment: Value,
    lookups: Vec<p3_lookup::Lookups<Val>>,
}

/// Decode `bytes` and run Plonky3's verify_batch on the result. Ok(()) = accepted.
macro_rules! check_bytes {
    ($cfg:expr, $airs:expr, $common:expr, $bytes:expr, $shape:expr, $pvs:expr) => {{
        match decode($bytes, $shape) {
            Err(e) => Err(format!("decode: {e}")),
            Ok(v) => match serde_json::from_value::<BatchProof<_>>(v) {
                Err(e) => Err(format!("serde: {e}")),
                Ok(proof) => {
                    // a malformed proof may make Plonky3 panic instead of returning Err; that is a reject
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        verify_batch($cfg, $airs, &proof, $pvs, $common)
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

struct Out {
    vector: Value,
    ok: bool,
}

fn quiet_panics() {
    std::panic::set_hook(Box::new(|_| {}));
}

/// Rejection cases built from the section map (plain tampering of a valid proof, per DESIGN-T8 §8).
fn tamper_cases(bytes: &[u8], sections: &[wire::Section]) -> Vec<Value> {
    let mut out = Vec::new();
    for s in sections.iter().filter(|s| s.len > 0) {
        let mut ats = vec![s.at, s.at + s.len - 1];
        ats.dedup();
        for at in ats {
            out.push(json!({"name": format!("flip {} @{}", s.name, at - s.at),
                "patch": [{"at": at, "hex": hex(&[bytes[at] ^ 0x01])}]}));
        }
    }
    // a field element set to p (non-canonical): first 8 bytes of the first ood section
    if let Some(s) = sections.iter().find(|s| s.name.starts_with("ood[") && s.len >= 8) {
        out.push(json!({"name": "non-canonical ood[0][0] = p", "patch": [{"at": s.at, "hex": hex(&wire::P.to_le_bytes())}]}));
    }
    out.push(json!({"name": "truncate 1", "truncate": bytes.len() - 1}));
    out.push(json!({"name": "extend 1", "insert": {"at": bytes.len(), "hex": "00"}}));
    out
}

fn apply_tamper(valid: &[u8], t: &Value) -> Vec<u8> {
    let mut b = valid.to_vec();
    for p in t["patch"].as_array().into_iter().flatten() {
        let at = p["at"].as_u64().unwrap() as usize;
        let h = unhex(p["hex"].as_str().unwrap());
        b[at..at + h.len()].copy_from_slice(&h);
    }
    if let Some(ins) = t.get("insert") {
        let at = ins["at"].as_u64().unwrap() as usize;
        b.splice(at..at, unhex(ins["hex"].as_str().unwrap()));
    }
    if let Some(n) = t.get("truncate") {
        b.truncate(n.as_u64().unwrap() as usize);
    }
    b
}

fn pvs_json(pvs: &[Vec<Val>]) -> Value {
    json!(pvs.iter().map(|p| p.iter().map(|x| x.as_canonical_u64().to_string()).collect::<Vec<_>>()).collect::<Vec<_>>())
}
fn pvs_from_json(v: &Value) -> Vec<Vec<Val>> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_array().unwrap().iter().map(|x| Val::from_u64(x.as_str().unwrap().parse().unwrap())).collect())
        .collect()
}

/// Prove one case, encode, decode, verify; optionally run the tamper sweep. Also self-checks the
/// exported DAG on every row of every trace (base constraints only).
fn run_case(case_name: &str, set: &Params, shift_arg: &str, seed: u64, sweep: bool) -> Out {
    let base = case(case_name, 0);
    let shift = if shift_arg == "auto" { auto_shift(set, &base.log_heights) } else { shift_arg.parse().unwrap() };
    let c = case(case_name, shift);
    let zk = set.zk as usize;
    let degs: Vec<usize> = c.log_heights.iter().map(|l| l + zk).collect();
    let trefs: Vec<&_> = c.traces.iter().collect();

    with_cfg!(set, seed, |config| {
        let pd = ProverData::from_airs_and_degrees(&config, &c.airs, &degs).expect("setup");
        let inst = StarkInstance::new_multiple(&c.airs, &trefs, &c.pvs);
        let t0 = Instant::now();
        let proof = prove_batch(&config, &inst, &pd).expect("prove_batch");
        let prove_ms = t0.elapsed().as_millis();
        verify_batch(&config, &c.airs, &proof, &c.pvs, &pd.common).expect("Plonky3 rejected its own proof");
        let pj = serde_json::to_value(&proof).unwrap();

        let lookups: Vec<_> = pd.common.lookups.clone();
        let pre_order = pd.common.preprocessed.as_ref().map(|g| g.matrix_to_instance.clone());
        let pre_commitment = pd
            .common
            .preprocessed
            .as_ref()
            .map(|g| serde_json::to_value(&g.commitment).unwrap())
            .unwrap_or(Value::Null);
        let vk = Vk {
            shape: shape::derive(set, &c.airs, &c.log_heights, &lookups, pre_order.as_deref()),
            pre_commitment,
            lookups,
        };
        let (bytes, sizes, sections) = encode(&pj, &vk.shape);

        // round trip: bytes -> Plonky3 proof -> verify_batch, recording the transcript
        tap_start();
        let t1 = Instant::now();
        let back = check_bytes!(&config, &c.airs, &pd.common, &bytes, &vk.shape, &c.pvs);
        let verify_ms = t1.elapsed().as_millis();
        let transcript = tap_take();
        let mut ok = back.is_ok();
        if !ok {
            eprintln!("ROUND TRIP FAILED: {back:?}");
        }
        // decode(encode(p)) must reproduce Plonky3's own serde tree exactly
        let same_tree = decode(&bytes, &vk.shape).map(|v| v == pj).unwrap_or(false);
        if !same_tree {
            eprintln!("decode(encode(proof)) differs from the Plonky3 serde tree");
            ok = false;
        }

        // DAG export + row self-check
        let mut dags = Vec::new();
        let mut row_check = Vec::new();
        for (i, air) in c.airs.iter().enumerate() {
            let d = dag::export(air, &vk.lookups[i]);
            let t = &c.traces[i];
            let n = t.height();
            let pre = <TestAir as BaseAir<Val>>::preprocessed_trace(air);
            let periodic = <TestAir as BaseAir<Val>>::periodic_columns(air);
            let mut bad_rows = 0;
            let mut checked = 0;
            for r in 0..n {
                let row = |k: usize| t.row_slice(k % n).unwrap().to_vec();
                let prow = |k: usize| pre.as_ref().map(|p| p.row_slice(k % n).unwrap().to_vec()).unwrap_or_default();
                let per: Vec<Val> = periodic.iter().map(|col| col[r % col.len()]).collect();
                let sel = (
                    if r == 0 { Val::ONE } else { Val::ZERO },
                    if r == n - 1 { Val::ONE } else { Val::ZERO },
                    if r == n - 1 { Val::ZERO } else { Val::ONE },
                );
                let vals = dag::eval_base_row(&d, &row(r), &row(r + 1), &prow(r), &prow(r + 1), &per, &c.pvs[i], sel);
                for v in vals.into_iter().flatten() {
                    checked += 1;
                    if v != Val::ZERO {
                        bad_rows += 1;
                    }
                }
            }
            // and one deliberately broken trace cell must violate some base constraint
            let mut broken_hits = 0;
            if t.width() > 0 {
                let mut tv = t.values.clone();
                tv[t.width() + 0] += Val::ONE; // row 1, column 0
                let tb = p3_matrix::dense::RowMajorMatrix::new(tv, t.width());
                for r in 0..3.min(n) {
                    let row = |k: usize| tb.row_slice(k % n).unwrap().to_vec();
                    let prow = |k: usize| pre.as_ref().map(|p| p.row_slice(k % n).unwrap().to_vec()).unwrap_or_default();
                    let per: Vec<Val> = periodic.iter().map(|col| col[r % col.len()]).collect();
                    let sel = (
                        if r == 0 { Val::ONE } else { Val::ZERO },
                        if r == n - 1 { Val::ONE } else { Val::ZERO },
                        if r == n - 1 { Val::ZERO } else { Val::ONE },
                    );
                    let vals = dag::eval_base_row(&d, &row(r), &row(r + 1), &prow(r), &prow(r + 1), &per, &c.pvs[i], sel);
                    broken_hits += vals.into_iter().flatten().filter(|v| *v != Val::ZERO).count();
                }
            }
            if bad_rows > 0 {
                eprintln!("DAG row check: instance {i}: {bad_rows} nonzero base constraint values on the valid trace");
                ok = false;
            }
            // a lookup-only column (MulLookups' last column) is not covered by base constraints
            let lookup_only = matches!(air, TestAir::MulLookups(_));
            if broken_hits == 0 && !lookup_only {
                eprintln!("DAG row check: instance {i}: a broken cell violates no base constraint");
                ok = false;
            }
            row_check.push(json!({"instance": i, "base_values_checked": checked, "nonzero_on_valid": bad_rows,
                "nonzero_after_breaking_row1_col0": broken_hits}));
            dags.push(d);
        }

        // tamper sweep
        let mut tamper_summary = Value::Null;
        let mut tampered = Vec::new();
        if sweep {
            quiet_panics();
            let cases = tamper_cases(&bytes, &sections);
            let mut unexpected = Vec::new();
            for t in &cases {
                let b = apply_tamper(&bytes, t);
                let r = check_bytes!(&config, &c.airs, &pd.common, &b, &vk.shape, &c.pvs);
                if r.is_ok() {
                    unexpected.push(t["name"].clone());
                }
            }
            // wrong public values (each instance with public values: first value + 1)
            let mut pv_cases = 0;
            for i in 0..c.pvs.len() {
                if c.pvs[i].is_empty() {
                    continue;
                }
                let mut pv = c.pvs.clone();
                pv[i][0] += Val::ONE;
                pv_cases += 1;
                if check_bytes!(&config, &c.airs, &pd.common, &bytes, &vk.shape, &pv).is_ok() {
                    unexpected.push(json!(format!("public value [{i}][0] + 1")));
                }
            }
            let _ = std::panic::take_hook();
            if !unexpected.is_empty() {
                ok = false;
                eprintln!("TAMPER: accepted {unexpected:?}");
            }
            tamper_summary = json!({"cases": cases.len() + pv_cases, "unexpected_accepts": unexpected});
            tampered = cases;
        }

        let vector = json!({
            "format": wire::FORMAT,
            "plonky3_rev": PLONKY3_REV,
            "case": case_name,
            "plonky3_test": format!("p3-batch-stark tests/simple.rs: test_{}{}", if case_name == "both_lookups_zk" { "batch_stark_" } else { "" }, case_name),
            "airs": c.airs.iter().map(|a| a.label()).collect::<Vec<_>>(),
            "log_heights": c.log_heights,
            "shift": shift,
            "seed": seed,
            "set": set,
            "shape": vk.shape,
            "public_values": pvs_json(&c.pvs),
            "preprocessed_commitment": vk.pre_commitment,
            "proof_hex": hex(&bytes),
            "sizes": sizes,
            "sections": sections,
            "prove_ms": prove_ms,
            "rust_verify_ms": verify_ms,
            "rust_verify": if back.is_ok() { "accepted".to_string() } else { format!("REJECTED {back:?}") },
            "decode_encode_identity": same_tree,
            "dag": dags,
            "dag_row_check": row_check,
            "tamper_sweep": tamper_summary,
            "tampered": tampered,
            "transcript_hash_inputs": transcript.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        });
        eprintln!(
            "{case_name}: set={} shift={shift} heights={:?} bytes={} prove={}ms verify={}ms folds={:?} caps={:?} round-trip={} sweep={} -> {}",
            set.name,
            c.log_heights,
            bytes.len(),
            prove_ms,
            verify_ms,
            vk.shape.log_arities,
            vk.shape.rounds.iter().map(|r| (r.name.clone(), r.cap_len)).collect::<Vec<_>>(),
            back.is_ok(),
            vector["tamper_sweep"],
            if ok { "OK" } else { "FAIL" }
        );
        Out { vector, ok }
    })
}

fn write_vector(path: &str, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn cmd_prove(args: &[String]) {
    let set = get_set(&arg(args, "--set").expect("--set"));
    let o = run_case(
        &arg(args, "--case").expect("--case"),
        &set,
        &arg(args, "--shift").unwrap_or("0".into()),
        arg(args, "--seed").map(|s| s.parse().unwrap()).unwrap_or(1),
        args.iter().any(|a| a == "--sweep"),
    );
    write_vector(&arg(args, "--out").expect("--out"), &o.vector);
    if !o.ok {
        std::process::exit(1);
    }
}

fn cmd_accept(args: &[String]) {
    // `--set P3`: each test with Plonky3's own FRI shape and ZK setting (PT for the plain tests,
    // PTZ for the *_zk tests), at Plonky3's heights
    let set_name = arg(args, "--set").expect("--set");
    let faithful = set_name == "P3";
    let set = get_set(if faithful { "PT" } else { &set_name });
    let shift = arg(args, "--shift").unwrap_or("auto".into());
    let dir = arg(args, "--outdir").expect("--outdir");
    let sweep = args.iter().any(|a| a == "--sweep");
    std::fs::create_dir_all(&dir).unwrap();
    let mut rows = Vec::new();
    let mut all_ok = true;
    for name in CASES {
        let set = if faithful && case(name, 0).zk_in_plonky3 { get_set("PTZ") } else { set.clone() };
        let o = run_case(name, &set, &shift, 1, sweep);
        all_ok &= o.ok;
        // ZK: a second seed must give different proof bytes for the same witness
        let mut fresh = Value::Null;
        if set.zk {
            let o2 = run_case(name, &set, &shift, 2, false);
            let differ = o2.vector["proof_hex"] != o.vector["proof_hex"];
            all_ok &= o2.ok && differ;
            fresh = json!(differ);
        }
        let file = format!("{dir}/{name}-{}.json", set.name.replace('+', "_").replace('=', ""));
        write_vector(&file, &o.vector);
        rows.push(json!({"case": name, "file": file, "ok": o.ok, "bytes": o.vector["sizes"]["total"],
            "prove_ms": o.vector["prove_ms"], "rust_verify_ms": o.vector["rust_verify_ms"],
            "log_heights": o.vector["log_heights"], "log_arities": o.vector["shape"]["log_arities"],
            "tamper_sweep": o.vector["tamper_sweep"], "seed2_bytes_differ": fresh,
            "transcript_hash_inputs": o.vector["transcript_hash_inputs"].as_array().unwrap().len()}));
    }
    let summary = json!({"set": set_name, "all_ok": all_ok, "cases": rows});
    write_vector(&format!("{dir}/accept-{}.json", set_name.replace('+', "_").replace('=', "")), &summary);
    eprintln!("accept {set_name}: {}", if all_ok { "ALL OK" } else { "FAILURES" });
    if !all_ok {
        std::process::exit(1);
    }
}

/// check FILE...: rebuild the verifying key from the vector's case/set/shift/seed, require the same
/// shape and preprocessed commitment, decode proof_hex (+ every tampered case), run verify_batch.
fn cmd_check(files: &[String]) {
    quiet_panics();
    let mut bad = 0;
    let mut n = 0;
    for f in files {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let set: Params = serde_json::from_value(v["set"].clone()).unwrap();
        let shape: Shape = serde_json::from_value(v["shape"].clone()).unwrap();
        let shift = v["shift"].as_u64().unwrap() as usize;
        let seed = v["seed"].as_u64().unwrap();
        let c = case(v["case"].as_str().unwrap(), shift);
        let zk = set.zk as usize;
        let degs: Vec<usize> = c.log_heights.iter().map(|l| l + zk).collect();
        let pvs = pvs_from_json(&v["public_values"]);
        let valid = unhex(v["proof_hex"].as_str().unwrap());
        with_cfg!(&set, seed, |config| {
            let pd = ProverData::from_airs_and_degrees(&config, &c.airs, &degs).expect("setup");
            let pre_order = pd.common.preprocessed.as_ref().map(|g| g.matrix_to_instance.clone());
            let s2 = shape::derive(&set, &c.airs, &c.log_heights, &pd.common.lookups, pre_order.as_deref());
            let pc = pd.common.preprocessed.as_ref().map(|g| serde_json::to_value(&g.commitment).unwrap()).unwrap_or(Value::Null);
            let vk_ok = s2 == shape && pc == v["preprocessed_commitment"];
            if !vk_ok {
                println!("FAIL {f}: verifying key differs from the vector's shape/preprocessed commitment");
                bad += 1;
            }
            let mut cases = if vk_ok { vec![("valid".to_string(), valid.clone(), true)] } else { vec![] };
            for t in v["tampered"].as_array().into_iter().flatten().filter(|_| vk_ok) {
                cases.push((t["name"].as_str().unwrap().to_string(), apply_tamper(&valid, t), false));
            }
            for (name, b, expect) in cases {
                let r = check_bytes!(&config, &c.airs, &pd.common, &b, &shape, &pvs);
                n += 1;
                let ok = r.is_ok() == expect;
                if !ok {
                    bad += 1;
                }
                if !ok || expect {
                    println!("{} {f} {name}: {}", if ok { "ok  " } else { "FAIL" }, if r.is_ok() { "ACCEPT" } else { "REJECT" });
                }
            }
        });
    }
    eprintln!("rust check: {n} cases, {bad} unexpected");
    if bad > 0 {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") => cmd_prove(&args[2..]),
        Some("accept") => cmd_accept(&args[2..]),
        Some("check") => cmd_check(&args[2..]),
        Some("sets") => {
            for s in all_sets() {
                println!("{}", serde_json::to_string(&s).unwrap());
            }
        }
        _ => {
            eprintln!("usage: prove|accept|check|sets (see src/main.rs)");
            std::process::exit(2);
        }
    }
}
