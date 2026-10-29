//! Parameter sets. These are the Prover task's provisional picks (conjectured ~100 / ~128 bits, plus
//! Track-4-shaped provable-regime sets for comparison); the Verifier re-picks from the Soundness
//! handoff. `sets` prints Plonky3's own security estimators (p3-uni-stark `security.rs`) for each.

use p3_air::symbolic::AirLayout;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_uni_stark::{
    ConjecturedSecurity, GrindingSites, LegacySecurity, OpeningShape, ProvenSecurity,
    StarkSecurityParams,
};
use serde_json::Value;

use crate::airs::{FibAir, MimcAir, Val};
use crate::cfg::{EF2, EF3, FriSet};
use crate::wire::Shape;

pub const PLONKY3_REV: &str = "0d803737b681774186cd283b1fd2d8e493655c82";

fn mk(name: &str, ext: usize, lb: usize, q: usize, qpow: usize, arity: usize, lf: usize) -> FriSet {
    FriSet {
        name: name.into(),
        ext,
        log_blowup: lb,
        log_final_poly_len: lf,
        max_log_arity: arity,
        num_queries: q,
        batch_pow_bits: 0,
        commit_pow_bits: 0,
        query_pow_bits: qpow,
        zk: false,
        num_random_codewords: 4,
        salt: 4,
        digest: 32,
    }
}

fn pw(mut s: FriSet, commit_pow: usize, batch_pow: usize) -> FriSet {
    s.commit_pow_bits = commit_pow;
    s.batch_pow_bits = batch_pow;
    s
}

pub fn all() -> Vec<FriSet> {
    let h25 = |mut s: FriSet| {
        s.digest = 25;
        s
    };
    vec![
        // conjectured regime: Plonky3's own estimator (ePrint 2025/2010 "random words") >= 100 / 128
        mk("C100", 2, 3, 27, 21, 3, 5),
        h25(mk("C100h", 2, 3, 27, 21, 3, 5)),
        mk("C128", 3, 3, 36, 22, 3, 5),
        // Track 4's provable-regime FRI shapes (rho, queries, 28-bit query grinding, digest bytes);
        // Plonky3's proven (list-decoding) estimator gives 100 and 128 bits for these
        h25(mk("P100", 3, 7, 22, 28, 3, 5)),
        mk("P128", 3, 5, 43, 28, 3, 5),
        // Soundness-phase picks (wip/pq-stark-soundness 6ac98c3, SOUNDNESS.md section 5; per-round
        // Johnson-bound analysis, e = 3, 32-byte digests). Their e = 3 is a binomial u^3 - 7 patch;
        // here it is Plonky3's stock cubic trinomial x^3 - x - 1 (same q = p^3).
        pw(mk("S100", 3, 5, 30, 27, 3, 7), 0, 0),
        pw(mk("S100b", 3, 8, 19, 25, 4, 8), 0, 0),
        pw(mk("S128", 3, 8, 26, 26, 4, 8), 15, 23),
        pw(mk("S128b", 3, 5, 41, 28, 3, 7), 7, 14),
        // their ZK rows (HidingFriPcs, num_random_codewords = e): run with --zkmin
        pw(mk("S100z", 3, 8, 19, 25, 4, 6), 0, 3),
        pw(mk("S128z", 3, 8, 26, 27, 3, 8), 13, 22),
        // tiny set for fast tests (not secure)
        mk("TOY", 2, 2, 4, 2, 2, 1),
        pw(mk("TOYPOW", 3, 2, 4, 3, 2, 1), 2, 2),
    ]
}

pub fn get(name: &str) -> FriSet {
    let base = name.split('+').next().unwrap();
    let mut s = all().into_iter().find(|s| s.name == base).unwrap_or_else(|| panic!("set {name}"));
    // overrides: NAME+lb=5+q=30+qpow=20+arity=2+lf=4+ext=3+cpow=0+bpow=0
    for kv in name.split('+').skip(1) {
        let (k, v) = kv.split_once('=').expect("k=v");
        let v: usize = v.parse().unwrap();
        match k {
            "lb" => s.log_blowup = v,
            "q" => s.num_queries = v,
            "qpow" => s.query_pow_bits = v,
            "cpow" => s.commit_pow_bits = v,
            "bpow" => s.batch_pow_bits = v,
            "arity" => s.max_log_arity = v,
            "lf" => s.log_final_poly_len = v,
            "ext" => s.ext = v,
            "rc" => s.num_random_codewords = v,
            "salt" => s.salt = v,
            "h" => s.digest = v,
            _ => panic!("override {k}"),
        }
    }
    s.name = name.to_string();
    s
}

pub fn from_json(v: &Value) -> FriSet {
    let u = |k: &str| v[k].as_u64().unwrap() as usize;
    FriSet {
        name: v["name"].as_str().unwrap().into(),
        ext: u("ext"),
        log_blowup: u("log_blowup"),
        log_final_poly_len: u("log_final_poly_len"),
        max_log_arity: u("max_log_arity"),
        num_queries: u("num_queries"),
        batch_pow_bits: u("batch_pow_bits"),
        commit_pow_bits: u("commit_pow_bits"),
        query_pow_bits: u("query_pow_bits"),
        zk: v["zk"].as_bool().unwrap(),
        num_random_codewords: u("num_random_codewords"),
        salt: u("salt"),
        digest: u("digest"),
    }
}

pub fn shape_from_json(v: &Value) -> Shape {
    serde_json::from_value(v.clone()).expect("shape")
}

fn regime(s: &FriSet) -> p3_security::fri::FriRegime {
    p3_security::fri::FriRegime {
        log_blowup: s.log_blowup,
        num_queries: s.num_queries,
        log_final_poly_len: s.log_final_poly_len,
        max_log_arity: s.max_log_arity,
        commit_pow_bits: s.commit_pow_bits,
        query_pow_bits: s.query_pow_bits,
    }
}

/// Plonky3's estimators for set `s`, AIR `air` ("fib" / "mimc"), trace length 2^log_n.
pub fn estimates(s: &FriSet, air: &str, log_n: usize) -> Value {
    let layout = AirLayout {
        main_width: if air == "fib" { 2 } else { 3 },
        num_public_values: if air == "fib" { 3 } else { 2 },
        num_periodic_columns: if air == "fib" { 0 } else { 1 },
        ..Default::default()
    };
    let dom = TwoAdicMultiplicativeCoset::<Val>::new(<Val as p3_field::PrimeCharacteristicRing>::ONE, log_n).unwrap();
    let openings = if s.zk { OpeningShape::hiding(s.num_random_codewords) } else { OpeningShape::new() };
    let grinding = GrindingSites { batch_combination: s.batch_pow_bits, ..GrindingSites::NONE };
    let modbits = 64 * s.ext - 1;
    macro_rules! p {
        ($ef:ty, $a:expr) => {
            StarkSecurityParams::from_air::<Val, $ef, _>(
                regime(s), $a, layout, dom, modbits, 4 * s.digest, 2, openings, grinding,
            )
        };
    }
    let params = match (s.ext, air) {
        (2, "fib") => p!(EF2, &FibAir),
        (2, _) => p!(EF2, &MimcAir::new()),
        (_, "fib") => p!(EF3, &FibAir),
        _ => p!(EF3, &MimcAir::new()),
    };
    let degree_bits = log_n + s.zk as usize;
    let pr = ProvenSecurity::compute_from_proof(degree_bits, &params);
    serde_json::json!({
        "conjectured_bits": ConjecturedSecurity::compute_from_params(&params, degree_bits).security_bits,
        "legacy_conjectured_bits": LegacySecurity::compute_from_params(&params, degree_bits).security_bits,
        "proven_udr_bits": pr.unique_decoding_bits,
        "proven_ldr_bits": pr.list_decoding_bits,
        "simple_lb_q_plus_pow": s.log_blowup * s.num_queries + s.query_pow_bits,
    })
}

pub fn print_sets() {
    let mut out = Vec::new();
    for s in all() {
        for (air, log_n) in [("fib", 16), ("mimc", 16)] {
            for zk in [false, true] {
                let mut s2 = s.clone();
                s2.zk = zk;
                let e = estimates(&s2, air, log_n);
                println!("{:7} zk={:5} {air:4} n=2^{log_n}: {e}", s.name, zk);
                out.push(serde_json::json!({"set": s2, "air": air, "log_n": log_n, "estimates": e}));
            }
        }
    }
    if let Some(path) = std::env::args().nth(2) {
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
}

/// Fiat-Shamir domain separators of the three nested transcripts (uni-stark, PCS, FRI), as Plonky3
/// builds them for this proof shape: rendered pattern (alternate Display), pattern hash (Keccak-256
/// of the rendering) and the full seed byte string absorbed into the challenger.
pub fn separators<EF: p3_field::ExtensionField<Val>, A: p3_air::BaseAir<Val>>(
    air: &A,
    s: &FriSet,
    shape: &Shape,
    degree_bits: usize,
) -> Value {
    use p3_challenger::fs::DomainSeparator;
    use p3_fri::{FriShape, PcsShape};
    use p3_uni_stark::StarkShape;
    let zk = s.zk as usize;
    let stark = StarkShape::new::<Val, A>(air, 0, degree_bits, degree_bits - zk, shape.num_chunks, s.zk, 0);
    // claimed evaluation counts: rounds [random], trace, quotient; per matrix, per point: values
    let rc = shape.rc;
    let mut counts = Vec::new();
    if s.zk {
        counts.push(vec![vec![s.ext + rc]]);
    }
    counts.push(vec![vec![shape.width + rc; 2]]);
    counts.push(vec![vec![s.ext + rc]; shape.num_chunks]);
    let pcs = PcsShape { claimed_evaluation_counts: counts, batch_pow_bits: s.batch_pow_bits };
    let params = p3_fri::FriParameters {
        log_blowup: s.log_blowup,
        log_final_poly_len: s.log_final_poly_len,
        max_log_arity: s.max_log_arity,
        num_queries: s.num_queries,
        batch_proof_of_work_bits: s.batch_pow_bits,
        commit_proof_of_work_bits: s.commit_pow_bits,
        query_proof_of_work_bits: s.query_pow_bits,
        mmcs: (),
    };
    let fri = FriShape::with_schedule(&params, shape.log_arities.clone(), degree_bits + s.log_blowup);
    fn one<U: p3_challenger::fs::Unit>(ds: &DomainSeparator<U>) -> Value {
        let mut seed = Vec::new();
        seed.extend_from_slice(ds.protocol_id());
        seed.extend_from_slice(&ds.pattern().pattern_hash());
        seed.extend_from_slice(&(ds.instance_label().len() as u32).to_be_bytes());
        seed.extend_from_slice(ds.instance_label());
        seed.push(0x80);
        serde_json::json!({
            "pattern": format!("{:#}", ds.pattern()),
            "pattern_hash": ds.pattern().pattern_hash().iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "seed": seed.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        })
    }
    serde_json::json!({
        "stark": one(&stark.domain_separator::<Val, EF>()),
        "pcs": one(&pcs.domain_separator::<Val, EF>()),
        "fri": one(&fri.domain_separator::<Val, EF>()),
    })
}
