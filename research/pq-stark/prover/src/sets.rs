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
    }
}

pub fn all() -> Vec<FriSet> {
    vec![
        // conjectured ("random words"/ethSTARK-style) ~100 and ~128 bits: lb*q + qpow
        mk("C100", 2, 3, 27, 19, 3, 3),
        mk("C128", 3, 3, 36, 20, 3, 3),
        // Track 4's provable-regime FRI shapes (rho, queries, 28-bit query grinding), deg-3 field
        mk("T4P100", 3, 7, 22, 28, 3, 5),
        mk("T4P128", 3, 5, 43, 28, 3, 5),
        // tiny set for fast tests (not secure)
        mk("TOY", 2, 2, 4, 2, 2, 1),
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
                regime(s), $a, layout, dom, modbits, 128, 2, openings, grinding,
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
