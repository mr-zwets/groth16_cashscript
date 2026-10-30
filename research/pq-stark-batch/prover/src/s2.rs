//! Track 8 S2 acceptance (DESIGN-T8 sec. 7, S2) for the statement AIRs M1 and M2 (src/stmt.rs):
//!
//!   s2 selftest --out F      Poseidon2 test vector + differential test against p3-goldilocks; native
//!                            relation vs the trace (NF, ROOT); Plonky3's own constraint checker
//!                            (`p3_air::check_all_constraints`) on honest traces; the bus multiset (exact,
//!                            and Plonky3's `p3_lookup::debug_util::check_lookups`); trace dumps for the
//!                            Python cross-check against AIR-SPEC's air8_ref.py
//!   s2 mutate --out F        single-cell mutation completeness with Plonky3's DebugConstraintBuilder
//!   s2 forced --out F        forced unsatisfying traces / wrong statements: prove (release build, so
//!                            Plonky3 does not pre-check) and require verify_batch to reject
//!   s2 pvs --out F           honest proofs checked against wrong public values and other verifying keys
//!   s2 batch --set S --count K --outdir D --out F   K random statements: prove, p3b-v1 round trip, verify
//!   s2 witness --case NAME --out F                  witness, public values and traces of one case (JSON)

use std::time::Instant;

use p3_air::{BaseAir, DebugConstraintBuilder, check_all_constraints};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::debug_util::{LookupDebugInstance, check_lookups};
use p3_matrix::Matrix;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::ViewPair;
use serde_json::{Value, json};

use crate::airs::{TestAir, stmt_case};
use crate::cfg::*;
use crate::stmt::*;
use crate::{SETUP_SEED, arg, run_case, write_vector};

/// Peak resident set size of this process so far (kB), from /proc/self/status VmHWM.
pub fn vmhwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|x| x.parse().ok()))
        })
        .unwrap_or(0)
}

fn s(x: Val) -> String {
    x.as_canonical_u64().to_string()
}
fn vs(x: &[Val]) -> Vec<String> {
    x.iter().map(|v| s(*v)).collect()
}

/// Indices of the constraints that fail on row `r` (window rows r, r+1 mod n), evaluated by Plonky3's
/// DebugConstraintBuilder with Plonky3's own selectors and periodic values.
fn row_failures(
    air: &TestAir,
    main: &RowMajorMatrix<Val>,
    pre: &Option<RowMajorMatrix<Val>>,
    pvs: &[Val],
    r: usize,
) -> Vec<usize> {
    let n = main.height();
    let r = r % n;
    let rn = (r + 1) % n;
    let local = main.row_slice(r).unwrap().to_vec();
    let next = main.row_slice(rn).unwrap().to_vec();
    let (pl, pn) = match pre {
        Some(p) => (p.row_slice(r).unwrap().to_vec(), p.row_slice(rn).unwrap().to_vec()),
        None => (vec![], vec![]),
    };
    let main_pair = ViewPair::new(RowMajorMatrixView::new_row(&local), RowMajorMatrixView::new_row(&next));
    let pre_pair = if pre.is_some() {
        ViewPair::new(RowMajorMatrixView::new_row(&pl), RowMajorMatrixView::new_row(&pn))
    } else {
        ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0))
    };
    let periodic = <TestAir as BaseAir<Val>>::periodic_values(air, r);
    let mut b = DebugConstraintBuilder::<Val>::new(
        r,
        main_pair,
        pre_pair,
        pvs,
        Val::from_bool(r == 0),
        Val::from_bool(r == n - 1),
        Val::from_bool(r != n - 1),
        &periodic,
    );
    <TestAir as p3_air::Air<_>>::eval(air, &mut b);
    b.failures().iter().map(|f| f.constraint).collect()
}

/// Plonky3's full-trace checker; returns (violations, constraints per row).
fn full_check(air: &TestAir, main: &RowMajorMatrix<Val>, pvs: &[Val]) -> (usize, usize) {
    let rep = check_all_constraints(air, main, pvs, None);
    (rep.failures.len(), rep.total_constraints_per_row)
}

/// Lookups of an M2 batch as Plonky3's setup derives them (verifying-key data).
fn m2_lookups(set: &Params, airs: &[TestAir]) -> Vec<p3_lookup::Lookups<Val>> {
    let zk = set.zk as usize;
    let degs = vec![LOG_N_HASH + zk, LOG_N_CTL + zk];
    with_cfg!(set, 1, |config| {
        let pd = ProverData::from_airs_and_degrees(&config, airs, &degs).expect("setup");
        pd.common.lookups.clone()
    })
}

/// Plonky3's debug lookup check (panics on an unbalanced bus); true = balanced.
fn p3_bus_ok(airs: &[TestAir], traces: &[RowMajorMatrix<Val>], pvs: &[Vec<Val>], lookups: &[p3_lookup::Lookups<Val>]) -> bool {
    let pres: Vec<_> = airs.iter().map(|a| <TestAir as BaseAir<Val>>::preprocessed_trace(a)).collect();
    let pers: Vec<Vec<Vec<Val>>> = airs.iter().map(|a| <TestAir as BaseAir<Val>>::periodic_columns(a).to_vec()).collect();
    let insts: Vec<LookupDebugInstance<'_, Val>> = (0..airs.len())
        .map(|i| LookupDebugInstance {
            main_trace: &traces[i],
            preprocessed_trace: &pres[i],
            public_values: &pvs[i],
            periodic_columns: &pers[i],
            lookups: &lookups[i],
            permutation_challenges: &[],
        })
        .collect();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check_lookups(&insts))).is_ok()
}

const LEAVES: [(&str, u64, u64); 3] = [("leaf 0", 0, 1), ("leaf 2^30-1", (1 << 30) - 1, 2), ("leaf random", 0x2b1c_9e37, 3)];

pub fn cmd_selftest(args: &[String]) {
    let out = arg(args, "--out").expect("--out");
    let dump = arg(args, "--dump");
    let mut res = serde_json::Map::new();
    let mut all = true;

    let (p2_ok, agree) = poseidon2_selftest(10_000);
    eprintln!("Poseidon2-Gl-8: test vector + differential vs p3-goldilocks on {agree} inputs: {}", if p2_ok { "PASS" } else { "FAIL" });
    res.insert("poseidon2".into(), json!({"test_vector_and_differential": p2_ok, "inputs_agreeing": agree, "inputs": 10_002}));
    all &= p2_ok;

    let set = get_set("Z128g+cpow=3+lpow=8");
    let mut rows = Vec::new();
    for (label, leaf, wseed) in LEAVES {
        let w = witness(leaf, wseed);
        let (nf, root) = native(&w);
        // M1
        let c1 = stmt_case(&format!("m1@{leaf}@{wseed}"), 0);
        let t = &c1.traces[0];
        let n = t.height();
        let trace_nf: Vec<Val> = t.row_slice(31).unwrap()[0..4].to_vec();
        let trace_root: Vec<Val> = t.row_slice(n - 1).unwrap()[0..4].to_vec();
        let m1_native = trace_nf == nf && trace_root == root;
        let (v1, k1) = full_check(&c1.airs[0], t, &c1.pvs[0]);
        // M2
        let c2 = stmt_case(&format!("m2@{leaf}@{wseed}"), 0);
        let (th, tc) = (&c2.traces[0], &c2.traces[1]);
        let (vh, kh) = full_check(&c2.airs[0], th, &c2.pvs[0]);
        let (vc, kc) = full_check(&c2.airs[1], tc, &c2.pvs[1]);
        let m2_native = tc.row_slice(0).unwrap()[8..12] == nf && tc.row_slice(31).unwrap()[8..12] == root;
        let bus = bus_balanced(th, tc);
        let lk = m2_lookups(&set, &c2.airs);
        let p3bus = p3_bus_ok(&c2.airs, &c2.traces, &c2.pvs, &lk);
        let ok = m1_native && v1 == 0 && k1 == 53 && vh == 0 && kh == 40 && vc == 0 && kc == 31 && m2_native && bus && p3bus;
        all &= ok;
        eprintln!(
            "{label}: M1 trace NF/ROOT == native {m1_native}, check_all_constraints {v1} violations ({k1} constraints/row); \
             M2 T_hash {vh} ({kh}/row), T_ctl {vc} ({kc}/row), NF/ROOT == native {m2_native}, bus exact {bus}, \
             Plonky3 check_lookups {p3bus} -> {}",
            if ok { "PASS" } else { "FAIL" }
        );
        rows.push(json!({"case": label, "leaf_index": leaf, "witness_seed": wseed, "public_values": vs(&c1.pvs[0]),
            "m1": {"trace_matches_native": m1_native, "violations": v1, "air_constraints_per_row": k1},
            "m2": {"t_hash_violations": vh, "t_hash_air_constraints_per_row": kh, "t_ctl_violations": vc,
                   "t_ctl_air_constraints_per_row": kc, "trace_matches_native": m2_native, "bus_exact": bus,
                   "plonky3_check_lookups": p3bus}, "pass": ok}));
        if let Some(dir) = &dump {
            // traces for the Python cross-check (air8_ref.py builds the same traces from this witness)
            let dumpv = json!({"leaf_index": leaf, "nk": vs(&w.nk), "r": vs(&w.r), "bits": w.bits,
                "sibs": w.sibs.iter().map(|x| vs(x)).collect::<Vec<_>>(), "ctx": vs(&w.ctx),
                "public_values": vs(&c1.pvs[0]),
                "m1": vs(&t.values), "t_hash": vs(&th.values), "t_ctl": vs(&tc.values)});
            std::fs::write(format!("{dir}/trace-{leaf}.json"), dumpv.to_string()).unwrap();
        }
    }
    res.insert("honest".into(), json!(rows));
    // a negative control for the bus checks: change nk in T_ctl row 0 only
    crate::quiet_panics();
    let c2 = stmt_case("m2@0@1", 0);
    let mut tc = c2.traces[1].clone();
    tc.values[0] += Val::ONE;
    let traces = vec![c2.traces[0].clone(), tc.clone()];
    let lk = m2_lookups(&set, &c2.airs);
    let neg = (!bus_balanced(&traces[0], &tc), !p3_bus_ok(&c2.airs, &traces, &c2.pvs, &lk), full_check(&c2.airs[1], &tc, &c2.pvs[1]).0 == 0);
    eprintln!("negative control (T_ctl nk + 1): exact bus rejects {}, check_lookups rejects {}, T_ctl AIR alone silent {}", neg.0, neg.1, neg.2);
    all &= neg.0 && neg.1;
    res.insert("bus_negative_control".into(), json!({"mutation": "T_ctl row 0 in0 + 1 (nk)", "exact_bus_rejects": neg.0,
        "check_lookups_rejects": neg.1, "t_ctl_air_alone_silent": neg.2}));
    res.insert("all_pass".into(), json!(all));
    write_vector(&out, &Value::Object(res));
    eprintln!("selftest: {}", if all { "ALL PASS" } else { "FAILURES" });
    if !all {
        std::process::exit(1);
    }
}

/// Mutation scan of one table: every cell + 1, alone; caught by a constraint of rows r-1 / r or (M2)
/// by the bus. Returns (cells, missed, caught only by the bus, histogram of the first failing constraint).
fn scan(
    air: &TestAir,
    main: &RowMajorMatrix<Val>,
    pvs: &[Val],
    bus: Option<&dyn Fn(&RowMajorMatrix<Val>) -> bool>,
) -> (usize, Vec<(usize, usize)>, usize, Vec<usize>) {
    let pre = <TestAir as BaseAir<Val>>::preprocessed_trace(air);
    let (n, w) = (main.height(), main.width());
    let mut m = main.clone();
    let mut missed = Vec::new();
    let mut bus_only = 0;
    let k = full_check(air, main, pvs).1;
    let mut hist = vec![0usize; k + 1];
    for r in 0..n {
        for c in 0..w {
            let old = m.values[r * w + c];
            m.values[r * w + c] = old + Val::ONE;
            let mut f = row_failures(air, &m, &pre, pvs, r + n - 1);
            f.extend(row_failures(air, &m, &pre, pvs, r));
            if let Some(&first) = f.iter().min() {
                hist[first] += 1;
            } else if bus.map(|b| !b(&m)).unwrap_or(false) {
                bus_only += 1;
                hist[k] += 1;
            } else {
                missed.push((r, c));
            }
            m.values[r * w + c] = old;
        }
    }
    (n * w, missed, bus_only, hist)
}

pub fn cmd_mutate(args: &[String]) {
    let out = arg(args, "--out").expect("--out");
    let (label, leaf, wseed) = LEAVES[2];
    let t0 = Instant::now();
    let c1 = stmt_case(&format!("m1@{leaf}@{wseed}"), 0);
    let (cells1, miss1, _, h1) = scan(&c1.airs[0], &c1.traces[0], &c1.pvs[0], None);
    eprintln!("M1 ({label}): {} / {cells1} cells caught; missed {:?}", cells1 - miss1.len(), &miss1[..miss1.len().min(10)]);
    let c2 = stmt_case(&format!("m2@{leaf}@{wseed}"), 0);
    let (th, tc) = (c2.traces[0].clone(), c2.traces[1].clone());
    let tc_for = tc.clone();
    let bus_h = move |m: &RowMajorMatrix<Val>| bus_balanced(m, &tc_for);
    let (cellsh, missh, bush, hh) = scan(&c2.airs[0], &th, &c2.pvs[0], Some(&bus_h));
    let th_for = th.clone();
    let bus_c = move |m: &RowMajorMatrix<Val>| bus_balanced(&th_for, m);
    let (cellsc, missc, busc, hc) = scan(&c2.airs[1], &tc, &c2.pvs[1], Some(&bus_c));
    eprintln!(
        "M2: T_hash {} / {cellsh} caught ({bush} by the bus only), T_ctl {} / {cellsc} caught ({busc} by the bus only); missed {:?} {:?}",
        cellsh - missh.len(),
        cellsc - missc.len(),
        &missh[..missh.len().min(10)],
        &missc[..missc.len().min(10)]
    );
    let all = miss1.is_empty() && missh.is_empty() && missc.is_empty();
    write_vector(
        &out,
        &json!({
            "method": "each main-trace cell + 1, alone; caught if Plonky3's DebugConstraintBuilder reports a failing \
                       constraint on row r-1 or r (the only windows that read the cell), or, for M2, if the exact \
                       bus-P2 multiset no longer balances. Histogram index = first failing constraint (emission order, \
                       0-based); the last bucket = bus only.",
            "witness": {"case": label, "leaf_index": leaf, "witness_seed": wseed},
            "m1": {"cells": cells1, "missed": miss1.len(), "first_failing_constraint_histogram": h1},
            "t_hash": {"cells": cellsh, "missed": missh.len(), "bus_only": bush, "first_failing_constraint_histogram": hh},
            "t_ctl": {"cells": cellsc, "missed": missc.len(), "bus_only": busc, "first_failing_constraint_histogram": hc},
            "seconds": t0.elapsed().as_secs_f64(),
            "all_caught": all,
        }),
    );
    eprintln!("mutate: {}", if all { "ALL CAUGHT" } else { "MISSES" });
    if !all {
        std::process::exit(1);
    }
}

/// Prove `traces` against `pvs` (no pre-check: release build) and run verify_batch with `verify_pvs`.
/// Returns (prover outcome, verifier outcome, proof bytes if any).
fn prove_and_verify(
    set: &Params,
    airs: &[TestAir],
    traces: &[RowMajorMatrix<Val>],
    pvs: &[Vec<Val>],
    verify_pvs: &[Vec<Val>],
    log_heights: &[usize],
    seed: u64,
) -> (String, String) {
    let zk = set.zk as usize;
    let degs: Vec<usize> = log_heights.iter().map(|l| l + zk).collect();
    let trefs: Vec<&_> = traces.iter().collect();
    with_cfg!(set, seed, SETUP_SEED, |config, setup_cfg| {
        let pd = ProverData::from_airs_and_degrees(&setup_cfg, airs, &degs).expect("setup");
        let inst = StarkInstance::new_multiple(airs, &trefs, pvs);
        let pr = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(&config, &inst, &pd)));
        match pr {
            Err(_) => ("prover panicked".into(), "no proof".into()),
            Ok(Err(e)) => (format!("prover error {e:?}"), "no proof".into()),
            Ok(Ok(proof)) => {
                let v = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    verify_batch(&config, airs, &proof, verify_pvs, &pd.common)
                }));
                let vr = match v {
                    Ok(Ok(())) => "ACCEPTED".to_string(),
                    Ok(Err(e)) => format!("rejected: {e:?}"),
                    Err(_) => "rejected (verifier panicked)".into(),
                };
                ("proof produced".into(), vr)
            }
        }
    })
}

pub fn cmd_forced(args: &[String]) {
    let out = arg(args, "--out").expect("--out");
    crate::quiet_panics();
    let set1 = get_set("Z128");
    let set2 = get_set("Z128g+cpow=3+lpow=8");
    let (_, leaf, wseed) = LEAVES[2];
    let c1 = stmt_case(&format!("m1@{leaf}@{wseed}"), 0);
    let c2 = stmt_case(&format!("m2@{leaf}@{wseed}"), 0);
    let other = public_values(&witness(12345, 99)); // a foreign statement
    // control: the honest M1 statement through the same path must be accepted
    let (p, v) = prove_and_verify(&set1, &c1.airs, &c1.traces, &c1.pvs, &c1.pvs, &c1.log_heights, 7);
    eprintln!("control M1 honest: {p}; verify_batch {v}");
    let mut controls_ok = v == "ACCEPTED";
    let (p2, v2) = prove_and_verify(&set2, &c2.airs, &c2.traces, &c2.pvs, &c2.pvs, &c2.log_heights, 7);
    eprintln!("control M2 honest: {p2}; verify_batch {v2}");
    controls_ok &= v2 == "ACCEPTED";
    let mut rows = Vec::new();
    let mut all = controls_ok;
    let mut run = |name: &str, what: &str, m2: bool, traces: Vec<RowMajorMatrix<Val>>, pvs: Vec<Vec<Val>>| {
        let (set, c) = if m2 { (&set2, &c2) } else { (&set1, &c1) };
        let t0 = Instant::now();
        let (p, v) = prove_and_verify(set, &c.airs, &traces, &pvs, &pvs, &c.log_heights, 7);
        let ok = v != "ACCEPTED";
        all &= ok;
        eprintln!("{name}: {p}; verify_batch {v} -> {}", if ok { "ok" } else { "UNEXPECTED ACCEPT" });
        rows.push(json!({"name": name, "what": what, "statement": if m2 {"M2"} else {"M1"}, "set": set.name,
            "prover": p, "verify_batch": v, "expected_reject": ok, "ms": t0.elapsed().as_millis()}));
    };
    let cell = |t: &RowMajorMatrix<Val>, r: usize, c: usize, v: Val| {
        let mut t = t.clone();
        let w = t.width();
        t.values[r * w + c] = v;
        t
    };
    let t1 = &c1.traces[0];
    let g = |t: &RowMajorMatrix<Val>, r: usize, c: usize| t.values[r * t.width() + c];
    run("m1 sbox cell", "u0 + 1 on row 1 (first full round): breaks A_0 and C_j", false, vec![cell(t1, 1, 8, g(t1, 1, 8) + Val::ONE)], c1.pvs.clone());
    run("m1 state cell", "s3 + 1 on row 300 (partial round)", false, vec![cell(t1, 300, 3, g(t1, 300, 3) + Val::ONE)], c1.pvs.clone());
    run("m1 sibling", "sibling u0 + 1 on slot 5's chain row (row 191): next slot input no longer matches", false, vec![cell(t1, 191, 8, g(t1, 191, 8) + Val::ONE)], c1.pvs.clone());
    run("m1 bit = 2", "path bit u4 = 2 on slot 7's chain row (row 255)", false, vec![cell(t1, 255, 12, Val::from_u64(2))], c1.pvs.clone());
    run("m1 z off", "z = 0 on row 5", false, vec![cell(t1, 5, 16, Val::ZERO)], c1.pvs.clone());
    run("m1 IV lane", "s7 (TAG_NF lane) + 1 on row 0", false, vec![cell(t1, 0, 7, g(t1, 0, 7) + Val::ONE)], c1.pvs.clone());
    let mut pv = c1.pvs.clone();
    pv[0][4] += Val::ONE;
    run("m1 claimed NF + 1", "honest trace, public NF[0] + 1 (prover and verifier use the claimed values)", false, c1.traces.clone(), pv);
    let mut pv = c1.pvs.clone();
    pv[0][0..4].copy_from_slice(&other[0..4]);
    run("m1 foreign ROOT", "honest trace, public ROOT of another tree", false, c1.traces.clone(), pv);
    // a full recomputation from a different nk: a consistent trace whose NF differs from the claim
    let mut w = witness(leaf, wseed);
    w.nk[0] += Val::ONE;
    let t_alt = m1_trace(&w);
    run("m1 other nk, claimed NF", "a consistent trace for nk' = nk + e0 under the original public values (NF and ROOT differ)", false, vec![t_alt], c1.pvs.clone());

    let (th, tc) = (&c2.traces[0], &c2.traces[1]);
    run("m2 T_ctl nk (bus only)", "T_ctl row 0 in0 + 1: every AIR constraint holds; only bus P2 is unbalanced", true, vec![th.clone(), cell(tc, 0, 0, g(tc, 0, 0) + Val::ONE)], c2.pvs.clone());
    run("m2 T_ctl r (bus only)", "T_ctl row 1 in5 + 1 (the leaf randomness r)", true, vec![th.clone(), cell(tc, 1, 5, g(tc, 1, 5) + Val::ONE)], c2.pvs.clone());
    run("m2 T_hash state", "T_hash s0 + 1 on row 40", true, vec![cell(th, 40, 0, g(th, 40, 0) + Val::ONE), tc.clone()], c2.pvs.clone());
    run("m2 T_hash carried input", "T_hash in3 + 1 on row 31 (a chain row, received on the bus)", true, vec![cell(th, 31, 19, g(th, 31, 19) + Val::ONE), tc.clone()], c2.pvs.clone());
    run("m2 T_ctl padding", "T_ctl row 64 out0 = 1 (a padding row)", true, vec![th.clone(), cell(tc, 64, 8, Val::ONE)], c2.pvs.clone());
    let mut pv = c2.pvs.clone();
    pv[1][0..4].copy_from_slice(&other[0..4]);
    run("m2 foreign ROOT", "honest traces, public ROOT of another tree", true, c2.traces.clone(), pv);
    let mut pv = c2.pvs.clone();
    pv[1][5] += Val::ONE;
    run("m2 claimed NF + 1", "honest traces, public NF[1] + 1", true, c2.traces.clone(), pv);

    write_vector(&out, &json!({"note": "release build: Plonky3's prover does not pre-check constraints, so a proof is \
        produced for each unsatisfying trace and verify_batch must reject it", "controls_accepted": controls_ok, "cases": rows, "all_rejected": all}));
    eprintln!("forced: {}", if all { "ALL REJECTED (controls accepted)" } else { "FAILURES" });
    if !all {
        std::process::exit(1);
    }
}

/// Honest proofs against wrong public values, and against other verifying keys.
pub fn cmd_pvs(args: &[String]) {
    let out = arg(args, "--out").expect("--out");
    crate::quiet_panics();
    let (_, leaf, wseed) = LEAVES[2];
    let mut rows = Vec::new();
    let mut all = true;
    let other = public_values(&witness(12345, 99));
    for (stmt, set_name) in [("m1", "Z128"), ("m2", "Z128g+cpow=3+lpow=8")] {
        let set = get_set(set_name);
        let c = stmt_case(&format!("{stmt}@{leaf}@{wseed}"), 0);
        let pi = c.pvs.len() - 1; // the instance carrying ROOT, NF, CTX
        let zk = set.zk as usize;
        let degs: Vec<usize> = c.log_heights.iter().map(|l| l + zk).collect();
        let trefs: Vec<&_> = c.traces.iter().collect();
        with_cfg!(&set, 11, SETUP_SEED, |config, setup_cfg| {
            let pd = ProverData::from_airs_and_degrees(&setup_cfg, &c.airs, &degs).expect("setup");
            let proof = prove_batch(&config, &StarkInstance::new_multiple(&c.airs, &trefs, &c.pvs), &pd).expect("prove");
            let check = |pvs: &Vec<Vec<Val>>| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_batch(&config, &c.airs, &proof, pvs, &pd.common)))
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            };
            let honest = check(&c.pvs);
            all &= honest;
            let mut cases: Vec<(String, Vec<Vec<Val>>)> = Vec::new();
            let names = ["ROOT", "NF", "CTX"];
            for k in 0..12 {
                let mut p = c.pvs.clone();
                p[pi][k] += Val::ONE;
                cases.push((format!("{}[{}] + 1", names[k / 4], k % 4), p));
            }
            let mut p = c.pvs.clone();
            p[pi][4] -= Val::ONE;
            cases.push(("NF[0] - 1".into(), p));
            let mut p = c.pvs.clone();
            p[pi][0..4].copy_from_slice(&other[0..4]);
            cases.push(("foreign ROOT (another tree)".into(), p));
            let mut p = c.pvs.clone();
            p[pi][8..12].copy_from_slice(&other[8..12]);
            cases.push(("other CTX (changed outputs)".into(), p));
            let mut p = c.pvs.clone();
            let (root, nf) = (p[pi][0..4].to_vec(), p[pi][4..8].to_vec());
            p[pi][0..4].copy_from_slice(&nf);
            p[pi][4..8].copy_from_slice(&root);
            cases.push(("ROOT and NF swapped".into(), p));
            let mut p = c.pvs.clone();
            p[pi][8..12].reverse();
            cases.push(("CTX lanes reversed".into(), p));
            let mut p = c.pvs.clone();
            p[pi].swap(0, 1);
            cases.push(("ROOT[0] and ROOT[1] swapped".into(), p));
            let mut rej = 0;
            let total = cases.len();
            for (name, p) in cases {
                let acc = check(&p);
                if acc {
                    all = false;
                    eprintln!("{stmt}: UNEXPECTED ACCEPT with {name}");
                }
                rej += !acc as usize;
                rows.push(json!({"statement": stmt, "set": set.name, "case": name, "accepted": acc}));
            }
            eprintln!("{stmt}: honest accepted {honest}; wrong public values rejected {rej} / {total}");
            // the same proof under other verifying keys (other parameters): must not verify
            let others: &[&str] = if stmt == "m1" { &["Z128+cap=5", "Z128g", "Z128+q=23", "Z128+qpow=23", "Z128+bpow=19"] } else { &["Z128g+cpow=2+lpow=8", "Z128g+cpow=3+lpow=0", "Z128g+cpow=3+lpow=8+cap=5"] };
            for o in others {
                let s2 = get_set(o);
                let acc = with_cfg!(&s2, 11, SETUP_SEED, |cfg2, setup2| {
                    let pd2 = ProverData::from_airs_and_degrees(&setup2, &c.airs, &degs).expect("setup");
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // the proof object is reused as is; same Rust type because the configs share it
                        let p: p3_batch_stark::BatchProof<_> = serde_json::from_value(serde_json::to_value(&proof).unwrap()).unwrap();
                        verify_batch(&cfg2, &c.airs, &p, &c.pvs, &pd2.common).is_ok()
                    }))
                    .unwrap_or(false)
                });
                if acc {
                    all = false;
                    eprintln!("{stmt}: UNEXPECTED ACCEPT under VK {o}");
                }
                eprintln!("{stmt}: proof for {} under VK {o}: {}", set.name, if acc { "ACCEPTED" } else { "rejected" });
                rows.push(json!({"statement": stmt, "set": set.name, "case": format!("verified under VK {o}"), "accepted": acc}));
            }
        });
    }
    // M2's preprocessed commitment: a VK built with another setup seed must reject an honest proof
    {
        let set = get_set("Z128g+cpow=3+lpow=8");
        let c = stmt_case(&format!("m2@{leaf}@{wseed}"), 0);
        let degs: Vec<usize> = c.log_heights.iter().map(|l| l + 1).collect();
        let trefs: Vec<&_> = c.traces.iter().collect();
        let acc = {
            let config = make_hcfg::<2>(&set, 11);
            let setup_ok = make_hcfg::<2>(&set, SETUP_SEED);
            let setup_other = make_hcfg::<2>(&set, SETUP_SEED ^ 1);
            let pd = ProverData::from_airs_and_degrees(&setup_ok, &c.airs, &degs).expect("setup");
            let pd_other = ProverData::from_airs_and_degrees(&setup_other, &c.airs, &degs).expect("setup");
            let proof = prove_batch(&config, &StarkInstance::new_multiple(&c.airs, &trefs, &c.pvs), &pd).expect("prove");
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_batch(&config, &c.airs, &proof, &c.pvs, &pd_other.common).is_ok()))
                .unwrap_or(false)
        };
        all &= !acc;
        eprintln!("m2: proof under a VK whose preprocessed commitment used another setup seed: {}", if acc { "ACCEPTED" } else { "rejected" });
        rows.push(json!({"statement": "m2", "set": set.name, "case": "VK with another preprocessed setup seed (other commitment)", "accepted": acc}));
    }
    write_vector(&out, &json!({"cases": rows, "all_as_expected": all}));
    eprintln!("pvs: {}", if all { "ALL AS EXPECTED" } else { "FAILURES" });
    if !all {
        std::process::exit(1);
    }
}

/// K random statements (random leaf index and witness), prove + p3b-v1 round trip + verify each.
pub fn cmd_batch(args: &[String]) {
    use rand::{RngExt, SeedableRng};
    let set = get_set(&arg(args, "--set").expect("--set"));
    let stmt = arg(args, "--stmt").unwrap_or("m1".into());
    let k: usize = arg(args, "--count").unwrap_or("24".into()).parse().unwrap();
    let base: u64 = arg(args, "--seed").unwrap_or("1000".into()).parse().unwrap();
    let outdir = arg(args, "--outdir");
    let out = arg(args, "--out").expect("--out");
    if let Some(d) = &outdir {
        std::fs::create_dir_all(d).unwrap();
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(base);
    let mut rows = Vec::new();
    let mut all = true;
    for i in 0..k {
        let leaf = rng.random::<u64>() & ((1 << DEPTH) - 1);
        let name = format!("{stmt}@{leaf}@{}", base + i as u64);
        let o = run_case(&name, &set, "0", base + i as u64, false);
        all &= o.ok;
        let b = o.vector["sizes"]["total"].as_u64().unwrap();
        rows.push(json!({"case": name, "ok": o.ok, "bytes": b, "prove_ms": o.vector["prove_ms"],
            "rust_verify_ms": o.vector["rust_verify_ms"], "sizes": o.vector["sizes"]}));
        if let Some(d) = &outdir {
            write_vector(&format!("{d}/{}-{}.json", name.replace('@', "-"), set.name.replace('+', "_").replace('=', "")), &o.vector);
        }
    }
    let bytes: Vec<f64> = rows.iter().map(|r| r["bytes"].as_u64().unwrap() as f64).collect();
    let mean = bytes.iter().sum::<f64>() / bytes.len() as f64;
    let sd = (bytes.iter().map(|b| (b - mean).powi(2)).sum::<f64>() / bytes.len() as f64).sqrt();
    let mut pm: Vec<u64> = rows.iter().map(|r| r["prove_ms"].as_u64().unwrap()).collect();
    pm.sort();
    let summary = json!({"set": set, "statement": stmt, "count": k, "all_ok": all,
        "bytes": {"mean": mean, "sd": sd, "min": bytes.iter().cloned().fold(f64::MAX, f64::min), "max": bytes.iter().cloned().fold(0.0, f64::max)},
        "prove_ms": {"median": pm[pm.len() / 2], "min": pm[0], "max": pm[pm.len() - 1]},
        "cases": rows});
    write_vector(&out, &summary);
    eprintln!("batch {stmt} {}: {k} statements, all ok {all}, bytes mean {mean:.0} sd {sd:.0}, prove median {} ms", set.name, pm[pm.len() / 2]);
    if !all {
        std::process::exit(1);
    }
}

/// Witness, public values and the traces of one statement case, as JSON (for S3/S4 and the Python check).
pub fn cmd_witness(args: &[String]) {
    let name = arg(args, "--case").expect("--case");
    let out = arg(args, "--out").expect("--out");
    let parts: Vec<&str> = name.split('@').collect();
    let w = witness(parts[1].parse().unwrap(), parts[2].parse().unwrap());
    let (nf, root) = native(&w);
    write_vector(
        &out,
        &json!({"case": name, "leaf_index": w.leaf_index, "nk": vs(&w.nk), "r": vs(&w.r), "bits": w.bits,
            "siblings": w.sibs.iter().map(|x| vs(x)).collect::<Vec<_>>(), "ctx": vs(&w.ctx),
            "nf": vs(&nf), "root": vs(&root), "public_values": vs(&public_values(&w)),
            "tag_nf": format!("{TAG_NF:#x}"), "periodic_columns": periodic_columns().iter().map(|c| vs(c)).collect::<Vec<_>>()}),
    );
}
