//! The p3b-v1 shape, derived from the verifying key only: AIRs, trace heights, the lookups and
//! preprocessed layout of the common data, and the parameter set. Nothing here reads a proof.

use p3_air::BaseAir;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks_for_domain;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{LogUpGadget, Lookups};

use crate::airs::TestAir;
use crate::cfg::{D, EF, Params, Val};
use crate::wire::{FORMAT, InstShape, MatShape, RoundShape, Shape};

/// Digests in the cap of a binary Merkle tree whose smallest committed matrix has height
/// 2^log_min_height. Plonky3 (`merkle-tree/src/mmcs/mod.rs`, `arity_schedule_and_proof_levels`)
/// keeps the proof down to the layer where the smallest matrix is injected, so the effective cap
/// height is min(cap_height, log_min_height).
pub fn cap_len(cap_height: usize, log_min_height: usize) -> usize {
    1 << cap_height.min(log_min_height)
}

pub fn derive(
    s: &Params,
    airs: &[TestAir],
    log_heights: &[usize],
    lookups: &[Lookups<Val>],
    pre_matrix_to_instance: Option<&[usize]>,
) -> Shape {
    let zk = s.zk as usize;
    let rc = if s.zk { s.num_random_codewords } else { 0 };
    let gadget = LogUpGadget::new();
    let mut instances = Vec::new();
    for (i, air) in airs.iter().enumerate() {
        let log_n = log_heights[i];
        let pre_w = <TestAir as BaseAir<Val>>::preprocessed_width(air);
        let layout = AirLayout {
            preprocessed_width: pre_w,
            main_width: air.width(),
            num_public_values: <TestAir as BaseAir<Val>>::num_public_values(air),
            num_periodic_columns: <TestAir as BaseAir<Val>>::num_periodic_columns(air),
            ..Default::default()
        };
        // the verifier sizes the quotient on the un-extended trace domain (verify_batch)
        let dom = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, log_n).unwrap();
        let log_chunks = get_log_num_quotient_chunks_for_domain::<Val, EF, _, _>(
            air, layout, dom, &lookups[i], zk, &gadget,
        );
        let nl = lookups[i].len();
        instances.push(InstShape {
            label: air.label(),
            log_n,
            degree_bits: log_n + zk,
            log_lde: log_n + zk + s.log_blowup,
            width: air.width(),
            opens_next: !<TestAir as BaseAir<Val>>::main_next_row_columns(air).is_empty(),
            num_public_values: <TestAir as BaseAir<Val>>::num_public_values(air),
            preprocessed_width: pre_w,
            preprocessed_next: pre_w > 0
                && !<TestAir as BaseAir<Val>>::preprocessed_next_row_columns(air).is_empty(),
            num_periodic: <TestAir as BaseAir<Val>>::num_periodic_columns(air),
            num_chunks: 1 << (log_chunks + zk),
            num_lookups: nl,
            perm_width: if nl == 0 { 0 } else { (nl + 1) * D },
        });
    }

    let mat = |i: usize, what: &str, width: usize, points: usize| MatShape {
        instance: i,
        what: what.into(),
        log_height: instances[i].log_lde,
        width,
        points,
    };
    let round = |name: &str, rc: usize, matrices: Vec<MatShape>| {
        let log_min = matrices.iter().map(|m| m.log_height).min().expect("empty round");
        RoundShape { name: name.into(), rc, cap_len: cap_len(s.cap_height, log_min), matrices }
    };
    let n = instances.len();
    let mut rounds = Vec::new();
    if s.zk {
        rounds.push(round("random", rc, (0..n).map(|i| mat(i, "random", D + rc, 1)).collect()));
    }
    rounds.push(round(
        "trace",
        rc,
        (0..n)
            .map(|i| mat(i, "trace", instances[i].width + rc, 1 + instances[i].opens_next as usize))
            .collect(),
    ));
    let mut q = Vec::new();
    for i in 0..n {
        for k in 0..instances[i].num_chunks {
            q.push(mat(i, &format!("quotient[{k}]"), D + rc, 1));
        }
    }
    rounds.push(round("quotient", rc, q));
    if let Some(order) = pre_matrix_to_instance {
        // the preprocessed commitment is built by the hiding MMCS too (salted) but carries no
        // random codewords
        rounds.push(round(
            "preprocessed",
            0,
            order
                .iter()
                .map(|&i| {
                    mat(i, "preprocessed", instances[i].preprocessed_width, 1 + instances[i].preprocessed_next as usize)
                })
                .collect(),
        ));
    }
    let has_lookups = instances.iter().any(|i| i.num_lookups > 0);
    if has_lookups {
        rounds.push(round(
            "permutation",
            rc,
            (0..n)
                .filter(|&i| instances[i].num_lookups > 0)
                .map(|i| mat(i, "permutation", instances[i].perm_width + rc, 2))
                .collect(),
        ));
    }

    // FRI: the inputs are the distinct LDE heights, tallest first
    let mut heights: Vec<usize> = instances.iter().map(|i| i.log_lde).collect();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();
    let log_final = s.log_final_poly_len + s.log_blowup;
    for &h in &heights {
        assert!(h > log_final, "FRI input height 2^{h} must exceed 2^{log_final} (strict, validate_input_height)");
    }
    let log_arities = p3_fri::fold_schedule(&heights, log_final, s.max_log_arity);
    // commit-phase tree of round r: one matrix of height (codeword height) / arity
    let mut fri_cap_lens = Vec::new();
    let mut h = heights[0];
    for &la in &log_arities {
        fri_cap_lens.push(cap_len(s.cap_height, h - la));
        h -= la;
    }

    Shape {
        format: FORMAT.into(),
        ext: D,
        zk: s.zk,
        salt: if s.zk { s.salt } else { 0 },
        digest: s.digest,
        cap_height: s.cap_height,
        log_blowup: s.log_blowup,
        instances,
        rounds,
        has_lookups,
        lookup_pow: has_lookups && s.lookup_pow_bits > 0,
        ood_pow: s.ood_pow_bits > 0,
        batch_pow: s.batch_pow_bits > 0,
        commit_pow: s.commit_pow_bits > 0,
        query_pow: s.query_pow_bits > 0,
        log_arities,
        fri_cap_lens,
        num_queries: s.num_queries,
        final_poly_len: 1 << s.log_final_poly_len,
    }
}
