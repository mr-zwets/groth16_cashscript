//! Track 8 statement AIRs (S2): M1 (one table) and M2 (T_hash + T_ctl, one global LogUp bus), written
//! from AIR-SPEC.md (bench branch wip/stark-usable-design, research/pq-stark/design-t8/AIR-SPEC.md),
//! which is normative. Constraint emission order is exactly AIR-SPEC sec. 3.4 (M1) and sec. 4.1/4.2
//! (M2): the verifier folds constraints by Horner in this order.
//!
//! - Poseidon2-Gl-8 (`perm`): the stock p3-goldilocks width-8 constants, round order of AIR-SPEC sec. 2
//!   (initial M_E, 4 full, 22 partial, 4 full; add_rc -> sbox x^7 -> matrix). Differentially tested
//!   against `p3_goldilocks::default_goldilocks_poseidon2_8()` (see `selftest`).
//! - M1 relation: NF = T(P(nk || IV_NF)), leaf = H(NF, r), node_i = H(swap_{b_i}(node_{i-1}, S_i)),
//!   ROOT = node_30. Public values ROOT[4], NF[4], CTX[4] (CTX is not constrained by the AIR; it is
//!   bound by the transcript, AIR-SPEC sec. 3.1).

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as RC_FINAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as RC_INIT,
    GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as RC_INT, MATRIX_DIAG_8_GOLDILOCKS as DIAG8,
};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use crate::cfg::Val;

/// ASCII "vc.nfv01" (< p)
pub const TAG_NF: u64 = 0x7663_2E6E_6676_3031;
pub const DEPTH: usize = 30;
pub const SLOT: usize = 32;
pub const LOG_N_HASH: usize = 10;
pub const LOG_N_CTL: usize = 7;
/// The global LogUp bus of M2.
pub const BUS: &str = "P2";

pub fn iv_nf() -> [Val; 4] {
    [Val::ZERO, Val::ZERO, Val::ZERO, Val::from_u64(TAG_NF)]
}

const M4: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

/// External matrix M_E (AIR-SPEC sec. 2): ME[i][j] = M4[i mod 4][j mod 4] * (2 if same 4-block else 1).
pub fn me(i: usize, j: usize) -> u64 {
    M4[i % 4][j % 4] * if i / 4 == j / 4 { 2 } else { 1 }
}
/// Internal matrix M_I = diag(DG) + J.
pub fn mi(i: usize, j: usize) -> Val {
    (if i == j { DIAG8[i] } else { Val::ZERO }) + Val::ONE
}

fn mv_me(x: &[Val; 8]) -> [Val; 8] {
    core::array::from_fn(|i| (0..8).map(|j| Val::from_u64(me(i, j)) * x[j]).sum())
}
fn mv_mi(x: &[Val; 8]) -> [Val; 8] {
    core::array::from_fn(|i| (0..8).map(|j| mi(i, j) * x[j]).sum())
}

/// Poseidon2-Gl-8, written out in the AIR's round order.
pub fn perm(input: [Val; 8]) -> [Val; 8] {
    let mut x = mv_me(&input);
    for r in 0..4 {
        x = mv_me(&core::array::from_fn(|i| (x[i] + RC_INIT[r][i]).exp_const_u64::<7>()));
    }
    for r in 0..22 {
        x[0] = (x[0] + RC_INT[r]).exp_const_u64::<7>();
        x = mv_mi(&x);
    }
    for r in 0..4 {
        x = mv_me(&core::array::from_fn(|i| (x[i] + RC_FINAL[r][i]).exp_const_u64::<7>()));
    }
    x
}

pub fn trunc(x: &[Val; 8]) -> [Val; 4] {
    [x[0], x[1], x[2], x[3]]
}
pub fn cat(a: &[Val; 4], b: &[Val; 4]) -> [Val; 8] {
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}
/// H(a, b) = T(P(a || b))
pub fn compress(a: &[Val; 4], b: &[Val; 4]) -> [Val; 4] {
    trunc(&perm(cat(a, b)))
}

/// The 11 periodic columns of period 32 (AIR-SPEC sec. 3.3): rc0..rc7, F, Pt, C.
pub fn periodic_columns() -> Vec<Vec<Val>> {
    let mut cols = vec![vec![Val::ZERO; SLOT]; 11];
    for r in 0..SLOT {
        let (rc, f, pt, c): ([Val; 8], u64, u64, u64) = match r {
            1..=4 => (RC_INIT[r - 1], 1, 0, 0),
            5..=26 => {
                let mut rc = [Val::ZERO; 8];
                rc[0] = RC_INT[r - 5];
                (rc, 0, 1, 0)
            }
            27..=30 => (RC_FINAL[r - 27], 1, 0, 0),
            31 => ([Val::ZERO; 8], 0, 0, 1),
            _ => ([Val::ZERO; 8], 0, 0, 0),
        };
        for i in 0..8 {
            cols[i][r] = rc[i];
        }
        cols[8][r] = Val::from_u64(f);
        cols[9][r] = Val::from_u64(pt);
        cols[10][r] = Val::from_u64(c);
    }
    cols
}

/// 32 rows (s[8], u[8]) of one permutation of `inp`, M1 / T_hash layout. Unused u cells are 0; the C
/// row's u cells are left 0 (M1 fills u0..u4 afterwards). Row 31's s is P(inp).
pub fn slot_rows(inp: [Val; 8], per: &[Vec<Val>]) -> Vec<([Val; 8], [Val; 8])> {
    let mut rows = Vec::with_capacity(SLOT);
    let mut s = inp;
    for r in 0..SLOT {
        let rc: [Val; 8] = core::array::from_fn(|i| per[i][r]);
        let (f, pt, c) = (per[8][r] == Val::ONE, per[9][r] == Val::ONE, per[10][r] == Val::ONE);
        let mut u = [Val::ZERO; 8];
        let mut nxt = s;
        if f {
            u = core::array::from_fn(|i| (s[i] + rc[i]).cube());
            nxt = mv_me(&core::array::from_fn(|i| u[i] * u[i] * (s[i] + rc[i])));
        } else if pt {
            u[0] = (s[0] + rc[0]).cube();
            let mut y = s;
            y[0] = u[0] * u[0] * (s[0] + rc[0]);
            nxt = mv_mi(&y);
        } else if !c {
            nxt = mv_me(&s);
        }
        rows.push((s, u));
        s = nxt;
    }
    rows
}

/// M1 / M2 witness: nk, r, the path bits (b_1 = LSB of the leaf index) and siblings, plus CTX.
#[derive(Clone, Debug)]
pub struct Witness {
    pub leaf_index: u64,
    pub nk: [Val; 4],
    pub r: [Val; 4],
    pub bits: Vec<u64>,
    pub sibs: Vec<[Val; 4]>,
    pub ctx: [Val; 4],
}

fn rand_val(rng: &mut StdRng) -> Val {
    loop {
        let x: u64 = rng.random();
        if x < crate::wire::P {
            return Val::from_u64(x);
        }
    }
}

/// Deterministic witness for a vector: `wseed` drives nk, r, the siblings and CTX (each CTX_k < 2^56).
pub fn witness(leaf_index: u64, wseed: u64) -> Witness {
    assert!(leaf_index < 1 << DEPTH);
    let mut rng = StdRng::seed_from_u64(wseed ^ 0x7438_5732_0000_0000);
    let nk = core::array::from_fn(|_| rand_val(&mut rng));
    let r = core::array::from_fn(|_| rand_val(&mut rng));
    let bits = (0..DEPTH).map(|i| (leaf_index >> i) & 1).collect();
    let sibs = (0..DEPTH).map(|_| core::array::from_fn(|_| rand_val(&mut rng))).collect();
    let ctx = core::array::from_fn(|_| Val::from_u64(rng.random::<u64>() >> 8));
    Witness { leaf_index, nk, r, bits, sibs, ctx }
}

/// Native relation (no trace): (NF, ROOT).
pub fn native(w: &Witness) -> ([Val; 4], [Val; 4]) {
    let nf = trunc(&perm(cat(&w.nk, &iv_nf())));
    let mut node = compress(&nf, &w.r);
    for (b, s) in w.bits.iter().zip(&w.sibs) {
        node = if *b == 1 { compress(s, &node) } else { compress(&node, s) };
    }
    (nf, node)
}

/// Public values in AIR-SPEC order: ROOT[0..4], NF[0..4], CTX[0..4].
pub fn public_values(w: &Witness) -> Vec<Val> {
    let (nf, root) = native(w);
    root.iter().chain(nf.iter()).chain(w.ctx.iter()).copied().collect()
}

fn swap(b: u64, out: &[Val; 4], sib: &[Val; 4]) -> [Val; 8] {
    if b == 1 { cat(sib, out) } else { cat(out, sib) }
}

// ------------------------------------------------------------------------------------------- M1

pub const M1_WIDTH: usize = 17;

#[derive(Clone)]
pub struct M1Air {
    pub periodic: Vec<Vec<Val>>,
}
impl M1Air {
    pub fn new() -> Self {
        Self { periodic: periodic_columns() }
    }
}

pub fn m1_trace(w: &Witness) -> RowMajorMatrix<Val> {
    let per = periodic_columns();
    let mut v = Vec::with_capacity(1024 * M1_WIDTH);
    let mut inp = cat(&w.nk, &iv_nf());
    for k in 0..SLOT {
        let mut sr = slot_rows(inp, &per);
        let (sib, b) = match k {
            0 => (w.r, 0),
            1..=30 => (w.sibs[k - 1], w.bits[k - 1]),
            _ => ([Val::ZERO; 4], 0),
        };
        for i in 0..4 {
            sr[31].1[i] = sib[i];
        }
        sr[31].1[4] = Val::from_u64(b);
        for (s, u) in &sr {
            v.extend_from_slice(s);
            v.extend_from_slice(u);
            v.push(if k == 0 { Val::ONE } else { Val::ZERO });
        }
        inp = swap(b, &trunc(&sr[31].0), &sib);
    }
    RowMajorMatrix::new(v, M1_WIDTH)
}

impl BaseAir<Val> for M1Air {
    fn width(&self) -> usize {
        M1_WIDTH
    }
    fn num_public_values(&self) -> usize {
        12
    }
    fn num_periodic_columns(&self) -> usize {
        11
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..8).chain([16]).collect()
    }
}

/// Shared pieces of the Poseidon2 round AIR (M1 and T_hash): (A) S-box and (C) round constraints.
struct Round<E> {
    s: Vec<E>,
    u: Vec<E>,
    sn: Vec<E>,
    rc: Vec<E>,
    f: E,
    pt: E,
    c: E,
    l: E,
}

impl<E: PrimeCharacteristicRing + Clone> Round<E>
where
    E: From<Val>,
{
    /// A_i: sigma_i (u_i - (s_i + rc_i)^3), sigma_0 = F + Pt, sigma_{i>=1} = F
    fn sbox(&self, i: usize) -> E {
        let sigma = if i == 0 { self.f.clone() + self.pt.clone() } else { self.f.clone() };
        let x = self.s[i].clone() + self.rc[i].clone();
        sigma * (self.u[i].clone() - x.cube())
    }
    /// C_j: (1 - C) s'_j - [F sum_i ME_ji u_i^2 (s_i + rc_i) + Pt (MI_j0 u_0^2 (s_0 + rc_0) + sum_{i>=1} MI_ji s_i)
    ///                      + L sum_i ME_ji s_i]
    fn round(&self, j: usize) -> E {
        let full: E = (0..8)
            .map(|i| {
                E::from(Val::from_u64(me(j, i)))
                    * self.u[i].clone()
                    * self.u[i].clone()
                    * (self.s[i].clone() + self.rc[i].clone())
            })
            .sum();
        let part: E = E::from(mi(j, 0)) * self.u[0].clone() * self.u[0].clone() * (self.s[0].clone() + self.rc[0].clone())
            + (1..8).map(|i| E::from(mi(j, i)) * self.s[i].clone()).sum::<E>();
        let lin: E = (0..8).map(|i| E::from(Val::from_u64(me(j, i))) * self.s[i].clone()).sum();
        (E::ONE - self.c.clone()) * self.sn[j].clone()
            - (self.f.clone() * full + self.pt.clone() * part + self.l.clone() * lin)
    }
}

fn exprs<AB: AirBuilder, T: Into<AB::Expr> + Copy>(xs: &[T]) -> Vec<AB::Expr> {
    xs.iter().map(|&x| x.into()).collect()
}

impl<AB: AirBuilder<F = Val>> Air<AB> for M1Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let loc: Vec<AB::Expr> = exprs::<AB, _>(main.current_slice());
        let nxt: Vec<AB::Expr> = exprs::<AB, _>(main.next_slice());
        let per: Vec<AB::Expr> = exprs::<AB, _>(builder.periodic_values());
        let pv: Vec<AB::Expr> = exprs::<AB, _>(builder.public_values());
        let (first, last, trans) = (builder.is_first_row(), builder.is_last_row(), builder.is_transition());
        let (f, pt, c) = (per[8].clone(), per[9].clone(), per[10].clone());
        let l = AB::Expr::ONE - f.clone() - pt.clone() - c.clone();
        let rd = Round {
            s: loc[0..8].to_vec(),
            u: loc[8..16].to_vec(),
            sn: nxt[0..8].to_vec(),
            rc: per[0..8].to_vec(),
            f: f.clone(),
            pt: pt.clone(),
            c: c.clone(),
            l: l.clone(),
        };
        let (s, u, z, zn) = (&loc[0..8], &loc[8..16], loc[16].clone(), nxt[16].clone());
        let u4 = u[4].clone();
        // 1-8 A_i
        for i in 0..8 {
            builder.assert_zero(rd.sbox(i));
        }
        // 9-16 B_i: tau_0 = L, tau_1..4 = Pt + L, tau_5..7 = Pt + L + C
        for i in 0..8 {
            let tau = match i {
                0 => l.clone(),
                1..=4 => pt.clone() + l.clone(),
                _ => pt.clone() + l.clone() + c.clone(),
            };
            builder.assert_zero(tau * u[i].clone());
        }
        // 17-24 C_j
        for j in 0..8 {
            builder.assert_zero(rd.round(j));
        }
        // 25-32 D_j: is_transition C (s'_j - w_j)
        for j in 0..8 {
            let w = if j < 4 {
                s[j].clone() + u4.clone() * (u[j].clone() - s[j].clone())
            } else {
                u[j - 4].clone() + u4.clone() * (s[j - 4].clone() - u[j - 4].clone())
            };
            builder.assert_zero(trans.clone() * c.clone() * (nxt[j].clone() - w));
        }
        // 33 E
        builder.assert_zero(c.clone() * u4.clone() * (u4.clone() - AB::Expr::ONE));
        // 34-36 F0, F1, F2
        builder.assert_zero(first.clone() * (z.clone() - AB::Expr::ONE));
        builder.assert_zero(trans.clone() * (zn - (AB::Expr::ONE - c.clone()) * z.clone()));
        builder.assert_zero(c.clone() * z.clone() * u4.clone());
        // 37-40 G_k
        let iv = iv_nf();
        for k in 0..4 {
            builder.assert_zero(first.clone() * (s[4 + k].clone() - AB::Expr::from(iv[k])));
        }
        // 41-44 H_j: C z (s_j - NF_j)
        for j in 0..4 {
            builder.assert_zero(c.clone() * z.clone() * (s[j].clone() - pv[4 + j].clone()));
        }
        // 45-48 I_j: is_last_row (s_j - ROOT_j)
        for j in 0..4 {
            builder.assert_zero(last.clone() * (s[j].clone() - pv[j].clone()));
        }
        // 49-53 J_i: is_last_row u_i
        for i in 0..5 {
            builder.assert_zero(last.clone() * u[i].clone());
        }
    }
}

// ------------------------------------------------------------------------------------------- M2

pub const THASH_WIDTH: usize = 24;
pub const TCTL_WIDTH: usize = 13;

/// T_hash: 32 independent permutations, n = 2^10. Main s[8] u[8] in[8]; preprocessed lvl_h.
#[derive(Clone)]
pub struct THashAir {
    pub periodic: Vec<Vec<Val>>,
}
impl THashAir {
    pub fn new() -> Self {
        Self { periodic: periodic_columns() }
    }
}

/// T_ctl: the control table, n = 2^7. Main in[8] out[4] b; preprocessed lvl, f_null, f_leaf, f_root, f_used.
#[derive(Clone, Copy)]
pub struct TCtlAir;

/// The slot inputs, outputs and bits of the relation, in T_ctl row order (rows 0..31).
fn m2_rows(w: &Witness) -> (Vec<[Val; 8]>, Vec<[Val; 4]>, Vec<u64>) {
    let (mut ins, mut outs, mut bs) = (vec![], vec![], vec![]);
    let mut inp = cat(&w.nk, &iv_nf());
    let mut b = 0;
    for k in 0..SLOT {
        let out = trunc(&perm(inp));
        ins.push(inp);
        outs.push(out);
        bs.push(b);
        let sib;
        (b, sib) = match k {
            0 => (0, w.r),
            1..=30 => (w.bits[k - 1], w.sibs[k - 1]),
            _ => break,
        };
        inp = swap(b, &out, &sib);
    }
    (ins, outs, bs)
}

/// (T_hash main 1024 x 24, T_ctl main 128 x 13)
pub fn m2_traces(w: &Witness) -> (RowMajorMatrix<Val>, RowMajorMatrix<Val>) {
    let per = periodic_columns();
    let (ins, outs, bs) = m2_rows(w);
    let mut th = Vec::with_capacity(1024 * THASH_WIDTH);
    for inp in &ins {
        for (s, u) in slot_rows(*inp, &per) {
            th.extend_from_slice(&s);
            th.extend_from_slice(&u);
            th.extend_from_slice(inp);
        }
    }
    let mut tc = vec![Val::ZERO; 128 * TCTL_WIDTH];
    for k in 0..SLOT {
        let row = &mut tc[k * TCTL_WIDTH..(k + 1) * TCTL_WIDTH];
        row[0..8].copy_from_slice(&ins[k]);
        row[8..12].copy_from_slice(&outs[k]);
        row[12] = Val::from_u64(bs[k]);
    }
    // row 32: in = (ROOT, 0, 0, 0, 0) (forced by N6 from row 31), out = 0, b = 0
    tc[32 * TCTL_WIDTH..32 * TCTL_WIDTH + 4].copy_from_slice(&outs[31]);
    (RowMajorMatrix::new(th, THASH_WIDTH), RowMajorMatrix::new(tc, TCTL_WIDTH))
}

impl BaseAir<Val> for THashAir {
    fn width(&self) -> usize {
        THASH_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(RowMajorMatrix::new((0..1024).map(|r| Val::from_u64((r / SLOT) as u64)).collect(), 1))
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        11
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..8).chain(16..24).collect()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl BaseAir<Val> for TCtlAir {
    fn width(&self) -> usize {
        TCTL_WIDTH
    }
    fn num_public_values(&self) -> usize {
        12
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut v = vec![Val::ZERO; 128 * 5];
        for k in 0..SLOT {
            v[k * 5] = Val::from_u64(k as u64);
            v[k * 5 + 1] = Val::from_bool(k == 0);
            v[k * 5 + 2] = Val::from_bool(k == 1);
            v[k * 5 + 3] = Val::from_bool(k == 31);
            v[k * 5 + 4] = Val::ONE;
        }
        Some(RowMajorMatrix::new(v, 5))
    }
    fn preprocessed_width(&self) -> usize {
        5
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..8).chain([12]).collect()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for THashAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let loc: Vec<AB::Expr> = exprs::<AB, _>(main.current_slice());
        let nxt: Vec<AB::Expr> = exprs::<AB, _>(main.next_slice());
        let lvl: AB::Expr = builder.preprocessed().current_slice()[0].into();
        let per: Vec<AB::Expr> = exprs::<AB, _>(builder.periodic_values());
        let (f, pt, c) = (per[8].clone(), per[9].clone(), per[10].clone());
        let l = AB::Expr::ONE - f.clone() - pt.clone() - c.clone();
        let rd = Round {
            s: loc[0..8].to_vec(),
            u: loc[8..16].to_vec(),
            sn: nxt[0..8].to_vec(),
            rc: per[0..8].to_vec(),
            f: f.clone(),
            pt: pt.clone(),
            c: c.clone(),
            l: l.clone(),
        };
        let (s, u, inp, inn) = (&loc[0..8], &loc[8..16], &loc[16..24], &nxt[16..24]);
        // 1-8 A_i
        for i in 0..8 {
            builder.assert_zero(rd.sbox(i));
        }
        // 9-16 B'_i: tau'_0 = L + C, tau'_1..7 = Pt + L + C
        for i in 0..8 {
            let tau = if i == 0 { l.clone() + c.clone() } else { pt.clone() + l.clone() + c.clone() };
            builder.assert_zero(tau * u[i].clone());
        }
        // 17-24 C_j
        for j in 0..8 {
            builder.assert_zero(rd.round(j));
        }
        // 25-32 K_j: L (s_j - in_j)
        for j in 0..8 {
            builder.assert_zero(l.clone() * (s[j].clone() - inp[j].clone()));
        }
        // 33-40 M_j: (1 - C)(in'_j - in_j)
        for j in 0..8 {
            builder.assert_zero((AB::Expr::ONE - c.clone()) * (inn[j].clone() - inp[j].clone()));
        }
        // bus P2: receive (lvl_h, in0..7, s0..3) with multiplicity -C on the C row
        let fields: Vec<AB::Expr> = std::iter::once(lvl).chain(inp.iter().cloned()).chain(s[0..4].iter().cloned()).collect();
        builder.push_interaction(BUS, fields, Count::bounded(-c, 1));
    }
}

impl<AB: AirBuilder<F = Val> + InteractionBuilder> Air<AB> for TCtlAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let loc: Vec<AB::Expr> = exprs::<AB, _>(main.current_slice());
        let nxt: Vec<AB::Expr> = exprs::<AB, _>(main.next_slice());
        let pre: Vec<AB::Expr> = exprs::<AB, _>(builder.preprocessed().current_slice());
        let pv: Vec<AB::Expr> = exprs::<AB, _>(builder.public_values());
        let trans = builder.is_transition();
        let (inp, out, b) = (&loc[0..8], &loc[8..12], loc[12].clone());
        let (inn, bn) = (&nxt[0..8], nxt[12].clone());
        let (lvl, f_null, f_leaf, f_root, f_used) =
            (pre[0].clone(), pre[1].clone(), pre[2].clone(), pre[3].clone(), pre[4].clone());
        let one = AB::Expr::ONE;
        let iv = iv_nf();
        // 1-4 N1_k: f_null (in_{4+k} - IV_NF[k])
        for k in 0..4 {
            builder.assert_zero(f_null.clone() * (inp[4 + k].clone() - AB::Expr::from(iv[k])));
        }
        // 5-8 N2_j: f_null (out_j - NF_j)
        for j in 0..4 {
            builder.assert_zero(f_null.clone() * (out[j].clone() - pv[4 + j].clone()));
        }
        // 9-12 N3_j: f_root (out_j - ROOT_j)
        for j in 0..4 {
            builder.assert_zero(f_root.clone() * (out[j].clone() - pv[j].clone()));
        }
        // 13 N4: (f_null + f_leaf) b
        builder.assert_zero((f_null.clone() + f_leaf) * b.clone());
        // 14 N5: b (b - 1)
        builder.assert_zero(b.clone() * (b.clone() - one.clone()));
        // 15-18 N6_j: is_transition (1 - b') (in'_j - out_j)
        for j in 0..4 {
            builder.assert_zero(trans.clone() * (one.clone() - bn.clone()) * (inn[j].clone() - out[j].clone()));
        }
        // 19-22 N7_j: is_transition b' (in'_{4+j} - out_j)
        for j in 0..4 {
            builder.assert_zero(trans.clone() * bn.clone() * (inn[4 + j].clone() - out[j].clone()));
        }
        // 23-26 N8_j: (1 - f_used) out_j; 27 N8_4: (1 - f_used) b; 28-31 N8_{5+j}: (1 - f_used) in_{4+j}
        let pad = one.clone() - f_used.clone();
        for j in 0..4 {
            builder.assert_zero(pad.clone() * out[j].clone());
        }
        builder.assert_zero(pad.clone() * b);
        for j in 0..4 {
            builder.assert_zero(pad.clone() * inp[4 + j].clone());
        }
        // bus P2: send (lvl, in0..7, out0..3) with multiplicity +f_used
        let fields: Vec<AB::Expr> = std::iter::once(lvl).chain(inp.iter().cloned()).chain(out.iter().cloned()).collect();
        builder.push_interaction(BUS, fields, Count::bounded(f_used, 1));
    }
}

/// Exact multiset check of bus P2 (native, no challenges): every T_hash receive equals a T_ctl send.
pub fn bus_balanced(th: &RowMajorMatrix<Val>, tc: &RowMajorMatrix<Val>) -> bool {
    let mut recv: Vec<Vec<u64>> = Vec::new();
    for r in 0..1024 {
        if r % SLOT == SLOT - 1 {
            let row = &th.values[r * THASH_WIDTH..(r + 1) * THASH_WIDTH];
            let mut t = vec![(r / SLOT) as u64];
            t.extend(row[16..24].iter().chain(&row[0..4]).map(|x| x.as_canonical_u64()));
            recv.push(t);
        }
    }
    let mut send: Vec<Vec<u64>> = Vec::new();
    for r in 0..SLOT {
        let row = &tc.values[r * TCTL_WIDTH..(r + 1) * TCTL_WIDTH];
        let mut t = vec![r as u64];
        t.extend(row[0..12].iter().map(|x| x.as_canonical_u64()));
        send.push(t);
    }
    recv.sort();
    send.sort();
    recv == send
}

/// Poseidon2 checks: AIR-SPEC sec. 2 test vector, and a differential test against p3-goldilocks's
/// `default_goldilocks_poseidon2_8()` on `n` random inputs (plus the all-zero and all-(p-1) inputs).
pub fn poseidon2_selftest(n: usize) -> (bool, usize) {
    use p3_symmetric::Permutation;
    let tv_in: [Val; 8] = core::array::from_fn(|i| Val::from_u64(i as u64));
    let tv_out: [u64; 8] = [
        0x020cf04a1b214d14,
        0x84e14aaaeacaed25,
        0x1ae0f640e81c7457,
        0xa4d204cbaeb0d8a5,
        0x0cf637b627b3a7ff,
        0x788d304d948b486b,
        0x7327133ea1949af4,
        0xf415abb924da395b,
    ];
    let tv_ok = perm(tv_in).iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>() == tv_out;
    let p2 = p3_goldilocks::default_goldilocks_poseidon2_8();
    let mut rng = StdRng::seed_from_u64(0x5032_4446);
    let mut inputs: Vec<[Val; 8]> = vec![[Val::ZERO; 8], [Val::NEG_ONE; 8]];
    for _ in 0..n {
        inputs.push(core::array::from_fn(|_| rand_val(&mut rng)));
    }
    let mut agree = 0;
    for x in &inputs {
        if p2.permute(*x) == perm(*x) {
            agree += 1;
        }
    }
    (tv_ok && agree == inputs.len(), agree)
}
