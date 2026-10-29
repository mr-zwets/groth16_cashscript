//! The two AIRs proved in Track 5.
//!
//! - `FibAir`: 2 columns (a, b), 3 public values (a0, b0, b_{n-1}); max constraint degree 2.
//! - `MimcAir`: Track 4's statement, a MiMC-7 chain y_out = F^(n-1)(x_in) with F(x) = (x + c_i)^7 and
//!   8 periodic round constants C[j] = SHA256("verifier.cash/pq-hash/rc" || u8 j) mod p.
//!   Plonky3 multiplies transition constraints by a degree-1 selector, so the round is split over
//!   3 columns to keep every constraint at total degree <= 3 (2 quotient chunks, like Track 4's
//!   H0 + X^n H1):
//!     X_i (state), A_i = (X_i + c_i)^3, B_i = A_i^2
//!     all rows:        A - s^3 = 0                (deg 3)
//!     all rows:        B - A^2 = 0                (deg 2)
//!     transition:      X' - B * s = 0             (deg 2 + selector = 3)
//!     first row:       X - x_in = 0               (deg 1 + selector = 2)
//!     last row:        X - y_out = 0              (deg 1 + selector = 2)
//!   so X_{i+1} = s^6 * s = (X_i + c_i)^7.

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha256};

pub type Val = Goldilocks;

// ---------------------------------------------------------------- Fibonacci

pub struct FibAir;

impl<F> BaseAir<F> for FibAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder> Air<AB> for FibAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let (a0, b0, out) = (pis[0], pis[1], pis[2]);
        let local = main.current_slice();
        let next = main.next_slice();
        let (l0, l1, n0, n1) = (local[0], local[1], next[0], next[1]);
        let mut first = builder.when_first_row();
        first.assert_eq(l0, a0);
        first.assert_eq(l1, b0);
        let mut tr = builder.when_transition();
        tr.assert_eq(l1, n0);
        tr.assert_eq(l0 + l1, n1);
        builder.when_last_row().assert_eq(l1, out);
    }
}

pub fn fib_trace(a0: u64, b0: u64, n: usize) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let mut v = Vec::with_capacity(2 * n);
    let (mut a, mut b) = (Val::from_u64(a0), Val::from_u64(b0));
    for _ in 0..n {
        v.push(a);
        v.push(b);
        let t = a + b;
        a = b;
        b = t;
    }
    let out = v[2 * n - 1];
    (RowMajorMatrix::new(v, 2), vec![Val::from_u64(a0), Val::from_u64(b0), out])
}

// ---------------------------------------------------------------- MiMC-7

pub fn round_constants() -> Vec<Val> {
    (0u8..8)
        .map(|j| {
            let mut h = Sha256::new();
            h.update(b"verifier.cash/pq-hash/rc");
            h.update([j]);
            let d = h.finalize();
            // LE integer of the 32-byte digest, reduced mod p
            let p: u128 = Val::ORDER_U64 as u128;
            let mut acc: u128 = 0;
            for &byte in d.iter().rev() {
                acc = ((acc << 8) | byte as u128) % p;
            }
            Val::from_u64(acc as u64)
        })
        .collect()
}

/// x_in for statement k, as in Track 4: LE(SHA256("verifier.cash/pq-hash/x_in" || u8 k)) mod p.
pub fn mimc_x_in(k: u8) -> Val {
    let mut h = Sha256::new();
    h.update(b"verifier.cash/pq-hash/x_in");
    h.update([k]);
    let d = h.finalize();
    let p: u128 = Val::ORDER_U64 as u128;
    let mut acc: u128 = 0;
    for &byte in d.iter().rev() {
        acc = ((acc << 8) | byte as u128) % p;
    }
    Val::from_u64(acc as u64)
}

pub struct MimcAir {
    pub rc: Vec<Vec<Val>>,
}

impl MimcAir {
    pub fn new() -> Self {
        Self { rc: vec![round_constants()] }
    }
}

impl BaseAir<Val> for MimcAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.rc)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for MimcAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let (x_in, y_out) = (pis[0], pis[1]);
        let c: AB::Expr = builder.periodic_values()[0].into();
        let local = main.current_slice();
        let next = main.next_slice();
        let (x, a, b, xn) = (local[0], local[1], local[2], next[0]);
        let s: AB::Expr = x.into() + c;
        builder.assert_eq(a, s.clone() * s.clone() * s.clone());
        builder.assert_eq(b, a.into() * a.into());
        builder.when_transition().assert_eq(xn, b.into() * s);
        builder.when_first_row().assert_eq(x, x_in);
        builder.when_last_row().assert_eq(x, y_out);
    }
}

pub fn mimc_trace(x_in: Val, n: usize) -> (RowMajorMatrix<Val>, Vec<Val>) {
    let rc = round_constants();
    let mut v = Vec::with_capacity(3 * n);
    let mut x = x_in;
    for i in 0..n {
        let s = x + rc[i % 8];
        let a = s * s * s;
        let b = a * a;
        v.push(x);
        v.push(a);
        v.push(b);
        x = b * s;
    }
    let y_out = v[3 * (n - 1)];
    (RowMajorMatrix::new(v, 3), vec![x_in, y_out])
}
