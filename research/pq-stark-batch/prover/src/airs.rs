//! Plonky3's batch-stark test AIRs, ported from `batch-stark/tests/simple.rs` at the pin
//! (0d803737, MIT/Apache-2.0). Constraint order, lookups and multiplicities are kept exactly; the
//! changes are: one enum `TestAir` instead of `DemoAir` / `DemoAirWithLookups`, slices instead of
//! the `FibRow` transmute, and public values computed in the field (the test's `fib_n` is u64
//! arithmetic, which overflows above 2^6 rows).
//!
//! The five acceptance cases of DESIGN-T8 S1 are built by `case()`:
//!   single_instance, three_instances_mixed_sizes, mixed_preprocessed, both_lookups_zk, periodic_air_zk
//! at Plonky3's heights plus `shift` (to meet the strict FRI height rule of a production set).

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::cfg::Val;

#[derive(Debug, Clone, Copy)]
pub struct FibonacciAir {
    pub log_height: usize,
}

impl<F: Field> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let n = 1 << self.log_height;
        let mut m = RowMajorMatrix::new(F::zero_vec(n), 1);
        for (i, v) in m.values.iter_mut().enumerate().take(n) {
            *v = F::from_u64(i as u64);
        }
        Some(m)
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a0 = pis[0];
        let b0 = pis[1];
        let x = pis[2];

        let local = main.current_slice();
        let next = main.next_slice();
        let (l_left, l_right) = (local[0], local[1]);
        let (n_left, n_right) = (next[0], next[1]);

        let mut wf = builder.when_first_row();
        wf.assert_eq(l_left, a0);
        wf.assert_eq(l_right, b0);

        let mut wt = builder.when_transition();
        wt.assert_eq(l_right, n_left);
        wt.assert_eq(l_left + l_right, n_right);

        builder.when_last_row().assert_eq(l_right, x);
    }
}

pub fn fib_trace(a: u64, b: u64, n: usize) -> RowMajorMatrix<Val> {
    assert!(n.is_power_of_two());
    let mut v = Val::zero_vec(n * 2);
    v[0] = Val::from_u64(a);
    v[1] = Val::from_u64(b);
    for i in 1..n {
        v[2 * i] = v[2 * i - 1];
        v[2 * i + 1] = v[2 * i - 2] + v[2 * i - 1];
    }
    RowMajorMatrix::new(v, 2)
}

/// right column of the last row of `fib_trace(0, 1, n)` (= F_n in the field)
pub fn fib_out(n: usize) -> Val {
    let (mut a, mut b) = (Val::ZERO, Val::ONE);
    for _ in 0..n {
        let t = a + b;
        a = b;
        b = t;
    }
    a
}

#[derive(Debug, Clone, Copy)]
pub struct MulAir {
    pub reps: usize,
}
impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        self.reps * 3 + 1
    }
}
impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        for i in 0..self.reps {
            let s = i * 3;
            let a = local[s];
            let b = local[s + 1];
            let c = local[s + 2];
            builder.assert_eq(a * b, c);
            builder.when_transition().assert_eq(b, next[s]);
            builder.when_transition().assert_eq(a + b, next[s + 1]);
        }
    }
}

pub fn mul_trace(rows: usize, reps: usize) -> RowMajorMatrix<Val> {
    assert!(rows.is_power_of_two());
    let w = reps * 3 + 1;
    let mut v = Val::zero_vec(rows * w);
    let last_idx = w - 1;
    for rep in 0..reps {
        let mut a = Val::ZERO;
        let mut b = Val::ONE;
        for i in 0..rows {
            let idx = i * w + rep * 3;
            v[idx] = a;
            v[idx + 1] = b;
            v[idx + 2] = v[idx] * v[idx + 1];
            if i != rows - 1 {
                v[i * w + last_idx] = b;
            }
            let tmp = a + b;
            a = b;
            b = tmp;
        }
    }
    RowMajorMatrix::new(v, w)
}

#[derive(Clone)]
pub struct PeriodicAir {
    pub periodic: Vec<Vec<Val>>,
}

impl PeriodicAir {
    pub fn new() -> Self {
        let f = Val::from_u64;
        Self { periodic: vec![vec![f(1), f(2), f(3), f(4)], vec![f(10), f(20)]] }
    }
    pub fn valid_trace(&self, rows: usize) -> RowMajorMatrix<Val> {
        let mut values = Val::zero_vec(rows * 2);
        for i in 0..rows {
            values[2 * i] = self.periodic[0][i % self.periodic[0].len()];
            values[2 * i + 1] = self.periodic[1][i % self.periodic[1].len()];
        }
        RowMajorMatrix::new(values, 2)
    }
}

impl BaseAir<Val> for PeriodicAir {
    fn width(&self) -> usize {
        2
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic.len()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PeriodicAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let p0 = builder.periodic_values()[0].into();
        let p1 = builder.periodic_values()[1].into();
        builder.assert_eq(local[0], p0);
        builder.assert_eq(local[1], p1);
    }
}

#[derive(Clone, Default)]
pub struct MulAirLookups {
    pub air: Option<MulAir>,
    pub is_local: bool,
    pub is_global: bool,
    pub global_names: Vec<String>,
}

impl MulAirLookups {
    fn mul(&self) -> MulAir {
        self.air.unwrap()
    }
}

impl<F> BaseAir<F> for MulAirLookups {
    fn width(&self) -> usize {
        <MulAir as BaseAir<F>>::width(&self.mul())
    }
}

impl<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder> Air<AB> for MulAirLookups {
    fn eval(&self, builder: &mut AB) {
        self.mul().eval(builder);
        let main = builder.main();
        let local = main.current_slice();
        let last_idx = <MulAir as BaseAir<AB::F>>::width(&self.mul()) - 1;
        let lut = local[last_idx];
        for rep in 0..self.mul().reps {
            let base_idx = rep * 3;
            let a = local[base_idx];
            let b = local[base_idx + 1];
            if self.is_local {
                builder.push_local_interaction(vec![
                    (vec![a.into()], Count::bounded(AB::Expr::ONE, 1)),
                    (vec![lut.into()], Count::provided(-AB::Expr::ONE)),
                ]);
            }
            if self.is_global {
                builder.push_interaction(&self.global_names[rep], [a.into(), b.into()], -1);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FibAirLookups {
    pub air: FibonacciAir,
    pub is_global: bool,
    pub name_and_mult: Option<(String, u64)>,
}

impl<F: Field> BaseAir<F> for FibAirLookups {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.air.preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
}

impl<AB: PermutationAirBuilder + InteractionBuilder> Air<AB> for FibAirLookups
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.air.eval(builder);
        if self.is_global {
            let main = builder.main();
            let left = main.current(0).unwrap();
            let right = main.current(1).unwrap();
            let (name, multiplicity) = match &self.name_and_mult {
                Some((n, m)) => (n.clone(), *m),
                None => ("MulFib".to_string(), 2),
            };
            builder.push_interaction(
                &name,
                [left.into(), right.into()],
                Count::bounded(AB::Expr::from_u64(multiplicity), multiplicity as u32),
            );
        }
    }
}

/// One enum over every test AIR, so a heterogeneous batch has one AIR type.
#[derive(Clone)]
pub enum TestAir {
    Fib(FibonacciAir),
    Mul(MulAir),
    Periodic(PeriodicAir),
    FibLookups(FibAirLookups),
    MulLookups(MulAirLookups),
}

impl TestAir {
    pub fn label(&self) -> String {
        match self {
            Self::Fib(a) => format!("fib(log_n={})", a.log_height),
            Self::Mul(a) => format!("mul(reps={})", a.reps),
            Self::Periodic(_) => "periodic".into(),
            Self::FibLookups(a) => format!("fib_lookups(log_n={}, global={})", a.air.log_height, a.is_global),
            Self::MulLookups(a) => format!(
                "mul_lookups(reps={}, local={}, global={})",
                a.mul().reps,
                a.is_local,
                a.is_global
            ),
        }
    }
}

impl BaseAir<Val> for TestAir {
    fn width(&self) -> usize {
        match self {
            Self::Fib(a) => <FibonacciAir as BaseAir<Val>>::width(a),
            Self::Mul(a) => <MulAir as BaseAir<Val>>::width(a),
            Self::Periodic(a) => a.width(),
            Self::FibLookups(a) => <FibonacciAir as BaseAir<Val>>::width(&a.air),
            Self::MulLookups(a) => <MulAir as BaseAir<Val>>::width(&a.mul()),
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Fib(a) => <FibonacciAir as BaseAir<Val>>::num_public_values(a),
            Self::FibLookups(a) => <FibonacciAir as BaseAir<Val>>::num_public_values(&a.air),
            _ => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::Fib(a) => a.preprocessed_trace(),
            Self::FibLookups(a) => a.air.preprocessed_trace(),
            _ => None,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Fib(_) | Self::FibLookups(_) => 1,
            _ => 0,
        }
    }
    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Periodic(a) => a.num_periodic_columns(),
            _ => 0,
        }
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        match self {
            Self::Periodic(a) => a.periodic_columns(),
            _ => Cow::Borrowed(&[]),
        }
    }
}

impl<AB: AirBuilder<F = Val> + PermutationAirBuilder + InteractionBuilder> Air<AB> for TestAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Fib(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
            Self::Periodic(a) => a.eval(builder),
            Self::FibLookups(a) => a.eval(builder),
            Self::MulLookups(a) => a.eval(builder),
        }
    }
}

/// One batch statement: AIRs, traces, public values, and whether the case builds its common data
/// from `from_airs_and_degrees` (lookup cases) or `from_instances`.
#[allow(dead_code)]
pub struct Case {
    pub name: String,
    pub airs: Vec<TestAir>,
    pub traces: Vec<RowMajorMatrix<Val>>,
    pub pvs: Vec<Vec<Val>>,
    pub log_heights: Vec<usize>,
    pub zk_in_plonky3: bool,
    pub uses_lookups: bool,
}

pub const CASES: [&str; 5] = [
    "single_instance",
    "three_instances_mixed_sizes",
    "mixed_preprocessed",
    "both_lookups_zk",
    "periodic_air_zk",
];

fn fib(log_n: usize) -> (TestAir, RowMajorMatrix<Val>, Vec<Val>) {
    let n = 1 << log_n;
    (
        TestAir::Fib(FibonacciAir { log_height: log_n }),
        fib_trace(0, 1, n),
        vec![Val::ZERO, Val::ONE, fib_out(n)],
    )
}
fn mul(log_n: usize, reps: usize) -> (TestAir, RowMajorMatrix<Val>, Vec<Val>) {
    (TestAir::Mul(MulAir { reps }), mul_trace(1 << log_n, reps), vec![])
}

/// Plonky3's test with every trace height multiplied by 2^shift.
pub fn case(name: &str, shift: usize) -> Case {
    let mk = |name: &str, items: Vec<(TestAir, RowMajorMatrix<Val>, Vec<Val>)>, logs: Vec<usize>, zk: bool| {
        let (mut airs, mut traces, mut pvs) = (vec![], vec![], vec![]);
        for (a, t, p) in items {
            airs.push(a);
            traces.push(t);
            pvs.push(p);
        }
        Case {
            name: name.into(),
            airs,
            traces,
            pvs,
            log_heights: logs,
            zk_in_plonky3: zk,
            uses_lookups: false,
        }
    };
    let s = shift;
    match name {
        // test_single_instance: fib, 32 rows (make_config, non-ZK)
        "single_instance" => mk(name, vec![fib(5 + s)], vec![5 + s], false),
        // test_three_instances_mixed_sizes: fib 16, mul(reps 2) 8, fib 8
        "three_instances_mixed_sizes" => mk(
            name,
            vec![fib(4 + s), mul(3 + s, 2), fib(3 + s)],
            vec![4 + s, 3 + s, 3 + s],
            false,
        ),
        // test_mixed_preprocessed: fib 16 (preprocessed), mul 16 (none)
        "mixed_preprocessed" => mk(name, vec![fib(4 + s), mul(4 + s, 2)], vec![4 + s, 4 + s], false),
        // test_periodic_air_zk: periodic, 64 rows (make_config_zk)
        "periodic_air_zk" => {
            let air = PeriodicAir::new();
            let t = air.valid_trace(1 << (6 + s));
            mk(name, vec![(TestAir::Periodic(air), t, vec![])], vec![6 + s], true)
        }
        // test_batch_stark_both_lookups_zk: mul(reps 2, local + global "MulFib") and fib (global,
        // multiplicity 2), 32 rows each (make_config_zk)
        "both_lookups_zk" => {
            let log_n = 5 + s;
            let n = 1 << log_n;
            let mul_l = MulAirLookups {
                air: Some(MulAir { reps: 2 }),
                is_local: true,
                is_global: true,
                global_names: vec!["MulFib".into(), "MulFib".into()],
            };
            let fib_l = FibAirLookups { air: FibonacciAir { log_height: log_n }, is_global: true, name_and_mult: None };
            let mut c = mk(
                name,
                vec![
                    (TestAir::MulLookups(mul_l), mul_trace(n, 2), vec![]),
                    (TestAir::FibLookups(fib_l), fib_trace(0, 1, n), vec![Val::ZERO, Val::ONE, fib_out(n)]),
                ],
                vec![log_n, log_n],
                true,
            );
            c.uses_lookups = true;
            c
        }
        _ => panic!("unknown case {name}; one of {CASES:?}"),
    }
}
