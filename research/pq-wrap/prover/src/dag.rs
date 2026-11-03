//! Constraint-DAG export. For each AIR of a batch: Plonky3's symbolic constraints (AIR plus LogUp,
//! as `p3_batch_stark::symbolic` builds them for the verifier) as one hash-consed node table, the
//! constraints in global emission order, and the periodic columns. A generator compiles this into
//! script; FORMAT.md ("Constraint DAG") gives the evaluation rule.

use std::collections::HashMap;

use p3_air::BaseAir;
use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt,
};
use p3_batch_stark::symbolic::{get_constraint_layout, get_symbolic_constraints};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{LogUpGadget, LookupProtocol, Lookups};
use serde_json::{Value, json};

use crate::airs::TestAir;
use crate::cfg::{EF, Val};

#[derive(Default)]
struct Table {
    nodes: Vec<Value>,
    is_ext: Vec<bool>,
    index: HashMap<String, usize>,
}

impl Table {
    fn add(&mut self, node: Value, ext: bool) -> usize {
        let key = node.to_string();
        if let Some(&i) = self.index.get(&key) {
            return i;
        }
        let i = self.nodes.len();
        self.nodes.push(node);
        self.is_ext.push(ext);
        self.index.insert(key, i);
        i
    }

    fn base(&mut self, e: &SymbolicExpression<Val>) -> usize {
        match e {
            SymbolicExpr::Leaf(l) => {
                let n = match l {
                    BaseLeaf::Variable(v) => match v.entry {
                        BaseEntry::Main { offset } => json!({"op": "main", "row": offset, "col": v.index}),
                        BaseEntry::Preprocessed { offset } => json!({"op": "pre", "row": offset, "col": v.index}),
                        BaseEntry::Periodic => json!({"op": "periodic", "col": v.index}),
                        BaseEntry::Public => json!({"op": "public", "col": v.index}),
                    },
                    BaseLeaf::IsFirstRow => json!({"op": "is_first_row"}),
                    BaseLeaf::IsLastRow => json!({"op": "is_last_row"}),
                    BaseLeaf::IsTransition => json!({"op": "is_transition"}),
                    BaseLeaf::Constant(c) => json!({"op": "const", "v": c.as_canonical_u64().to_string()}),
                };
                self.add(n, false)
            }
            SymbolicExpr::Add { x, y, .. } => {
                let (a, b) = (self.base(x), self.base(y));
                self.add(json!({"op": "add", "a": a, "b": b}), false)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (a, b) = (self.base(x), self.base(y));
                self.add(json!({"op": "sub", "a": a, "b": b}), false)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (a, b) = (self.base(x), self.base(y));
                self.add(json!({"op": "mul", "a": a, "b": b}), false)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.base(x);
                self.add(json!({"op": "neg", "a": a}), false)
            }
        }
    }

    fn ext(&mut self, e: &SymbolicExpressionExt<Val, EF>) -> usize {
        let bin = |t: &mut Self, op: &str, a: usize, b: usize| {
            let ext = t.is_ext[a] || t.is_ext[b];
            t.add(json!({"op": op, "a": a, "b": b}), ext)
        };
        match e {
            SymbolicExpr::Leaf(l) => match l {
                // a lifted base expression shares the base nodes
                ExtLeaf::Base(b) => self.base(b),
                ExtLeaf::ExtVariable(v) => {
                    let n = match v.entry {
                        ExtEntry::Permutation { offset } => json!({"op": "perm", "row": offset, "col": v.index}),
                        ExtEntry::Challenge => json!({"op": "challenge", "col": v.index}),
                        ExtEntry::PermutationValue => json!({"op": "perm_value", "col": v.index}),
                    };
                    self.add(n, true)
                }
                ExtLeaf::ExtConstant(c) => {
                    let co: Vec<String> = <EF as BasedVectorSpace<Val>>::as_basis_coefficients_slice(c)
                        .iter()
                        .map(|x| x.as_canonical_u64().to_string())
                        .collect();
                    self.add(json!({"op": "ext_const", "v": co}), true)
                }
            },
            SymbolicExpr::Add { x, y, .. } => {
                let (a, b) = (self.ext(x), self.ext(y));
                bin(self, "add", a, b)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (a, b) = (self.ext(x), self.ext(y));
                bin(self, "sub", a, b)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (a, b) = (self.ext(x), self.ext(y));
                bin(self, "mul", a, b)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.ext(x);
                let ext = self.is_ext[a];
                self.add(json!({"op": "neg", "a": a}), ext)
            }
        }
    }
}

fn layout_for(air: &TestAir) -> AirLayout {
    AirLayout {
        preprocessed_width: <TestAir as BaseAir<Val>>::preprocessed_width(air),
        main_width: air.width(),
        num_public_values: <TestAir as BaseAir<Val>>::num_public_values(air),
        num_periodic_columns: <TestAir as BaseAir<Val>>::num_periodic_columns(air),
        ..Default::default()
    }
}

pub fn export(air: &TestAir, lookups: &Lookups<Val>) -> Value {
    let g = LogUpGadget::new();
    let layout = layout_for(air);
    let (base, ext) = get_symbolic_constraints::<Val, EF, _, _>(air, layout, lookups, &g);
    let order = get_constraint_layout::<Val, EF, _, _>(air, layout, lookups, &g);
    assert_eq!(order.base_indices.len(), base.len());
    assert_eq!(order.ext_indices.len(), ext.len());
    let mut t = Table::default();
    let total = base.len() + ext.len();
    let mut slots: Vec<Option<Value>> = vec![None; total];
    for (c, &gi) in base.iter().zip(&order.base_indices) {
        let id = t.base(c);
        slots[gi] = Some(json!({"node": id, "field": "base"}));
    }
    for (c, &gi) in ext.iter().zip(&order.ext_indices) {
        let id = t.ext(c);
        slots[gi] = Some(json!({"node": id, "field": "ext"}));
    }
    let constraints: Vec<Value> = slots.into_iter().map(|s| s.expect("dense global order")).collect();
    let periodic: Vec<Vec<String>> = <TestAir as BaseAir<Val>>::periodic_columns(air)
        .iter()
        .map(|c| c.iter().map(|x| x.as_canonical_u64().to_string()).collect())
        .collect();
    let lookups_v = serde_json::to_value(lookups).unwrap();
    json!({
        "air": air.label(),
        "width": air.width(),
        "preprocessed_width": layout.preprocessed_width,
        "num_public_values": layout.num_public_values,
        "periodic_columns": periodic,
        "num_lookups": lookups.len(),
        "num_permutation_challenges": lookups.len() * g.num_challenges(),
        "permutation_width_ext": if lookups.is_empty() { 0 } else { lookups.len() + 1 },
        "fold": "acc = sum_{i<K} alpha^(K-1-i) * C_i over the constraints in this order (Horner: acc = acc*alpha + C_i); check acc * inv_vanishing(zeta) == quotient(zeta)",
        "nodes": t.nodes,
        "node_is_ext": t.is_ext,
        "constraints": constraints,
        "lookups": lookups_v,
    })
}

/// Evaluate the exported DAG's base-field constraints on two concrete trace rows (row r, r+1 mod n)
/// with the row's selectors, periodic values and public values. Constraint i -> value.
pub fn eval_base_row(
    dag: &Value,
    local: &[Val],
    next: &[Val],
    pre_local: &[Val],
    pre_next: &[Val],
    periodic: &[Val],
    public: &[Val],
    sel: (Val, Val, Val),
) -> Vec<Option<Val>> {
    let nodes = dag["nodes"].as_array().unwrap();
    let mut val: Vec<Option<Val>> = Vec::with_capacity(nodes.len());
    let u = |v: &Value| v.as_u64().unwrap() as usize;
    for n in nodes {
        let get = |k: &str, val: &Vec<Option<Val>>| val[u(&n[k])];
        let x = match n["op"].as_str().unwrap() {
            "main" => Some(if u(&n["row"]) == 0 { local[u(&n["col"])] } else { next[u(&n["col"])] }),
            "pre" => Some(if u(&n["row"]) == 0 { pre_local[u(&n["col"])] } else { pre_next[u(&n["col"])] }),
            "periodic" => Some(periodic[u(&n["col"])]),
            "public" => Some(public[u(&n["col"])]),
            "is_first_row" => Some(sel.0),
            "is_last_row" => Some(sel.1),
            "is_transition" => Some(sel.2),
            "const" => Some(Val::from_u64(n["v"].as_str().unwrap().parse().unwrap())),
            "add" => get("a", &val).zip(get("b", &val)).map(|(a, b)| a + b),
            "sub" => get("a", &val).zip(get("b", &val)).map(|(a, b)| a - b),
            "mul" => get("a", &val).zip(get("b", &val)).map(|(a, b)| a * b),
            "neg" => get("a", &val).map(|a| -a),
            _ => None, // extension leaves: not evaluated here
        };
        val.push(x);
    }
    dag["constraints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| if c["field"] == "base" { val[u(&c["node"])] } else { None })
        .collect()
}
