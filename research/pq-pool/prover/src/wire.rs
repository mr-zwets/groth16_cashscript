//! p3b-v1: canonical byte format for Plonky3 batch-stark proofs (SHA-256, Goldilocks, D = 3).
//! See FORMAT.md. Works on the `serde_json::Value` of `BatchProof<SC>`, so one encoder serves the
//! plain and the hiding PCS. Every length comes from a `Shape` that `shape::derive` computes from
//! the verifying key (AIRs, trace heights, common data, parameter set); the encoder checks that the
//! proof has exactly that shape, and the decoder rebuilds Plonky3's serde tree from bytes + shape.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const P: u64 = 0xFFFF_FFFF_0000_0001;
pub const FORMAT: &str = "p3b-v1";

/// Per-instance shape (verifying-key data).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InstShape {
    pub label: String,
    /// log2 of the trace height n_i
    pub log_n: usize,
    /// Plonky3's `degree_bits[i]` = log n_i + zk
    pub degree_bits: usize,
    /// log2 of the LDE height of every matrix of this instance = degree_bits + log_blowup
    pub log_lde: usize,
    pub width: usize,
    pub opens_next: bool,
    pub num_public_values: usize,
    pub preprocessed_width: usize,
    pub preprocessed_next: bool,
    pub num_periodic: usize,
    /// quotient chunks committed (ZK included)
    pub num_chunks: usize,
    /// lookups declared by this instance (0 = none)
    pub num_lookups: usize,
    /// opened permutation values per point = (num_lookups + 1) * D, or 0
    pub perm_width: usize,
}

/// One committed matrix inside a PCS round.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MatShape {
    pub instance: usize,
    /// "random" | "trace" | "quotient[k]" | "preprocessed" | "permutation"
    pub what: String,
    pub log_height: usize,
    /// base columns committed (random codewords included)
    pub width: usize,
    /// opening points: 1 (zeta) or 2 (zeta, zeta * g_i)
    pub points: usize,
}

/// One PCS input round = one commitment = one Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoundShape {
    pub name: String,
    /// random codewords per matrix in this round (zk; 0 for the preprocessed round)
    pub rc: usize,
    pub matrices: Vec<MatShape>,
    /// digests in this round's Merkle cap
    pub cap_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Shape {
    pub format: String,
    pub ext: usize,
    pub zk: bool,
    pub salt: usize,
    pub digest: usize,
    pub cap_height: usize,
    pub log_blowup: usize,
    pub instances: Vec<InstShape>,
    /// PCS rounds in opening order: [random], trace, quotient, [preprocessed], [permutation]
    pub rounds: Vec<RoundShape>,
    pub has_lookups: bool,
    /// witnesses present in the bytes (bits > 0); an absent witness decodes to 0
    pub lookup_pow: bool,
    pub ood_pow: bool,
    pub batch_pow: bool,
    pub commit_pow: bool,
    pub query_pow: bool,
    pub log_arities: Vec<usize>,
    /// digests in each FRI commit-phase cap
    pub fri_cap_lens: Vec<usize>,
    pub num_queries: usize,
    pub final_poly_len: usize,
}

impl Shape {
    fn round(&self, name: &str) -> Option<&RoundShape> {
        self.rounds.iter().find(|r| r.name == name)
    }
}

#[derive(Default, Clone, Debug, Serialize)]
pub struct Sizes {
    pub roots: usize,
    pub terminals: usize,
    pub ood_values: usize,
    pub random_values: usize,
    pub pow_witnesses: usize,
    pub fri_roots: usize,
    pub final_poly: usize,
    pub input_leaves: usize,
    pub input_salts: usize,
    pub input_siblings: usize,
    pub fri_leaves: usize,
    pub fri_salts: usize,
    pub fri_siblings: usize,
    pub counts: usize,
    pub total: usize,
}

/// Byte offset and length of every top-level section, in order (for tests and tooling).
#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub at: usize,
    pub len: usize,
}

type Bucket = fn(&mut Sizes) -> &mut usize;

struct W<'a> {
    out: &'a mut Vec<u8>,
    sizes: &'a mut Sizes,
    sections: &'a mut Vec<Section>,
    h: usize,
}

fn u64v(v: &Value) -> u64 {
    v.as_u64().expect("u64")
}
fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap_or_else(|| panic!("array expected, got {v}"))
}
fn ef_coeffs(v: &Value) -> Vec<u64> {
    arr(&v["value"]).iter().map(u64v).collect()
}
fn digest(v: &Value) -> Vec<u8> {
    arr(v).iter().map(|b| b.as_u64().unwrap() as u8).collect()
}

impl W<'_> {
    fn begin(&mut self, name: impl Into<String>) {
        self.sections.push(Section { name: name.into(), at: self.out.len(), len: 0 });
    }
    fn end(&mut self) {
        let s = self.sections.last_mut().unwrap();
        s.len = self.out.len() - s.at;
    }
    fn base(&mut self, x: u64, b: Bucket) {
        assert!(x < P, "non-canonical base element");
        self.out.extend_from_slice(&x.to_le_bytes());
        *b(self.sizes) += 8;
    }
    fn ef(&mut self, v: &Value, b: Bucket) {
        let c = ef_coeffs(v);
        assert_eq!(c.len(), 3);
        for x in c {
            self.base(x, b);
        }
    }
    fn efs(&mut self, v: &Value, n: usize, b: Bucket) {
        let l = arr(v);
        assert_eq!(l.len(), n, "ext vector length");
        for e in l {
            self.ef(e, b);
        }
    }
    fn raw(&mut self, x: &[u8], b: Bucket) {
        self.out.extend_from_slice(x);
        *b(self.sizes) += x.len();
    }
    fn cap(&mut self, v: &Value, len: usize, b: Bucket) {
        let cap = arr(&v["cap"]);
        assert_eq!(cap.len(), len, "cap length");
        for d in cap {
            let d = digest(d);
            assert_eq!(d.len(), self.h);
            self.raw(&d, b);
        }
    }
    fn digests(&mut self, list: &Value, b: Bucket) {
        let l = arr(list);
        assert!(l.len() < 65536);
        self.raw(&(l.len() as u16).to_le_bytes(), |s| &mut s.counts);
        for d in l {
            let d = digest(d);
            assert_eq!(d.len(), self.h);
            self.raw(&d, b);
        }
    }
    fn pow(&mut self, v: &Value, present: bool) {
        if present {
            self.base(u64v(v), |s| &mut s.pow_witnesses);
        } else {
            assert_eq!(u64v(v), 0, "absent PoW witness must be 0");
        }
    }
}

/// Encode Plonky3's `BatchProof` serde tree as p3b-v1 bytes. Panics if the proof does not have `s`.
pub fn encode(p: &Value, s: &Shape) -> (Vec<u8>, Sizes, Vec<Section>) {
    let mut out = Vec::new();
    let mut sizes = Sizes::default();
    let mut sections = Vec::new();
    let mut w = W { out: &mut out, sizes: &mut sizes, sections: &mut sections, h: s.digest };
    let n = s.instances.len();

    // degree_bits are verifying-key data: checked, not encoded
    let db: Vec<usize> = arr(&p["degree_bits"]).iter().map(|x| u64v(x) as usize).collect();
    assert_eq!(db, s.instances.iter().map(|i| i.degree_bits).collect::<Vec<_>>(), "degree_bits");

    let c = &p["commitments"];
    let cap_of = |name: &str| s.round(name).map(|r| r.cap_len).unwrap();
    w.begin("root.trace");
    w.cap(&c["main"], cap_of("trace"), |s| &mut s.roots);
    w.end();
    assert_eq!(c["permutation"].is_null(), !s.has_lookups);
    if s.has_lookups {
        w.begin("root.permutation");
        w.cap(&c["permutation"], cap_of("permutation"), |s| &mut s.roots);
        w.end();
    }
    w.begin("root.quotient");
    w.cap(&c["quotient_chunks"], cap_of("quotient"), |s| &mut s.roots);
    w.end();
    assert_eq!(c["random"].is_null(), !s.zk);
    if s.zk {
        w.begin("root.random");
        w.cap(&c["random"], cap_of("random"), |s| &mut s.roots);
        w.end();
    }

    let terms = arr(&p["lookup_terminals"]);
    assert_eq!(terms.len(), n);
    for (i, (t, is)) in terms.iter().zip(&s.instances).enumerate() {
        assert_eq!(t.is_null(), is.num_lookups == 0, "terminal presence");
        if is.num_lookups > 0 {
            w.begin(format!("terminal[{i}]"));
            w.ef(t, |s| &mut s.terminals);
            w.end();
        }
    }

    let insts = arr(&p["opened_values"]["instances"]);
    assert_eq!(insts.len(), n);
    for (i, (iv, is)) in insts.iter().zip(&s.instances).enumerate() {
        let b = &iv["base_opened_values"];
        w.begin(format!("ood[{i}]"));
        w.efs(&b["trace_local"], is.width, |s| &mut s.ood_values);
        assert_eq!(b["trace_next"].is_null(), !is.opens_next);
        if is.opens_next {
            w.efs(&b["trace_next"], is.width, |s| &mut s.ood_values);
        }
        assert_eq!(b["preprocessed_local"].is_null(), is.preprocessed_width == 0);
        assert_eq!(b["preprocessed_next"].is_null(), !is.preprocessed_next);
        if is.preprocessed_width > 0 {
            w.efs(&b["preprocessed_local"], is.preprocessed_width, |s| &mut s.ood_values);
        }
        if is.preprocessed_next {
            w.efs(&b["preprocessed_next"], is.preprocessed_width, |s| &mut s.ood_values);
        }
        let qc = arr(&b["quotient_chunks"]);
        assert_eq!(qc.len(), is.num_chunks);
        for ch in qc {
            w.efs(ch, 3, |s| &mut s.ood_values);
        }
        assert_eq!(b["random"].is_null(), !s.zk);
        if s.zk {
            w.efs(&b["random"], 3, |s| &mut s.ood_values);
        }
        w.efs(&iv["permutation_local"], is.perm_width, |s| &mut s.ood_values);
        w.efs(&iv["permutation_next"], is.perm_width, |s| &mut s.ood_values);
        w.end();
    }

    // grinding witnesses of the batch layer
    assert_eq!(p["lookup_pow_witness"].is_null(), !s.has_lookups);
    if s.has_lookups {
        w.begin("pow.lookup");
        w.pow(&p["lookup_pow_witness"], s.lookup_pow);
        w.end();
    }
    w.begin("pow.ood");
    w.pow(&p["ood_pow_witness"], s.ood_pow);
    w.end();

    let f = if s.zk {
        // hiding PCS proof = (opened values of the random codewords, FRI proof)
        let rv = arr(&p["opening_proof"][0]);
        assert_eq!(rv.len(), s.rounds.len());
        w.begin("random_values");
        for (round, rs) in rv.iter().zip(&s.rounds) {
            let mats = arr(round);
            assert_eq!(mats.len(), rs.matrices.len());
            for (m, ms) in mats.iter().zip(&rs.matrices) {
                let pts = arr(m);
                assert_eq!(pts.len(), ms.points);
                for pt in pts {
                    w.efs(pt, rs.rc, |s| &mut s.random_values);
                }
            }
        }
        w.end();
        &p["opening_proof"][1]
    } else {
        &p["opening_proof"]
    };
    w.begin("pow.batch");
    w.pow(&f["batch_pow_witness"], s.batch_pow);
    w.end();
    let commits = arr(&f["commit_phase_commits"]);
    assert_eq!(commits.len(), s.log_arities.len(), "FRI rounds");
    w.begin("fri.roots");
    for (cm, &cl) in commits.iter().zip(&s.fri_cap_lens) {
        w.cap(cm, cl, |s| &mut s.fri_roots);
    }
    w.end();
    let cpw = arr(&f["commit_pow_witnesses"]);
    assert_eq!(cpw.len(), s.log_arities.len());
    w.begin("pow.commit");
    for x in cpw {
        w.pow(x, s.commit_pow);
    }
    w.end();
    w.begin("final_poly");
    w.efs(&f["final_poly"], s.final_poly_len, |s| &mut s.final_poly);
    w.end();
    w.begin("pow.query");
    w.pow(&f["query_pow_witness"], s.query_pow);
    w.end();

    let inputs = arr(&f["input_openings"]);
    assert_eq!(inputs.len(), s.rounds.len());
    for (b, rs) in inputs.iter().zip(&s.rounds) {
        let ov = arr(&b["opened_values"]);
        assert_eq!(ov.len(), s.num_queries);
        w.begin(format!("input.{}.rows", rs.name));
        for q in ov {
            let mats = arr(q);
            assert_eq!(mats.len(), rs.matrices.len());
            for (m, ms) in mats.iter().zip(&rs.matrices) {
                let row = arr(m);
                assert_eq!(row.len(), ms.width, "row width");
                for x in row {
                    w.base(u64v(x), |s| &mut s.input_leaves);
                }
            }
        }
        w.end();
        let proof = if s.zk {
            let salts = arr(&b["opening_proof"][0]);
            assert_eq!(salts.len(), s.num_queries);
            w.begin(format!("input.{}.salts", rs.name));
            for q in salts {
                let mats = arr(q);
                assert_eq!(mats.len(), rs.matrices.len());
                for m in mats {
                    let row = arr(m);
                    assert_eq!(row.len(), s.salt);
                    for x in row {
                        w.base(u64v(x), |s| &mut s.input_salts);
                    }
                }
            }
            w.end();
            &b["opening_proof"][1]
        } else {
            &b["opening_proof"]
        };
        w.begin(format!("input.{}.siblings", rs.name));
        w.digests(&proof["sibling_hashes"], |s| &mut s.input_siblings);
        w.end();
    }

    let cpo = arr(&f["commit_phase_openings"]);
    assert_eq!(cpo.len(), s.log_arities.len());
    for (r, (st, la)) in cpo.iter().zip(&s.log_arities).enumerate() {
        let sv = arr(&st["sibling_values"]);
        assert_eq!(sv.len(), s.num_queries);
        w.begin(format!("fri[{r}].values"));
        for q in sv {
            w.efs(q, (1 << la) - 1, |s| &mut s.fri_leaves);
        }
        w.end();
        let proof = if s.zk {
            let salts = arr(&st["opening_proof"][0]);
            assert_eq!(salts.len(), s.num_queries);
            w.begin(format!("fri[{r}].salts"));
            for q in salts {
                let mats = arr(q);
                assert_eq!(mats.len(), 1);
                let row = arr(&mats[0]);
                assert_eq!(row.len(), s.salt);
                for x in row {
                    w.base(u64v(x), |s| &mut s.fri_salts);
                }
            }
            w.end();
            &st["opening_proof"][1]
        } else {
            &st["opening_proof"]
        };
        w.begin(format!("fri[{r}].siblings"));
        w.digests(&proof["sibling_hashes"], |s| &mut s.fri_siblings);
        w.end();
    }
    sizes.total = out.len();
    (out, sizes, sections)
}

struct R<'a> {
    b: &'a [u8],
    i: usize,
    h: usize,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err("truncated".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn base(&mut self) -> Result<u64, String> {
        let v = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
        if v >= P {
            return Err("non-canonical field element".into());
        }
        Ok(v)
    }
    fn bases(&mut self, n: usize) -> Result<Value, String> {
        Ok(json!((0..n).map(|_| self.base()).collect::<Result<Vec<_>, _>>()?))
    }
    fn ef(&mut self) -> Result<Value, String> {
        let c: Vec<u64> = (0..3).map(|_| self.base()).collect::<Result<_, _>>()?;
        Ok(json!({"value": c, "_phantom": null}))
    }
    fn efs(&mut self, n: usize) -> Result<Value, String> {
        Ok(Value::Array((0..n).map(|_| self.ef()).collect::<Result<_, _>>()?))
    }
    fn cap(&mut self, len: usize) -> Result<Value, String> {
        let h = self.h;
        let mut v = Vec::new();
        for _ in 0..len {
            v.push(json!(self.take(h)?.to_vec()));
        }
        Ok(json!({"cap": v, "_marker": null}))
    }
    fn digests(&mut self) -> Result<Value, String> {
        let n = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let h = self.h;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(json!(self.take(h)?.to_vec()));
        }
        Ok(Value::Array(v))
    }
    fn pow(&mut self, present: bool) -> Result<Value, String> {
        Ok(json!(if present { self.base()? } else { 0 }))
    }
}

/// Decode p3b-v1 bytes into Plonky3's `BatchProof` serde tree. Err on any malformed input
/// (truncated, trailing bytes, non-canonical field element).
pub fn decode(bytes: &[u8], s: &Shape) -> Result<Value, String> {
    let mut r = R { b: bytes, i: 0, h: s.digest };
    let cap_of = |name: &str| s.round(name).map(|r| r.cap_len).unwrap();
    let main = r.cap(cap_of("trace"))?;
    let perm = if s.has_lookups { r.cap(cap_of("permutation"))? } else { Value::Null };
    let quot = r.cap(cap_of("quotient"))?;
    let random = if s.zk { r.cap(cap_of("random"))? } else { Value::Null };
    let mut terms = Vec::new();
    for is in &s.instances {
        terms.push(if is.num_lookups > 0 { r.ef()? } else { Value::Null });
    }
    let mut insts = Vec::new();
    for is in &s.instances {
        let tl = r.efs(is.width)?;
        let tn = if is.opens_next { r.efs(is.width)? } else { Value::Null };
        let pl = if is.preprocessed_width > 0 { r.efs(is.preprocessed_width)? } else { Value::Null };
        let pn = if is.preprocessed_next { r.efs(is.preprocessed_width)? } else { Value::Null };
        let mut qc = Vec::new();
        for _ in 0..is.num_chunks {
            qc.push(r.efs(3)?);
        }
        let rnd = if s.zk { r.efs(3)? } else { Value::Null };
        let perm_l = r.efs(is.perm_width)?;
        let perm_n = r.efs(is.perm_width)?;
        insts.push(json!({
            "base_opened_values": {"trace_local": tl, "trace_next": tn, "preprocessed_local": pl,
                "preprocessed_next": pn, "quotient_chunks": qc, "random": rnd},
            "permutation_local": perm_l, "permutation_next": perm_n,
        }));
    }
    let lookup_w = if s.has_lookups { r.pow(s.lookup_pow)? } else { Value::Null };
    let ood_w = r.pow(s.ood_pow)?;
    let rand_ov = if s.zk {
        let mut rounds = Vec::new();
        for rs in &s.rounds {
            let mut mats = Vec::new();
            for ms in &rs.matrices {
                let mut pts = Vec::new();
                for _ in 0..ms.points {
                    pts.push(r.efs(rs.rc)?);
                }
                mats.push(Value::Array(pts));
            }
            rounds.push(Value::Array(mats));
        }
        Some(Value::Array(rounds))
    } else {
        None
    };
    let bw = r.pow(s.batch_pow)?;
    let mut commits = Vec::new();
    for &cl in &s.fri_cap_lens {
        commits.push(r.cap(cl)?);
    }
    let mut cpw = Vec::new();
    for _ in &s.log_arities {
        cpw.push(r.pow(s.commit_pow)?);
    }
    let fp = r.efs(s.final_poly_len)?;
    let qw = r.pow(s.query_pow)?;
    let mut inputs = Vec::new();
    for rs in &s.rounds {
        let mut ov = Vec::new();
        for _ in 0..s.num_queries {
            let mut mats = Vec::new();
            for ms in &rs.matrices {
                mats.push(r.bases(ms.width)?);
            }
            ov.push(Value::Array(mats));
        }
        let salts = if s.zk {
            let mut qs = Vec::new();
            for _ in 0..s.num_queries {
                let mut mats = Vec::new();
                for _ in &rs.matrices {
                    mats.push(r.bases(s.salt)?);
                }
                qs.push(Value::Array(mats));
            }
            Some(Value::Array(qs))
        } else {
            None
        };
        let pruned = json!({"sibling_hashes": r.digests()?});
        inputs.push(match salts {
            Some(sa) => json!({"opened_values": ov, "opening_proof": [sa, pruned]}),
            None => json!({"opened_values": ov, "opening_proof": pruned}),
        });
    }
    let mut cpo = Vec::new();
    for la in &s.log_arities {
        let mut sv = Vec::new();
        for _ in 0..s.num_queries {
            sv.push(r.efs((1usize << la) - 1)?);
        }
        let salts = if s.zk {
            let mut qs = Vec::new();
            for _ in 0..s.num_queries {
                qs.push(json!([r.bases(s.salt)?]));
            }
            Some(Value::Array(qs))
        } else {
            None
        };
        let pruned = json!({"sibling_hashes": r.digests()?});
        cpo.push(match salts {
            Some(sa) => json!({"sibling_values": sv, "opening_proof": [sa, pruned]}),
            None => json!({"sibling_values": sv, "opening_proof": pruned}),
        });
    }
    if r.i != bytes.len() {
        return Err(format!("{} trailing bytes", bytes.len() - r.i));
    }
    let fri = json!({"batch_pow_witness": bw, "commit_phase_commits": commits,
        "commit_pow_witnesses": cpw, "input_openings": inputs, "commit_phase_openings": cpo,
        "final_poly": fp, "query_pow_witness": qw});
    let opening = match rand_ov {
        Some(rv) => json!([rv, fri]),
        None => fri,
    };
    Ok(json!({
        "commitments": {"main": main, "permutation": perm, "quotient_chunks": quot, "random": random},
        "opened_values": {"instances": insts},
        "opening_proof": opening,
        "lookup_terminals": terms,
        "degree_bits": s.instances.iter().map(|i| i.degree_bits).collect::<Vec<_>>(),
        "lookup_pow_witness": lookup_w,
        "ood_pow_witness": ood_w,
    }))
}
