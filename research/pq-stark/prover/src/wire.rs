//! Canonical byte format (FORMAT.md, "p3s-v1") <-> Plonky3's serde tree of `Proof<SC>`.
//!
//! The conversion works on the `serde_json::Value` of the proof, so one encoder serves every
//! configuration (degree-2/3 extension, plain or hiding PCS). The layout depends only on a
//! `Shape` the verifier knows from its verifying key; the encoder checks that the proof has it.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const P: u64 = 0xFFFF_FFFF_0000_0001;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Shape {
    pub ext: usize,           // D
    pub width: usize,         // W, main trace columns
    pub opens_next: bool,     // trace_next present
    pub num_chunks: usize,    // C, quotient chunks
    pub zk: bool,             // hiding PCS: random commitment + random opened values + salts
    pub salt: usize,          // salt elements per leaf (zk only)
    pub rc: usize,            // hiding PCS random codewords per committed matrix (zk only)
    pub log_arities: Vec<usize>,
    pub num_queries: usize,
    pub final_poly_len: usize,
    pub ood_pow: bool,
    pub batch_pow: bool,
    pub commit_pow: bool,
    pub query_pow: bool,
    /// base-field widths of the committed matrices per input batch, in proof order
    pub batch_widths: Vec<Vec<usize>>,
}

#[derive(Default, Clone, Debug, Serialize)]
pub struct Sizes {
    pub header: usize,
    pub roots: usize,
    pub ood_values: usize,
    pub pow_witnesses: usize,
    pub final_poly: usize,
    pub input_leaves: usize,
    pub input_salts: usize,
    pub input_siblings: usize,
    pub fri_leaves: usize,
    pub fri_siblings: usize,
    pub counts: usize,
    pub total: usize,
}

struct W<'a> {
    out: &'a mut Vec<u8>,
    sizes: &'a mut Sizes,
}

fn u64v(v: &Value) -> u64 {
    v.as_u64().expect("u64")
}

fn ef_coeffs(v: &Value) -> Vec<u64> {
    v["value"].as_array().expect("ef").iter().map(u64v).collect()
}

fn digest(v: &Value) -> Vec<u8> {
    v.as_array().expect("digest").iter().map(|b| b.as_u64().unwrap() as u8).collect()
}

fn cap_root(v: &Value) -> Vec<u8> {
    let cap = v["cap"].as_array().expect("cap");
    assert_eq!(cap.len(), 1, "cap height 0 expected");
    digest(&cap[0])
}

impl W<'_> {
    fn base(&mut self, x: u64, bucket: fn(&mut Sizes) -> &mut usize) {
        assert!(x < P, "non-canonical base element");
        self.out.extend_from_slice(&x.to_le_bytes());
        *bucket(self.sizes) += 8;
    }
    fn ef(&mut self, v: &Value, d: usize, bucket: fn(&mut Sizes) -> &mut usize) {
        let c = ef_coeffs(v);
        assert_eq!(c.len(), d);
        for x in c {
            self.base(x, bucket);
        }
    }
    fn raw(&mut self, b: &[u8], bucket: fn(&mut Sizes) -> &mut usize) {
        self.out.extend_from_slice(b);
        *bucket(self.sizes) += b.len();
    }
    fn digests(&mut self, list: &Value, bucket: fn(&mut Sizes) -> &mut usize) {
        let l = list.as_array().expect("digests");
        assert!(l.len() < 65536);
        self.raw(&(l.len() as u16).to_le_bytes(), |s| &mut s.counts);
        for d in l {
            let d = digest(d);
            assert_eq!(d.len(), 32);
            self.raw(&d, bucket);
        }
    }
}

/// Encode Plonky3's proof tree into the p3s-v1 byte string. Panics if the proof does not have `shape`.
pub fn encode(p: &Value, s: &Shape) -> (Vec<u8>, Sizes) {
    let mut out = Vec::new();
    let mut sizes = Sizes::default();
    let mut w = W { out: &mut out, sizes: &mut sizes };
    let d = s.ext;
    let degree_bits = u64v(&p["degree_bits"]);
    assert!(degree_bits < 64);
    w.raw(&[degree_bits as u8], |s| &mut s.header);

    let c = &p["commitments"];
    w.raw(&cap_root(&c["trace"]), |s| &mut s.roots);
    w.raw(&cap_root(&c["quotient_chunks"]), |s| &mut s.roots);
    assert_eq!(c["random"].is_null(), !s.zk);
    if s.zk {
        w.raw(&cap_root(&c["random"]), |s| &mut s.roots);
    }

    let ov = &p["opened_values"];
    let tl = ov["trace_local"].as_array().unwrap();
    assert_eq!(tl.len(), s.width);
    for e in tl {
        w.ef(e, d, |s| &mut s.ood_values);
    }
    assert_eq!(ov["trace_next"].is_null(), !s.opens_next);
    if s.opens_next {
        let tn = ov["trace_next"].as_array().unwrap();
        assert_eq!(tn.len(), s.width);
        for e in tn {
            w.ef(e, d, |s| &mut s.ood_values);
        }
    }
    assert!(ov["preprocessed_local"].is_null() && ov["preprocessed_next"].is_null());
    let qc = ov["quotient_chunks"].as_array().unwrap();
    assert_eq!(qc.len(), s.num_chunks);
    for chunk in qc {
        let chunk = chunk.as_array().unwrap();
        assert_eq!(chunk.len(), d);
        for e in chunk {
            w.ef(e, d, |s| &mut s.ood_values);
        }
    }
    assert_eq!(ov["random"].is_null(), !s.zk);
    if s.zk {
        let r = ov["random"].as_array().unwrap();
        assert_eq!(r.len(), d);
        for e in r {
            w.ef(e, d, |s| &mut s.ood_values);
        }
    }
    let ood_w = u64v(&p["ood_pow_witness"]);
    if s.ood_pow {
        w.base(ood_w, |s| &mut s.pow_witnesses);
    } else {
        assert_eq!(ood_w, 0);
    }

    let f = if s.zk {
        // hiding PCS proof = (opened values of the random codewords, FRI proof)
        let rv = p["opening_proof"][0].as_array().unwrap();
        let pts = [1usize, if s.opens_next { 2 } else { 1 }, 1];
        assert_eq!(rv.len(), 3);
        for (ri, round) in rv.iter().enumerate() {
            let mats = round.as_array().unwrap();
            assert_eq!(mats.len(), if ri == 2 { s.num_chunks } else { 1 });
            for m in mats {
                let m = m.as_array().unwrap();
                assert_eq!(m.len(), pts[ri]);
                for pt in m {
                    let pt = pt.as_array().unwrap();
                    assert_eq!(pt.len(), s.rc);
                    for e in pt {
                        w.ef(e, d, |s| &mut s.ood_values);
                    }
                }
            }
        }
        &p["opening_proof"][1]
    } else {
        &p["opening_proof"]
    };
    let bw = u64v(&f["batch_pow_witness"]);
    if s.batch_pow {
        w.base(bw, |s| &mut s.pow_witnesses);
    } else {
        assert_eq!(bw, 0);
    }
    let commits = f["commit_phase_commits"].as_array().unwrap();
    assert_eq!(commits.len(), s.log_arities.len());
    for cm in commits {
        w.raw(&cap_root(cm), |s| &mut s.roots);
    }
    let cpw = f["commit_pow_witnesses"].as_array().unwrap();
    assert_eq!(cpw.len(), s.log_arities.len());
    for x in cpw {
        if s.commit_pow {
            w.base(u64v(x), |s| &mut s.pow_witnesses);
        } else {
            assert_eq!(u64v(x), 0);
        }
    }
    let fp = f["final_poly"].as_array().unwrap();
    assert_eq!(fp.len(), s.final_poly_len);
    for e in fp {
        w.ef(e, d, |s| &mut s.final_poly);
    }
    let qw = u64v(&f["query_pow_witness"]);
    if s.query_pow {
        w.base(qw, |s| &mut s.pow_witnesses);
    } else {
        assert_eq!(qw, 0);
    }

    let inputs = f["input_openings"].as_array().unwrap();
    assert_eq!(inputs.len(), s.batch_widths.len());
    for (b, widths) in inputs.iter().zip(&s.batch_widths) {
        let (ov, proof) = input_parts(b, s.zk);
        let ov = ov.as_array().unwrap();
        assert_eq!(ov.len(), s.num_queries);
        for q in ov {
            let mats = q.as_array().unwrap();
            assert_eq!(mats.len(), widths.len());
            for (m, &wd) in mats.iter().zip(widths) {
                let row = m.as_array().unwrap();
                assert_eq!(row.len(), wd, "row width");
                for x in row {
                    w.base(u64v(x), |s| &mut s.input_leaves);
                }
            }
        }
        if s.zk {
            // hiding MMCS: per query, per matrix, `salt` base elements
            let salts = &b["opening_proof"][0];
            let salts = salts.as_array().unwrap();
            assert_eq!(salts.len(), s.num_queries);
            for q in salts {
                let mats = q.as_array().unwrap();
                assert_eq!(mats.len(), widths.len());
                for m in mats {
                    let row = m.as_array().unwrap();
                    assert_eq!(row.len(), s.salt);
                    for x in row {
                        w.base(u64v(x), |s| &mut s.input_salts);
                    }
                }
            }
        }
        w.digests(&proof["sibling_hashes"], |s| &mut s.input_siblings);
    }

    let cpo = f["commit_phase_openings"].as_array().unwrap();
    assert_eq!(cpo.len(), s.log_arities.len());
    for (r, la) in cpo.iter().zip(&s.log_arities) {
        let sv = r["sibling_values"].as_array().unwrap();
        assert_eq!(sv.len(), s.num_queries);
        for q in sv {
            let q = q.as_array().unwrap();
            assert_eq!(q.len(), (1 << la) - 1);
            for e in q {
                w.ef(e, d, |s| &mut s.fri_leaves);
            }
        }
        if s.zk {
            let salts = r["opening_proof"][0].as_array().unwrap();
            assert_eq!(salts.len(), s.num_queries);
            for q in salts {
                let mats = q.as_array().unwrap();
                assert_eq!(mats.len(), 1);
                let row = mats[0].as_array().unwrap();
                assert_eq!(row.len(), s.salt);
                for x in row {
                    w.base(u64v(x), |s| &mut s.input_salts);
                }
            }
            w.digests(&r["opening_proof"][1]["sibling_hashes"], |s| &mut s.fri_siblings);
        } else {
            w.digests(&r["opening_proof"]["sibling_hashes"], |s| &mut s.fri_siblings);
        }
    }
    sizes.total = out.len();
    (out, sizes)
}

fn input_parts(b: &Value, zk: bool) -> (&Value, &Value) {
    if zk {
        (&b["opened_values"], &b["opening_proof"][1])
    } else {
        (&b["opened_values"], &b["opening_proof"])
    }
}

/// Decode a p3s-v1 byte string back into Plonky3's serde tree. Returns Err on any malformed input
/// (short, trailing bytes, non-canonical field element, wrong digest count field).
pub fn decode(bytes: &[u8], s: &Shape) -> Result<Value, String> {
    let mut r = R { b: bytes, i: 0 };
    let d = s.ext;
    let degree_bits = r.byte()? as u64;
    let cap = |r: &mut R| -> Result<Value, String> {
        Ok(json!({"cap": [r.take(32)?.to_vec()], "_marker": null}))
    };
    let trace = cap(&mut r)?;
    let quot = cap(&mut r)?;
    let random = if s.zk { cap(&mut r)? } else { Value::Null };
    let tl: Vec<Value> = (0..s.width).map(|_| r.ef(d)).collect::<Result<_, _>>()?;
    let tn = if s.opens_next {
        Value::Array((0..s.width).map(|_| r.ef(d)).collect::<Result<_, _>>()?)
    } else {
        Value::Null
    };
    let mut qc = Vec::new();
    for _ in 0..s.num_chunks {
        qc.push(Value::Array((0..d).map(|_| r.ef(d)).collect::<Result<_, _>>()?));
    }
    let rnd = if s.zk {
        Value::Array((0..d).map(|_| r.ef(d)).collect::<Result<_, _>>()?)
    } else {
        Value::Null
    };
    let rand_ov = if s.zk {
        let pts = [1usize, if s.opens_next { 2 } else { 1 }, 1];
        let mut rounds = Vec::new();
        for ri in 0..3 {
            let nm = if ri == 2 { s.num_chunks } else { 1 };
            let mut mats = Vec::new();
            for _ in 0..nm {
                let mut ps = Vec::new();
                for _ in 0..pts[ri] {
                    ps.push(Value::Array((0..s.rc).map(|_| r.ef(d)).collect::<Result<_, _>>()?));
                }
                mats.push(Value::Array(ps));
            }
            rounds.push(Value::Array(mats));
        }
        Some(Value::Array(rounds))
    } else {
        None
    };
    let ood_w = if s.ood_pow { r.base()? } else { 0 };
    let bw = if s.batch_pow { r.base()? } else { 0 };
    let mut commits = Vec::new();
    for _ in &s.log_arities {
        commits.push(cap(&mut r)?);
    }
    let mut cpw = Vec::new();
    for _ in &s.log_arities {
        cpw.push(json!(if s.commit_pow { r.base()? } else { 0 }));
    }
    let fp: Vec<Value> = (0..s.final_poly_len).map(|_| r.ef(d)).collect::<Result<_, _>>()?;
    let qw = if s.query_pow { r.base()? } else { 0 };
    let mut inputs = Vec::new();
    for widths in &s.batch_widths {
        let mut ov = Vec::new();
        for _ in 0..s.num_queries {
            let mut mats = Vec::new();
            for &wd in widths {
                let row: Vec<u64> = (0..wd).map(|_| r.base()).collect::<Result<_, _>>()?;
                mats.push(json!(row));
            }
            ov.push(Value::Array(mats));
        }
        let salts = if s.zk {
            let mut qs = Vec::new();
            for _ in 0..s.num_queries {
                let mut mats = Vec::new();
                for _ in widths {
                    let row: Vec<u64> = (0..s.salt).map(|_| r.base()).collect::<Result<_, _>>()?;
                    mats.push(json!(row));
                }
                qs.push(Value::Array(mats));
            }
            Some(Value::Array(qs))
        } else {
            None
        };
        let sib = r.digests()?;
        let pruned = json!({"sibling_hashes": sib});
        inputs.push(match salts {
            Some(sa) => json!({"opened_values": ov, "opening_proof": [sa, pruned]}),
            None => json!({"opened_values": ov, "opening_proof": pruned}),
        });
    }
    let mut cpo = Vec::new();
    for la in &s.log_arities {
        let mut sv = Vec::new();
        for _ in 0..s.num_queries {
            sv.push(Value::Array(
                (0..(1usize << la) - 1).map(|_| r.ef(d)).collect::<Result<_, _>>()?,
            ));
        }
        if s.zk {
            let mut qs = Vec::new();
            for _ in 0..s.num_queries {
                let row: Vec<u64> = (0..s.salt).map(|_| r.base()).collect::<Result<_, _>>()?;
                qs.push(json!([row]));
            }
            let sib = r.digests()?;
            cpo.push(json!({"sibling_values": sv, "opening_proof": [qs, {"sibling_hashes": sib}]}));
        } else {
            let sib = r.digests()?;
            cpo.push(json!({"sibling_values": sv, "opening_proof": {"sibling_hashes": sib}}));
        }
    }
    let fri = json!({"batch_pow_witness": bw, "commit_phase_commits": commits,
        "commit_pow_witnesses": cpw, "input_openings": inputs, "commit_phase_openings": cpo,
        "final_poly": fp, "query_pow_witness": qw});
    let opening = match rand_ov {
        Some(rv) => json!([rv, fri]),
        None => fri,
    };
    if r.i != bytes.len() {
        return Err(format!("{} trailing bytes", bytes.len() - r.i));
    }
    Ok(json!({
        "commitments": {"trace": trace, "quotient_chunks": quot, "random": random},
        "opened_values": {"trace_local": tl, "trace_next": tn, "preprocessed_local": null,
            "preprocessed_next": null, "quotient_chunks": qc, "random": rnd},
        "opening_proof": opening,
        "degree_bits": degree_bits,
        "ood_pow_witness": ood_w,
    }))
}

struct R<'a> {
    b: &'a [u8],
    i: usize,
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
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn base(&mut self) -> Result<u64, String> {
        let v = u64::from_le_bytes(self.take(8)?.try_into().unwrap());
        if v >= P {
            return Err("non-canonical field element".into());
        }
        Ok(v)
    }
    fn ef(&mut self, d: usize) -> Result<Value, String> {
        let c: Vec<u64> = (0..d).map(|_| self.base()).collect::<Result<_, _>>()?;
        Ok(json!({"value": c, "_phantom": null}))
    }
    fn digests(&mut self) -> Result<Value, String> {
        let n = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(json!(self.take(32)?.to_vec()));
        }
        Ok(Value::Array(v))
    }
}
