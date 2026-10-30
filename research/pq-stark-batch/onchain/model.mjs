// Reference model of the CashVM verifier for Plonky3 p3-batch-stark proofs in p3b-v1 (../prover/FORMAT.md), Track 8
// S4: one table (M1), one LDE height, no preprocessed columns, no lookups, Merkle cap 0, ZK or not. It follows the
// on-chain algorithm step by step (digest-chain transcript, DEEP with one hinted inverse per query, binary pair folds,
// LIFO Merkle records, constraint DAG multiplied through by (zeta - 1)(zeta - g^-1)), so that model-agree.mjs can
// check it against the independent reference verifier ../verifier/verify-batch.mjs before the script is generated.
//
// Track 5's model (research/pq-stark/verifier/model.mjs, imported read-only) supplies the generic parts: field,
// DEEP norm/adjugate, query evaluation (runQuery: DEEP, folds, final polynomial), Merkle record programs. p3b-v1
// differs from p3s-v1 in: no header byte (degree_bits are VK data), the batch-stark transcript prefix (domain
// separator, degree_bits observed as an extension element), an optional ood PoW (0 bits here), and the AIR, which is
// the exported constraint DAG with periodic columns and public values.
//
// Public values (AIR-SPEC §3.1): ROOT[4] (verifying-key / statement constant baked into the script), NF[4] (a witness
// item, each < p), CTX[4] (computed by the script from the spending transaction's outputs, ctx.mjs).
//
// Witness of layout (b) (encodeB), bottom of the stack first:
//   L_q   per query: leaf preimages of the input rounds (random, trace, quotient: rows ‖ salts), FRI siblings (+ salt), T_q
//   R_*   per tree, Merkle record programs (Track 4 LIFO scheme), RG records per push
//   PT    ROOTS (trace, quotient, random caps), OOD (observation order), [BPOW], FROOTS, [CPOW], FIN, [QPOW]
//   NF    the nullifier, 32 bytes (4 x u64 LE)
import {createHash} from 'node:crypto';
import {extField} from '../../pq-stark/prover/verify.mjs';
import {
  Reject, md, pw, inv, g2, rev, le8, sha, leNum, normAdj, proofConsts, hintT, runQuery, canonicalTree, lifoPrograms, lifoRun, OPS,
  oodObservationOrder,
} from '../../pq-stark/verifier/model.mjs';
import {P, vkFromVector, batchSeparator, pcsSeparator, friSeparator, applyTamper} from '../verifier/verify-batch.mjs';

export {P, Reject, md, pw, inv, g2, rev, le8, sha, leNum, OPS, applyTamper};

// ---- extended verifying key: everything the script bakes in ----
const seedObs = (b) => { const out = [le8(b.length)]; for (let o = 0; o < b.length; o += 7) out.push(le8(leNum(b.subarray(o, Math.min(o + 7, b.length))))); return Buffer.concat(out); };
export function vkxFromVector(v) {
  const b = vkFromVector(v);
  if (b.inst.length !== 1 || b.hasPre || b.hasLookups) throw new Error('S4 generator: one table, no preprocessed columns, no lookups');
  if (b.capHeight !== 0) throw new Error('S4 generator: Merkle cap 0 (layout b)');
  if (b.opow !== 0) throw new Error('S4 generator: ood PoW 0');
  const I = b.inst[0], D = 3;
  if (!I.opensNext) throw new Error('S4 generator: trace opened at zeta g');
  // VK-time checks the per-proof verifier relies on (DESIGN-T8 §2.3/2.4): strict FRI height, hiding budget
  if (!(I.logLde > b.logFinal)) throw new Error('VK: strict FRI height rule');
  if (b.zk) for (const r of b.rounds) for (const m of r.matrices) if (2 ** I.logN < 2 * (D * m.points + b.Q)) throw new Error('VK: hiding budget');
  const F = extField(D);
  const claims = b.rounds.map((r) => r.matrices.map((m) => ({points: m.points, values: m.width, width: m.width})));
  const vk = {
    D, h: 32, Q: b.Q, logN: I.logN, n: 1 << I.logN, zk: b.zk, rc: b.rc, salt: b.salt, degreeBits: I.degreeBits, logH: I.logLde,
    logFinal: b.logFinal, logArities: b.logArities, width: I.width, C: I.numChunks, claims, L: b.L, logBlowup: b.logBlowup,
    maxLogArity: b.maxLogArity, bpow: b.bpow, cpow: b.cpow, qpow: b.qpow, opow: 0, numPublic: I.numPublic, dag: I.dag, periodicCols: I.periodic,
  };
  // separators: the byte strings the challenger observes (constants)
  const counts = [];
  b.rounds.forEach((r) => counts.push(r.matrices.map((m) => Array.from({length: m.points}, () => m.width))));
  const sepB = batchSeparator(b), sepP = pcsSeparator(b, counts), sepF = friSeparator(b);
  // first hash input prefix: batch seed, then degree_bits as an extension element [b, 0, 0]
  const SO = {batch: Buffer.concat([seedObs(sepB.seed), le8(I.degreeBits), le8(0), le8(0)]), pcs: seedObs(sepP.seed), fri: seedObs(sepF.seed)};
  const S = vk.logArities.reduce((s, x) => s + x, 0);
  const flat = []; let off = 0;
  claims.forEach((round, bi) => round.forEach((m, mi) => { for (let pt = 0; pt < m.points; pt++) { flat.push({batch: bi, mat: mi, pt, off, width: m.values}); off += m.values; } }));
  const numVals = off;
  const nRoots = vk.zk ? 3 : 2;
  const oodVals = 2 * vk.width + vk.C * D + (vk.zk ? D + claims.reduce((s, round) => s + round.reduce((t, m) => t + m.points * vk.rc, 0), 0) : 0);
  const batchBytes = claims.map((round) => round.reduce((s, m) => s + 8 * (m.width + vk.salt), 0));
  const friBytes = vk.logArities.map((la) => ((1 << la) - 1) * 8 * D + 8 * vk.salt);
  const qBytes = batchBytes.reduce((s, x) => s + x, 0) + friBytes.reduce((s, x) => s + x, 0) + 8;
  const trees = [];
  claims.forEach((_, bi) => trees.push({kind: 'in', b: bi, depth: vk.logH, shift: 0}));
  let sh = 0; vk.logArities.forEach((la, r) => { sh += la; trees.push({kind: 'fri', r, depth: vk.logH - sh, shift: sh}); });
  // quotient recomposition constants (as verify-batch.mjs / Track 5)
  const logC = Math.log2(vk.C);
  const logQD = vk.degreeBits + logC - (vk.zk ? 1 : 0); const chunkLog = logQD - logC;
  if (chunkLog !== vk.logN) throw new Error('chunk size differs from n');
  const gQ = g2(logQD);
  const shifts = Array.from({length: vk.C}, (_, i) => 7n * pw(gQ, i) % P);
  const kc = shifts.map((s) => inv(pw(s, 1n << BigInt(chunkLog))));
  const zpConst = shifts.map((si, i) => shifts.reduce((acc, _, j) => (j === i ? acc : acc * inv(md(pw(si, 1n << BigInt(chunkLog)) * kc[j] - 1n)) % P), 1n));
  // periodic columns: interpolant coefficients over the size-m subgroup (evaluated at zeta^(n/m))
  const periodic = vk.periodicCols.map((col) => {
    const m = col.length, lm = Math.log2(m), wi = inv(g2(lm)), mi = inv(BigInt(m));
    if (!Number.isInteger(lm) || lm > vk.logN) throw new Error('VK: periodic column period');
    return {lm, coef: Array.from({length: m}, (_, k) => md(col.reduce((s, c, j) => s + c * pw(wi, BigInt(j * k)), 0n) * mi))};
  });
  const rounds = vk.logArities.map((la) => {
    const a = 1 << la, ga = g2(la);
    return {la, a, W: Array.from({length: a}, (_, j) => pw(ga, rev(j, la))), ainv: inv(BigInt(a))};
  });
  // selector scale of every DAG node: value = numerator / ((zeta - 1)(zeta - g^-1))^scale
  const scale = [];
  vk.dag.nodes.forEach((nd, k) => {
    switch (nd.op) {
      case 'is_first_row': case 'is_last_row': case 'is_transition': scale[k] = 1; break;
      case 'add': case 'sub': scale[k] = Math.max(scale[nd.a], scale[nd.b]); break;
      case 'mul': scale[k] = scale[nd.a] + scale[nd.b]; break;
      case 'neg': scale[k] = scale[nd.a]; break;
      case 'main': case 'periodic': case 'public': case 'const': scale[k] = 0; break;
      default: throw new Error('S4 generator: DAG op ' + nd.op);
    }
  });
  const maxScale = Math.max(...vk.dag.constraints.map((c) => scale[c.node]));
  for (const c of vk.dag.constraints) if (c.field !== 'base') throw new Error('S4 generator: extension constraints (LogUp) are S5');
  return {
    ...vk, F, SO, S, flat, numVals, nRoots, oodVals, batchBytes, friBytes, qBytes, trees, shifts, kc, zpConst, periodic, rounds,
    scale, maxScale, gN: g2(vk.logN), gH: g2(vk.logH), e8: 8 * D, batchWidths: claims.map((r) => r.map((m) => m.width)),
    base: b, // verify-batch.mjs VK (for the agreement check)
  };
}

// ---- lenient parse: the proof bytes walked with the shape; missing bytes read as zero ----
export function lenientParse(buf, vk) {
  let o = 0, short = false;
  const take = (n) => { const b = Buffer.alloc(n); const end = Math.min(o + n, buf.length); if (end - o < n) short = true; if (end > o) buf.copy(b, 0, o, end); o += n; return b; };
  const h = vk.h, e8 = vk.e8;
  const pr = {};
  pr.ROOTS = take(vk.nRoots * h);                 // trace cap, quotient cap, [random cap] (cap 0: one digest each)
  pr.OODraw = take(vk.oodVals * e8);
  pr.OOD = oodObservationOrder(vk, pr.OODraw);
  pr.BPOW = vk.bpow ? take(8) : null;
  pr.FROOTS = take(vk.logArities.length * h);
  pr.CPOW = vk.cpow ? take(8 * vk.logArities.length) : null;
  pr.FIN = take(vk.L * e8);
  pr.QPOW = vk.qpow ? take(8) : null;
  const sibList = () => { const n = take(2).readUInt16LE(); return Array.from({length: n}, () => take(h)); };
  pr.inputs = vk.claims.map((round) => {
    const rows = Array.from({length: vk.Q}, () => round.map((m) => take(8 * m.width)));
    const salts = vk.zk ? Array.from({length: vk.Q}, () => round.map(() => take(8 * vk.salt))) : null;
    return {rows, salts, sibs: sibList()};
  });
  pr.fri = vk.logArities.map((la) => {
    const sib = Array.from({length: vk.Q}, () => take(((1 << la) - 1) * e8));
    const salts = vk.zk ? Array.from({length: vk.Q}, () => take(8 * vk.salt)) : null;
    return {sib, salts, sibs: sibList()};
  });
  pr.trailing = o < buf.length ? buf.subarray(o) : Buffer.alloc(0);
  pr.short = short;
  return pr;
}

// public values as transcript bytes: ROOT (constant) ‖ NF (witness) ‖ CTX (transaction)
export const pisBytes = (pis) => Buffer.concat(pis.map(le8));

// ---- transcript as the script computes it: a chain of SHA-256 digests, samples popped from the end ----
class Pop {
  constructor(d, log) { this.d = d; this.pos = 32; this.log = log; }
  slice8() { if (this.pos === 0) { this.log?.push(this.d.toString('hex')); this.d = sha(this.d); this.pos = 32; } this.pos -= 8; return this.d.subarray(this.pos, this.pos + 8); }
  u64() { const s = this.slice8(); let v = 0n; for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(s[i]); return v; }
  base() { const v = this.u64(); if (v >= P) throw new Reject('sample >= p'); return v; }
  ext(D) { return Array.from({length: D}, () => this.base()); }
  low(bits) { return Number(this.u64() & ((1n << BigInt(bits)) - 1n)); }
}
export function transcript(vk, pr, pis) {
  const D = vk.D, h = vk.h;
  const t = {hashes: []};
  const H = (...p) => { const d = sha(...p); t.hashes.push(Buffer.concat(p.map((x) => Buffer.from(x))).toString('hex')); return d; };
  const d1 = H(vk.SO.batch, pr.ROOTS.subarray(0, h), pisBytes(pis));
  t.alpha = new Pop(d1).ext(D);
  const d2 = H(d1, pr.ROOTS.subarray(h));       // quotient cap, random cap (ood PoW: 0 bits)
  t.zeta = new Pop(d2).ext(D);
  let d = H(d2, vk.SO.pcs, pr.OOD);
  const pow = (dd, w, bits) => { const d2_ = H(dd, w); const pp = new Pop(d2_); if (pp.low(bits) !== 0) throw new Reject('PoW'); return pp; };
  let pp = vk.bpow ? pow(d, pr.BPOW, vk.bpow) : new Pop(d);
  t.alphaP = pp.ext(D); d = pp.d;
  t.betas = [];
  vk.logArities.forEach((_, r) => {
    const x = H(d, r === 0 ? vk.SO.fri : Buffer.alloc(0), pr.FROOTS.subarray(r * h, r * h + h));
    pp = vk.cpow ? pow(x, pr.CPOW.subarray(8 * r, 8 * r + 8), vk.cpow) : new Pop(x);
    t.betas.push(pp.ext(D)); d = pp.d;
  });
  const f = H(d, pr.FIN);
  pp = vk.qpow ? pow(f, pr.QPOW, vk.qpow) : new Pop(f); pp.log = t.hashes;
  t.idx = Array.from({length: vk.Q}, () => pp.low(vk.logH));
  t.G = pp.d;
  return t;
}

// ---- AIR at zeta: constraint DAG, every value multiplied through by Dd^scale, Dd = (zeta - 1)(zeta - g^-1) ----
export function airCheck(vk, c, t, pis) {
  const F = vk.F;
  const zN = F.pow(c.zeta, vk.n);
  const zh = F.sub(zN, F.one());
  if (F.isZero(zh)) throw new Reject('zeta in trace domain');
  if (vk.zk && F.isZero(F.add(zN, F.one()))) throw new Reject('zeta in ext trace domain');
  const D1 = F.sub(c.zeta, F.one()), D2 = F.sub(c.zeta, F.lift(inv(vk.gN))), Dd = F.mul(D1, D2);
  const selW = {is_first_row: F.mul(zh, D2), is_last_row: F.mul(zh, D1), is_transition: F.mul(Dd, D2)};
  const per = vk.periodic.map(({lm, coef}) => {
    const y = F.pow(c.zeta, 1n << BigInt(vk.logN - lm));
    let acc = F.zero(); for (let k = coef.length - 1; k >= 0; k--) acc = F.add(F.mul(acc, y), F.lift(coef[k]));
    return acc;
  });
  const up = (x, k) => { for (let i = 0; i < k; i++) x = F.mul(x, Dd); return x; };
  const val = [];
  vk.dag.nodes.forEach((nd, k) => {
    const s = vk.scale;
    switch (nd.op) {
      case 'main': val[k] = (nd.row === 0 ? c.traceLocal : c.traceNext)[nd.col]; break;
      case 'periodic': val[k] = per[nd.col]; break;
      case 'public': val[k] = F.lift(pis[nd.col]); break;
      case 'const': val[k] = F.lift(BigInt(nd.v)); break;
      case 'is_first_row': case 'is_last_row': case 'is_transition': val[k] = selW[nd.op]; break;
      case 'add': val[k] = F.add(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
      case 'sub': val[k] = F.sub(up(val[nd.a], s[k] - s[nd.a]), up(val[nd.b], s[k] - s[nd.b])); break;
      case 'mul': val[k] = F.mul(val[nd.a], val[nd.b]); break;
      case 'neg': val[k] = F.neg(val[nd.a]); break;
    }
  });
  let acc = F.zero();
  for (const cn of vk.dag.constraints) acc = F.add(F.mul(acc, t.alpha), up(val[cn.node], vk.maxScale - vk.scale[cn.node]));
  let q = F.zero();
  for (let i = 0; i < vk.C; i++) {
    let zp = F.lift(vk.zpConst[i]);
    for (let j = 0; j < vk.C; j++) if (j !== i) zp = F.mul(zp, F.sub(F.smul(zN, vk.kc[j]), F.one()));
    let ch = F.zero(); c.chunks[i].forEach((e, k) => { ch = F.add(ch, F.mul(e, F.basis(k))); });
    q = F.add(q, F.mul(zp, ch));
  }
  if (!F.eq(acc, up(F.mul(q, zh), vk.maxScale))) throw new Reject('OOD constraint mismatch');
}

// ---- the whole on-chain check (model) and the layout (b) witness ----
export function encodeB(vk, buf, pis) {
  const pr = lenientParse(buf, vk);
  const h = vk.h;
  const out = {pr};
  let t; try { t = transcript(vk, pr, pis); } catch (e) { if (!(e instanceof Reject)) throw e; out.reject = e.message; t = null; }
  out.t = t;
  const c = t ? proofConsts(vk, pr, t) : null; out.c = c;
  const idx = t ? t.idx : Array(vk.Q).fill(0);
  out.T = idx.map((i) => (c ? hintT(vk, c, i) : 0n));
  out.L = idx.map((_, q) => Buffer.concat([
    ...pr.inputs.map((inp, b) => Buffer.concat(vk.claims[b].flatMap((m, mi) => [inp.rows[q][mi], ...(vk.zk ? [inp.salts[q][mi]] : [])]))),
    ...pr.fri.map((f) => Buffer.concat([f.sib[q], ...(vk.zk ? [f.salts[q]] : [])])),
    le8(out.T[q]),
  ]));
  const dig = idx.map(() => []);
  if (t) {
    for (let q = 0; q < vk.Q; q++) {
      try { dig[q] = runQuery(vk, pr, t, c, q, out.T[q]).digests; }
      catch (e) { if (!(e instanceof Reject)) throw e; out.reject ??= e.message; dig[q] = null; }
    }
  }
  const sibLists = [...pr.inputs.map((x) => x.sibs), ...pr.fri.map((x) => x.sibs)];
  const roots = [...Array.from({length: vk.nRoots}, (_, i) => pr.ROOTS.subarray(i * h, i * h + h))];
  if (vk.zk) roots.unshift(roots.pop());   // trees: random, trace, quotient; ROOTS: trace, quotient, random
  vk.logArities.forEach((_, r) => roots.push(pr.FROOTS.subarray(r * h, r * h + h)));
  out.roots = roots;
  out.records = vk.trees.map((tr, ti) => {
    const recs = idx.map((i, q) => ({q, leaf: i >>> tr.shift, digest: dig[q]?.[ti] ?? Buffer.alloc(h)}));
    const can = canonicalTree(h, tr.depth, recs.map((x) => [x.leaf, x.digest]), sibLists[ti]);
    const lp = lifoPrograms(h, tr.depth, recs, can.map);
    const progs = lp.programs.map((p) => p.bytes);
    if (can.leftover.length) { progs[progs.length - 1] = Buffer.concat([progs[progs.length - 1], ...can.leftover]); out.leftover = (out.leftover ?? 0) + can.leftover.length; }
    return progs;
  });
  if (pr.trailing.length) { const lr = out.records[out.records.length - 1]; lr[lr.length - 1] = Buffer.concat([lr[lr.length - 1], pr.trailing]); }
  out.PT = {ROOTS: pr.ROOTS, OOD: pr.OOD, BPOW: pr.BPOW, FROOTS: pr.FROOTS, CPOW: pr.CPOW, FIN: pr.FIN, QPOW: pr.QPOW};
  return out;
}

// model verdict: every check the script makes, in its order (statement, transcript, AIR, queries, Merkle)
export function verifyModel(vk, buf, pis) {
  if (pis.some((x) => x < 0n || x >= P)) return {ok: false, reason: 'non-canonical public value'};
  const enc = encodeB(vk, buf, pis);
  try {
    if (enc.pr.short) throw new Reject('truncated proof');
    if (enc.reject) throw new Reject(enc.reject);
    const {t, c, pr} = enc;
    airCheck(vk, c, t, pis);
    const digs = t.idx.map((_, q) => runQuery(vk, pr, t, c, q, enc.T[q]).digests);
    vk.trees.forEach((tr, ti) => {
      const why = lifoRun(vk.h, tr.depth, vk.Q, (q) => digs[q][ti], (q) => t.idx[q] >>> tr.shift, enc.records[ti], enc.roots[ti]);
      if (why) throw new Reject(`tree ${ti}: ${why}`);
    });
    return {ok: true, enc};
  } catch (e) { if (!(e instanceof Reject)) throw e; return {ok: false, reason: e.message, enc}; }
}
void createHash; void normAdj;
