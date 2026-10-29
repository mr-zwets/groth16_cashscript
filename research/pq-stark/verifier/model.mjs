// Reference model of the CashVM verifier for Plonky3 uni-stark proofs in p3s-v1 (../prover/FORMAT.md), and the
// prover-side encoder of its witness. It follows the on-chain algorithm step by step (digest-chain transcript,
// DEEP with one hinted inverse per query, binary pair folds from s^-1, LIFO Merkle records), so that
// test-model.mjs can check it against the independent reference verifier ../prover/verify.mjs on every case
// before the script is generated.
//
// Witness of layout (b) (encodeB), bottom of the stack first:
//   L_q   per query q: the leaf preimages of the input batches (rows, ZK salts), then per FRI round the a-1 sibling
//         values (+ ZK salt), then T_q (8 B): T_q = 1 / (N_zeta(x0) N_zetag(x0) s0) (a hint; the script checks it)
//   R_*   per tree, Merkle record programs in sorted leaf order (Track 4 LIFO scheme), grouped RG per push
//   PT    ROOTS, OOD, [BPOW], FROOTS, [CPOW], FIN, [QPOW]: the transcript part of the proof, as written by Plonky3
// The Merkle hints come from the proof's own pruned multiproof, so a tampered proof is encoded the way an honest
// prover would encode it (missing siblings become zero digests, unused siblings and trailing bytes ride at the end
// of a record), and the script decides.
import {createHash} from 'node:crypto';
import {P, extField, makeVk, separators, applyTamper} from '../prover/verify.mjs';
import {AIRDEF, evalExpr} from './air.mjs';

export {P, applyTamper};
export class Reject extends Error {}
export const md = (a) => { a %= P; return a < 0n ? a + P : a; };
export const pw = (b, e) => { let r = 1n; b = md(b); e = BigInt(e); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
export const inv = (a) => pw(a, P - 2n);
export const g2 = (k) => pw(7n, (P - 1n) >> BigInt(k));
export const rev = (i, bits) => { let r = 0; for (let b = 0; b < bits; b++) r = (r << 1) | ((i >>> b) & 1); return r >>> 0; };
export const le8 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest();
export const leNum = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };

// ---- extended verifying key: everything the script bakes in ----
export function makeVkx(air, logN, set, numChunks) {
  const vk = makeVk(air, logN, set, numChunks);
  const A = AIRDEF[air];
  const D = vk.D, F = extField(D);
  // separator seeds as the byte strings the challenger observes (FieldUnit::observe_seed: u64 LE length, then
  // 7-byte LE chunks, each as one u64 LE)
  const seps = separators(vk);
  const seedObs = (b) => { const out = [le8(b.length)]; for (let o = 0; o < b.length; o += 7) out.push(le8(leNum(b.subarray(o, Math.min(o + 7, b.length))))); return Buffer.concat(out); };
  const S = vk.logArities.reduce((s, x) => s + x, 0);
  // opening claims flattened: {batch, mat, pt (0 = zeta, 1 = zeta g), off (alpha' power offset), width}
  const flat = []; let off = 0;
  const batchWidths = vk.claims.map((round) => round.map((m) => m.width));
  vk.claims.forEach((round, b) => round.forEach((m, mi) => { for (let pt = 0; pt < m.points; pt++) { flat.push({batch: b, mat: mi, pt, off, width: m.values}); off += m.values; } }));
  const numVals = off;
  // byte layout of the proof prefix (PT) and of a query blob
  const h = vk.h, e8 = 8 * D;
  const nRoots = vk.zk ? 3 : 2;
  const oodVals = 2 * vk.width + vk.C * D + (vk.zk ? D + vk.claims.reduce((s, round) => s + round.reduce((t, m) => t + m.points * vk.rc, 0), 0) : 0);
  const batchBytes = vk.claims.map((round) => round.reduce((s, m) => s + 8 * (m.width + vk.salt), 0));
  const friBytes = vk.logArities.map((la) => ((1 << la) - 1) * e8 + 8 * vk.salt);
  const qBytes = batchBytes.reduce((s, x) => s + x, 0) + friBytes.reduce((s, x) => s + x, 0) + 8;
  // trees: input batches (height logH), FRI rounds (height logH - S_r)
  const trees = [];
  batchWidths.forEach((_, b) => trees.push({kind: 'in', b, depth: vk.logH, shift: 0}));
  let sh = 0; vk.logArities.forEach((la, r) => { sh += la; trees.push({kind: 'fri', r, depth: vk.logH - sh, shift: sh}); });
  // quotient recomposition constants
  const logC = Math.log2(vk.C);
  const logQD = vk.degreeBits + logC - (vk.zk ? 1 : 0); const chunkLog = logQD - logC;
  if (chunkLog !== logN) throw new Error('chunk size differs from n');
  const gQ = g2(logQD);
  const shifts = Array.from({length: vk.C}, (_, i) => 7n * pw(gQ, i) % P);
  const kc = shifts.map((s) => inv(pw(s, 1n << BigInt(chunkLog))));   // Z_j(x) = x^n k_j - 1
  const zpConst = shifts.map((si, i) => shifts.reduce((acc, _, j) => (j === i ? acc : acc * inv(md(pw(si, 1n << BigInt(chunkLog)) * kc[j] - 1n)) % P), 1n));
  // periodic columns: interpolant coefficients over the size-m subgroup (evaluated at zeta^(n/m))
  const periodic = A.periodic.map((col) => {
    const m = col.length, lm = Math.log2(m), wi = inv(g2(lm)), mi = inv(BigInt(m));
    return {lm, coef: Array.from({length: m}, (_, k) => md(col.reduce((s, c, j) => s + c * pw(wi, BigInt(j * k)), 0n) * mi))};
  });
  // fold constants: per round r, a_r, la_r; W_r[j] = ga_r^rev(j, la_r) (x of slot j = s_r W_r[j])
  const rounds = vk.logArities.map((la) => {
    const a = 1 << la, ga = g2(la);
    return {la, a, W: Array.from({length: a}, (_, j) => pw(ga, rev(j, la))), ainv: inv(BigInt(a))};
  });
  return {
    ...vk, F, A, seps, SO: {stark: seedObs(seps.stark.seed), pcs: seedObs(seps.pcs.seed), fri: seedObs(seps.fri.seed)},
    S, flat, numVals, batchWidths, nRoots, oodVals, batchBytes, friBytes, qBytes, trees, shifts, kc, zpConst, periodic, rounds,
    gN: g2(logN), gH: g2(vk.logH), e8,
  };
}
export const vkxFromVector = (v) => makeVkx(v.air, v.log_n, v.set, v.shape.num_chunks);

// The challenger observes the opened values claim by claim (ZK: each claim's random-codeword values right after
// it); the proof stores trace local, trace next, quotient chunks, [random, random-codeword values]. The witness
// carries them in observation order (identical to the proof order when not ZK).
export function oodObservationOrder(vk, raw) {
  const e8 = vk.e8, W = vk.width, C = vk.C, D = vk.D;
  const val = (i) => raw.subarray(i * e8, i * e8 + e8);
  let p = 0; const take = (n) => Array.from({length: n}, () => val(p++));
  const tl = take(W), tn = take(W), ch = Array.from({length: C}, () => take(D));
  if (!vk.zk) return Buffer.concat([...tl, ...tn, ...ch.flat()]);
  const rnd = take(D);
  const ro = vk.claims.map((round) => round.map((m) => Array.from({length: m.points}, () => take(vk.rc))));
  return Buffer.concat([...rnd, ...ro[0][0][0], ...tl, ...ro[1][0][0], ...tn, ...ro[1][0][1], ...ch.flatMap((c, m) => [...c, ...ro[2][m][0]])]);
}

// ---- lenient parse: the proof bytes walked with the shape; missing bytes read as zero ----
export function lenientParse(buf, vk) {
  let o = 0, short = false;
  const take = (n) => { const b = Buffer.alloc(n); const end = Math.min(o + n, buf.length); if (end - o < n) short = true; if (end > o) buf.copy(b, 0, o, end); o += n; return b; };
  const h = vk.h, e8 = vk.e8;
  const pr = {};
  pr.header = take(1)[0];
  pr.ROOTS = take(vk.nRoots * h);
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
  const d1 = H(vk.SO.stark, pr.ROOTS.subarray(0, h), ...pis.map(le8));
  t.alpha = new Pop(d1).ext(D);
  const d2 = H(d1, pr.ROOTS.subarray(h));
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

// ---- per-proof constants ----
// multiplication matrix of z (columns: z u^k), in the basis 1, u, .., u^{D-1}
export function mulMatrix(F, z) { const cols = []; let c = z; for (let k = 0; k < F.D; k++) { cols.push(c); c = F.mul(c, F.basis(k === F.D - 1 ? 0 : 1)); } return cols; }
// z - x for x in F_p: N(x) = det(M_z - x I) = -(x^3 - t x^2 + c x - d) (D = 3) or x^2 - t x + d (D = 2) up to sign;
// 1 / (z - x) = adj(x) / N(x), adj(x) = chi(x) / (x - z) = x^{D-1} + B x^{D-2} + .. with EF coefficients
export function normAdj(F, z) {
  const D = F.D;
  const cols = []; { let c = z; const u = F.basis(1); for (let k = 0; k < D; k++) { cols.push(c); c = F.mul(c, u); } }
  const M = (i, j) => cols[j][i];
  const t = md(Array.from({length: D}, (_, i) => M(i, i)).reduce((a, b) => a + b));
  if (D === 3) {
    const c = md(M(0, 0) * M(1, 1) - M(0, 1) * M(1, 0) + M(0, 0) * M(2, 2) - M(0, 2) * M(2, 0) + M(1, 1) * M(2, 2) - M(1, 2) * M(2, 1));
    const d = md(M(0, 0) * (M(1, 1) * M(2, 2) - M(1, 2) * M(2, 1)) - M(0, 1) * (M(1, 0) * M(2, 2) - M(1, 2) * M(2, 0)) + M(0, 2) * (M(1, 0) * M(2, 1) - M(1, 1) * M(2, 0)));
    // chi(x) = x^3 - t x^2 + c x - d = (x - z)(x^2 + B x + C), B = z - t, C = z^2 - t z + c
    const B = F.sub(z, F.lift(t)); const C = F.add(F.sub(F.mul(z, z), F.smul(z, t)), F.lift(c));
    return {t, c, d, B, C, N: (x) => md(-(((x - t) * x % P + c) * x % P - d)), adj: (x) => F.add(F.add(F.lift(x * x % P), F.smul(B, x)), C)};
  }
  const d = md(M(0, 0) * M(1, 1) - M(0, 1) * M(1, 0));
  const B = F.sub(z, F.lift(t));
  // chi(x) = x^2 - t x + d = (z - x)(zbar - x); N(x) = -chi(x) = (z - x)(x + B), B = z - t = -zbar
  return {t, d, B, N: (x) => md(-((x - t) * x + d)), adj: (x) => F.add(F.lift(x), B)};
}
export function proofConsts(vk, pr, t) {
  const F = vk.F, D = vk.D;
  const c = {};
  c.zeta = t.zeta; c.zetaG = F.smul(t.zeta, vk.gN);
  c.na = [normAdj(F, c.zeta), normAdj(F, c.zetaG)];
  c.apow = [F.one()]; for (let i = 1; i < vk.numVals; i++) c.apow.push(F.mul(c.apow[i - 1], t.alphaP));
  // opened values per claim, in observation order (the OOD witness item)
  let p = 0;
  const vals = vk.flat.map((cl) => Array.from({length: cl.width}, () => { const o = p * 8 * D; p++; return Array.from({length: D}, (_, k) => leNum(pr.OOD.subarray(o + 8 * k, o + 8 * k + 8))); }));
  if (p !== vk.oodVals) throw new Error('ood layout');
  const tb = vk.zk ? 1 : 0, W = vk.width;
  const traceLocal = vals[tb].slice(0, W), traceNext = vals[tb + 1].slice(0, W);
  const chunks = vk.flat.map((cl, i) => [cl, i]).filter(([cl]) => cl.batch === tb + 1).map(([, i]) => vals[i].slice(0, D));
  // A_z = sum over claims at point z of sum_k apow[off+k] v_k
  c.A = [F.zero(), F.zero()];
  vk.flat.forEach((cl, i) => { vals[i].forEach((v, k) => { c.A[cl.pt] = F.add(c.A[cl.pt], F.mul(c.apow[cl.off + k], v)); }); });
  c.traceLocal = traceLocal; c.traceNext = traceNext; c.chunks = chunks;
  return c;
}

// AIR identity at zeta, multiplied through by (zeta - 1)(zeta - g^-1): no inversion
export function airCheck(vk, c, t, pis) {
  const F = vk.F;
  const zN = F.pow(c.zeta, vk.n);
  const zh = F.sub(zN, F.one());
  if (F.isZero(zh)) throw new Reject('zeta in trace domain');
  if (vk.zk && F.isZero(F.add(zN, F.one()))) throw new Reject('zeta in ext trace domain');
  const D1 = F.sub(c.zeta, F.one()), D2 = F.sub(c.zeta, F.lift(inv(vk.gN)));
  const selW = {first: F.mul(zh, D2), last: F.mul(zh, D1), trans: F.mul(F.mul(D1, D2), D2), null: F.mul(D1, D2)};
  const per = vk.periodic.map(({lm, coef}) => {
    const y = F.pow(c.zeta, 1n << BigInt(vk.logN - lm));
    let acc = F.zero(); for (let k = coef.length - 1; k >= 0; k--) acc = F.add(F.mul(acc, y), F.lift(coef[k]));
    return acc;
  });
  const ctx = {loc: c.traceLocal, nxt: c.traceNext, pis, per};
  const lets = {}; for (const [k, e] of Object.entries(vk.A.lets)) lets[k] = evalExpr(F, e, ctx, lets);
  let acc = F.zero();
  for (const [sel, e] of vk.A.constraints) acc = F.add(F.mul(acc, t.alpha), F.mul(selW[sel], evalExpr(F, e, ctx, lets)));
  let q = F.zero();
  for (let i = 0; i < vk.C; i++) {
    let zp = F.lift(vk.zpConst[i]);
    for (let j = 0; j < vk.C; j++) if (j !== i) zp = F.mul(zp, F.sub(F.smul(zN, vk.kc[j]), F.one()));
    let ch = F.zero(); c.chunks[i].forEach((e, k) => { ch = F.add(ch, F.mul(e, F.basis(k))); });
    q = F.add(q, F.mul(zp, ch));
  }
  if (!F.eq(acc, F.mul(F.mul(q, zh), F.mul(D1, D2)))) throw new Reject('OOD constraint mismatch');
}

// ---- one query (as the script): returns the leaf digests per tree and the computed values ----
export function queryData(vk, pr, q) {
  const rows = pr.inputs.map((inp, b) => vk.claims[b].map((m, mi) => Array.from({length: m.width}, (_, j) => leNum(inp.rows[q][mi].subarray(8 * j, 8 * j + 8)))));
  const pre = pr.inputs.map((inp, b) => Buffer.concat(vk.claims[b].flatMap((m, mi) => [inp.rows[q][mi], ...(vk.zk ? [inp.salts[q][mi]] : [])])));
  return {rows, pre};
}
export function sOf(vk, idx) {
  // s0 = g_H^rev(idx >> la0, logH - la0)
  const la0 = vk.logArities[0];
  return pw(vk.gH, rev(idx >>> la0, vk.logH - la0));
}
export function hintT(vk, c, idx) {
  const s0 = sOf(vk, idx); const x0 = 7n * s0 % P * vk.rounds[0].W[idx % vk.rounds[0].a] % P;
  const prod = c.na[0].N(x0) * c.na[1].N(x0) % P * s0 % P;
  return prod === 0n ? 0n : inv(prod);
}
export function runQuery(vk, pr, t, c, q, T) {
  const F = vk.F, D = vk.D, h = vk.h;
  const idx = t.idx[q];
  const {rows, pre} = queryData(vk, pr, q);
  const digests = pre.map((b) => sha(b).subarray(0, h));
  // x0 = 7 s0 W0[pos0]
  const s0 = sOf(vk, idx), r0 = vk.rounds[0];
  const xown = s0 * r0.W[idx % r0.a] % P, x0 = 7n * xown % P;
  const N0 = c.na[0].N(x0), N1 = c.na[1].N(x0);
  if (N0 * N1 % P * s0 % P * T % P !== 1n) throw new Reject('hint T');
  let sinv = T * N0 % P * N1 % P;
  // numerators per point
  const num = [F.zero(), F.zero()];
  vk.flat.forEach((cl) => { rows[cl.batch][cl.mat].forEach((v, j) => { num[cl.pt] = F.add(num[cl.pt], F.smul(c.apow[cl.off + j], v)); }); });
  const n0 = F.sub(c.A[0], num[0]), n1 = F.sub(c.A[1], num[1]);
  let ro = F.add(F.smul(F.mul(n0, c.na[0].adj(x0)), N1), F.smul(F.mul(n1, c.na[1].adj(x0)), N0));
  ro = F.smul(ro, T * s0 % P);
  // folds
  let folded = ro, di = idx;
  vk.rounds.forEach((rd, r) => {
    const pos = di % rd.a;
    const sib = pr.fri[r].sib[q];
    const vals = []; let s = 0;
    for (let j = 0; j < rd.a; j++) vals.push(j === pos ? folded : Array.from({length: D}, (_, k) => leNum(sib.subarray((s * D + k) * 8, (s * D + k) * 8 + 8)))), s += j === pos ? 0 : 1;
    const leaf = Buffer.concat([...vals.flatMap((e) => e.map(le8)), ...(vk.zk ? [pr.fri[r].salts[q]] : [])]);
    digests.push(sha(leaf).subarray(0, h));
    // binary pair levels: x_m^-1 = sinv^(2^l) * ga^(-2^l rev(m, la-1-l))
    let cur = vals, si = sinv;
    const ga = g2(rd.la);
    for (let l = 0; l < rd.la; l++) {
      const be = F.pow(t.betas[r], 1n << BigInt(l));
      const half = cur.length / 2, gl = inv(pw(ga, 1n << BigInt(l)));
      const nxt = [];
      for (let m = 0; m < half; m++) {
        const xi = si * pw(gl, rev(m, rd.la - 1 - l)) % P;
        const u = cur[2 * m], v = cur[2 * m + 1];
        nxt.push(F.add(F.add(u, v), F.smul(F.mul(be, F.sub(u, v)), xi)));
      }
      cur = nxt; si = si * si % P;
    }
    folded = F.smul(cur[0], rd.ainv);
    // next s^-1: sinv^a * W_{r+1}[pos_{r+1}]  (si is now sinv^a)
    di = Math.floor(di / rd.a);
    if (r + 1 < vk.rounds.length) { const nr = vk.rounds[r + 1]; sinv = si * nr.W[di % nr.a] % P; }
  });
  // final polynomial at xf = xown^(2^S)
  const xf = pw(xown, 1n << BigInt(vk.S));
  const fin = Array.from({length: vk.L}, (_, i) => Array.from({length: D}, (_, k) => leNum(pr.FIN.subarray((i * D + k) * 8, (i * D + k) * 8 + 8))));
  let e = F.zero(); for (let i = fin.length - 1; i >= 0; i--) e = F.add(F.smul(e, xf), fin[i]);
  if (!F.eq(e, folded)) throw new Reject(`FRI final polynomial mismatch (query ${q})`);
  return {digests, idx};
}

// ---- Merkle: Plonky3 pruned multiproof -> node map, then sorted LIFO record programs (Track 4 scheme) ----
export const OPS = {F1: 1, F2: 2, F4: 3, F8: 4, F16: 5, MERGE: 6, DUPM: 7, PARK: 8, ROOT: 9};
const FRESH_RUNS = [[16, OPS.F16], [8, OPS.F8], [4, OPS.F4], [2, OPS.F2], [1, OPS.F1]];
const node = (h) => (a, b) => sha(a, b).subarray(0, h);
export function canonicalTree(h, depth, leaves, sibs) {
  const H = node(h); const map = new Map(); let ok = true;
  const byIdx = new Map();
  for (const [k, lh] of leaves) { if (byIdx.has(k)) { if (!byIdx.get(k).equals(lh)) ok = false; } else byIdx.set(k, lh); }
  let nodes = [...byIdx.keys()].sort((a, b) => a - b).map((k) => ({k, d: byIdx.get(k)}));
  let cur = 0;
  for (let level = 0; level < depth; level++) {
    const next = [];
    for (const nd of nodes) map.set(`${level}:${nd.k}`, nd.d);   // every known node (full paths for layout a)
    for (let i = 0; i < nodes.length;) {
      const parent = Math.floor(nodes[i].k / 2), start = 2 * parent, inp = []; let m = i;
      for (let p = 0; p < 2; p++) {
        if (m < nodes.length && nodes[m].k === start + p) inp.push(nodes[m++].d);
        else { let s = sibs[cur++]; if (!s) { ok = false; s = Buffer.alloc(h); } map.set(`${level}:${start + p}`, s); inp.push(s); }
      }
      next.push({k: parent, d: H(inp[0], inp[1])}); i = m;
    }
    nodes = next;
  }
  return {map, root: nodes[0]?.d, used: cur, leftover: sibs.slice(cur), ok};
}
export function lifoPrograms(h, depth, recs, map) {
  const H = node(h);
  const sorted = [...recs].sort((x, y) => x.leaf - y.leaf || x.q - y.q);
  const parked = []; const programs = []; let siblings = 0;
  for (let i = 0; i < sorted.length; i++) {
    const rc = sorted[i], next = sorted[i + 1];
    let k = (1 << depth) + rc.leaf, cur = rc.digest, level = 0;
    const prog = [Uint8Array.of(rc.q)]; let run = [];
    const flush = () => { let m = run.length, at = 0; for (const [len, id] of FRESH_RUNS) while (m >= len) { prog.push(Uint8Array.of(id), ...run.slice(at, at + len)); at += len; m -= len; } run = []; };
    if (i > 0 && sorted[i - 1].leaf === rc.leaf) { flush(); prog.push(Uint8Array.of(OPS.DUPM)); parked.pop(); }
    for (;;) {
      const nk = next ? ((1 << depth) + next.leaf) >> level : -1;
      const top = parked[parked.length - 1];
      if (k === 1) { flush(); prog.push(Uint8Array.of(OPS.ROOT)); break; }
      if (next && (nk === k || nk === (k ^ 1))) { flush(); prog.push(Uint8Array.of(OPS.PARK)); parked.push([k, cur]); break; }
      if (top && top[0] === (k ^ 1)) { flush(); prog.push(Uint8Array.of(OPS.MERGE)); parked.pop(); cur = k & 1 ? H(top[1], cur) : H(cur, top[1]); }
      else {
        const sib = map.get(`${level}:${(k ^ 1) - (1 << (depth - level))}`) ?? Buffer.alloc(h);
        run.push(sib); siblings++; cur = k & 1 ? H(sib, cur) : H(cur, sib);
      }
      k >>= 1; level++;
    }
    programs.push({q: rc.q, bytes: Buffer.concat(prog)});
  }
  return {programs, siblings};
}
// execute record programs exactly as the script does
export function lifoRun(h, depth, Q, digestOf, leafOf, programs, root) {
  const H = node(h); const parked = []; let acc = 0n; let rootOk = 0;
  for (const bytes of programs) {
    let o = 0; const q = bytes[o++]; if (q === undefined || q >= Q) return 'bad sigma';
    acc += 1n << BigInt(q);
    let k = (1 << depth) + leafOf(q), cur = digestOf(q), done = false;
    while (!done) {
      if (o >= bytes.length) return 'program ends early';
      const op = bytes[o++]; const fresh = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}[op];
      if (fresh) { for (let i = 0; i < fresh; i++) { const sib = bytes.subarray(o, o + h); o += h; if (sib.length < h) return 'short sibling'; cur = k & 1 ? H(sib, cur) : H(cur, sib); k >>= 1; } }
      else if (op === OPS.MERGE) { const [pk, pd] = parked.pop() ?? []; if (pk === undefined || pk + k !== 4 * (k >> 1) + 1) return 'bad merge'; cur = k & 1 ? H(pd, cur) : H(cur, pd); k >>= 1; }
      else if (op === OPS.DUPM) { const [pk, pd] = parked.pop() ?? []; if (pk !== k || !Buffer.from(pd).equals(Buffer.from(cur))) return 'duplicate leaf mismatch'; }
      else if (op === OPS.PARK) { parked.push([k, cur]); done = true; }
      else if (op === OPS.ROOT) { if (k !== 1 || !Buffer.from(cur).equals(root)) return 'root mismatch'; rootOk++; done = true; }
      else return 'bad op';
    }
    if (o !== bytes.length) return 'trailing program bytes';
  }
  if (parked.length) return 'parked left';
  if (acc !== (1n << BigInt(Q)) - 1n) return 'sigma not a permutation';
  return null;
}

// ---- the whole on-chain check (model) and the layout (b) witness ----
export function encodeB(vk, buf, pis, opts = {}) {
  const pr = lenientParse(buf, vk);
  const h = vk.h;
  const out = {pr};
  let t; try { t = transcript(vk, pr, pis); } catch (e) { if (!(e instanceof Reject)) throw e; out.reject = e.message; t = null; }
  out.t = t;
  // per query: blob L_q = batch preimages ‖ fri sibling values (+ salt) per round ‖ T
  const c = t ? proofConsts(vk, pr, t) : null; out.c = c;
  const idx = t ? t.idx : Array(vk.Q).fill(0);
  out.T = idx.map((i) => (c ? hintT(vk, c, i) : 0n));
  out.L = idx.map((_, q) => Buffer.concat([
    ...pr.inputs.map((inp, b) => Buffer.concat(vk.claims[b].flatMap((m, mi) => [inp.rows[q][mi], ...(vk.zk ? [inp.salts[q][mi]] : [])]))),
    ...pr.fri.map((f) => Buffer.concat([f.sib[q], ...(vk.zk ? [f.salts[q]] : [])])),
    le8(out.T[q]),
  ]));
  // leaf digests per tree per query (as the script computes them; FRI leaves hold the computed folds)
  const dig = idx.map(() => []);
  if (t) {
    for (let q = 0; q < vk.Q; q++) {
      try { dig[q] = runQuery(vk, pr, t, c, q, out.T[q]).digests; }
      catch (e) { if (!(e instanceof Reject)) throw e; out.reject ??= e.message; dig[q] = null; }
    }
  }
  // records per tree, from the proof's own multiproofs (digests: computed where possible, else the bytes as given)
  const sibLists = [...pr.inputs.map((x) => x.sibs), ...pr.fri.map((x) => x.sibs)];
  const roots = [...Array.from({length: vk.nRoots}, (_, i) => pr.ROOTS.subarray(i * h, i * h + h))];
  if (vk.zk) roots.unshift(roots.pop());   // ZK: batches are random, trace, quotient; ROOTS = trace, quotient, random
  vk.logArities.forEach((_, r) => roots.push(pr.FROOTS.subarray(r * h, r * h + h)));
  out.roots = roots;
  out.records = vk.trees.map((tr, ti) => {
    const recs = idx.map((i, q) => ({q, leaf: i >>> tr.shift, digest: dig[q]?.[ti] ?? Buffer.alloc(h)}));
    const can = canonicalTree(h, tr.depth, recs.map((x) => [x.leaf, x.digest]), sibLists[ti]);
    (out.maps ??= [])[ti] = can.map;
    const lp = lifoPrograms(h, tr.depth, recs, can.map);
    const progs = lp.programs.map((p) => p.bytes);
    if (can.leftover.length) { progs[progs.length - 1] = Buffer.concat([progs[progs.length - 1], ...can.leftover]); out.leftover = (out.leftover ?? 0) + can.leftover.length; }
    return progs;
  });
  if (pr.trailing.length) { const lr = out.records[out.records.length - 1]; lr[lr.length - 1] = Buffer.concat([lr[lr.length - 1], pr.trailing]); }
  out.PT = {ROOTS: Buffer.concat([Buffer.from([pr.header]), pr.ROOTS]), OOD: pr.OOD, BPOW: pr.BPOW, FROOTS: pr.FROOTS, CPOW: pr.CPOW, FIN: pr.FIN, QPOW: pr.QPOW};
  out.headerOk = pr.header === vk.degreeBits;
  return out;
}

// model verdict: every check the script makes, in its order (transcript, AIR, queries, Merkle)
export function verifyModel(vk, buf, pis) {
  const enc = encodeB(vk, buf, pis);
  try {
    if (!enc.headerOk) throw new Reject('degree_bits');
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

// ---- layout (a) witness: per query the blob L_q (as layout b) and the full authentication paths of every tree,
// read from the node map of the proof's own multiproof (missing nodes: zero digests) ----
export function encodeA(vk, buf, pis) {
  const enc = encodeB(vk, buf, pis);
  // the layout (a) witness carries full paths, not the pruned multiproof: bytes the multiproof does not consume
  // cannot reach the script, so a byte string that is not a well-formed p3s-v1 proof is refused here
  // (flagged, not thrown: the test sweep reports whether the script itself rejects; production encoders refuse)
  enc.malformed = enc.pr.trailing.length ? `${enc.pr.trailing.length} trailing byte(s)` : enc.leftover ? `${enc.leftover} unused sibling digest(s) for the transcript's indices` : null;
  const idx = enc.t ? enc.t.idx : Array(vk.Q).fill(0);
  enc.paths = idx.map((i) => Buffer.concat(vk.trees.flatMap((tr, ti) => Array.from({length: tr.depth}, (_, l) => enc.maps[ti].get(`${l}:${((i >>> tr.shift) >>> l) ^ 1}`) ?? Buffer.alloc(vk.h)))));
  // G: the final transcript digest (thread commitment for two-transaction plans)
  enc.G = enc.t ? enc.t.G : Buffer.alloc(32);
  return enc;
}
