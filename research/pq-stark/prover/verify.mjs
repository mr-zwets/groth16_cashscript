#!/usr/bin/env node
// Independent JavaScript (BigInt) reference verifier for Plonky3 uni-stark proofs in the p3s-v1 byte
// format (FORMAT.md). It shares no code with Plonky3 or with the Rust prover: every Fiat-Shamir step,
// domain separator, Merkle multiproof, FRI fold and AIR identity is re-derived here from the spec.
// This file is the specification the CashVM verifier follows.
//
// Usage: node verify.mjs [--trace] vectors/*.json     (exit 1 on any unexpected verdict)
//   --trace  also compare every SHA-256 transcript input with the Rust verifier's recording
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ------------------------------------------------------------------------- Goldilocks
export const P = 0xffffffff00000001n;
export const STATS = { on: false };
const iters = (len) => 1 + Math.floor((len + 8) / 64); // SHA-256 compression calls (CashVM hash iterations)
const sha = (b, tag = 'other') => {
  if (STATS.on) { const t = (STATS[tag] ??= { calls: 0, bytes: 0, iterations: 0 }); t.calls++; t.bytes += b.length; t.iterations += iters(b.length); }
  return createHash('sha256').update(b).digest();
};
const md = (a) => { a %= P; return a < 0n ? a + P : a; };
const pw = (b, e) => { let r = 1n; b = md(b); e = BigInt(e); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
const inv = (a) => { if (md(a) === 0n) throw new V('inverse of zero'); return pw(a, P - 2n); };
// two-adic generator of order 2^k: 7^((p-1)/2^k)   (7 generates F_p^*)
const g2 = (k) => pw(7n, (P - 1n) >> BigInt(k));
const GEN = 7n; // coset shift of every LDE (Plonky3 Val::GENERATOR)
const rev = (i, bits) => { let r = 0; for (let b = 0; b < bits; b++) r = (r << 1) | ((i >>> b) & 1); return r >>> 0; };
const le64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b; };
const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
const be32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };

class V extends Error {} // verification failure

// ------------------------------------------------------------------------- extension fields
// D=2: F_p[u]/(u^2 - 7)  (Plonky3 BinomialExtensionField<Goldilocks,2>)
// D=3: F_p[x]/(x^3 - x - 1) (Plonky3 CubicTrinomialExtensionField<Goldilocks>)
export function extField(D) {
  const F = { D };
  F.zero = () => Array(D).fill(0n);
  F.one = () => [1n, ...Array(D - 1).fill(0n)];
  F.lift = (a) => [md(a), ...Array(D - 1).fill(0n)];
  F.add = (a, b) => a.map((x, i) => md(x + b[i]));
  F.sub = (a, b) => a.map((x, i) => md(x - b[i]));
  F.neg = (a) => a.map((x) => md(-x));
  F.smul = (a, k) => a.map((x) => x * k % P);
  F.mul = (a, b) => {
    if (STATS.on) STATS.ext_mul = (STATS.ext_mul ?? 0) + 1;
    const c = Array(2 * D - 1).fill(0n);
    for (let i = 0; i < D; i++) for (let j = 0; j < D; j++) c[i + j] += a[i] * b[j];
    if (D === 2) return [md(c[0] + 7n * c[2]), md(c[1])];
    // x^3 = x + 1, x^4 = x^2 + x
    return [md(c[0] + c[3]), md(c[1] + c[3] + c[4]), md(c[2] + c[4])];
  };
  F.eq = (a, b) => a.every((x, i) => md(x - b[i]) === 0n);
  F.isZero = (a) => a.every((x) => md(x) === 0n);
  F.pow = (a, e) => { let r = F.one(); let b = a; e = BigInt(e); while (e > 0n) { if (e & 1n) r = F.mul(r, b); b = F.mul(b, b); e >>= 1n; } return r; };
  const ORDER = P ** BigInt(D);
  F.inv = (a) => { if (STATS.on) STATS.ext_inv = (STATS.ext_inv ?? 0) + 1; if (F.isZero(a)) throw new V('ext inverse of zero'); return F.pow(a, ORDER - 2n); };
  F.div = (a, b) => F.mul(a, F.inv(b));
  // u^k basis element
  F.basis = (k) => { const e = F.zero(); e[k] = 1n; return e; };
  return F;
}

// ------------------------------------------------------------------------- Keccak-256 (original padding)
const RC = [0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64);
function keccakF(s) {
  for (let r = 0; r < 24; r++) {
    const C = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) { const d = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) s[x + y] ^= d; }
    const B = Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & M64 & B[(x + 2) % 5 + 5 * y]);
    s[0] ^= RC[r];
  }
}
export function keccak256(msg) {
  const rate = 136; const m = Buffer.from(msg);
  const padLen = rate - (m.length % rate);
  const p = Buffer.concat([m, Buffer.alloc(padLen)]);
  p[m.length] ^= 0x01; p[p.length - 1] ^= 0x80;
  const s = Array(25).fill(0n);
  for (let o = 0; o < p.length; o += rate) {
    for (let i = 0; i < rate / 8; i++) s[i] ^= p.readBigUInt64LE(o + 8 * i);
    keccakF(s);
  }
  const out = Buffer.alloc(32); for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], 8 * i);
  return out;
}

// ------------------------------------------------------------------------- Fiat-Shamir (SerializingChallenger64 over HashChallenger<u8, SHA-256>)
class Challenger {
  constructor(log) { this.inb = []; this.outb = []; this.log = log; }
  clone() { const c = new Challenger(null); c.inb = [...this.inb]; c.outb = [...this.outb]; return c; }
  observe(bytes) { if (bytes.length === 0) return; this.outb = []; for (const b of bytes) this.inb.push(b); }
  observeU64(v) { this.observe(le64(v)); }
  observeExt(e) { for (const c of e) this.observeU64(c); }
  flush() {
    const input = Buffer.from(this.inb);
    if (this.log) this.log.push(input.toString('hex'));
    const d = sha(input, 'transcript');
    this.inb = [...d]; this.outb = [...d];
  }
  byte() { if (this.outb.length === 0) this.flush(); return this.outb.pop(); }
  u64() { let v = 0n; for (let i = 0; i < 8; i++) v |= BigInt(this.byte()) << BigInt(8 * i); return v; }
  base() { for (;;) { const v = this.u64(); if (v < P) return v; } } // rejection sampling (p ~ 2^64 - 2^32)
  ext(D) { return Array.from({ length: D }, () => this.base()); }
  bits(n) { return Number(this.u64() & ((1n << BigInt(n)) - 1n)); }
  // FieldUnit<Goldilocks>::observe_seed: length, then 7-byte LE chunks, each as one field element
  seed(bytes) {
    this.observeU64(BigInt(bytes.length));
    for (let o = 0; o < bytes.length; o += 7) { let v = 0n; for (let i = 0; i < 7 && o + i < bytes.length; i++) v |= BigInt(bytes[o + i]) << BigInt(8 * i); this.observeU64(v); }
  }
  // GrindingChallenger::check_witness: squeeze one byte, observe the witness, low `bits` of the next u64 must be 0
  pow(bits, w) { if (bits === 0) return true; this.byte(); this.observeU64(w); return this.bits(bits) === 0; }
}

// ------------------------------------------------------------------------- domain separators (p3-challenger fs)
const PSTR = P.toString();
const algTag = (deg, id) => `Algebra(${PSTR}^${deg};${keccak256(Buffer.from(id)).toString('hex')})`;
const EXT_ID = { 2: 'p3-power-basis-v1:X^2-7', 3: 'p3-power-basis-v1:X^3-X-1' };
function renderPattern(steps) {
  const n = steps.length; const width = String(n - 1).length; let ind = 0;
  let s = `Plonky3 Fiat-Shamir Transcript (${n} interactions)\n`;
  steps.forEach(([h, kind, label, len, tag], i) => {
    if (h === 'End') ind = Math.max(0, ind - 1);
    s += String(i).padStart(width, '0') + ' ' + '  '.repeat(ind) + `${h} ${kind} ${label.length} ${label} ${len} ${tag}\n`;
    if (h === 'Begin') ind++;
  });
  return s;
}
function separatorSeed(name, steps, chunks) {
  const id = Buffer.alloc(64); id[0] = 1; Buffer.from(name).copy(id, 1); id[63] = name.length;
  const pattern = renderPattern(steps);
  const label = Buffer.concat(chunks.flatMap((c) => [be32(c.length), c]));
  return { pattern, seed: Buffer.concat([id, keccak256(Buffer.from(pattern)), be32(label.length), label, Buffer.from([0x80])]) };
}
function separators(vk) {
  const B = algTag(1, 'p3-scalar-basis-v1'); const E = algTag(vk.D, EXT_ID[vk.D]);
  const at = (kind, label, len, tag) => ['Atomic', kind, label, len, tag];
  const st = [at('Message', 'trace_commitment', 'Scalar', 'Opaque'), at('Public', 'public_values', `Fixed(${vk.numPublic})`, B),
    at('Challenge', 'alpha', 'Scalar', E), at('Message', 'quotient_commitment', 'Scalar', 'Opaque')];
  if (vk.zk) st.push(at('Message', 'random_commitment', 'Scalar', 'Opaque'));
  st.push(at('Challenge', 'zeta', 'Scalar', E), ['Begin', 'Protocol', 'opening_argument', 'None', 'Marker'], ['End', 'Protocol', 'opening_argument', 'None', 'Marker']);
  const stark = separatorSeed('p3-uni-stark', st, [vk.degreeBits, vk.logN, vk.width, 0, vk.numPeriodic, vk.C, 1, 0].map(be64));
  const pc = []; const pl = [be64(vk.claims.length)];
  for (const round of vk.claims) { pl.push(be64(round.length)); for (const m of round) { pl.push(be64(m.points)); for (let i = 0; i < m.points; i++) pc.push(at('Message', 'claimed_evaluations', `Fixed(${m.values})`, E)); } }
  if (vk.bpow) pc.push(at('Pow', 'batch_pow', `Fixed(${vk.bpow})`, B));
  pc.push(at('Challenge', 'alpha', 'Scalar', E), ['Begin', 'Protocol', 'low_degree_test', 'None', 'Marker'], ['End', 'Protocol', 'low_degree_test', 'None', 'Marker']);
  const pcs = separatorSeed('p3-fri-pcs', pc, pl);
  const fr = [];
  for (let r = 0; r < vk.logArities.length; r++) {
    fr.push(at('Message', 'commit_phase_commitment', 'Scalar', 'Opaque'));
    if (vk.cpow) fr.push(at('Pow', 'commit_pow', `Fixed(${vk.cpow})`, B));
    fr.push(at('Challenge', 'fold_challenge', 'Scalar', E));
  }
  fr.push(at('Message', 'final_poly', `Fixed(${vk.L})`, E));
  if (vk.qpow) fr.push(at('Pow', 'query_pow', `Fixed(${vk.qpow})`, B));
  fr.push(at('Challenge', 'query_indices', `Fixed(${vk.Q})`, `Bits(${vk.logH})`));
  const fri = separatorSeed('p3-fri', fr, [vk.logBlowup, vk.maxLogArity, ...vk.logArities].map(be64));
  return { stark, pcs, fri };
}

// ------------------------------------------------------------------------- AIRs
function roundConstants() {
  return Array.from({ length: 8 }, (_, j) => {
    const d = sha(Buffer.concat([Buffer.from('verifier.cash/pq-hash/rc'), Buffer.from([j])]));
    let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(d[i]); return v % P;
  });
}
// AIR = width, public count, periodic columns, constraint list evaluated in Plonky3's eval() order.
// ctx: { loc, nxt (EF arrays), pis (base), per (EF array), first, last, trans (EF selectors) }
const AIRS = {
  fib: {
    width: 2, numPublic: 3, periodic: [],
    constraints: (F, c) => [
      F.mul(c.first, F.sub(c.loc[0], F.lift(c.pis[0]))),
      F.mul(c.first, F.sub(c.loc[1], F.lift(c.pis[1]))),
      F.mul(c.trans, F.sub(c.loc[1], c.nxt[0])),
      F.mul(c.trans, F.sub(F.add(c.loc[0], c.loc[1]), c.nxt[1])),
      F.mul(c.last, F.sub(c.loc[1], F.lift(c.pis[2]))),
    ],
  },
  mimc: {
    width: 3, numPublic: 2, periodic: [roundConstants()],
    constraints: (F, c) => {
      const s = F.add(c.loc[0], c.per[0]);
      const [x, a, b] = c.loc;
      return [
        F.sub(a, F.mul(F.mul(s, s), s)),
        F.sub(b, F.mul(a, a)),
        F.mul(c.trans, F.sub(c.nxt[0], F.mul(b, s))),
        F.mul(c.first, F.sub(x, F.lift(c.pis[0]))),
        F.mul(c.last, F.sub(x, F.lift(c.pis[1]))),
      ];
    },
  },
};

// ------------------------------------------------------------------------- verifying key from (air, log n, parameter set)
export function makeVk(air, logN, set, numChunks) {
  const A = AIRS[air]; if (!A) throw new Error(`unknown air ${air}`);
  const zk = !!set.zk; const D = set.ext; const rc = zk ? set.num_random_codewords : 0;
  const degreeBits = logN + (zk ? 1 : 0);
  const logH = degreeBits + set.log_blowup; // every committed LDE has this height
  const logFinal = set.log_blowup + set.log_final_poly_len;
  const logArities = []; for (let h = logH; h > logFinal;) { const la = Math.min(h - logFinal, set.max_log_arity); logArities.push(la); h -= la; }
  // opening claims, in Plonky3 order: [random], trace (zeta, zeta*g), quotient chunks (zeta)
  const claims = [];
  if (zk) claims.push([{ points: 1, values: D + rc, width: D + rc }]);
  claims.push([{ points: 2, values: A.width + rc, width: A.width + rc }]);
  claims.push(Array.from({ length: numChunks }, () => ({ points: 1, values: D + rc, width: D + rc })));
  return {
    air, A, logN, n: 1 << logN, zk, D, rc, salt: zk ? set.salt : 0, h: set.digest ?? 32, degreeBits, logH, logFinal, logArities,
    width: A.width, numPublic: A.numPublic, numPeriodic: A.periodic.length, C: numChunks, claims,
    L: 1 << set.log_final_poly_len, Q: set.num_queries, logBlowup: set.log_blowup, maxLogArity: set.max_log_arity,
    bpow: set.batch_pow_bits, cpow: set.commit_pow_bits, qpow: set.query_pow_bits, opow: 0,
  };
}

// ------------------------------------------------------------------------- p3s-v1 parser
export function parse(buf, vk) {
  let o = 0; const sec = {};
  const take = (n, s) => { if (o + n > buf.length) throw new V('truncated'); const b = buf.subarray(o, o + n); (sec[s] ??= []).push([o, n]); o += n; return b; };
  const base = (s) => { const v = take(8, s).readBigUInt64LE(); if (v >= P) throw new V('non-canonical field element'); return v; };
  const ext = (s) => Array.from({ length: vk.D }, () => base(s));
  const H = vk.h;
  const digests = (s) => { const n = take(2, 'counts').readUInt16LE(); return Array.from({ length: n }, () => Buffer.from(take(H, s))); };
  const pr = { sec };
  pr.degreeBits = take(1, 'header')[0];
  pr.traceRoot = Buffer.from(take(H, 'roots')); pr.quotRoot = Buffer.from(take(H, 'roots'));
  if (vk.zk) pr.randRoot = Buffer.from(take(H, 'roots'));
  pr.traceLocal = Array.from({ length: vk.width }, () => ext('ood'));
  pr.traceNext = Array.from({ length: vk.width }, () => ext('ood'));
  pr.chunks = Array.from({ length: vk.C }, () => Array.from({ length: vk.D }, () => ext('ood')));
  if (vk.zk) {
    pr.random = Array.from({ length: vk.D }, () => ext('ood'));
    // random-codeword openings: round -> matrix -> point -> rc values
    pr.randOpen = vk.claims.map((round) => round.map((m) => Array.from({ length: m.points }, () => Array.from({ length: vk.rc }, () => ext('ood')))));
  }
  pr.batchPow = vk.bpow ? base('pow') : 0n;
  pr.friRoots = vk.logArities.map(() => Buffer.from(take(H, 'roots')));
  pr.commitPow = vk.logArities.map(() => (vk.cpow ? base('pow') : 0n));
  pr.finalPoly = Array.from({ length: vk.L }, () => ext('final'));
  pr.queryPow = vk.qpow ? base('pow') : 0n;
  pr.inputs = vk.claims.map((round) => {
    const rows = Array.from({ length: vk.Q }, () => round.map((m) => Array.from({ length: m.width }, () => base('input_leaves'))));
    const salts = vk.zk ? Array.from({ length: vk.Q }, () => round.map(() => Array.from({ length: vk.salt }, () => base('salts')))) : null;
    return { rows, salts, sibs: digests('input_siblings') };
  });
  pr.fri = vk.logArities.map((la) => {
    const sib = Array.from({ length: vk.Q }, () => Array.from({ length: (1 << la) - 1 }, () => ext('fri_leaves')));
    const salts = vk.zk ? Array.from({ length: vk.Q }, () => Array.from({ length: vk.salt }, () => base('salts'))) : null;
    return { sib, salts, sibs: digests('fri_siblings') };
  });
  if (o !== buf.length) throw new V(`${buf.length - o} trailing bytes`);
  return pr;
}

// ------------------------------------------------------------------------- Merkle multiproof (Plonky3 pruned frontier, binary, cap height 0)
function merkleVerify(root, logH, indices, leaves, sibs, what, h) {
  const hs = (b, t) => sha(b, t).subarray(0, h); // Merkle digests: SHA-256 truncated to h bytes (h = 32: untruncated)
  const byIdx = new Map();
  indices.forEach((idx, q) => {
    if (idx >= 2 ** logH) throw new V(`${what}: index out of range`);
    const prev = byIdx.get(idx);
    if (prev) { if (!prev.equals(leaves[q])) throw new V(`${what}: inconsistent duplicate opening`); } else byIdx.set(idx, leaves[q]);
  });
  let nodes = [...byIdx.keys()].sort((a, b) => a - b).map((idx) => ({ idx, d: hs(byIdx.get(idx), 'merkle_leaf') }));
  let cur = 0;
  for (let level = 0; level < logH; level++) {
    const next = [];
    for (let i = 0; i < nodes.length;) {
      const parent = Math.floor(nodes[i].idx / 2); const start = parent * 2; const inp = [];
      let m = i;
      for (let pos = 0; pos < 2; pos++) {
        if (m < nodes.length && nodes[m].idx === start + pos) inp.push(nodes[m++].d);
        else { if (cur >= sibs.length) throw new V(`${what}: too few siblings`); inp.push(sibs[cur++]); }
      }
      next.push({ idx: parent, d: hs(Buffer.concat(inp), 'merkle_node') }); i = m;
    }
    nodes = next;
  }
  if (cur !== sibs.length) throw new V(`${what}: sibling count mismatch`);
  if (nodes.length !== 1 || nodes[0].idx !== 0 || !nodes[0].d.equals(root)) throw new V(`${what}: root mismatch`);
}

// ------------------------------------------------------------------------- the verifier
export { V, Challenger, le64 };
export function verify(vk, pis, buf, opts = {}) {
  const F = extField(vk.D); const D = vk.D;
  for (const x of pis) if (x >= P) throw new V('non-canonical public value');
  if (pis.length !== vk.numPublic) throw new V('public value count');
  const pr = parse(buf, vk);
  if (pr.degreeBits !== vk.degreeBits) throw new V('degree_bits');
  const log = opts.log ?? null;
  const ch = new Challenger(log);
  const seps = separators(vk);

  // ---- uni-stark transcript
  ch.seed(seps.stark.seed);
  ch.observe(pr.traceRoot);
  for (const x of pis) ch.observeU64(x);
  const alpha = ch.ext(D);
  ch.observe(pr.quotRoot);
  if (vk.zk) ch.observe(pr.randRoot);
  const zeta = ch.ext(D);
  const n = vk.n; const gN = g2(vk.logN);
  const zetaN = F.pow(zeta, n);
  if (F.eq(zetaN, F.one())) throw new V('zeta in trace domain');
  if (vk.zk && F.eq(F.pow(zeta, 2 * n), F.one())) throw new V('zeta in ext trace domain');
  const zetaNext = F.smul(zeta, gN);

  // opening claims: per round, per matrix: [{z, values}] (zk: the rc random-codeword values are appended)
  const claims = [];
  const app = (vals, ri, mi, pi) => (vk.zk ? [...vals, ...pr.randOpen[ri][mi][pi]] : vals);
  let ri = 0;
  if (vk.zk) claims.push([[{ z: zeta, v: app(pr.random, ri, 0, 0) }]]), ri++;
  claims.push([[{ z: zeta, v: app(pr.traceLocal, ri, 0, 0) }, { z: zetaNext, v: app(pr.traceNext, ri, 0, 1) }]]); ri++;
  claims.push(pr.chunks.map((c, m) => [{ z: zeta, v: app(c, ri, m, 0) }]));

  // ---- PCS transcript (nested)
  ch.seed(seps.pcs.seed);
  for (const round of claims) for (const m of round) for (const pt of m) for (const e of pt.v) ch.observeExt(e);
  if (!ch.pow(vk.bpow, pr.batchPow)) throw new V('batch PoW');
  const alphaP = ch.ext(D);

  // ---- FRI transcript (nested)
  ch.seed(seps.fri.seed);
  const betas = [];
  for (let r = 0; r < vk.logArities.length; r++) {
    ch.observe(pr.friRoots[r]);
    if (!ch.pow(vk.cpow, pr.commitPow[r])) throw new V('commit PoW');
    betas.push(ch.ext(D));
  }
  for (const e of pr.finalPoly) ch.observeExt(e);
  if (opts.atQueryPow) return opts.atQueryPow(ch, pr); // test hook: re-grinding a tampered proof
  if (!ch.pow(vk.qpow, pr.queryPow)) throw new V('query PoW');
  const idx = Array.from({ length: vk.Q }, () => ch.bits(vk.logH));

  // ---- input openings: Merkle multiproofs
  const roots = vk.zk ? [pr.randRoot, pr.traceRoot, pr.quotRoot] : [pr.traceRoot, pr.quotRoot];
  vk.claims.forEach((round, b) => {
    const inp = pr.inputs[b];
    const leaves = idx.map((_, q) => Buffer.concat(round.flatMap((m, mi) => [
      ...inp.rows[q][mi].map(le64), ...(vk.zk ? inp.salts[q][mi].map(le64) : [])])));
    merkleVerify(roots[b], vk.logH, idx, leaves, inp.sibs, `input batch ${b}`, vk.h);
  });

  // ---- reduced openings (DEEP quotients batched with powers of alphaP; one ladder: all heights equal)
  const numVals = claims.flat(2).reduce((s, pt) => s + pt.v.length, 0);
  const apow = [F.one()]; for (let i = 1; i < numVals; i++) apow.push(F.mul(apow[i - 1], alphaP));
  const sumZ = []; let off = 0;
  for (const round of claims) for (const m of round) for (const pt of m) {
    let s = F.zero(); pt.v.forEach((e, k) => { s = F.add(s, F.mul(apow[off + k], e)); }); sumZ.push({ s, off, z: pt.z }); off += pt.v.length;
  }
  const gH = g2(vk.logH);
  const ro = idx.map((index, q) => {
    const x = GEN * pw(gH, rev(index, vk.logH)) % P;
    let acc = F.zero(); let k = 0;
    claims.forEach((round, b) => round.forEach((m, mi) => m.forEach((pt) => {
      const { s, off: o2, z } = sumZ[k++];
      const row = pr.inputs[b].rows[q][mi];
      let sx = F.zero(); row.forEach((v, j) => { sx = F.add(sx, F.smul(apow[o2 + j], v)); });
      const den = F.sub(z, F.lift(x));
      if (F.isZero(den)) throw new V('opening point equals query point');
      acc = F.add(acc, F.div(F.sub(s, sx), den));
    })));
    return acc;
  });

  // ---- FRI folding per query
  const groupIdx = vk.logArities.map(() => []); const groupRows = vk.logArities.map(() => []);
  idx.forEach((index, q) => {
    let di = index; let folded = ro[q]; let h = vk.logH;
    vk.logArities.forEach((la, r) => {
      const a = 1 << la; const pos = di % a;
      const ev = []; let s = 0;
      for (let j = 0; j < a; j++) ev.push(j === pos ? folded : pr.fri[r].sib[q][s++]);
      const hf = h - la; di = Math.floor(di / a);
      // fold = value at beta of the degree < a interpolant through the coset points (bit-reversed order)
      const start = pw(g2(hf + la), rev(di, hf)); const ga = g2(la);
      const xs = Array.from({ length: a }, (_, j) => start * pw(ga, rev(j, la)) % P);
      folded = lagrangeAt(F, xs, ev, betas[r]);
      groupIdx[r].push(di); groupRows[r].push(ev); h = hf;
    });
    if (h !== vk.logFinal) throw new V('final height');
    const xf = pw(g2(vk.logFinal), rev(di, vk.logFinal));
    let e = F.zero(); for (let i = pr.finalPoly.length - 1; i >= 0; i--) e = F.add(F.smul(e, xf), pr.finalPoly[i]);
    if (!F.eq(e, folded)) throw new V(`FRI final polynomial mismatch (query ${q})`);
  });
  // ---- FRI commit-phase Merkle multiproofs
  let h = vk.logH;
  vk.logArities.forEach((la, r) => {
    h -= la;
    const leaves = groupRows[r].map((ev, q) => Buffer.concat([...ev.flatMap((e) => e.map(le64)), ...(vk.zk ? pr.fri[r].salts[q].map(le64) : [])]));
    merkleVerify(pr.friRoots[r], h, groupIdx[r], leaves, pr.fri[r].sibs, `fri round ${r}`, vk.h);
  });

  // ---- quotient recomposition at zeta
  const logC = Math.log2(vk.C);
  const logQD = vk.degreeBits + logC - (vk.zk ? 1 : 0); // quotient domain: shift 7, size 2^logQD
  const chunkLog = logQD - logC; const gQ = g2(logQD);
  const shifts = Array.from({ length: vk.C }, (_, i) => GEN * pw(gQ, i) % P);
  const Zat = (i, pt) => F.sub(F.pow(F.smul(pt, inv(shifts[i])), 2 ** chunkLog), F.one());
  const Zb = (i, x) => md(pw(x * inv(shifts[i]) % P, 2 ** chunkLog) - 1n);
  let quotient = F.zero();
  for (let i = 0; i < vk.C; i++) {
    let zp = F.one();
    for (let j = 0; j < vk.C; j++) if (j !== i) zp = F.mul(zp, F.smul(Zat(j, zeta), inv(Zb(j, shifts[i]))));
    let chunk = F.zero(); pr.chunks[i].forEach((e, k) => { chunk = F.add(chunk, F.mul(e, F.basis(k))); });
    quotient = F.add(quotient, F.mul(zp, chunk));
  }

  // ---- AIR at zeta (selectors of the size-n trace domain, unnormalised as in Plonky3)
  const zh = F.sub(zetaN, F.one());
  const gInv = inv(gN);
  const sel = {
    first: F.div(zh, F.sub(zeta, F.one())),
    last: F.div(zh, F.sub(zeta, F.lift(gInv))),
    trans: F.sub(zeta, F.lift(gInv)),
  };
  const per = vk.A.periodic.map((col) => periodicAt(F, col, zeta, vk.logN));
  const cs = vk.A.constraints(F, { loc: pr.traceLocal, nxt: pr.traceNext, pis, per, ...sel });
  let accum = F.zero(); for (const c of cs) accum = F.add(F.mul(accum, alpha), c);
  if (!F.eq(F.mul(accum, F.inv(zh)), quotient)) throw new V('OOD constraint mismatch');
  return { idx, seps };
}

// value at z of the interpolant through (xs[i], ys[i]) (xs base field, distinct)
function lagrangeAt(F, xs, ys, z) {
  let acc = F.zero();
  for (let i = 0; i < xs.length; i++) {
    let num = F.one(); let den = 1n;
    for (let j = 0; j < xs.length; j++) if (j !== i) { num = F.mul(num, F.sub(z, F.lift(xs[j]))); den = den * md(xs[i] - xs[j]) % P; }
    acc = F.add(acc, F.mul(ys[i], F.smul(num, inv(den))));
  }
  return acc;
}
// periodic column of period m = col.length at z: interpolate col over the size-m subgroup at z^(n/m)
function periodicAt(F, col, z, logN) {
  const m = col.length; const lm = Math.log2(m);
  const y = F.pow(z, 2 ** (logN - lm)); const g = g2(lm);
  return lagrangeAt(F, Array.from({ length: m }, (_, i) => pw(g, i)), col.map((c) => F.lift(c)), y);
}

// ------------------------------------------------------------------------- CLI
// tampered case = valid proof bytes + overwrite patches, then an optional insertion, then an optional truncation
export function applyTamper(hex, t) {
  let b = Buffer.from(hex, 'hex');
  for (const p of t.patch ?? []) Buffer.from(p.hex, 'hex').copy(b, p.at);
  if (t.insert) b = Buffer.concat([b.subarray(0, t.insert.at), Buffer.from(t.insert.hex, 'hex'), b.subarray(t.insert.at)]);
  if (t.truncate !== undefined) b = b.subarray(0, t.truncate);
  return b.toString('hex');
}
export function vkFromVector(v) {
  return makeVk(v.air, v.log_n, v.set, v.shape.num_chunks);
}
function check(v, file, trace) {
  const vk = vkFromVector(v);
  // the shape this verifier derives must equal the prover's
  const s = v.shape;
  const ok = JSON.stringify(vk.logArities) === JSON.stringify(s.log_arities) && vk.Q === s.num_queries && vk.L === s.final_poly_len
    && vk.width === s.width && vk.zk === s.zk && JSON.stringify(vk.claims.map((r) => r.map((m) => m.width))) === JSON.stringify(s.batch_widths);
  if (!ok) throw new Error(`${file}: derived shape differs from the prover's`);
  const cases = [{ name: 'valid', hex: v.proof_hex, pis: v.public_values, expect: true }, ...(v.tampered ?? []).map((t) => ({ name: t.name, hex: applyTamper(v.proof_hex, t), pis: t.public_values ?? v.public_values, expect: false }))];
  let bad = 0;
  for (const c of cases) {
    let res; const log = [];
    try { const r = verify(vk, c.pis.map(BigInt), Buffer.from(c.hex, 'hex'), { log: trace && c.name === 'valid' ? log : null }); res = 'ACCEPT';
      if (trace && c.name === 'valid') {
        const seps = r.seps; const dbg = v.debug_separators;
        for (const k of ['stark', 'pcs', 'fri']) {
          if (seps[k].pattern !== dbg[k].pattern) throw new Error(`${file}: ${k} pattern differs from Plonky3's`);
          if (seps[k].seed.toString('hex') !== dbg[k].seed) throw new Error(`${file}: ${k} seed differs from Plonky3's`);
        }
        const rt = v.transcript_hash_inputs;
        if (rt.length !== log.length || rt.some((h, i) => h !== log[i])) throw new Error(`${file}: transcript differs from Plonky3's (${log.length} vs ${rt.length} hashes)`);
      }
    } catch (e) { if (!(e instanceof V)) throw e; res = `REJECT (${e.message})`; }
    const good = res.startsWith('ACCEPT') === c.expect;
    if (!good) bad++;
    console.log(`${good ? 'ok  ' : 'FAIL'} ${file} ${c.name}: ${res}`);
  }
  return [cases.length, bad];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2); const trace = args.includes('--trace');
  if (args.includes('--stats')) {
    // per valid proof: hash calls / bytes / SHA-256 iterations by role, extension-field multiplications and
    // inversions done by this (unoptimised) reference verifier
    const out = {};
    for (const f of args.filter((a) => !a.startsWith('--'))) {
      const v = JSON.parse(readFileSync(f, 'utf8'));
      for (const k of Object.keys(STATS)) if (k !== 'on') delete STATS[k];
      STATS.on = true; verify(vkFromVector(v), v.public_values.map(BigInt), Buffer.from(v.proof_hex, 'hex')); STATS.on = false;
      out[f.split('/').pop()] = Object.fromEntries(Object.entries(STATS).filter(([k]) => k !== 'on'));
    }
    console.log(JSON.stringify(out, null, 1)); process.exit(0);
  }
  let total = 0; let bad = 0;
  for (const f of args.filter((a) => !a.startsWith('--'))) { const [t, b] = check(JSON.parse(readFileSync(f, 'utf8')), f, trace); total += t; bad += b; }
  console.log(`js verify: ${total} cases, ${bad} unexpected`);
  process.exit(bad ? 1 : 0);
}
