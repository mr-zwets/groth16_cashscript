#!/usr/bin/env node
// verify-batch.mjs: an independent JavaScript (BigInt) reference verifier for Plonky3 p3-batch-stark
// proofs in the p3b-v1 byte format (../prover/FORMAT.md), Plonky3 pin 0d80373, SHA-256 / Goldilocks /
// cubic trinomial extension. Track 8 S3 (DESIGN-T8 §7).
//
// It shares no code with Plonky3 or with the Rust prover. Every Fiat-Shamir step, domain separator,
// Merkle multiproof (mixed-height injection, caps, salts), per-height DEEP ladder, FRI fold with
// roll-ins, LogUp challenge layout, quotient recomposition and the constraint DAG are re-derived here
// from the spec and the pinned Plonky3 source. Field, Keccak and challenger primitives are copied
// (not imported) from Track 5's research/pq-stark/prover/verify.mjs.
//
// Covers: N tables, mixed heights (injection, per-height ladders, roll-ins), preprocessed columns
// (salted, no random codewords), periodic columns, LogUp (single-terminal layout, global/local buses,
// lookup PoW), Merkle caps, ZK (hiding PCS: salts, random codewords, randomized quotient).
//
// The verifying key is built from vector data that is VK data, never from the proof: the parameter set,
// per-instance AIR metadata, the constraint DAG (with periodic columns and lookups), the preprocessed
// commitment. The PCS round layout, Merkle cap lengths and the FRI schedule are re-derived here and must
// equal the vector's `shape`.
//
// Usage: node verify-batch.mjs [--trace] [--cases FILE.json] VECTOR.json...
//   --trace   compare every SHA-256 transcript input with the Rust verifier's recording (valid case)
//   --cases   tampered-case list to use instead of each vector's own `tampered` (see agree.mjs)
// Exit 1 on any unexpected verdict.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ------------------------------------------------------------------------- Goldilocks
export const P = 0xffffffff00000001n;
const sha = (b) => createHash('sha256').update(b).digest();
const md = (a) => { a %= P; return a < 0n ? a + P : a; };
const pw = (b, e) => { let r = 1n; b = md(b); e = BigInt(e); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
export class V extends Error {} // verification failure (a reject); any other exception is a bug
const inv = (a) => { if (md(a) === 0n) throw new V('inverse of zero'); return pw(a, P - 2n); };
const g2 = (k) => pw(7n, (P - 1n) >> BigInt(k)); // two-adic generator of order 2^k (7 generates F_p^*)
const GEN = 7n; // Val::GENERATOR: LDE coset shift, disjoint-domain shift
const rev = (i, bits) => { let r = 0; for (let b = 0; b < bits; b++) r = (r << 1) | ((i >>> b) & 1); return r >>> 0; };
const le64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const be64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
const be32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };

// ------------------------------------------------------------------------- F_p[x]/(x^3 - x - 1)
const D = 3;
export const E = {
  zero: () => [0n, 0n, 0n],
  one: () => [1n, 0n, 0n],
  lift: (a) => [md(a), 0n, 0n],
  add: (a, b) => [md(a[0] + b[0]), md(a[1] + b[1]), md(a[2] + b[2])],
  sub: (a, b) => [md(a[0] - b[0]), md(a[1] - b[1]), md(a[2] - b[2])],
  neg: (a) => [md(-a[0]), md(-a[1]), md(-a[2])],
  smul: (a, k) => [a[0] * k % P, a[1] * k % P, a[2] * k % P],
  mul: (a, b) => {
    const c0 = a[0] * b[0]; const c1 = a[0] * b[1] + a[1] * b[0]; const c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0];
    const c3 = a[1] * b[2] + a[2] * b[1]; const c4 = a[2] * b[2];
    return [md(c0 + c3), md(c1 + c3 + c4), md(c2 + c4)]; // x^3 = x + 1, x^4 = x^2 + x
  },
  eq: (a, b) => a[0] === b[0] && a[1] === b[1] && a[2] === b[2],
  isZero: (a) => a[0] === 0n && a[1] === 0n && a[2] === 0n,
};
E.pow = (a, e) => { let r = E.one(); let b = a; e = BigInt(e); while (e > 0n) { if (e & 1n) r = E.mul(r, b); b = E.mul(b, b); e >>= 1n; } return r; };
E.inv = (a) => { if (E.isZero(a)) throw new V('ext inverse of zero'); return E.pow(a, P ** 3n - 2n); };
E.div = (a, b) => E.mul(a, E.inv(b));
E.basis = (k) => { const e = E.zero(); e[k] = 1n; return e; };
// from_ext_basis_coefficients over D consecutive extension values: sum_k v_k * x^k
const recompose = (vs) => vs.reduce((acc, v, k) => E.add(acc, E.mul(v, E.basis(k))), E.zero());

// ------------------------------------------------------------------------- Keccak-256 (pattern hash)
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
function keccak256(msg) {
  const rate = 136; const m = Buffer.from(msg);
  const p = Buffer.concat([m, Buffer.alloc(rate - (m.length % rate))]);
  p[m.length] ^= 0x01; p[p.length - 1] ^= 0x80;
  const s = Array(25).fill(0n);
  for (let o = 0; o < p.length; o += rate) { for (let i = 0; i < rate / 8; i++) s[i] ^= p.readBigUInt64LE(o + 8 * i); keccakF(s); }
  const out = Buffer.alloc(32); for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], 8 * i);
  return out;
}

// ------------------------------------------------------------------------- challenger
// SerializingChallenger64<Goldilocks, HashChallenger<u8, SHA-256, 32>>
class Challenger {
  constructor(log) { this.inb = []; this.outb = []; this.log = log; }
  observe(bytes) { if (bytes.length === 0) return; this.outb = []; for (const b of bytes) this.inb.push(b); }
  observeU64(v) { this.observe(le64(v)); }
  observeExt(e) { for (const c of e) this.observeU64(c); }
  observeCap(cap) { for (const d of cap) this.observe(d); }
  flush() {
    const input = Buffer.from(this.inb);
    if (this.log) this.log.push(input.toString('hex'));
    const d = sha(input); this.inb = [...d]; this.outb = [...d];
  }
  byte() { if (this.outb.length === 0) this.flush(); return this.outb.pop(); }
  u64() { let v = 0n; for (let i = 0; i < 8; i++) v |= BigInt(this.byte()) << BigInt(8 * i); return v; }
  base() { for (;;) { const v = this.u64(); if (v < P) return v; } }
  ext() { return [this.base(), this.base(), this.base()]; }
  bits(n) { return Number(this.u64() & ((1n << BigInt(n)) - 1n)); }
  // DomainSeparator::seed through FieldUnit<Goldilocks>: length, then 7-byte LE chunks, one element each
  seed(bytes) {
    this.observeU64(BigInt(bytes.length));
    for (let o = 0; o < bytes.length; o += 7) { let v = 0n; for (let i = 0; i < 7 && o + i < bytes.length; i++) v |= BigInt(bytes[o + i]) << BigInt(8 * i); this.observeU64(v); }
  }
  // GrindingChallenger::check_witness: 0 bits -> true without absorbing (the witness must then be 0, which
  // p3b-v1 guarantees by omitting it); else squeeze, observe the witness, the low `bits` of a u64 must be 0
  pow(bits, w) { if (bits === 0) return true; this.byte(); this.observeU64(w); return this.bits(bits) === 0; }
}

// ------------------------------------------------------------------------- domain separators (p3-challenger fs)
const PSTR = P.toString();
const algTag = (deg, id) => `Algebra(${PSTR}^${deg};${keccak256(Buffer.from(id)).toString('hex')})`;
const TB = algTag(1, 'p3-scalar-basis-v1'); const TE = algTag(3, 'p3-power-basis-v1:X^3-X-1');
const at = (kind, label, len, tag) => ['Atomic', kind, label, len, tag];
const marker = (h, label) => [h, 'Protocol', label, 'None', 'Marker'];
function renderPattern(steps) {
  const width = String(steps.length - 1).length; let ind = 0;
  let s = `Plonky3 Fiat-Shamir Transcript (${steps.length} interactions)\n`;
  steps.forEach(([h, kind, label, len, tag], i) => {
    if (h === 'End') ind = Math.max(0, ind - 1);
    s += String(i).padStart(width, '0') + ' ' + '  '.repeat(ind) + `${h} ${kind} ${label.length} ${label} ${len} ${tag}\n`;
    if (h === 'Begin') ind++;
  });
  return s;
}
function separator(name, steps, chunks) {
  const id = Buffer.alloc(64); id[0] = 1; Buffer.from(name).copy(id, 1); id[63] = name.length;
  const pattern = renderPattern(steps);
  const label = Buffer.concat(chunks.flatMap((c) => [be32(c.length), c]));
  return { pattern, seed: Buffer.concat([id, keccak256(Buffer.from(pattern)), be32(label.length), label, Buffer.from([0x80])]) };
}
// batch-stark/src/transcript.rs BatchShape::domain_separator
export function batchSeparator(vk) {
  const st = [];
  for (const _ of vk.inst) st.push(at('Message', 'degree_bits', 'Scalar', TE));
  st.push(at('Message', 'main_commitment', 'Scalar', 'Opaque'));
  for (const I of vk.inst) st.push(at('Public', 'public_values', `Fixed(${I.numPublic})`, TB));
  if (vk.hasPre) st.push(at('Message', 'preprocessed_commitment', 'Scalar', 'Opaque'));
  if (vk.hasLookups) {
    st.push(at('Pow', 'lookup_pow', `Fixed(${vk.lpow})`, TB));
    st.push(at('Challenge', 'lookup_alpha', 'Scalar', TE), at('Challenge', 'lookup_beta', 'Scalar', TE));
    st.push(at('Message', 'permutation_commitment', 'Scalar', 'Opaque'));
    for (const I of vk.inst) if (I.numLookups > 0) st.push(at('Message', 'lookup_terminal', 'Scalar', TE));
  }
  st.push(at('Challenge', 'constraint_challenge', 'Scalar', TE), at('Message', 'quotient_commitment', 'Scalar', 'Opaque'));
  if (vk.zk) st.push(at('Message', 'randomization_commitment', 'Scalar', 'Opaque'));
  st.push(at('Pow', 'ood_pow', `Fixed(${vk.opow})`, TB), at('Challenge', 'zeta', 'Scalar', TE));
  st.push(marker('Begin', 'opening_argument'), marker('End', 'opening_argument'));
  const chunks = [vk.inst.length, ...vk.inst.map((I) => I.width), ...vk.inst.map((I) => I.preWidth)].map(be64);
  return separator('p3-batch-stark', st, chunks);
}
// fri/src/pcs_transcript.rs PcsShape::domain_separator
export function pcsSeparator(vk, counts) {
  const st = [];
  for (const r of counts) for (const m of r) for (const w of m) st.push(at('Message', 'claimed_evaluations', `Fixed(${w})`, TE));
  if (vk.bpow) st.push(at('Pow', 'batch_pow', `Fixed(${vk.bpow})`, TB));
  st.push(at('Challenge', 'alpha', 'Scalar', TE), marker('Begin', 'low_degree_test'), marker('End', 'low_degree_test'));
  const chunks = [be64(counts.length)];
  for (const r of counts) { chunks.push(be64(r.length)); for (const m of r) chunks.push(be64(m.length)); }
  return separator('p3-fri-pcs', st, chunks);
}
// fri/src/transcript.rs FriShape::domain_separator
export function friSeparator(vk) {
  const st = [];
  for (const _ of vk.logArities) {
    st.push(at('Message', 'commit_phase_commitment', 'Scalar', 'Opaque'));
    if (vk.cpow) st.push(at('Pow', 'commit_pow', `Fixed(${vk.cpow})`, TB));
    st.push(at('Challenge', 'fold_challenge', 'Scalar', TE));
  }
  st.push(at('Message', 'final_poly', `Fixed(${vk.L})`, TE));
  if (vk.qpow) st.push(at('Pow', 'query_pow', `Fixed(${vk.qpow})`, TB));
  st.push(at('Challenge', 'query_indices', `Fixed(${vk.Q})`, `Bits(${vk.logH})`));
  return separator('p3-fri', st, [vk.logBlowup, vk.maxLogArity, ...vk.logArities].map(be64));
}

// ------------------------------------------------------------------------- verifying key
// p3_fri::fold_schedule (fri/src/config.rs)
export function foldSchedule(heights, logFinal, maxLogArity) {
  if (!heights.length || heights[0] <= logFinal) return [];
  const out = []; let h = heights[0]; let next = 1;
  while (h > logFinal) {
    let mf = h - logFinal;
    if (next < heights.length) mf = Math.min(mf, h - heights[next]);
    const la = Math.min(mf, maxLogArity); out.push(la); h -= la;
    if (heights[next] === h) next++;
  }
  return out;
}
const capLen = (capHeight, logMin) => 2 ** Math.min(capHeight, logMin);

// LogUp challenge layout (batch-stark transcript.rs lay_out_lookup_challenges): bus ids in first-use order
// (a global bus keeps its id across instances, every local lookup gets a fresh one); per instance one
// [bus_prefix[bus], beta] pair per lookup; bus_prefix[k] = alpha + (k + 1) * beta^max_width.
function lookupLayout(dags) {
  const global = new Map(); const gwidth = new Map(); let nextBus = 0; let maxW = 1;
  const busIds = dags.map((d) => (d.lookups ?? []).map((l) => {
    const ws = l.elements.map((t) => t.length);
    if (ws.some((w) => w !== ws[0])) throw new Error('VK: lookup tuple widths differ');
    const w = ws.length ? ws[0] : 0; maxW = Math.max(maxW, w);
    if (l.kind === 'Local') return nextBus++;
    const name = l.kind.Global;
    if (!global.has(name)) global.set(name, nextBus++);
    if (l.elements.length) { if (!gwidth.has(name)) gwidth.set(name, w); else if (gwidth.get(name) !== w) throw new Error(`VK: bus ${name} width mismatch`); }
    return global.get(name);
  }));
  return { busIds, maxW, numBuses: nextBus };
}

// vector -> verifying key. Takes only VK data; re-derives the PCS layout, caps and FRI schedule.
export function vkFromVector(v) {
  const s = v.set; const sh = v.shape; const zk = !!s.zk;
  if (s.ext !== 3 || s.digest !== 32) throw new Error('only D = 3, SHA-256 digests');
  const rc = zk ? s.num_random_codewords : 0;
  const inst = sh.instances.map((I, i) => {
    const d = v.dag[i];
    const numLookups = (d.lookups ?? []).length;
    if (numLookups !== I.num_lookups || d.periodic_columns.length !== I.num_periodic) throw new Error('VK: DAG disagrees with instance metadata');
    return {
      logN: I.log_n, degreeBits: I.log_n + (zk ? 1 : 0), logLde: I.log_n + (zk ? 1 : 0) + s.log_blowup,
      width: I.width, opensNext: I.opens_next, numPublic: I.num_public_values, preWidth: I.preprocessed_width, preNext: I.preprocessed_next,
      numChunks: I.num_chunks, numLookups, permWidth: numLookups ? (numLookups + 1) * D : 0,
      dag: d, periodic: d.periodic_columns.map((c) => c.map(BigInt)),
    };
  });
  const N = inst.length;
  const mat = (i, w, points) => ({ inst: i, logH: inst[i].logLde, width: w, points });
  const round = (name, rcR, matrices) => ({ name, rc: rcR, matrices, capLen: capLen(s.cap_height, Math.min(...matrices.map((m) => m.logH))) });
  const rounds = [];
  if (zk) rounds.push(round('random', rc, inst.map((_, i) => mat(i, D + rc, 1))));
  rounds.push(round('trace', rc, inst.map((I, i) => mat(i, I.width + rc, 1 + (I.opensNext ? 1 : 0)))));
  rounds.push(round('quotient', rc, inst.flatMap((I, i) => Array.from({ length: I.numChunks }, () => mat(i, D + rc, 1)))));
  const preOrder = inst.map((I, i) => (I.preWidth > 0 ? i : -1)).filter((i) => i >= 0);
  const hasPre = preOrder.length > 0;
  if (hasPre) rounds.push(round('preprocessed', 0, preOrder.map((i) => mat(i, inst[i].preWidth, 1 + (inst[i].preNext ? 1 : 0)))));
  const hasLookups = inst.some((I) => I.numLookups > 0);
  if (hasLookups) rounds.push(round('permutation', rc, inst.map((I, i) => (I.numLookups ? mat(i, I.permWidth + rc, 2) : null)).filter(Boolean)));
  const heights = [...new Set(inst.map((I) => I.logLde))].sort((a, b) => b - a);
  const logFinal = s.log_final_poly_len + s.log_blowup;
  for (const h of heights) if (!(h > logFinal)) throw new Error('VK: FRI input height not above the final height (strict rule)');
  const logArities = foldSchedule(heights, logFinal, s.max_log_arity);
  const friCaps = []; { let h = heights[0]; for (const la of logArities) { friCaps.push(capLen(s.cap_height, h - la)); h -= la; } }
  const pre = v.preprocessed_commitment ? v.preprocessed_commitment.cap.map((d) => Buffer.from(d)) : null;
  if (!!pre !== hasPre) throw new Error('VK: preprocessed commitment presence');
  const vk = {
    zk, rc, salt: zk ? s.salt : 0, capHeight: s.cap_height, inst, rounds, hasPre, hasLookups, pre,
    lookups: lookupLayout(inst.map((I) => I.dag)),
    logBlowup: s.log_blowup, maxLogArity: s.max_log_arity, logArities, friCaps, logFinal, logH: heights[0],
    L: 2 ** s.log_final_poly_len, Q: s.num_queries,
    bpow: s.batch_pow_bits, cpow: s.commit_pow_bits, qpow: s.query_pow_bits, opow: s.ood_pow_bits, lpow: s.lookup_pow_bits,
  };
  // the derived layout must equal the prover's shape
  const mine = { rounds: rounds.map((r) => [r.name, r.rc, r.capLen, r.matrices.map((m) => [m.inst, m.logH, m.width, m.points])]), logArities, friCaps };
  const theirs = {
    rounds: sh.rounds.map((r) => [r.name, r.rc, r.cap_len, r.matrices.map((m) => [m.instance, m.log_height, m.width, m.points])]),
    logArities: sh.log_arities, friCaps: sh.fri_cap_lens,
  };
  if (JSON.stringify(mine) !== JSON.stringify(theirs)) throw new Error(`VK: derived layout differs from the vector shape\n${JSON.stringify(mine)}\n${JSON.stringify(theirs)}`);
  if (sh.lookup_pow !== (hasLookups && vk.lpow > 0) || sh.ood_pow !== vk.opow > 0 || sh.batch_pow !== vk.bpow > 0 || sh.commit_pow !== vk.cpow > 0
    || sh.query_pow !== vk.qpow > 0 || sh.final_poly_len !== vk.L || sh.num_queries !== vk.Q || sh.zk !== zk) throw new Error('VK: PoW/FRI flags differ from the vector shape');
  return vk;
}

// ------------------------------------------------------------------------- p3b-v1 parser
// rec (optional): receives { label, kind, at, len } for every element read, in byte order. Kinds: digest,
// count, base, ext, pow. The tamper generator (gen-cases.mjs) places its edits with this map.
export function parse(buf, vk, rec = null) {
  let o = 0;
  const take = (n, label, kind) => { if (o + n > buf.length) throw new V('truncated'); if (rec) rec({ label, kind, at: o, len: n }); const b = buf.subarray(o, o + n); o += n; return b; };
  const fe = (b) => { const x = b.readBigUInt64LE(); if (x >= P) throw new V('non-canonical field element'); return x; };
  const base = (l, kind = 'base') => fe(take(8, l, kind));
  const ext = (l) => { const b = take(24, l, 'ext'); return [fe(b.subarray(0, 8)), fe(b.subarray(8, 16)), fe(b.subarray(16, 24))]; };
  const exts = (n, l) => Array.from({ length: n }, (_, k) => ext(`${l}[${k}]`));
  const bases = (n, l) => Array.from({ length: n }, (_, k) => base(`${l}[${k}]`));
  const cap = (n, l) => Array.from({ length: n }, (_, k) => Buffer.from(take(32, `${l}[${k}]`, 'digest')));
  const digests = (l) => { const n = take(2, `${l}.count`, 'count').readUInt16LE(); return Array.from({ length: n }, (_, k) => Buffer.from(take(32, `${l}[${k}]`, 'digest'))); };
  const R = Object.fromEntries(vk.rounds.map((r) => [r.name, r]));
  const pr = {};
  pr.mainCap = cap(R.trace.capLen, 'cap.trace');
  pr.permCap = vk.hasLookups ? cap(R.permutation.capLen, 'cap.permutation') : null;
  pr.quotCap = cap(R.quotient.capLen, 'cap.quotient');
  pr.randCap = vk.zk ? cap(R.random.capLen, 'cap.random') : null;
  pr.terminals = vk.inst.map((I, i) => (I.numLookups ? ext(`terminal[${i}]`) : null));
  pr.ood = vk.inst.map((I, i) => ({
    traceLocal: exts(I.width, `ood[${i}].trace_local`), traceNext: I.opensNext ? exts(I.width, `ood[${i}].trace_next`) : null,
    preLocal: I.preWidth ? exts(I.preWidth, `ood[${i}].pre_local`) : null, preNext: I.preNext ? exts(I.preWidth, `ood[${i}].pre_next`) : null,
    chunks: Array.from({ length: I.numChunks }, (_, k) => exts(D, `ood[${i}].chunk[${k}]`)), random: vk.zk ? exts(D, `ood[${i}].random`) : null,
    permLocal: exts(I.permWidth, `ood[${i}].perm_local`), permNext: exts(I.permWidth, `ood[${i}].perm_next`),
  }));
  pr.lookupPow = vk.hasLookups && vk.lpow > 0 ? base('pow.lookup', 'pow') : 0n;
  pr.oodPow = vk.opow > 0 ? base('pow.ood', 'pow') : 0n;
  pr.randVals = vk.zk ? vk.rounds.map((r) => r.matrices.map((m, mi) => Array.from({ length: m.points }, (_, p) => exts(r.rc, `random_values.${r.name}[${mi}][${p}]`)))) : null;
  pr.batchPow = vk.bpow > 0 ? base('pow.batch', 'pow') : 0n;
  pr.friCaps = vk.friCaps.map((c, r) => cap(c, `cap.fri[${r}]`));
  pr.commitPow = vk.logArities.map((_, r) => (vk.cpow > 0 ? base(`pow.commit[${r}]`, 'pow') : 0n));
  pr.finalPoly = exts(vk.L, 'final_poly');
  pr.queryPow = vk.qpow > 0 ? base('pow.query', 'pow') : 0n;
  pr.inputs = vk.rounds.map((r) => {
    const rows = Array.from({ length: vk.Q }, (_, q) => r.matrices.map((m, mi) => bases(m.width, `row.${r.name}[q${q}][m${mi}]`)));
    const salts = vk.zk ? Array.from({ length: vk.Q }, (_, q) => r.matrices.map((_, mi) => bases(vk.salt, `salt.${r.name}[q${q}][m${mi}]`))) : null;
    return { rows, salts, sibs: digests(`sib.${r.name}`) };
  });
  pr.fri = vk.logArities.map((la, r) => {
    const vals = Array.from({ length: vk.Q }, (_, q) => exts(2 ** la - 1, `fri[${r}].value[q${q}]`));
    const salts = vk.zk ? Array.from({ length: vk.Q }, (_, q) => bases(vk.salt, `fri[${r}].salt[q${q}]`)) : null;
    return { vals, salts, sibs: digests(`fri[${r}].sib`) };
  });
  if (o !== buf.length) throw new V(`${buf.length - o} trailing bytes`);
  return pr;
}

// ------------------------------------------------------------------------- Merkle multiproof
// Plonky3 MerkleTreeMmcs (binary, SHA-256) verify_batch_pruned with mixed heights and caps:
// - leaf = H(rows of every tallest matrix, round order; each row already salted under ZK)
// - after the compression that produces a layer of width 2^h, matrices of height 2^h are injected:
//   node = C(node, H(their rows at the node index))
// - the walk stops at the cap layer: proof levels = max(total - min(cap, total), last injection level)
// - missing siblings are read in walk order (ascending node index per level), the list must be consumed
// rows[q][m] = Buffer of the (salted) row of matrix m for query q; idx[q] = leaf index in the tallest layer
function merkleVerify(cap, logHs, idx, rows, sibs, capHeight, what) {
  const maxLog = Math.max(...logHs); const total = maxLog;
  const shorter = [...new Set(logHs.filter((h) => h < maxLog))];
  const lastInj = shorter.length ? Math.max(...shorter.map((h) => maxLog - h)) : 0;
  const levels = Math.max(total - Math.min(capHeight, total), lastInj);
  if (cap.length !== 2 ** (total - levels)) throw new V(`${what}: wrong cap size`);
  const byH = (h) => logHs.map((x, m) => (x === h ? m : -1)).filter((m) => m >= 0);
  const hashRows = (q, ms) => sha(Buffer.concat(ms.map((m) => rows[q][m])));
  const rowsEq = (a, b, ms) => ms.every((m) => rows[a][m].equals(rows[b][m]));
  const all = logHs.map((_, m) => m);
  // representatives: first query per distinct leaf; duplicates must carry identical rows
  const rep = new Map();
  idx.forEach((i, q) => {
    if (i >= 2 ** maxLog) throw new V(`${what}: index out of range`);
    if (!rep.has(i)) rep.set(i, q); else if (!rowsEq(rep.get(i), q, all)) throw new V(`${what}: inconsistent duplicate opening`);
  });
  const tallest = byH(maxLog);
  let nodes = [...rep.keys()].sort((a, b) => a - b).map((i) => ({ i, d: hashRows(rep.get(i), tallest), members: [rep.get(i)] }));
  let cur = 0;
  for (let level = 1; level <= levels; level++) {
    const next = [];
    for (let k = 0; k < nodes.length;) {
      const parent = Math.floor(nodes[k].i / 2); const inp = []; let members = [];
      for (let pos = 0; pos < 2; pos++) {
        if (k < nodes.length && nodes[k].i === 2 * parent + pos) { inp.push(nodes[k].d); members = members.concat(nodes[k].members); k++; }
        else { if (cur >= sibs.length) throw new V(`${what}: too few siblings`); inp.push(sibs[cur++]); }
      }
      next.push({ i: parent, d: sha(Buffer.concat(inp)), members });
    }
    nodes = next;
    const inj = byH(maxLog - level);
    if (inj.length) for (const n of nodes) {
      const lead = n.members[0];
      for (const q of n.members) if (!rowsEq(lead, q, inj)) throw new V(`${what}: inconsistent injected rows in one group`);
      n.d = sha(Buffer.concat([n.d, hashRows(lead, inj)]));
    }
  }
  if (cur !== sibs.length) throw new V(`${what}: sibling count mismatch`);
  for (const n of nodes) if (n.i >= cap.length || !n.d.equals(cap[n.i])) throw new V(`${what}: cap mismatch`);
}

// ------------------------------------------------------------------------- algebra helpers
function lagrangeAt(xs, ys, z) { // value at z (EF) of the interpolant through (xs[i] base, ys[i] EF)
  let acc = E.zero();
  for (let i = 0; i < xs.length; i++) {
    let num = E.one(); let den = 1n;
    for (let j = 0; j < xs.length; j++) if (j !== i) { num = E.mul(num, E.sub(z, E.lift(xs[j]))); den = den * md(xs[i] - xs[j]) % P; }
    acc = E.add(acc, E.mul(ys[i], E.smul(num, inv(den))));
  }
  return acc;
}
// periodic column of period m on the size-n trace subgroup, at z: interpolate over the size-m subgroup at z^(n/m)
function periodicAt(col, z, logN) {
  const m = col.length; const lm = Math.log2(m);
  if (!Number.isInteger(lm) || lm > logN) throw new Error('VK: periodic column period');
  const y = E.pow(z, 2n ** BigInt(logN - lm)); const g = g2(lm);
  return lagrangeAt(Array.from({ length: m }, (_, i) => pw(g, i)), col.map((c) => E.lift(c)), y);
}
const powOf2 = (a, k) => { for (let i = 0; i < k; i++) a = E.mul(a, a); return a; };

// constraint DAG at zeta (FORMAT.md "Constraint DAG"): Horner fold over the constraints in emission order
function foldDag(dag, ctx, alpha) {
  const val = new Array(dag.nodes.length);
  dag.nodes.forEach((n, k) => {
    let r;
    switch (n.op) {
      case 'main': r = (n.row === 0 ? ctx.traceLocal : ctx.traceNext)[n.col]; break;
      case 'pre': r = (n.row === 0 ? ctx.preLocal : ctx.preNext)[n.col]; break;
      case 'periodic': r = ctx.periodic[n.col]; break;
      case 'public': r = E.lift(ctx.pis[n.col]); break;
      case 'is_first_row': r = ctx.sel.first; break;
      case 'is_last_row': r = ctx.sel.last; break;
      case 'is_transition': r = ctx.sel.trans; break;
      case 'const': r = E.lift(BigInt(n.v)); break;
      case 'ext_const': r = n.v.map((x) => md(BigInt(x))); break;
      case 'perm': r = (n.row === 0 ? ctx.permLocal : ctx.permNext)[n.col]; break;
      case 'challenge': r = ctx.challenges[n.col]; break;
      case 'perm_value': r = ctx.permValues[n.col]; break;
      case 'add': r = E.add(val[n.a], val[n.b]); break;
      case 'sub': r = E.sub(val[n.a], val[n.b]); break;
      case 'mul': r = E.mul(val[n.a], val[n.b]); break;
      case 'neg': r = E.neg(val[n.a]); break;
      default: throw new Error(`DAG op ${n.op}`);
    }
    if (r === undefined) throw new Error(`DAG node ${k} (${n.op}) reads a value the VK does not provide`);
    val[k] = r;
  });
  let acc = E.zero();
  for (const c of dag.constraints) acc = E.add(E.mul(acc, alpha), val[c.node]);
  return acc;
}

// ------------------------------------------------------------------------- the verifier
// pis: per instance, arrays of BigInt (must be canonical). Returns { log } on accept, throws V on reject.
export function verify(vk, pis, buf, opts = {}) {
  if (pis.length !== vk.inst.length) throw new V('public value instance count');
  pis.forEach((p, i) => {
    if (p.length !== vk.inst[i].numPublic) throw new V('public value count');
    for (const x of p) if (x < 0n || x >= P) throw new V('non-canonical public value');
  });
  const pr = parse(buf, vk);
  const ch = new Challenger(opts.log ?? null);

  // ---- batch-stark transcript
  ch.seed(batchSeparator(vk).seed);
  for (const I of vk.inst) ch.observeExt([BigInt(I.degreeBits), 0n, 0n]);
  ch.observeCap(pr.mainCap);
  for (const p of pis) for (const x of p) ch.observeU64(x);
  if (vk.hasPre) ch.observeCap(vk.pre);
  let challenges = vk.inst.map(() => []);
  if (vk.hasLookups) {
    if (!ch.pow(vk.lpow, pr.lookupPow)) throw new V('lookup PoW');
    const la = ch.ext(); const lb = ch.ext();
    const gamma = E.pow(lb, vk.lookups.maxW);
    const prefix = []; let pf = la;
    for (let k = 0; k < vk.lookups.numBuses; k++) { pf = E.add(pf, gamma); prefix.push(pf); }
    challenges = vk.lookups.busIds.map((ids) => ids.flatMap((b) => [prefix[b], lb]));
    ch.observeCap(pr.permCap);
    for (const t of pr.terminals) if (t) ch.observeExt(t);
  }
  const alpha = ch.ext();
  ch.observeCap(pr.quotCap);
  if (vk.zk) ch.observeCap(pr.randCap);
  if (!ch.pow(vk.opow, pr.oodPow)) throw new V('ood PoW');
  const zeta = ch.ext();

  // ---- opening claims, round by round (batch-stark verifier commitments_with_opening_points)
  const zetaNext = vk.inst.map((I) => E.smul(zeta, g2(I.logN))); // trace-domain (un-extended) generator
  const claims = vk.rounds.map((r, ri) => r.matrices.map((m, mi) => {
    const I = vk.inst[m.inst]; const o = pr.ood[m.inst];
    let pts;
    switch (r.name) {
      case 'random': pts = [[zeta, o.random]]; break;
      case 'trace': pts = [[zeta, o.traceLocal]]; if (I.opensNext) pts.push([zetaNext[m.inst], o.traceNext]); break;
      case 'quotient': { const k = mi - r.matrices.findIndex((x) => x.inst === m.inst); pts = [[zeta, o.chunks[k]]]; break; }
      case 'preprocessed': pts = [[zeta, o.preLocal]]; if (I.preNext) pts.push([zetaNext[m.inst], o.preNext]); break;
      case 'permutation': pts = [[zeta, o.permLocal], [zetaNext[m.inst], o.permNext]]; break;
      default: throw new Error(r.name);
    }
    return { logH: m.logH, pts: pts.map(([z, vals], pi) => ({ z, v: vk.zk ? [...vals, ...pr.randVals[ri][mi][pi]] : vals })) };
  }));

  // ---- PCS transcript (nested)
  ch.seed(pcsSeparator(vk, claims.map((r) => r.map((m) => m.pts.map((p) => p.v.length)))).seed);
  for (const r of claims) for (const m of r) for (const p of m.pts) for (const e of p.v) ch.observeExt(e);
  if (vk.bpow && !ch.pow(vk.bpow, pr.batchPow)) throw new V('batch PoW');
  const alphaP = ch.ext();

  // ---- FRI transcript (nested)
  ch.seed(friSeparator(vk).seed);
  const betas = vk.logArities.map((_, r) => {
    ch.observeCap(pr.friCaps[r]);
    if (vk.cpow && !ch.pow(vk.cpow, pr.commitPow[r])) throw new V('commit PoW');
    return ch.ext();
  });
  for (const e of pr.finalPoly) ch.observeExt(e);
  if (opts.atQueryPow) return opts.atQueryPow(ch, pr);
  if (vk.qpow && !ch.pow(vk.qpow, pr.queryPow)) throw new V('query PoW');
  const idx = Array.from({ length: vk.Q }, () => ch.bits(vk.logH));
  if (opts.transcriptOnly) return { idx };

  // ---- input openings: one Merkle multiproof per PCS round
  const roots = { random: pr.randCap, trace: pr.mainCap, quotient: pr.quotCap, preprocessed: vk.pre, permutation: pr.permCap };
  vk.rounds.forEach((r, b) => {
    const inp = pr.inputs[b]; const logHs = r.matrices.map((m) => m.logH); const top = Math.max(...logHs);
    const rows = idx.map((_, q) => r.matrices.map((m, mi) => Buffer.concat([...inp.rows[q][mi].map(le64), ...(vk.zk ? inp.salts[q][mi].map(le64) : [])])));
    merkleVerify(roots[r.name], logHs, idx.map((i) => i >> (vk.logH - top)), rows, inp.sibs, vk.capHeight, `input round ${r.name}`);
  });

  // ---- reduced openings: one alpha' ladder per LDE height, walking (round, matrix, point, column)
  const ladderOff = new Map(); const pointSum = [];
  let maxLadder = 0;
  for (const r of claims) for (const m of r) for (const p of m.pts) { const off = ladderOff.get(m.logH) ?? 0; ladderOff.set(m.logH, off + p.v.length); maxLadder = Math.max(maxLadder, off + p.v.length); }
  const apow = [E.one()]; for (let k = 1; k < maxLadder; k++) apow.push(E.mul(apow[k - 1], alphaP));
  ladderOff.clear();
  for (const r of claims) for (const m of r) for (const p of m.pts) {
    const off = ladderOff.get(m.logH) ?? 0; ladderOff.set(m.logH, off + p.v.length);
    let s = E.zero(); p.v.forEach((e, k) => { s = E.add(s, E.mul(apow[off + k], e)); });
    pointSum.push({ off, s });
  }
  const ro = idx.map((index, q) => {
    const acc = new Map(); let k = 0;
    claims.forEach((r, b) => r.forEach((m, mi) => {
      const x = GEN * pw(g2(m.logH), rev(index >> (vk.logH - m.logH), m.logH)) % P;
      const row = pr.inputs[b].rows[q][mi];
      for (const p of m.pts) {
        const { off, s } = pointSum[k++];
        let sx = E.zero(); row.forEach((v, j) => { sx = E.add(sx, E.smul(apow[off + j], v)); });
        const den = E.sub(p.z, E.lift(x));
        if (E.isZero(den)) throw new V('opening point equals query point');
        acc.set(m.logH, E.add(acc.get(m.logH) ?? E.zero(), E.div(E.sub(s, sx), den)));
      }
    }));
    return acc;
  });

  // ---- FRI: fold every query, rolling in shorter heights with beta^arity
  const groupIdx = vk.logArities.map(() => []); const groupRows = vk.logArities.map(() => []);
  idx.forEach((index, q) => {
    const red = ro[q]; let h = vk.logH; let di = index;
    let folded = red.get(h); if (!folded) throw new Error('no reduced opening at the top height');
    let used = 1;
    vk.logArities.forEach((la, r) => {
      const a = 2 ** la; const pos = di % a; const ev = []; let s = 0;
      for (let j = 0; j < a; j++) ev.push(j === pos ? folded : pr.fri[r].vals[q][s++]);
      const hf = h - la; di = Math.floor(di / a);
      const start = pw(g2(hf + la), rev(di, hf)); const ga = g2(la);
      folded = lagrangeAt(Array.from({ length: a }, (_, j) => start * pw(ga, rev(j, la)) % P), ev, betas[r]);
      groupIdx[r].push(di); groupRows[r].push(ev); h = hf;
      if (red.has(h)) { folded = E.add(folded, E.mul(powOf2(betas[r], la), red.get(h))); used++; }
    });
    if (h !== vk.logFinal) throw new Error('final height');
    if (used !== red.size) throw new Error('unconsumed reduced openings');
    const xf = pw(g2(vk.logFinal), rev(di, vk.logFinal));
    let e = E.zero(); for (let i = pr.finalPoly.length - 1; i >= 0; i--) e = E.add(E.smul(e, xf), pr.finalPoly[i]);
    if (!E.eq(e, folded)) throw new V(`FRI final polynomial mismatch (query ${q})`);
  });
  // commit-phase multiproofs
  { let h = vk.logH;
    vk.logArities.forEach((la, r) => {
      h -= la;
      const rows = groupRows[r].map((ev, q) => [Buffer.concat([...ev.flatMap((e) => e.map(le64)), ...(vk.zk ? pr.fri[r].salts[q].map(le64) : [])])]);
      merkleVerify(pr.friCaps[r], [h], groupIdx[r], rows, pr.fri[r].sibs, vk.capHeight, `fri round ${r}`);
    }); }

  // ---- constraints at zeta, per instance
  vk.inst.forEach((I, i) => {
    const o = pr.ood[i]; const logN = I.logN; const n = 2n ** BigInt(logN);
    const zh = E.sub(E.pow(zeta, n), E.one());
    if (E.isZero(zh)) throw new V('zeta in trace domain');
    const gInv = inv(g2(logN));
    const sel = { first: E.div(zh, E.sub(zeta, E.one())), last: E.div(zh, E.sub(zeta, E.lift(gInv))), trans: E.sub(zeta, E.lift(gInv)) };
    // quotient: disjoint coset GEN * H_(degreeBits + logChunks), split into numChunks cosets
    const C = I.numChunks; const logC = Math.log2(C); const logChunks = logC - (vk.zk ? 1 : 0);
    const logQD = I.degreeBits + logChunks; const chunkLog = logQD - logC; const gQ = g2(logQD);
    const shifts = Array.from({ length: C }, (_, k) => GEN * pw(gQ, k) % P);
    const Zat = (k) => E.sub(powOf2(E.smul(zeta, inv(shifts[k])), chunkLog), E.one());
    const Zb = (k, x) => md(pw(x * inv(shifts[k]) % P, 2n ** BigInt(chunkLog)) - 1n);
    let quotient = E.zero();
    for (let k = 0; k < C; k++) {
      let zp = E.one();
      for (let j = 0; j < C; j++) if (j !== k) zp = E.mul(zp, E.smul(Zat(j), inv(Zb(j, shifts[k]))));
      quotient = E.add(quotient, E.mul(zp, recompose(o.chunks[k])));
    }
    const permRec = (flat) => Array.from({ length: flat.length / D }, (_, c) => recompose(flat.slice(D * c, D * c + D)));
    const ctx = {
      traceLocal: o.traceLocal, traceNext: o.traceNext ?? Array.from({ length: I.width }, E.zero),
      preLocal: o.preLocal ?? [], preNext: o.preNext ?? Array.from({ length: I.preWidth }, E.zero),
      periodic: I.periodic.map((col) => periodicAt(col, zeta, logN)), pis: pis[i], sel,
      permLocal: permRec(o.permLocal), permNext: permRec(o.permNext), challenges: challenges[i],
      permValues: pr.terminals[i] ? [pr.terminals[i]] : [],
    };
    const acc = foldDag(I.dag, ctx, alpha);
    if (!E.eq(E.mul(acc, E.inv(zh)), quotient)) throw new V(`OOD constraint mismatch (instance ${i})`);
  });

  // ---- LogUp: the terminals of the whole batch sum to zero
  if (vk.hasLookups) {
    let t = E.zero(); for (const x of pr.terminals) if (x) t = E.add(t, x);
    if (!E.isZero(t)) throw new V('LogUp terminal sum non-zero');
  }
  return { idx, separators: { batch: batchSeparator(vk) } };
}

// ------------------------------------------------------------------------- cases
// tampered case = valid bytes; optional `replace` (whole proof hex), then patches, insertion, truncation
export function applyTamper(hex, t) {
  let b = Buffer.from(t.replace ?? hex, 'hex');
  for (const p of t.patch ?? []) Buffer.from(p.hex, 'hex').copy(b, p.at);
  if (t.insert) b = Buffer.concat([b.subarray(0, t.insert.at), Buffer.from(t.insert.hex, 'hex'), b.subarray(t.insert.at)]);
  if (t.truncate !== undefined) b = b.subarray(0, t.truncate);
  return b;
}
export const pisOf = (pv) => pv.map((p) => p.map((x) => BigInt(x)));
// one verdict: { accept, why }
export function runCase(vk, v, t, log) {
  try { verify(vk, pisOf(t?.public_values ?? v.public_values), t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex'), { log }); return { accept: true }; }
  catch (e) { if (!(e instanceof V)) throw e; return { accept: false, why: e.message }; }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2); const trace = args.includes('--trace');
  const ci = args.indexOf('--cases'); const casesFile = ci >= 0 ? args[ci + 1] : null;
  const files = args.filter((a, i) => !a.startsWith('--') && !(ci >= 0 && i === ci + 1));
  const ext = casesFile ? JSON.parse(readFileSync(casesFile, 'utf8')) : null;
  let total = 0; let bad = 0;
  for (const f of files) {
    const v = JSON.parse(readFileSync(f, 'utf8')); const vk = vkFromVector(v);
    const log = [];
    const t0 = Date.now(); const r = runCase(vk, v, null, trace ? log : null); const ms = Date.now() - t0;
    total++; if (!r.accept) bad++;
    let tr = '';
    if (trace) {
      const rt = v.transcript_hash_inputs; const same = rt.length === log.length && rt.every((h, i) => h === log[i]);
      tr = same ? ` transcript identical (${log.length} hashes)` : ` TRANSCRIPT DIFFERS (${log.length} vs ${rt.length})`;
      if (!same) bad++;
    }
    console.log(`${r.accept ? 'ok  ' : 'FAIL'} ${f} valid: ${r.accept ? 'ACCEPT' : `REJECT (${r.why})`} ${ms} ms${tr}`);
    const cases = ext ? (ext[f.split('/').pop()] ?? []) : (v.tampered ?? []);
    for (const t of cases) {
      const c = runCase(vk, v, t, null); total++;
      if (c.accept) { bad++; console.log(`FAIL ${f} ${t.name}: ACCEPT`); }
    }
  }
  console.log(`js verify-batch: ${total} cases, ${bad} unexpected`);
  process.exit(bad ? 1 : 0);
}
