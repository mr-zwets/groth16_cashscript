// Code generator: CashVM (BCH 2026) verifier for Plonky3 uni-stark proofs in p3s-v1 (SHA-256, Goldilocks, D = 2 or 3).
// It follows model.mjs step by step. Approach of the Track 4 generator (groth16_cashscript research/pq-hash/verifier/gen.mjs):
// shared OP_DEFINE functions, loops, LIFO Merkle records with a depth pin per tree; field arithmetic with the Track 5
// field-cost techniques (research/pq-stark/field): packed F_p^D values in 26-byte slots, packed rotation columns of
// beta for the folds (PAIRK), packed dot products for the DEEP numerators, group-packed final polynomial (gpd),
// window tables for the query point.
//
// Layout (b) stack at entry (bottom first; witness of model.mjs encodeB):
//   L_{Q-1} .. L_0     query blobs (processed from the bottom: query Q-1 first)
//   R<t>_<i>           Merkle record groups, tree by tree
//   ROOTS OOD [BPOW] FROOTS [CPOW] FIN [QPOW]   the transcript part of the proof (OOD in observation order)
// Phases: (1) transcript, PoW checks, indices; (2) AIR identity at zeta and per-proof constants; (3) final polynomial
// unpack; (4) one query function call per query (DEEP, folds, final polynomial; leaf digests to the altstack);
// (5) Merkle authentication of every tree from the leaf digests (LIFO records); (6) depth pin and cleanup.
import {asm, fresh, Stk} from './lib/asm.mjs';
import {compileSlp, V, K, op, chk, call, add, sub, mul, modp, sum, ex} from './lib/slp.mjs';
import {P, pw, inv, g2, rev, le8, OPS} from './model.mjs';

const B0 = Uint8Array.of(0);
const R = (x) => modp(x, P);
const names = (b, n) => Array.from({length: n}, (_, i) => b + i);

// ---- extension-field expressions (lazy: one OP_MOD per output coefficient) ----
// D = 3: F_p[u]/(u^3 - u - 1); D = 2: F_p[u]/(u^2 - 7)
export function mulE(D, A, B) {
  A = A.map(ex); B = B.map(ex);
  const c = Array(2 * D - 1).fill(null);
  for (let i = 0; i < D; i++) for (let j = 0; j < D; j++) { const t = mul(A[i], B[j]); c[i + j] = c[i + j] ? add(c[i + j], t) : t; }
  if (D === 3) return [add(c[0], c[3]), add(add(c[1], c[3]), c[4]), add(c[2], c[4])];
  return [add(c[0], mul(c[2], K(7))), c[1]];
}
export function sqE(D, A) {
  A = A.map(ex);
  if (D === 3) {
    const c0 = mul(A[0], A[0]), c1 = mul(mul(A[0], A[1]), K(2)), c2 = add(mul(mul(A[0], A[2]), K(2)), mul(A[1], A[1])), c3 = mul(mul(A[1], A[2]), K(2)), c4 = mul(A[2], A[2]);
    return [add(c0, c3), add(add(c1, c3), c4), add(c2, c4)];
  }
  return [add(mul(A[0], A[0]), mul(mul(A[1], A[1]), K(7))), mul(mul(A[0], A[1]), K(2))];
}
// u * a (linear, unreduced): D = 3: (a2, a0 + a2, a1); D = 2: (7 a1, a0)
export const mulU = (D, A) => (D === 3 ? [A[2], add(A[0], A[2]), A[1]] : [mul(A[1], K(7)), A[0]]);

// program builder; with `fn` (function ids) the products are calls to the shared functions
export class PB {
  constructor(D, fn) { this.D = D; this.fn = fn; this.prog = []; }
  let(expr, name) { const nm = name ?? fresh('v'); this.prog.push([nm, expr]); return nm; }
  red(expr, name) { return this.let(R(expr), name); }
  chk(expr) { this.prog.push([null, expr]); }
  call(id, args, nout, out) { const outs = out ?? Array.from({length: nout}, () => fresh('f')); this.prog.push([outs, call(id, args.map(ex))]); return outs; }
  mul(A, B, out) { return this.fn ? this.call(this.fn.MULE, [...A, ...B], this.D, out) : mulE(this.D, A, B).map((x, i) => this.red(x, out?.[i])); }
  sq(A, out) { return this.fn ? this.call(this.fn.SQE, A, this.D, out) : sqE(this.D, A).map((x, i) => this.red(x, out?.[i])); }
  mulF(A, s, out) { return this.fn ? this.call(this.fn.MULF, [...A, s], this.D, out) : A.map((a, i) => this.red(mul(ex(a), ex(s)), out?.[i])); }
  mm(a, b, out) { return this.fn ? this.call(this.fn.MM, [a, b], 1, out ? [out] : undefined)[0] : this.red(mul(ex(a), ex(b)), out); }
  add(A, B, out) { return this.fn ? this.call(this.fn.ADDE, [...A, ...B], this.D, out) : A.map((a, i) => this.red(add(ex(a), ex(B[i])), out?.[i])); }
  // A - B for B < 2p
  sub(A, B, out) { return this.fn ? this.call(this.fn.SUBE, [...A, ...B], this.D, out) : A.map((a, i) => this.red(add(sub(ex(a), ex(B[i])), K(2n * P)), out?.[i])); }
  pow2k(x, k) { for (let i = 0; i < k; i++) x = this.mm(x, x); return x; }
}

// compile a program in sections (for size and op-cost attribution): names used by later sections are kept
function compileSec(stk, prog, cuts, keep, after) {
  const bounds = [0, ...cuts, prog.length];
  const refs = (e, acc) => { if (e.t === 'v') acc.add(e.n); else if (e.args) e.args.forEach((x) => refs(x, acc)); return acc; };
  for (let k = 0; k + 1 < bounds.length; k++) {
    const later = new Set();
    for (const [, e] of prog.slice(bounds[k + 1])) refs(e, later);
    compileSlp(stk, prog.slice(bounds[k], bounds[k + 1]), {keep: [...keep, ...later]});
    after?.(k);
  }
}
function localFn(args, build) {
  const s = new Stk(args);
  const outs = build(s);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length || s.st.length !== outs.length) throw new Error('local function leaves ' + (extra.join(',') || s.st.join(',')));
  s.arrange(outs);
  return s.bytes();
}
const slpFn = (args, prog, outs) => localFn(args, (s) => { compileSlp(s, prog, {keep: outs}); return outs; });

// ---- packed helpers (Track 5 field cost) ----
export const SK = 26;     // fold slots (bytes)
export const SB = 17;     // dot-product / final-polynomial slots (bytes): sums of < 2^8 products of 64-bit values
// unpack a packed value (non-negative slots) into n numbers, slot 0 deepest
const unpackCode = (n, sb, red = false) => [sb * n, 'NUM2BIN', ...Array(n - 1).fill([sb, 'SPLIT']), ...Array.from({length: n}, () => [n - 1, 'ROLL', 'BIN2NUM', ...(red ? [P, 'MOD'] : [])])].flat();
// packed rotation columns of b (canonical names): column k = b * u^k, slot j at 2^(8 sb j); entries < 2p (D = 3) / 7p (D = 2)
function rotColumns(D, bn, sb) {
  let col = bn.map((x) => V(x));
  const cols = [];
  for (let k = 0; k < D; k++) {
    cols.push(sum(...col.map((t, j) => (j === 0 ? t : op('LSHIFTNUM', t, K(8 * sb * j))))));
    col = mulU(D, col);
  }
  return cols;
}
// PAIRK: [R_0 .. R_{D-1} (packed rotation columns of beta'), xi, u, v (packed)] -> o = u + v + xi beta' (u - v)
//   d = u - v + BIAS (slots p 2^137 > 2^207 > any input slot), unpacked and reduced; T = sum_k d_k R_k (slot < D p 7p < 2^133);
//   o slots < 2^(b+1) + 2^197 for input slots < 2^b: inputs < 2^64 -> < 2^198; after 4 levels < 2^202 (< 2^207, BIN2NUM-safe)
function pairkBody(D) {
  const BIAS = Array.from({length: D}, (_, k) => (P << 137n) << BigInt(8 * SK * k)).reduce((x, y) => x + y);
  const st = new Stk([...names('R', D), 'xi', 's', ...names('d', D)]);
  st.code.push(...asm('2DUP', 'ADD', 'ROT', 'ROT', 'SUB', BIAS, 'ADD', ...unpackCode(D, SK, true)));
  for (let k = D - 1; k >= 0; k--) {
    if (k < D - 1) st.roll('d' + k);
    st.roll('R' + k); st.raw(['MUL'], 2, ['p' + k]);
    if (k < D - 1) st.raw(['ADD'], 2, ['p' + k]);
    st.rename(st.top(), 'T');
  }
  st.roll('xi'); st.raw(['MUL'], 2, ['xT']); st.raw(['ADD'], 2, ['o']);
  return st.bytes();
}

export function makeGen(vk, pis, opts = {}) {
  const D = vk.D, h = vk.h, Q = vk.Q, e8 = 8 * D, NR = vk.logArities.length;
  const RG = opts.recGroup ?? 2;
  const fns = new Map(); let nextId = 16;
  const defFn = (name, body, id) => { id ??= nextId++; fns.set(name, {id, body: Uint8Array.from(body)}); return id; };
  const marks = [];
  const mark = (stk, label) => { marks.push([label, stk.code.length]); if (opts.markers) stk.emit('NOP'); };
  const trunc = h < 32 ? [h, 'SPLIT', 'DROP'] : [];
  const F = {};
  const GH = vk.L >= 256 ? 8 : Math.min(4, vk.L), GG = vk.L / GH;

  // ---------------- shared functions ----------------
  F.MM = defFn('MM', asm('MUL', P, 'MOD'));
  { const b = new PB(D); mulE(D, names('a', D), names('b', D)).forEach((x, i) => b.red(x, 'c' + i)); F.MULE = defFn('MULE', slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D))); }
  { const b = new PB(D); sqE(D, names('a', D)).forEach((x, i) => b.red(x, 'c' + i)); F.SQE = defFn('SQE', slpFn(names('a', D), b.prog, names('c', D))); }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(mul(V(x), V('s')), 'c' + i)); F.MULF = defFn('MULF', slpFn([...names('a', D), 's'], b.prog, names('c', D))); }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(add(V(x), V('b' + i)), 'c' + i)); F.ADDE = defFn('ADDE', slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D))); }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(add(sub(V(x), V('b' + i)), K(2n * P)), 'c' + i)); F.SUBE = defFn('SUBE', slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D))); }
  // POP8: [d r] -> [d r' v]: v = the last 8 bytes of r as a big-endian u64 (r empty: d = r = SHA256(d) first)
  F.POP8 = defFn('POP8', asm('SIZE', 'NOT', 'IF', 'DROP', 'SHA256', 'DUP', 'ENDIF', 'SIZE', 8, 'SUB', 'SPLIT', 'REVERSEBYTES', B0, 'CAT', 'BIN2NUM'));
  // POPB: [d r] -> [v d r'], v a base-field sample (v >= p: reject; Plonky3 would resample, probability 2^-32)
  F.POPB = defFn('POPB', asm(F.POP8, 'INVOKE', 'DUP', P, 'LESSTHAN', 'VERIFY', 'ROT', 'ROT'));
  // PKL: a block of n F_p^D values (e8 bytes each) -> n packed values (SK slots, first deepest)
  {
    const Z = new Uint8Array(SK - 8);
    const expand = [...Array.from({length: D - 1}, (_, k) => [8 + k * SK, 'SPLIT', Z, 'SWAP', 'CAT', 'CAT']).flat(), B0, 'CAT'];
    F.PKL = defFn('PKL', asm('BEGIN', e8, 'SPLIT', 'SWAP', ...expand, 'BIN2NUM', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'));
  }
  F.PAIRK = defFn('PAIRK', pairkBody(D));
  { const cb = new PB(D); rotColumns(D, names('b', D), SK).forEach((x, k) => cb.let(x, 'R' + k)); F.COLSK = defFn('COLSK', slpFn(names('b', D), cb.prog, names('R', D))); }
  // ENC: canonical F_p^D value (D numbers) -> its D x 8 bytes (u64 LE each)
  F.ENC = defFn('ENC', asm(Array.from({length: D}, (_, k) => [k === 0 ? D - 1 : D - k, 'ROLL', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP', ...(k ? ['CAT'] : [])]).flat()));
  // TBL<la>: [G] -> [G^rev(0) .. G^rev(2^la - 1)] (bit-reversed powers, la bits), by doubling
  const tblFn = (la) => {
    const key = 'TBL' + la; if (F[key]) return F[key];
    const s = new Stk(['G']);
    const b = new PB(D, F);
    const m = ['G']; for (let i = 1; i < la; i++) m.push(b.mm(m[i - 1], m[i - 1]));   // m[i] = G^(2^i)
    compileSlp(s, b.prog, {keep: m});
    s.push(1, 'T0');
    for (let bb = 0; bb < la; bb++) {
      const mult = m[la - 1 - bb], n = 1 << bb;
      for (let i = 0; i < n; i++) { s.pick('T' + i); s.pick(mult); s.raw([F.MM, 'INVOKE'], 2, ['T' + (n + i)]); }
    }
    for (const x of m) s.drop(x);
    s.arrange(names('T', 1 << la));
    return (F[key] = defFn(key, s.bytes()));
  };

  const nOv = vk.oodVals;
  const ovE = (i) => names(`ov${i}_`, D);
  const claimVals = []; { let p = 0; for (const cl of vk.flat) { claimVals.push(Array.from({length: cl.width}, () => ovE(p++))); } }
  const tb = vk.zk ? 1 : 0;
  const traceLocal = claimVals[tb].slice(0, vk.width), traceNext = claimVals[tb + 1].slice(0, vk.width);
  const chunkIdx = vk.flat.map((cl, i) => [cl, i]).filter(([cl]) => cl.batch === tb + 1).map(([, i]) => i);
  const chunks = chunkIdx.map((i) => claimVals[i].slice(0, D));
  const zeta = names('ze', D), alpha = names('al', D), alphaP = names('ap', D);
  const la0 = vk.logArities[0], hf0 = vk.logH - la0, nT = Math.ceil(hf0 / 4);
  const arities = [...new Set(vk.logArities)];
  const nTrees = vk.trees.length;
  const g = {vk, D, h, Q, F, fns, defFn, marks, mark, trunc, GG, GH, emitQuery, tblFn, claimVals};
  // phase 1: transcript from the PT items (names ROOTS OOD BPOW FROOTS CPOW FIN QPOW on S; ROOTS without its header byte)
  g.transcript = (S, {pow = true, keepG = false} = {}) => {
    // ---------------- phase 1: transcript ----------------
    const obs = (parts) => { // [d r] -> d = SHA256(d ‖ parts), r = d
      S.drop('r'); S.roll('d');
      for (const p of parts) { if (typeof p === 'string') S.roll(p); else S.push(p); S.raw(['CAT'], 2, ['d']); }
      S.raw(['SHA256', 'DUP'], 1, ['d', 'r']);
    };
    const sampleExt = (base) => { for (let k = 0; k < D; k++) S.raw([F.POPB, 'INVOKE'], 2, [base + k, 'd', 'r']); return names(base, D); };
    const powCheck = (wname, bits) => {
      obs([wname]);
      S.raw([F.POP8, 'INVOKE', ...(pow ? [1n << BigInt(bits), 'MOD', 0, 'NUMEQUALVERIFY'] : ['DROP'])], 2, ['d', 'r']);
    };
    S.push(vk.SO.stark, 'd'); S.pick('ROOTS'); S.raw([h, 'SPLIT', 'DROP'], 1, ['x']); S.raw(['CAT'], 2, ['d']);
    S.push(Buffer.concat(pis.map(le8)), 'x'); S.raw(['CAT', 'SHA256', 'DUP'], 2, ['d', 'r']);
    sampleExt('al');
    S.pick('ROOTS'); S.raw([h, 'SPLIT', 'NIP'], 1, ['rq']);
    obs(['rq']);
    sampleExt('ze');
    S.pick('OOD', 'ood2');
    obs([vk.SO.pcs, 'ood2']);
    if (vk.bpow) powCheck('BPOW', vk.bpow);
    sampleExt('ap');
    if (vk.cpow) S.roll('CPOW');
    for (let r = 0; r < NR; r++) {
      S.pick('FROOTS'); S.raw([...(r ? [r * h, 'SPLIT', 'NIP'] : []), ...(r < NR - 1 ? [h, 'SPLIT', 'DROP'] : [])], 1, ['fr']);
      obs(r === 0 ? [vk.SO.fri, 'fr'] : ['fr']);
      if (vk.cpow) {
        if (r < NR - 1) { S.roll('CPOW'); S.raw([8, 'SPLIT', 'SWAP'], 1, ['CPOW', 'cw']); } else { S.roll('CPOW'); S.rename('CPOW', 'cw'); }
        powCheck('cw', vk.cpow);
      }
      sampleExt(`be${r}_`);
    }
    S.pick('FIN', 'fin2');
    obs(['fin2']);
    if (vk.qpow) powCheck('QPOW', vk.qpow);
    // indices idx0 .. idx_{Q-1} (idx0 deepest)
    S.raw([Q, 'TOALTSTACK', 'BEGIN', F.POP8, 'INVOKE', 1n << BigInt(vk.logH), 'MOD', 'ROT', 'ROT', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], 2, [...names('idx', Q), 'd', 'r']);
    S.drop('r'); if (keepG) S.rename('d', 'G'); else S.drop('d');
    mark(S, 'transcript');

  };
  // OOD -> numbers ov<i>_<k>
  g.parseOOD = (S) => {
    S.roll('OOD');
    S.raw(['BEGIN', 8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'], 1, Array.from({length: nOv * D}, (_, i) => `ov${Math.floor(i / D)}_${i % D}`));
  };
  g.air = (S) => {
    // ---- AIR identity at zeta (multiplied through by (zeta - 1)(zeta - g^-1)) ----
    mark(S, 'air-start');
    {
      const b = new PB(D, F);
      // zeta^(2^i), i = 1 .. logN (keep the ones periodic columns need)
      const zp = {0: zeta}; let cur = zeta;
      for (let i = 1; i <= vk.logN; i++) { cur = b.sq(cur); zp[i] = cur; }
      const zN = zp[vk.logN];
      const one = [K(1), ...Array(D - 1).fill(K(0))];
      const subBase = (A, c) => [b.red(add(sub(ex(A[0]), K(c)), K(P))), ...A.slice(1)];
      const zh = subBase(zN, 1n);
      // zeta^n != 1 (zh != 0): at least one coefficient non-zero
      b.chk(chk('VERIFY', zh.slice(1).reduce((acc, x) => op('BOOLOR', acc, ex(x)), ex(zh[0]))));
      if (vk.zk) { const zp1 = [b.red(add(ex(zN[0]), K(1))), ...zN.slice(1)]; b.chk(chk('VERIFY', zp1.slice(1).reduce((acc, x) => op('BOOLOR', acc, ex(x)), ex(zp1[0])))); }
      const D1 = subBase(zeta, 1n), D2 = subBase(zeta, inv(vk.gN));
      const D12 = b.mul(D1, D2);
      const selW = {first: b.mul(zh, D2), last: b.mul(zh, D1), trans: b.mul(D12, D2), null: D12};
      const air0 = b.prog.length;
      const per = vk.periodic.map(({lm, coef}) => {
        const y = zp[vk.logN - lm];
        let acc = [K(coef[coef.length - 1]), ...Array(D - 1).fill(K(0))].map((x) => b.let(x));
        for (let k = coef.length - 2; k >= 0; k--) { acc = b.mul(acc, y); acc = [b.red(add(V(acc[0]), K(coef[k]))), ...acc.slice(1)]; }
        return acc;
      });
      // ---- AIR-specific: constraints from the AIR description ----
      const lets = {};
      const evalE = (e) => {
        switch (e[0]) {
          case 'loc': return traceLocal[e[1]];
          case 'nxt': return traceNext[e[1]];
          case 'per': return per[e[1]];
          case 'let': return lets[e[1]];
          case 'add': { const [x, y] = [e[1], e[2]]; if (y[0] === 'pub' || y[0] === 'k') return [b.red(add(ex(evalE(x)[0]), K(y[0] === 'pub' ? pis[y[1]] : BigInt(y[1])))), ...evalE(x).slice(1)]; return b.add(evalE(x), evalE(y)); }
          case 'sub': { const [x, y] = [e[1], e[2]]; if (y[0] === 'pub' || y[0] === 'k') return subBase(evalE(x), md0(y[0] === 'pub' ? pis[y[1]] : BigInt(y[1]))); return b.sub(evalE(x), evalE(y)); }
          case 'mul': return b.mul(evalE(e[1]), evalE(e[2]));
          default: throw new Error('air expr ' + e[0]);
        }
      };
      for (const [k, e] of Object.entries(vk.A.lets)) lets[k] = evalE(e);
      let acc = null;
      for (const [sel, e] of vk.A.constraints) {
        const term = b.mul(selW[String(sel)], evalE(e));
        acc = acc ? b.add(b.mul(acc, alpha), term) : term;
      }
      const air1 = b.prog.length;
      // ---- quotient recomposition: q = sum_i zp_i chunk_i, chunk_i = sum_k ood_{i,k} u^k ----
      let q = null;
      for (let i = 0; i < vk.C; i++) {
        let zpi = null;
        for (let j = 0; j < vk.C; j++) if (j !== i) { const zj = subBase(b.mulF(zN, K(vk.kc[j])), 1n); zpi = zpi ? b.mul(zpi, zj) : zj; }
        // chunk_i = sum_k ood_{i,k} u^k
        let ch = null;
        for (let k = 0; k < D; k++) {
          let t = chunks[i][k].map((x) => V(x)); for (let j = 0; j < k; j++) t = mulU(D, t);
          ch = ch ? ch.map((x, c) => add(x, t[c])) : t;
        }
        const chN = ch.map((x) => b.red(x));
        const term = zpi ? b.mulF(b.mul(zpi, chN), K(vk.zpConst[i])) : (vk.zpConst[i] === 1n ? chN : b.mulF(chN, K(vk.zpConst[i])));
        q = q ? b.add(q, term) : term;
      }
      const rhs = b.mul(b.mul(q, zh), D12);
      acc.forEach((x, k) => b.chk(chk('NUMEQUALVERIFY', V(x), V(rhs[k]))));
      void one;
      const keepOut = [...alphaP, ...zeta, ...claimVals.flat(2)];
      compileSec(S, b.prog, [air0, air1], keepOut, (k) => mark(S, ['air-generic-a', 'air-specific', 'air-generic-b'][k]));
      var airSteps = air1 - air0;
      // drop what the AIR used and nothing else needs
      for (const x of [...alpha, ...traceLocal.flat(), ...traceNext.flat(), ...chunks.flat()]) if (S.has(x) && !claimVals.flat(2).includes(x)) S.drop(x);

    }

    return airSteps;
  };
  g.consts = (S) => {
    // ---- DEEP constants ----
    {
      const b = new PB(D, F);
      const zg = b.mulF(zeta, K(vk.gN));
      const ptz = [zeta, zg];
      ptz.forEach((z, pi) => {
        // columns z u^k (canonical), M(i, j) = col_j[i]
        const cols = [z]; for (let k = 1; k < D; k++) cols.push(mulU(D, cols[k - 1].map(ex)).map((x) => b.red(x)));
        const M = (i, j) => V(cols[j][i]);
        if (D === 3) {
          b.red(add(add(M(0, 0), M(1, 1)), M(2, 2)), `nt${pi}`);
          const m2 = (i, j) => add(mul(M(i, i), M(j, j)), K(P * P)), s2 = (i, j) => mul(M(i, j), M(j, i));
          b.red(sub(add(add(m2(0, 1), m2(0, 2)), m2(1, 2)), add(add(s2(0, 1), s2(0, 2)), s2(1, 2))), `nc${pi}`);
          const minor = (a, bb, c, d) => sub(add(mul(M(a[0], a[1]), M(bb[0], bb[1])), K(P * P)), mul(M(c[0], c[1]), M(d[0], d[1])));
          const det = sub(add(add(mul(M(0, 0), R(minor([1, 1], [2, 2], [1, 2], [2, 1]))), mul(M(0, 2), R(minor([1, 0], [2, 1], [1, 1], [2, 0])))), K(P * P)), mul(M(0, 1), R(minor([1, 0], [2, 2], [1, 2], [2, 0]))));
          b.red(det, `nd${pi}`);
          // B = z - t, C = z^2 - t z + c
          b.red(add(sub(V(z[0]), V(`nt${pi}`)), K(P)), `nB${pi}_0`); b.let(V(z[1]), `nB${pi}_1`); b.let(V(z[2]), `nB${pi}_2`);
          const z2 = b.sq(z); const tz = b.mulF(z, `nt${pi}`);
          const cc = b.sub(z2, tz);
          b.red(add(V(cc[0]), V(`nc${pi}`)), `nC${pi}_0`); b.let(V(cc[1]), `nC${pi}_1`); b.let(V(cc[2]), `nC${pi}_2`);
        } else {
          b.red(add(M(0, 0), M(1, 1)), `nt${pi}`);
          b.red(sub(add(mul(M(0, 0), M(1, 1)), K(P * P)), mul(M(0, 1), M(1, 0))), `nd${pi}`);
          b.red(add(sub(V(z[0]), V(`nt${pi}`)), K(P)), `nB${pi}_0`); b.let(V(z[1]), `nB${pi}_1`);
        }
      });
      // alpha' powers, A_z, packed row constants
      const apow = [null, alphaP];
      for (let i = 2; i < vk.numVals; i++) apow.push(b.mul(apow[i - 1], alphaP));
      const Az = [null, null];
      vk.flat.forEach((cl, ci) => claimVals[ci].forEach((v, k) => {
        const t = cl.off + k === 0 ? v : b.mul(apow[cl.off + k], v);
        Az[cl.pt] = Az[cl.pt] ? b.add(Az[cl.pt], t) : t;
      }));
      Az.forEach((a, pi) => (a ?? Array(D).fill(null)).forEach((x, k) => b.let(x ? V(x) : K(0), `nA${pi}_${k}`)));
      // per row value (batch b, matrix m, column j): K = sum_pt sum_k apow[off_pt + j]_k 2^(8 SB (D pt + k))
      const rowKeys = [];
      vk.claims.forEach((round, bi) => round.forEach((m, mi) => { for (let j = 0; j < m.width; j++) rowKeys.push([bi, mi, j]); }));
      rowKeys.forEach(([bi, mi, j], ri) => {
        const terms = [];
        vk.flat.filter((cl) => cl.batch === bi && cl.mat === mi).forEach((cl) => {
          const a = cl.off + j === 0 ? null : apow[cl.off + j];
          for (let k = 0; k < D; k++) {
            const sh = 8 * SB * (D * cl.pt + k);
            const t = a ? V(a[k]) : K(k === 0 ? 1 : 0);
            terms.push(sh ? op('LSHIFTNUM', t, K(sh)) : t);
          }
        });
        b.let(sum(...terms), `kr${ri}`);
      });
      compileSlp(S, b.prog, {keep: [...names('nt', 2), ...names('nd', 2), ...(D === 3 ? names('nc', 2) : []), ...[0, 1].flatMap((pi) => [...names(`nB${pi}_`, D), ...(D === 3 ? names(`nC${pi}_`, D) : []), ...names(`nA${pi}_`, D)]), ...rowKeys.map((_, ri) => `kr${ri}`)]});
      for (const x of [...zeta, ...alphaP, ...claimVals.flat(2)]) if (S.has(x)) S.drop(x);
      var nRows = rowKeys.length;
    }
    mark(S, 'deep-consts');
    // ---- fold columns: per round r, level l: packed rotation columns of beta_r^(2^l) ----
    {
      const b = new PB(D, F);
      for (let r = 0; r < NR; r++) {
        let be = names(`be${r}_`, D);
        for (let l = 0; l < vk.logArities[r]; l++) {
          if (l) be = b.sq(be);
          b.call(F.COLSK, be, D, names(`fc${r}_${l}_`, D));
        }
      }
      compileSlp(S, b.prog, {keep: []});
    }
    // ---- tables: s0 windows over di0 = idx >> la0 (T<k>), bit-reversed powers per arity (W<a>) ----
    for (let k = 0; k < nT; k++) {
      // nibble k of di0 contributes G_k^rev4(nib), G_k = g_H^(2^(hf0 - 4 - 4k)) (a root of order 2^(logH - hf0 + 4 + 4k))
      const Gk = g2(vk.logH - (hf0 - 4 - 4 * k));
      S.push(Gk, 'G'); S.raw([tblFn(4), 'INVOKE'], 1, names(`T${k}_`, 16));
    }
    for (const la of arities) { S.push(g2(la), 'G'); S.raw([tblFn(la), 'INVOKE'], 1, names(`W${la}_`, 1 << la)); }
    mark(S, 'tables');

  };
  g.unpack = (S) => {
    // ---------------- phase 3: final polynomial unpack (group-packed, Track 5 gpd) ----------------
    {
      const Z = new Uint8Array(SB - 8);
      const expand = D === 3
        ? [8, 'SPLIT', 8, 'SPLIT', Z, 'CAT', 'SWAP', Z, 'CAT', 'SWAP', 'CAT', 'SWAP', Z, 'CAT', 'SWAP', 'CAT']
        : [8, 'SPLIT', Z, 'CAT', 'SWAP', Z, 'CAT', 'SWAP', 'CAT'];
      const Pn = names('PF', GG);
      S.raw([GG, 'BEGIN', 0, 'SWAP', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0, Pn);
      S.roll('FIN');
      const CH = Math.min(16, vk.L);
      S.raw(['BEGIN', CH * e8, 'SPLIT', 'SWAP',
        'BEGIN', e8, 'SPLIT', 'SWAP', ...expand, GG + 2, 'ROLL', 'SWAP', 'CAT', 'ROT', 'ROT', 'SIZE', 'NOT', 'UNTIL', 'DROP',
        'SIZE', 'NOT', 'UNTIL', 'DROP'], GG + 1, Pn);
      S.raw([GG, 'TOALTSTACK', 'BEGIN', GG - 1, 'ROLL', B0, 'CAT', 'BIN2NUM', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], GG, Pn);
    }
    mark(S, 'unpack');

  };
  g.merkleFns = () => {
      const MARKER = Uint8Array.of(0x00, 0x80);
      const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256', ...trunc];
      const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
      defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4);
      defFn('F8', asm(OPS.F4, 'INVOKE', 'DROP', OPS.F4, 'INVOKE'), OPS.F8);
      defFn('F16', asm(OPS.F8, 'INVOKE', 'DROP', OPS.F8, 'INVOKE'), OPS.F16);
      {
        const m = new Stk(['k', 'cur', 'rb']);
        m.raw(['FROMALTSTACK', 'FROMALTSTACK'], 0, ['pk', 'pd']);
        m.pick('k'); m.raw([1, 'RSHIFTNUM'], 1, ['kh']);
        const b = new PB(D);
        b.chk(chk('NUMEQUALVERIFY', add(V('pk'), V('k')), add(mul(V('kh'), K(4)), K(1))));
        b.let(sub(V('k'), mul(V('kh'), K(2))), 'bit');
        compileSlp(m, b.prog, {keep: ['kh']});
        m.arrange(['kh', 'rb', 'cur', 'pd', 'bit']);
        m.raw(['ROLL', 'CAT', 'SHA256', ...trunc], 3, ['cur']);
        m.arrange(['kh', 'cur', 'rb']); m.push(0);
        defFn('MERGE', m.bytes(), OPS.MERGE);
        const d = new Stk(['k', 'cur', 'rb']);
        d.raw(['FROMALTSTACK'], 0, ['pk']); d.pick('k'); d.raw(['NUMEQUALVERIFY'], 2);
        d.raw(['FROMALTSTACK'], 0, ['pd']); d.pick('cur'); d.raw(['EQUALVERIFY'], 2); d.push(0);
        defFn('DUPM', d.bytes(), OPS.DUPM);
        const pk = new Stk(['k', 'cur', 'rb']);
        pk.roll('cur'); pk.raw(['TOALTSTACK'], 1); pk.roll('k'); pk.raw(['TOALTSTACK'], 1); pk.push(1);
        defFn('PARK', pk.bytes(), OPS.PARK);
        const rt = new Stk(['root', 'acc', 'k', 'cur', 'rb']);
        rt.roll('cur'); rt.pick('root'); rt.raw(['EQUALVERIFY'], 2); rt.roll('k'); rt.raw([1, 'NUMEQUALVERIFY'], 1); rt.push(1);
        defFn('ROOT', rt.bytes(), OPS.ROOT);
      }
  };
  return g;

    // ---------------- one query ----------------
    function emitQuery(Qs, {toAlt = true} = {}) {
      const KC = /^(kr|nA|nB|nC|nt|nc|nd|fc|T\d|W\d|PF)/;
      const keepC = () => Qs.st.filter((x) => KC.test(x));
      // window tables: s0 = prod_k T<k>[nibble_k(idx >> la0)]
      Qs.pick('idx', 'v'); Qs.raw([la0, 'RSHIFTNUM'], 1, ['v']);
      for (let k = 0; k < nT; k++) {
        const last = k === nT - 1;
        if (!last) Qs.raw(['DUP'], 0, ['nb']);
        const d = Qs.depth(`T${k}_0`) - 1;
        Qs.raw([...(last ? [] : [16, 'MOD']), d, 'SWAP', 'SUB', 'PICK'], 1, ['t']);
        if (k === 0) { if (last) { Qs.rename('t', 's0'); break; } Qs.raw(['SWAP', 4, 'RSHIFTNUM'], 2, ['x', 'v']); continue; }
        if (last) { Qs.raw([F.MM, 'INVOKE'], 2, ['s0']); break; }
        Qs.raw(['ROT', F.MM, 'INVOKE', 'SWAP', 4, 'RSHIFTNUM'], 3, ['x', 'v']);
      }
      const pickW = (la, posExpr, out) => {   // W<la>[pos] with pos = (idx >> sh) mod 2^la
        Qs.pick('idx', 'v'); Qs.raw([...(posExpr ? [posExpr, 'RSHIFTNUM'] : []), 1 << la, 'MOD'], 1, ['v']);
        const d = Qs.depth(`W${la}_0`) - 1;
        Qs.raw([d, 'SWAP', 'SUB', 'PICK'], 1, [out]);
      };
      pickW(la0, 0, 'w0');
      {
        const b = new PB(D, F);
        b.mm('s0', 'w0', 'xo');
        b.red(mul(V('xo'), K(7)), 'x0');
        compileSlp(Qs, b.prog, {keep: ['s0', 'xo']});
      }
      mark(Qs, 'q-x');
      // split L: batch preimages, FRI blocks, T
      Qs.roll('L');
      const parts = [...vk.batchBytes.map((_, i) => 'bp' + i), ...vk.friBytes.map((_, r) => 'fb' + r), 'TT'];
      const lens = [...vk.batchBytes, ...vk.friBytes];
      Qs.raw(lens.map((n) => [n, 'SPLIT']).flat().length ? lens.map((n) => [n, 'SPLIT']).flat() : [], 1, parts);
      // K blob: idx (4 B) ‖ leaf digests
      Qs.pick('idx'); Qs.raw([4, 'NUM2BIN'], 1, ['kb']);
      // batch digests and row values
      const rowNames = [];
      vk.claims.forEach((round, bi) => {
        Qs.pick('bp' + bi, 'hx'); Qs.raw(['SHA256', ...trunc], 1, ['dg']); Qs.roll('kb'); Qs.roll('dg'); Qs.raw(['CAT'], 2, ['kb']);
        Qs.roll('bp' + bi);
        // per matrix: row (8 w bytes) [‖ salt]
        const outs = [];
        round.forEach((m, mi) => { for (let j = 0; j < m.width; j++) outs.push(`rw${bi}_${mi}_${j}`); });
        const code = [];
        round.forEach((m, mi) => {
          for (let j = 0; j < m.width; j++) code.push(8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP');
          if (vk.salt) code.push(8 * vk.salt, 'SPLIT', 'NIP');
        });
        code.push('DROP');
        Qs.raw(code, 1, outs);
        rowNames.push(...outs);
      });
      Qs.roll('TT'); Qs.raw([B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY'], 1, ['T']);   // canonical hint (no T + p twin)
      // ---- DEEP ----
      {
        const b = new PB(D, F);
        // N_pt(x0), adj_pt(x0)
        const x2 = D === 3 ? b.mm('x0', 'x0') : null;
        const N = [0, 1].map((pi) => {
          if (D === 3) {
            const n1 = b.red(add(mul(add(sub(V('x0'), V(`nt${pi}`)), K(P)), V('x0')), V(`nc${pi}`)));
            const n2 = b.mm(n1, 'x0');
            return b.red(add(sub(V(`nd${pi}`), V(n2)), K(P)));
          }
          const n1 = b.red(add(mul(add(sub(V('x0'), V(`nt${pi}`)), K(P)), V('x0')), V(`nd${pi}`)));
          return b.red(sub(K(P), V(n1)));
        });
        // T N0 N1 s0 == 1; sinv = T N0 N1
        const tn = b.mm(b.mm('T', N[0]), N[1]);
        b.chk(chk('NUMEQUALVERIFY', R(mul(V(tn), V('s0'))), K(1)));
        b.let(V(tn), 'si0');
        // packed dot products of the row values with the alpha' columns (both points at once)
        const npt = vk.flat.some((cl) => cl.pt === 1) ? 2 : 1;
        b.let(sum(...rowNames.map((rn, ri) => mul(V(rn), V(`kr${ri}`)))), 'dot');
        compileSlp(Qs, b.prog, {keep: [...keepC(), 's0', 'x0', 'xo', 'si0', 'T', ...(x2 ? [x2] : []), ...N]});
        Qs.roll('dot'); Qs.raw(unpackCode(npt * D, SB, true), 1, names('dp', npt * D));
        const b2 = new PB(D, F);
        const num = [0, 1].map((pi) => names(`nA${pi}_`, D).map((a, k) => b2.red(add(sub(V(a), pi < npt ? V(`dp${pi * D + k}`) : K(0)), K(P)))));
        const adj = [0, 1].map((pi) => (D === 3
          ? [b2.red(add(add(V(x2), mul(V(`nB${pi}_0`), V('x0'))), V(`nC${pi}_0`))), b2.red(add(mul(V(`nB${pi}_1`), V('x0')), V(`nC${pi}_1`))), b2.red(add(mul(V(`nB${pi}_2`), V('x0')), V(`nC${pi}_2`)))]
          : [b2.red(add(V('x0'), V(`nB${pi}_0`))), `nB${pi}_1`]));
        // ro = (num0 adj0 N1 + num1 adj1 N0) T s0
        const ts = b2.mm('T', 's0');
        const m0 = b2.mm(N[1], ts), m1 = b2.mm(N[0], ts);
        const p0 = mulE(D, num[0], adj[0]), p1 = mulE(D, num[1], adj[1]);
        const ro = p0.map((x, k) => b2.red(add(mul(R(x), V(m0)), mul(R(p1[k]), V(m1)))));
        compileSlp(Qs, b2.prog, {keep: [...keepC(), 'xo', 'si0', ...ro]});
        // encoded ro (round-0 slot value)
        Qs.raw([], 0);
        ro.forEach((x, k) => Qs.rename(x, 'fv' + k));
        for (const x of ['s0', 'x0', 'T', ...(x2 ? [x2] : []), ...N, ts, m0, m1]) if (Qs.has(x)) Qs.drop(x);
      }
      mark(Qs, 'q-deep');
      // ---- folds ----
      let S_acc = 0;
      for (let r = 0; r < NR; r++) {
        const la = vk.logArities[r], a = 1 << la;
        // pos_r = (idx >> S_{r-1}) mod a; leaf = block[0 : 24 pos] ‖ enc(fold) ‖ block[24 pos :] (‖ salt)
        for (let k = 0; k < D; k++) Qs.pick('fv' + k);
        Qs.raw([F.ENC, 'INVOKE'], D, ['fe']);
        Qs.roll('fb' + r);
        if (vk.salt) Qs.raw([((1 << la) - 1) * e8, 'SPLIT'], 1, ['blk', 'salt']);
        else Qs.rename('fb' + r, 'blk');
        Qs.roll('blk'); Qs.pick('idx'); Qs.raw([...(S_acc ? [S_acc, 'RSHIFTNUM'] : []), a, 'MOD', e8, 'MUL', 'SPLIT'], 2, ['bl', 'br']);
        Qs.roll('bl'); Qs.roll('fe'); Qs.raw(['CAT'], 2, ['bl']); Qs.roll('br'); Qs.raw(['CAT'], 2, ['leaf']);
        if (vk.salt) { Qs.pick('leaf'); Qs.roll('salt'); Qs.raw(['CAT', 'SHA256', ...trunc], 2, ['dg']); }
        else { Qs.pick('leaf'); Qs.raw(['SHA256', ...trunc], 1, ['dg']); }
        Qs.roll('kb'); Qs.roll('dg'); Qs.raw(['CAT'], 2, ['kb']);
        for (let k = 0; k < D; k++) Qs.drop('fv' + k);
        Qs.roll('leaf'); Qs.raw([F.PKL, 'INVOKE'], 1, names('v', a));
        // FOLD<la>: [v_0 .. v_{a-1}, columns per level, X = s^-1] -> packed unscaled fold
        const key = 'FOLD' + la;
        if (!F[key]) {
          const args = [...names('v', a), ...Array.from({length: la}, (_, l) => names(`c${l}_`, D)).flat(), 'X'];
          const b = new PB(D, F);
          const ga = g2(la);
          let cur = names('v', a), X = 'X';
          for (let l = 0; l < la; l++) {
            const half = cur.length / 2, nxt = [];
            for (let m = 0; m < half; m++) {
              const cm = inv(pw(ga, rev(m, la - 1)));     // = (ga^(2^l))^-rev(m, la-1-l) for m < half
              const xi = m === 0 ? X : b.mm(X, K(cm));
              nxt.push(b.call(F.PAIRK, [...names(`c${l}_`, D), xi, cur[2 * m], cur[2 * m + 1]], 1, l === la - 1 ? ['o'] : undefined)[0]);
            }
            cur = nxt;
            if (l < la - 1) X = b.mm(X, X);
          }
          F[key] = defFn(key, slpFn(args, b.prog, ['o']));
        }
        {
          const si = `si${r}`;
          const b = new PB(D, F);
          b.call(F[key], [...names('v', a), ...Array.from({length: la}, (_, l) => names(`fc${r}_${l}_`, D)).flat(), si], 1, ['fo']);
          compileSlp(Qs, b.prog, {keep: [...keepC(), si]});
        }
        // unpack, reduce, times 1/a: fold value (canonical)
        const ainv = inv(BigInt(a));
        Qs.roll('fo');
        Qs.raw([SK * D, 'NUM2BIN', ...Array(D - 1).fill([SK, 'SPLIT']).flat(), ...Array.from({length: D}, () => [D - 1, 'ROLL', 'BIN2NUM', P, 'MOD', ainv, F.MM, 'INVOKE']).flat()], 1, names('fv', D));
        S_acc += la;
        // next s^-1 = (s^-1)^a W<la'>[(idx >> S_r) mod a']
        {
          const b = new PB(D, F);
          const sa = b.pow2k(`si${r}`, la);
          if (r + 1 < NR) {
            compileSlp(Qs, b.prog, {keep: []});
            const la2 = vk.logArities[r + 1];
            pickW(la2, S_acc, 'wn');
            const b3 = new PB(D, F); b3.mm(sa, 'wn', `si${r + 1}`); compileSlp(Qs, b3.prog, {keep: []});
          } else { compileSlp(Qs, b.prog, {keep: []}); Qs.drop(sa); }
        }
      }
      mark(Qs, 'q-folds');
      // ---- final polynomial at xf = xo^(2^S) (gpd: GG powers, packed products, Horner over GH groups) ----
      {
        const b = new PB(D, F);
        const y = b.pow2k('xo', vk.S);
        compileSlp(Qs, b.prog, {keep: []});
        Qs.roll(y);
        const Yn = names('Y', GG + 1).slice(1);
        if (GG > 1) {
          F.PW ??= defFn('PW', asm('2DUP', 'MUL', P, 'MOD', 'SWAP'));
          Qs.raw(['DUP', ...Array(GG - 1).fill([F.PW, 'INVOKE']), 'DROP'], 1, Yn);
        } else Qs.rename(y, 'Y1');
        Qs.raw(['TOALTSTACK'], 1);                 // y^GG
        Qs.pick('PF0', 'acc');
        for (let k = GG - 1; k >= 1; k--) { Qs.roll('Y' + k); Qs.pick('PF' + k); Qs.raw(['MUL', 'ADD'], 3, ['acc']); }
        const nsl = D * GH;
        const sl = names('sl', nsl);
        Qs.roll('acc');
        Qs.raw([SB * nsl, 'NUM2BIN', ...Array(nsl - 1).fill([SB, 'SPLIT']).flat()], 1, sl);
        Qs.raw(Array.from({length: D}, () => [D - 1, 'ROLL', 'BIN2NUM']).flat(), D, names('ra', D));
        Qs.raw(['FROMALTSTACK'], 0, ['YG']);
        if (GH > 1) {
          if (!F.HG) {
            const st = new Stk([...names('t', D), ...names('ra', D), 'YG']);
            for (let k = 0; k < D; k++) { st.roll('t' + k); st.raw(['BIN2NUM'], 1, ['u' + k]); }
            const b = new PB(D);
            for (let k = 0; k < D; k++) b.red(add(mul(V('ra' + k), V('YG')), V('u' + k)), 'o' + k);
            compileSlp(st, b.prog, {keep: ['YG']});
            st.arrange([...names('o', D), 'YG']);
            F.HG = defFn('HG', st.bytes());
          }
          for (let m = GH - 2; m >= 0; m--) Qs.raw([F.HG, 'INVOKE'], 2 * D + 1, [...names('ra', D), 'YG']);
        }
        Qs.drop('YG');
        const cb = new PB(D);
        names('ra', D).forEach((x, k) => cb.chk(chk('NUMEQUALVERIFY', R(V(x)), V('fv' + k))));
        compileSlp(Qs, cb.prog);
      }
      Qs.drop('idx');
      if (toAlt) { Qs.roll('kb'); Qs.raw(['TOALTSTACK'], 1); }
      mark(Qs, 'q-final');
    }
}

// layout (b): one input
export function build(vk, pis, opts = {}) {
  const g = makeGen(vk, pis, opts);
  const {D, h, Q, F, fns, defFn, marks, mark, trunc, GG, GH, emitQuery} = g;
  const RG = opts.recGroup ?? 2, NR = vk.logArities.length, e8 = 8 * D, nTrees = vk.trees.length;
  void D; void GG; void GH;
  // ---------------- initial stack ----------------
  const nRec = Math.ceil(Q / RG);
  const init = [];
  for (let q = Q - 1; q >= 0; q--) init.push('L' + q);
  for (let t = 0; t < nTrees; t++) for (let i = 0; i < nRec; i++) init.push(`R${t}_${i}`);
  const pt = ['ROOTS', 'OOD', ...(vk.bpow ? ['BPOW'] : []), 'FROOTS', ...(vk.cpow ? ['CPOW'] : []), 'FIN', ...(vk.qpow ? ['QPOW'] : [])];
  const ptLen = {ROOTS: 1 + vk.nRoots * h, OOD: vk.oodVals * e8, BPOW: 8, FROOTS: NR * h, CPOW: 8 * NR, FIN: vk.L * e8, QPOW: 8};
  init.push(...pt);
  if (opts.padSlot) init.push('PAD');
  const S = new Stk(init);
  S.emit('DEPTH', init.length, 'NUMEQUALVERIFY');
  if (opts.padSlot) S.raw(['SIZE', 0, 'SWAP', 'NUM2BIN', 'EQUALVERIFY'], 1);
  for (const x of pt) { S.pick(x); S.raw(['SIZE', 'NIP', ptLen[x], 'NUMEQUALVERIFY'], 1); }
  // ROOTS = degree_bits (the proof header byte) ‖ roots
  S.roll('ROOTS'); S.raw([1, 'SPLIT', 'SWAP', Uint8Array.of(vk.degreeBits), 'EQUALVERIFY'], 1, ['ROOTS']);
  mark(S, 'entry');

  g.transcript(S);
  g.parseOOD(S);
  const airSteps = g.air(S);
  g.consts(S);
  g.unpack(S);
  // ---------------- phase 4: queries ----------------
  // the index list must sit below everything the query function reads: move constants above it
  {
    const lo = S.st.indexOf('idx0');
    for (const x of S.st.slice(0, lo)) if (!/^(L\d|R\d|ROOTS|FROOTS)/.test(x)) S.roll(x);
  }
  {
    S.push(Q, 'qcnt');
    const Qs = S.clone();
    const qWant = S.st.filter((x) => x !== 'idx' + (Q - 1)).slice(1);
    Qs.bottom(); Qs.rename(Qs.top(), 'L');
    Qs.raw(['SIZE', vk.qBytes, 'NUMEQUALVERIFY'], 0);
    Qs.roll('idx' + (Q - 1)); Qs.rename(Qs.top(), 'idx');
    emitQuery(Qs);
    if (Qs.st.length === qWant.length && Qs.st.every((x) => qWant.includes(x))) Qs.arrange(qWant);
    if (Qs.st.join('|') !== qWant.join('|')) {
      const extra = Qs.st.filter((x) => !qWant.includes(x)), missing = qWant.filter((x) => !Qs.st.includes(x));
      throw new Error(`query function leaves extra [${extra}] missing [${missing}]`);
    }
    F.Q = defFn('Q', Qs.bytes());
    S.raw(['BEGIN', F.Q, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
    S.st.splice(0, Q);
    for (let q = 0; q < Q; q++) S.st.splice(S.st.indexOf('idx' + q), 1);
  }
  mark(S, 'queries');
  // drop the per-proof constants; pull the Q leaf-digest blobs K_0 .. K_{Q-1} (K_0 deepest)
  for (const x of [...S.st]) if (!/^(L\d|R\d|ROOTS|FROOTS)/.test(x)) S.drop(x);
  S.raw(Array(Q).fill('FROMALTSTACK'), 0, names('K', Q));

  g.merkleFns();
  {
    const MARKER = Uint8Array.of(0x00, 0x80);
    // tree roots: input batches (ZK: random, trace, quotient; ROOTS holds trace, quotient, random), then FRI rounds
    const rootSrc = vk.trees.map((tr) => {
      if (tr.kind === 'fri') return ['FROOTS', tr.r * h];
      const ri = vk.zk ? [2, 0, 1][tr.b] : tr.b;
      return ['ROOTS', ri * h];
    });
    let idREC = null;
    vk.trees.forEach((tr, ti) => {
      S.raw([MARKER, 'TOALTSTACK'], 0);
      S.push(tr.shift, 'pS'); S.push(1 << tr.depth, 'pK'); S.push(4 + ti * h, 'pO');
      S.push(0, 'rbc');
      const [src, off] = rootSrc[ti];
      S.pick(src, 'root'); S.raw([...(off ? [off, 'SPLIT', 'NIP'] : []), h, 'SPLIT', 'DROP'], 0);
      S.push(0, 'acc'); S.push(Q, 'cnt');
      if (idREC === null) {
        const m = S.clone();
        // the current group; when used up, the next push comes from the bottom of the stack, and only after a whole
        // number of RG records (each push holds exactly RG records, the last one Q mod RG: no repacking)
        { const dc = m.depth('cnt'); m.roll('rbc'); m.raw(['SIZE', 'NOT', 'IF', 'DROP', dc, 'PICK', RG, 'MOD', Q % RG, 'NUMEQUALVERIFY', 'DEPTH', '1SUB', 'ROLL', 'ENDIF'], 1, ['rb']); }
        m.raw([1, 'SPLIT', 'SWAP', 'BIN2NUM'], 1, ['rb', 'sg']);
        // sigma < Q (else the shift below and the pick would misbehave)
        m.pick('sg'); m.raw([0, Q, 'WITHIN', 'VERIFY'], 1);
        m.push(1); m.pick('sg'); m.raw(['LSHIFTNUM'], 2, ['pw']); m.roll('acc'); m.raw(['ADD'], 2, ['acc']);
        { m.roll('sg'); const dl = m.depth('K' + (Q - 1)) - 1 + Q - 1; m.raw([dl, 'SWAP', 'SUB', 'PICK'], 1, ['Kc']); }
        m.raw([4, 'SPLIT'], 1, ['ix', 'Kc']);
        m.pick('pO'); m.raw([4, 'SUB', 'SPLIT', 'NIP', h, 'SPLIT', 'DROP'], 2, ['cur']);
        m.roll('ix'); m.raw(['BIN2NUM'], 1, ['ix']); m.pick('pS'); m.raw(['RSHIFTNUM'], 2, ['ix']); m.pick('pK'); m.raw(['ADD'], 2, ['k']);
        m.arrange([...m.st.filter((x) => !['root', 'acc', 'k', 'cur', 'rb'].includes(x)), 'root', 'acc', 'k', 'cur', 'rb']);
        m.raw(['BEGIN', 1, 'SPLIT', 'SWAP', 'DUP', 10, 'LESSTHAN', 'VERIFY', 'INVOKE', 'UNTIL'], 3, ['rbc']);
        m.arrange(S.st);
        idREC = defFn('REC', m.bytes());
      }
      S.raw(['BEGIN', idREC, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
      S.st.splice(0, nRec);
      S.roll('acc'); S.raw([(1n << BigInt(Q)) - 1n, 'NUMEQUALVERIFY'], 1);
      S.roll('rbc'); S.raw([0, 'EQUALVERIFY'], 1);
      S.raw(['FROMALTSTACK', MARKER, 'EQUALVERIFY'], 0);
      S.drop('root'); S.drop('pO'); S.drop('pK'); S.drop('pS');
      S.emit('DEPTH', S.st.length, 'NUMEQUALVERIFY');
    });
  }
  mark(S, 'merkle');
  // ---------------- phase 6: cleanup ----------------
  if (S.st.some((x) => /^(R\d|L\d|idx)/.test(x))) throw new Error('unconsumed witness items ' + S.st.filter((x) => /^(R\d|L\d|idx)/.test(x)));
  S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length);
  S.push(1);
  mark(S, 'end');
  return {main: S.bytes(), fns, init, marks, airSteps, GG, GH};

}
const md0 = (x) => ((BigInt(x) % P) + P) % P;

export function redeemOf(built) {
  const pro = [];
  for (const [, f] of built.fns) pro.push(...asm(f.body, f.id, 'DEFINE'));
  return Uint8Array.from([...pro, ...built.main]);
}
