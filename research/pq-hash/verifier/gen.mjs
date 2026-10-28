// Code generator for the pq-hash STARK verifier on CashVM (BCH 2026: OP_DEFINE/OP_INVOKE, loops, shift opcodes).
//
// buildB(prm, statement, opts) returns the layout (b) program: functions defined with OP_DEFINE plus a main program,
// and the symbolic stack names expected at entry (unlocking push order, bottom first). The code is written for size:
// the field and STARK steps are shared functions (MULE, SQE, MULF, MM, PAIR, NA, DEEPPT, GRP, HORN, ...) called from
// straight-line programs (lib/slp.mjs), and uniform repetitions are loops.
//
// Layout (b) unlocking (bottom -> top):
//   R<t>_<i>  record blobs, tree by tree, records in sorted leaf order (sigma ‖ Merkle program)
//   L<q>      leaf blobs in query order: trace ‖ comp ‖ fri1 ‖ ... ‖ T_q (8 B hint)
//   ST rT rC OOD rF1.. FIN NONCE   the public transcript
// Phases: (1) transcript, grinding, indices, AIR at z, per-proof constants; (2) Merkle authentication of all trees
// (LIFO programs, parked nodes on the altstack); (3) final polynomial unpack, then one query function call per query
// (DEEP, folds, final polynomial check). Unlocking data is consumed from the bottom of the stack (DEPTH 1SUB ROLL), so
// every other item keeps a fixed depth at each program point; items a function reads at fixed depth sit above the
// index list, which shrinks by one per query.
import {asm, fresh, Stk} from './lib/asm.mjs';
import {compileSlp, V, K, chk, call, add, sub, mul, modp, sum, ex} from './lib/slp.mjs';
import {P, powp, invp, rou, sha, leNum} from './field.mjs';
import {OPS} from './model.mjs';

const B0 = Uint8Array.of(0);
const R = (x) => modp(x, P);
const names = (b, e) => Array.from({length: e}, (_, i) => b + i);

// ---- extension-field expressions (lazy; one OP_MOD per output coefficient) ----
export function mulE(e, A, B) {
  A = A.map(ex); B = B.map(ex);
  if (e === 3) return [
    add(mul(A[0], B[0]), mul(add(mul(A[1], B[2]), mul(A[2], B[1])), K(7))),
    add(add(mul(A[0], B[1]), mul(A[1], B[0])), mul(mul(A[2], B[2]), K(7))),
    add(add(mul(A[0], B[2]), mul(A[2], B[0])), mul(A[1], B[1]))];
  return [add(mul(A[0], B[0]), mul(mul(A[1], B[1]), K(7))), add(mul(A[0], B[1]), mul(A[1], B[0]))];
}
export function sqE(e, A) {
  A = A.map(ex);
  if (e === 3) return [
    add(mul(A[0], A[0]), mul(mul(A[1], A[2]), K(14))),
    add(mul(mul(A[0], A[1]), K(2)), mul(mul(A[2], A[2]), K(7))),
    add(mul(mul(A[0], A[2]), K(2)), mul(A[1], A[1]))];
  return [add(mul(A[0], A[0]), mul(mul(A[1], A[1]), K(7))), mul(mul(A[0], A[1]), K(2))];
}

// program builder; with `fn` (function ids) the products are calls to the shared functions
export class PB {
  constructor(e, fn) { this.e = e; this.fn = fn; this.prog = []; }
  let(expr, name) { const nm = name ?? fresh('v'); this.prog.push([nm, expr]); return nm; }
  red(expr, name) { return this.let(R(expr), name); }
  chk(expr) { this.prog.push([null, expr]); }
  call(id, args, nout, out) { const outs = out ?? Array.from({length: nout}, () => fresh('f')); this.prog.push([outs, call(id, args.map(ex))]); return outs; }
  mul(A, B, out) { return this.fn ? this.call(this.fn.MULE, [...A, ...B], this.e, out) : mulE(this.e, A, B).map((x, i) => this.red(x, out?.[i])); }
  sq(A, out) { return this.fn ? this.call(this.fn.SQE, A, this.e, out) : sqE(this.e, A).map((x, i) => this.red(x, out?.[i])); }
  mulF(A, s, out) { return this.fn ? this.call(this.fn.MULF, [...A, s], this.e, out) : A.map((a, i) => this.red(mul(ex(a), ex(s)), out?.[i])); }
  mm(a, b) { return this.fn ? this.call(this.fn.MM, [a, b], 1)[0] : this.red(mul(ex(a), ex(b))); }
  add(A, B, out) { return this.fn?.ADDE ? this.call(this.fn.ADDE, [...A, ...B], this.e, out) : A.map((a, i) => this.red(add(ex(a), ex(B[i])), out?.[i])); }
  // A - B for B < 2^64 (raw or canonical): + 2p keeps the dividend positive
  sub(A, B, out) { return this.fn?.SUBE ? this.call(this.fn.SUBE, [...A, ...B], this.e, out) : A.map((a, i) => this.red(add(sub(ex(a), ex(B[i])), K(2n * P)), out?.[i])); }
  subBase0(A, c) { return [this.fn?.ADDC ? this.call(this.fn.ADDC, [A[0], K(2n * P - BigInt(c))], 1)[0] : this.red(add(sub(ex(A[0]), ex(c)), K(2n * P))), ...A.slice(1)]; }
  pow2k(x, k) { for (let i = 0; i < k; i++) x = this.mm(x, x); return x; }
}

// compile a local function: args (bottom first) -> outs (bottom first)
function localFn(args, build) {
  const s = new Stk(args);
  const outs = build(s);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length || s.st.length !== outs.length) throw new Error('local function leaves ' + (extra.join(',') || s.st.join(',')));
  s.arrange(outs);
  return s.bytes();
}
// compile a program in sections (for size accounting): names used by later sections are kept until then
function compileSections(stk, prog, cuts, keep, after) {
  const bounds = [0, ...cuts, prog.length];
  const refs = (e, acc) => { if (e.t === 'v') acc.add(e.n); else if (e.args) e.args.forEach((x) => refs(x, acc)); return acc; };
  for (let k = 0; k + 1 < bounds.length; k++) {
    const later = new Set();
    for (const [, e] of prog.slice(bounds[k + 1])) refs(e, later);
    compileSlp(stk, prog.slice(bounds[k], bounds[k + 1]), {keep: [...keep, ...later]});
    after?.(k);
  }
}
const slpFn = (args, prog, outs) => localFn(args, (s) => { compileSlp(s, prog, {keep: outs}); return outs; });

// shared generator context: parameters, function registry (ids from 16; Merkle ops use 1..9), size marks
export function makeCtx(prm, opts = {}) {
  const {e, s, h, r, a, D, sizes, trees} = prm;
  const e8 = 8 * e;
  const G = Math.min(opts.group ?? 32, D);
  const SLOT = 136;                       // packed slot width: sums of 32 products of 64-bit values are < 2^133
  const fns = new Map();
  let nextId = 16;
  const defFn = (name, body, id) => { id ??= nextId++; fns.set(name, {id, body: Uint8Array.from(body)}); return id; };
  const sizes_ = [];
  const mark = (stk, label) => { sizes_.push([label, stk.code.length]); if (opts.markers) stk.emit('NOP'); };
  const trunc = h < 32 ? [h, 'SPLIT', 'DROP'] : [];
  const F = {};

  const gam = (j) => names(`ga${j}_`, e);
  const dzOut = e === 3 ? ['m0', 'z1', 'z2', 'K0', 'K1', 'K2', 'cA', 'cB'] : ['m0', 'z1', 'cN'];
  return {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, sizes_, mark, trunc, F, gam, dzOut};
}

export function defineShared(c) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  // ---------------- shared functions ----------------
  F.MM = defFn('MM', asm('MUL', P, 'MOD'));
  { const b = new PB(e); mulE(e, names('a', e), names('b', e)).forEach((x, i) => b.red(x, 'c' + i)); F.MULE = defFn('MULE', slpFn([...names('a', e), ...names('b', e)], b.prog, names('c', e))); }
  { const b = new PB(e); sqE(e, names('a', e)).forEach((x, i) => b.red(x, 'c' + i)); F.SQE = defFn('SQE', slpFn(names('a', e), b.prog, names('c', e))); }
  { const b = new PB(e); names('a', e).forEach((x, i) => b.red(mul(V(x), V('s')), 'c' + i)); F.MULF = defFn('MULF', slpFn([...names('a', e), 's'], b.prog, names('c', e))); }
  { const b = new PB(e); names('a', e).forEach((x, i) => b.red(add(V(x), V('b' + i)), 'c' + i)); F.ADDE = defFn('ADDE', slpFn([...names('a', e), ...names('b', e)], b.prog, names('c', e))); }
  { const b = new PB(e); names('a', e).forEach((x, i) => b.red(add(sub(V(x), V('b' + i)), K(2n * P)), 'c' + i)); F.SUBE = defFn('SUBE', slpFn([...names('a', e), ...names('b', e)], b.prog, names('c', e))); }
  F.ADDC = defFn('ADDC', asm('ADD', P, 'MOD'));
  { const b = new PB(e, F); const m = b.mul(names('a', e), names('z', e)); b.red(add(V(m[0]), V('k')), 'c0'); m.slice(1).forEach((x, i) => b.let(V(x), 'c' + (i + 1)));
    F.HSTEP = defFn('HSTEP', slpFn([...names('a', e), ...names('z', e), 'k'], b.prog, names('c', e))); }
  const Ecode = e === 3
    ? [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD']
    : [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD'];
  F.E = defFn('E', asm(Ecode));
  // PAIR: u + v + g (u - v) for u, v < 2^64, g canonical
  {
    const b = new PB(e, F);
    const d = Array.from({length: e}, (_, c) => b.let(add(sub(V('u' + c), V('v' + c)), K(2n * P))));
    const gd = b.mul(names('g', e), d);
    for (let c = 0; c < e; c++) b.red(add(add(V('u' + c), V('v' + c)), V(gd[c])), 'o' + c);
    F.PAIR = defFn('PAIR', slpFn([...names('g', e), ...names('u', e), ...names('v', e)], b.prog, names('o', e)));
  }
  // NA: norm and adjugate of (x - zz) for base-field x, from the per-proof constants of zz
  const naArgs = e === 3 ? ['x', 'm0', 'z1', 'z2', 'K0', 'K1', 'K2', 'cA', 'cB'] : ['x', 'm0', 'cN'];
  {
    const b = new PB(e);
    b.let(add(V('x'), V('m0')), 'w');
    if (e === 3) {
      b.let(mul(V('w'), V('w')), 'w2');
      b.red(add(mul(V('w'), add(V('w2'), V('cA'))), V('cB')), 'N');
      b.red(add(V('w2'), V('K0')), 'a0'); b.red(add(mul(V('w'), V('z1')), V('K1')), 'a1'); b.red(add(mul(V('w'), V('z2')), V('K2')), 'a2');
      F.NA = defFn('NA', slpFn(naArgs, b.prog, ['N', 'a0', 'a1', 'a2']));
    } else {
      b.red(add(mul(V('w'), V('w')), V('cN')), 'N'); b.red(V('w'), 'a0');
      F.NA = defFn('NA', slpFn(naArgs, b.prog, ['N', 'a0']));
    }
  }
  // DEEPPT: f0(x) = n * a1 n1 + m * a2 n2, n = g1 X + g2 Y + g4 H0 + g5 H1 - C1, m = g3 X - C2
  const deepArgs = ['X', 'Y', ...names('H', e), ...names('J', e), ...names('a', e), 'n1', ...names('b', e), 'n2',
    ...[1, 2, 3, 4, 5].flatMap((j) => names(`g${j}_`, e)), ...names('C', e), ...names('D', e)];
  {
    const b = new PB(e, F);
    const i1 = b.mulF(names('a', e), 'n1'), i2 = b.mulF(names('b', e), 'n2');
    const p4 = b.mul(names('g4_', e), names('H', e)), p5 = b.mul(names('g5_', e), names('J', e));
    const nn = Array.from({length: e}, (_, c) => b.red(sum(mul(V('g1_' + c), V('X')), mul(V('g2_' + c), V('Y')), V(p4[c]), V(p5[c]), sub(K(P), V('C' + c)))));
    const mm = Array.from({length: e}, (_, c) => b.red(add(mul(V('g3_' + c), V('X')), sub(K(P), V('D' + c)))));
    const t1 = b.mul(nn, i1), t2 = b.mul(mm, i2);
    b.add(t1, t2, names('f', e));
    F.DEEPPT = defFn('DEEPPT', slpFn(deepArgs, b.prog, names('f', e)));
  }
  // HORN: acc' = acc * YG + unpack(P) (P packs e slots of SLOT bits)
  F.HORN = defFn('HORN', localFn([...names('a', e), 'P', 'Y'], (st) => {
    st.roll('P');
    for (let c = 0; c < e - 1; c++) st.raw(['DUP', 1, SLOT, 'LSHIFTNUM', 'MOD', 'SWAP', SLOT, 'RSHIFTNUM'], 1, ['u' + c, 'P']);
    st.rename('P', 'u' + (e - 1));
    const b = new PB(e);
    for (let c = 0; c < e; c++) b.red(add(mul(V('a' + c), V('Y')), V('u' + c)), 'o' + c);
    compileSlp(st, b.prog);
    return names('o', e);
  }));
  // POWS: y -> y^1 .. y^G (loop, counter on the altstack)
  F.POWS = defFn('POWS', asm('DUP', G - 1, 'TOALTSTACK', 'BEGIN', 'DUP', 2, 'PICK', 'MUL', P, 'MOD', 'SWAP', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP', 'DROP'));
  // XPOW: v -> 7 * w_N^v (square and multiply over the bits of v)
  F.XPOW = defFn('XPOW', asm(7, rou(sizes[0]), 'ROT', 'BEGIN', 'DUP', 2, 'MOD', 'IF', 'ROT', 2, 'PICK', 'MUL', P, 'MOD', 'ROT', 'ROT', 'ENDIF',
    1, 'RSHIFTNUM', 'SWAP', 'DUP', 'MUL', P, 'MOD', 'SWAP', 'DUP', 'NOT', 'UNTIL', '2DROP'));
  // PARSE8: a 64-byte chunk -> 8 values (8-byte LE, unsigned; first value deepest)
  F.PARSE8 = defFn('PARSE8', asm(Array.from({length: 7}, () => [8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP']), B0, 'CAT', 'BIN2NUM'));

  // DZ(z, w): constants for the norm/adjugate of (x - w z), x in F_p: m0 = p - zc0, and (e = 3) z1, z2, K0 = -7 z1 z2,
  // K1 = 7 z2^2, K2 = z1^2, cA = -21 z1 z2, cB = -(49 z2^3 + 7 z1^3); (e = 2) z1, cN = -7 z1^2  (zc = w z)
  {
    const b = new PB(e);
    const zc = names('y', e).map((x) => b.red(mul(V(x), V('w'))));
    b.red(sub(K(P), V(zc[0])), 'm0');
    if (e === 3) {
      b.let(V(zc[1]), 'z1'); b.let(V(zc[2]), 'z2');
      b.red(mul(mul(V('z1'), V('z2')), K(P - 7n)), 'K0');
      b.red(mul(mul(V('z2'), V('z2')), K(7)), 'K1');
      b.red(mul(V('z1'), V('z1')), 'K2');
      b.red(mul(mul(V('z1'), V('z2')), K(P - 21n)), 'cA');
      b.red(add(mul(mul(mul(V('z2'), V('z2')), V('z2')), K(49)), mul(mul(mul(V('z1'), V('z1')), V('z1')), K(7))), 'q');
      b.red(sub(K(P), V('q')), 'cB');
    } else {
      b.let(V(zc[1]), 'z1');
      b.red(mul(mul(V('z1'), V('z1')), K(P - 7n)), 'cN');
    }
    F.DZ = defFn('DZ', slpFn([...names('y', e), 'w'], b.prog, dzOut));
  }
  // FOLD<a>: binary fold of a coset of a values with x0^-1 = X and beta^(2^l) (l < log2 a): pairs (j, j + half),
  // g = beta^(2^l) x_j^-1; returns the unscaled fold (a times the folded value)
  const foldArgs = (ai) => [...Array.from({length: ai}, (_, j) => names(`v${j}_`, e)).flat(), ...Array.from({length: Math.log2(ai)}, (_, l) => names(`b${l}_`, e)).flat(), 'X'];
  // recursive: FOLD<a> = the a/2 level-0 pair steps, then FOLD<a/2> on the results with X^2 and beta^2.. (FOLD2 = one pair)
  const arSet = new Set(); for (const ai of a) for (let x = ai; x >= 2; x >>= 1) arSet.add(x);
  for (const ai of [...arSet].sort((x, y) => x - y)) {
    const b = new PB(e, F);
    const wai = invp(rou(ai)), half = ai / 2;
    const nxt = [];
    for (let j = 0; j < half; j++) {
      const xj = j === 0 ? 'X' : b.mm('X', K(powp(wai, BigInt(j))));
      const g = b.mulF(names('b0_', e), xj);
      nxt.push(b.call(F.PAIR, [...g, ...names(`v${j}_`, e), ...names(`v${j + half}_`, e)], e, ai === 2 ? names('o', e) : undefined));
    }
    if (ai > 2) { const X2 = b.mm('X', 'X'); b.call(F['FOLD' + half], [...nxt.flat(), ...Array.from({length: Math.log2(ai) - 1}, (_, l) => names(`b${l + 1}_`, e)).flat(), X2], e, names('o', e)); }
    F['FOLD' + ai] = defFn('FOLD' + ai, slpFn(foldArgs(ai), b.prog, names('o', e)));
  }

  // Merkle op functions (ids 1..9: the op bytes of the record programs)
  const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256', ...trunc];
  const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
  defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4);
  defFn('F8', asm(OPS.F4, 'INVOKE', 'DROP', OPS.F4, 'INVOKE'), OPS.F8);
  defFn('F16', asm(OPS.F8, 'INVOKE', 'DROP', OPS.F8, 'INVOKE'), OPS.F16);
  {
    const m = new Stk(['k', 'cur', 'rb']);
    m.raw(['FROMALTSTACK', 'FROMALTSTACK'], 0, ['pk', 'pd']);
    m.pick('k'); m.raw([1, 'RSHIFTNUM'], 1, ['kh']);
    const b = new PB(e);
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
}

// Fiat-Shamir transcript from the PT items rT rC OOD rF.. FIN NONCE (names on S); keeps the roots, FIN and a copy of
// OOD (OODc); leaves alpha, z, gamma, beta and the indices idx_lo..idx_{hi-1}
export function emitTranscript(c, S, statement, {grinding = true, lo = 0, hi = c.s} = {}) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  const rF = Array.from({length: r - 1}, (_, i) => 'rF' + (i + 1));
  // ---------------- phase 1: transcript ----------------
  const t0 = sha(prm.TAG, statement);
  const absorb = (prev, item, keepItem, len) => {
    if (keepItem) S.pick(item); else S.roll(item);
    S.raw(['SIZE', len, 'NUMEQUALVERIFY'], 0);
    if (prev instanceof Uint8Array) S.raw([prev, 'SWAP', 'CAT', 'SHA256'], 1, [fresh('t')]);
    else { S.roll(prev); S.raw(['SWAP', 'CAT', 'SHA256'], 2, [fresh('t')]); }
    return S.top();
  };
  const challenge = (t, tag, out) => { S.pick(t); S.raw([tag, 'CAT', 'SHA256', F.E, 'INVOKE'], 1, names(out, e)); };
  let t = absorb(t0, 'rT', true, h);
  [1, 2, 3, 4].forEach((j) => challenge(t, Uint8Array.of(0x61, j), `al${j}_`));
  t = absorb(t, 'rC', true, h);
  challenge(t, Uint8Array.of(0x7a), 'z');
  if (e === 3) { S.pick('z1'); S.pick('z2'); S.raw(['BOOLOR', 'VERIFY'], 2); } else { S.pick('z1'); S.raw(['VERIFY'], 1); }
  S.pick('OOD'); S.rename(S.top(), 'OODc');
  t = absorb(t, 'OOD', false, 5 * e8);
  [1, 2, 3, 4, 5].forEach((j) => challenge(t, Uint8Array.of(0x67, j), `ga${j}_`));
  challenge(t, Uint8Array.of(0x62), 'be0_');
  for (let i = 1; i < r; i++) { t = absorb(t, rF[i - 1], true, h); challenge(t, Uint8Array.of(0x62), `be${i}_`); }
  t = absorb(t, 'FIN', true, e8 * D);
  t = absorb(t, 'NONCE', false, 8);
  S.rename(t, 'G');
  if (grinding) {
    const mask = ((1n << BigInt(prm.g)) - 1n) << BigInt(32 - prm.g);
    const mb = Uint8Array.of(Number(mask >> 24n) & 255, Number(mask >> 16n) & 255, Number(mask >> 8n) & 255, Number(mask) & 255);
    S.pick('G'); S.raw([4, 'SPLIT', 'DROP', mb, 'AND', new Uint8Array(4), 'EQUALVERIFY'], 1);
  }
  // indices idx_q = LE(SHA256(G ‖ u16 q)[0:3]) mod N_1, q = hi-1 .. lo (idx_lo ends on top of the list)
  const N1 = sizes[1];
  if (N1 > 1 << 24) throw new Error('N1 too large for a 3-byte index');
  S.roll('G');
  if (hi > lo) S.raw([hi - 1, 'BEGIN', '2DUP', 2, 'NUM2BIN', 'CAT', 'SHA256', 3, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', N1, 'MOD', 'ROT', 'ROT',
    '1SUB', 'DUP', lo, 'LESSTHAN', 'UNTIL', '2DROP'], 1, Array.from({length: hi - lo}, (_, k) => 'idx' + (hi - 1 - k)));
  else S.drop('G');
  mark(S, 'transcript');

}

// AIR identity at z (withAir) and the per-proof constants the queries use (gamma, dC1, dC2, dz*, bp*)
export function emitAirConsts(c, S, statement, {withAir = true, withConsts = true} = {}) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  // ---------------- phase 1: AIR identity at z, per-proof constants ----------------
  {
    S.roll('OODc');
    const ood = ['oX', 'oY', 'oW', 'oA', 'oB'].flatMap((x) => names(x, e));
    { const nfull = Math.floor(ood.length / 8), rest = ood.length - 8 * nfull;
      S.raw([...Array.from({length: nfull}, () => [64, 'SPLIT', 'SWAP', F.PARSE8, 'INVOKE', 8, 'ROLL']),
        ...Array.from({length: rest - 1}, () => [8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP']), B0, 'CAT', 'BIN2NUM'], 1, ood); }
    const b = new PB(e, F);
    const [X, Y, W, A, Bv] = ['oX', 'oY', 'oW', 'oA', 'oB'].map((x) => names(x, e));   // raw (< 2^64): every consumer accepts raw inputs
    const cut0 = b.prog.length;
    const n = BigInt(prm.n), wl = powp(prm.wn, n - 1n);
    let zz = names('z', e);
    for (let i = 0; i < 13; i++) zz = b.sq(zz);
    const zp = zz; for (let i = 0; i < 3; i++) zz = b.sq(zz); const zn = zz;
    // c(z) = Pc(zp): Horner with base coefficients
    let cz = [K(prm.Pc[7]), ...Array(e - 1).fill(K(0))];
    for (let k = 6; k >= 0; k--) cz = b.call(F.HSTEP, [...cz, ...zp, K(prm.Pc[k])], e);
    const sv = b.add(cz, X);
    const C1 = b.sub(Y, b.mul(b.sq(sv), sv));
    const C2 = b.sub(W, b.mul(b.sq(Y), sv));
    const zm = b.subBase0(names('z', e), wl), z1 = b.subBase0(names('z', e), 1n), zn1 = b.subBase0(zn, 1n);
    const lhs = b.mul(b.mul(b.mul(b.add(b.mul(zn, Bv), A), zn1), z1), zm);
    const xx = b.subBase0(X, leNum(statement.subarray(0, 8))), xy = b.subBase0(X, leNum(statement.subarray(8, 16)));
    const q1 = b.mul(b.add(b.mul(names('al1_', e), C1), b.mul(names('al2_', e), C2)), b.mul(b.sq(zm), z1));
    const q2 = b.mul(b.mul(names('al3_', e), xx), b.mul(zn1, zm));
    const q3 = b.mul(b.mul(names('al4_', e), xy), b.mul(zn1, z1));
    const rhs = b.add(b.add(q1, q2), q3);
    if (withAir) lhs.forEach((x, i) => b.chk(chk('NUMEQUALVERIFY', V(x), V(rhs[i]))));
    else b.prog.length = cut0;
    const cut1 = b.prog.length;
    // DEEP constants at z: C1 = g1 X + g2 Y + g4 H0 + g5 H1, C2 = g3 X(wz)
    const p1 = b.mul(gam(1), X), p2 = b.mul(gam(2), Y), p4 = b.mul(gam(4), A), p5 = b.mul(gam(5), Bv);
    b.add(b.add(p1, p2), b.add(p4, p5), names('dC1_', e));
    b.mul(gam(3), W, names('dC2_', e));
    const cut2 = b.prog.length;
    // norm/adjugate constants of (x - z) and (x - wz) for base-field x (function DZ, scale 1 and w_n)
    for (const [zi, w] of [[0, 1n], [1, prm.wn]]) b.call(F.DZ, [...names('z', e), w], dzOut.length, dzOut.map((x) => `dz${zi}_` + x));
    const cut3 = b.prog.length;
    // beta powers bp<i>_<l>_<c> = beta_i^(2^l)
    for (let i = 0; i < r; i++) {
      let bp = names(`be${i}_`, e);
      for (let l = 0; (1 << l) < a[i]; l++) {
        if (l > 0) bp = b.sq(bp, names(`bp${i}_${l}_`, e));
        else { bp.forEach((x, c) => b.let(V(x), `bp${i}_${l}_${c}`)); bp = names(`bp${i}_0_`, e); }
      }
    }
    const keepAll = [...[1, 2, 3, 4, 5].flatMap(gam), ...b.prog.flatMap(([n]) => (Array.isArray(n) ? n : [n])).filter((n) => typeof n === 'string' && n.startsWith('bp'))];
    compileSections(S, b.prog, [cut1, cut2, cut3], keepAll, (k) => mark(S, 'air-' + k));
    for (const x of [...S.st]) if (/^(al\d_\d|z\d|be\d_\d|o[XYWAB]\d)$/.test(x)) S.drop(x);
    if (!withConsts) for (const x of [...S.st]) if (/^(ga\d_\d|dC\d_\d|dz\d_|bp\d)/.test(x)) S.drop(x);
  }
}

// lift what the query function reads above the index list, then the runtime-indexed w_a tables
export function emitLiftTables(c, S, bottomIdx, keepBelow) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  // everything the query function reads must sit above the index list
  { const lo = S.st.indexOf(bottomIdx); for (const x of S.st.slice(0, lo)) if (!keepBelow.test(x)) S.roll(x); }
  // runtime-indexed tables per distinct arity a_i (i >= 1): Wp<a>_<j> = w_a^j, Wn<a>_<j> = w_a^-j (loops)
  const arities = [...new Set(a.slice(1))];
  for (const ai of arities) {
    for (const [nm, w] of [['Wp', rou(ai)], ['Wn', invp(rou(ai))]]) {
      S.raw([1, ai - 1, 'BEGIN', 'OVER', w, 'MUL', P, 'MOD', 'SWAP', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0, Array.from({length: ai}, (_, j) => `${nm}${ai}_${j}`));
    }
  }

}

// final polynomial: FIN -> packed coefficients C0..C{D-1} (C0 deepest)
export function emitUnpack(c, S) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  {
    const Z9 = new Uint8Array(9);
    const pack = e === 3
      ? [8, 'SPLIT', 8, 'SPLIT', B0, 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'BIN2NUM']
      : [8, 'SPLIT', B0, 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'BIN2NUM'];
    const CH = Math.min(16, D);
    const idU1 = defFn('UNP1', asm(e8, 'SPLIT', 'SWAP', pack, 'SWAP'));
    const idU = defFn('UNP', asm(Array.from({length: CH - 1}, () => [idU1, 'INVOKE']), pack));
    S.roll('FIN');
    const nch = D / CH;
    S.raw([Array.from({length: nch - 1}, () => [CH * e8, 'SPLIT'])], 1, Array.from({length: nch}, (_, c) => 'fch' + c));
    for (let c = 0; c < nch; c++) { S.roll('fch' + c); S.raw([idU, 'INVOKE'], 1, Array.from({length: CH}, (_, i) => 'C' + (c * CH + i))); }
  }

}

// one query, from its leaf blob 'L' (leaves ‖ T) and index 'idx' on Q: DEEP, folds, final polynomial (all checks)
export function emitQuery(c, Q) {
  const {prm, opts, e, s, h, r, a, D, sizes, trees, e8, G, SLOT, fns, defFn, mark, trunc, F, gam, dzOut} = c;
  void prm; void opts; void s; void h; void r; void D; void trees; void e8; void G; void SLOT; void fns; void mark; void trunc; void gam; void dzOut; void sizes;
  const k0 = a[0];
  Q.pick('idx'); Q.raw([F.XPOW, 'INVOKE'], 1, ['x0']);
  for (let i = 1; i < r; i++) { Q.pick('idx'); Q.raw([...(i > 1 ? [sizes[i], 'MOD'] : []), Math.log2(sizes[i + 1]), 'RSHIFTNUM'], 1, ['sl' + i]); }
  Q.drop('idx');
  mark(Q, 'q-entry');
  // parse: L = 64-byte chunks ‖ T (8 B)
  const nch = prm.leafBytes / 64;
  if (!Number.isInteger(nch)) throw new Error('leaf bytes not a multiple of 64');
  Q.roll('L');
  Q.raw([prm.leafBytes, 'SPLIT', B0, 'CAT', 'BIN2NUM', 'SWAP', Array.from({length: nch - 1}, () => [64, 'SPLIT'])], 1, ['T', ...Array.from({length: nch}, (_, c) => 'ch' + c)]);
  const vals = [];
  for (let j = 0; j < k0; j++) vals.push('tX' + j, 'tY' + j);
  for (let j = 0; j < k0; j++) vals.push(...names(`cA${j}_`, e), ...names(`cB${j}_`, e));
  for (let i = 1; i < r; i++) for (let j = 0; j < a[i]; j++) vals.push(...names(`v${i}_${j}_`, e));
  const chOrder = [];
  { let c = (16 * k0 + 2 * e8 * k0) / 64; const lay = [];
    for (let i = 1; i < r; i++) { const n = a[i] * e8 / 64; lay.push(Array.from({length: n}, (_, x) => c + x)); c += n; }
    for (let x = 0; x < (16 * k0 + 2 * e8 * k0) / 64; x++) chOrder.push(x);
    for (let i = r - 2; i >= 0; i--) chOrder.push(...lay[i]); }
  for (const c of chOrder) { Q.roll('ch' + c); Q.raw([F.PARSE8, 'INVOKE'], 1, vals.slice(8 * c, 8 * c + 8)); }
  mark(Q, 'q-parse');
  // DEEP: norms/adjugates, one Montgomery batch with the hinted inverse T, then f0 at the k0 coset points
  const b = new PB(e, F);
  const w0 = rou(k0);
  const xs = Array.from({length: k0}, (_, j) => (j === 0 ? 'x0' : b.mm('x0', K(powp(w0, j)))));
  const dz = (zi) => (e === 3 ? ['m0', 'z1', 'z2', 'K0', 'K1', 'K2', 'cA', 'cB'] : ['m0', 'cN']).map((x) => `dz${zi}_` + x);
  const na = xs.map((x) => [0, 1].map((zi) => { const o = b.call(F.NA, [x, ...dz(zi)], e === 3 ? 4 : 2); return {N: o[0], adj: e === 3 ? o.slice(1) : [o[1], `dz${zi}_z1`]}; }));
  const E = [...na.flatMap(([u, v]) => [u.N, v.N]), 'x0'];
  const pre = [E[0]];
  for (let m = 1; m < E.length; m++) pre.push(b.mm(pre[m - 1], E[m]));
  b.chk(chk('NUMEQUALVERIFY', V(b.mm(pre[E.length - 1], 'T')), K(1)));
  const inv = new Array(E.length);
  let Tm = 'T';
  for (let m = E.length - 1; m >= 1; m--) { inv[m] = b.mm(Tm, pre[m - 1]); Tm = b.mm(Tm, E[m]); }
  inv[0] = Tm;
  const x0inv = inv[E.length - 1];
  const consts = [...[1, 2, 3, 4, 5].flatMap(gam), ...names('dC1_', e), ...names('dC2_', e)];
  const f0 = xs.map((_, j) => b.call(F.DEEPPT, ['tX' + j, 'tY' + j, ...names(`cA${j}_`, e), ...names(`cB${j}_`, e),
    ...na[j][0].adj, inv[2 * j], ...na[j][1].adj, inv[2 * j + 1], ...consts], e));
  const foldB = (bb, i, cur, X) => bb.call(F['FOLD' + a[i]], [...cur.flat(), ...Array.from({length: Math.log2(a[i])}, (_, l) => names(`bp${i}_${l}_`, e)).flat(), X], e);
  let Fv = foldB(b, 0, f0, x0inv);
  const keepC = () => Q.st.filter((x) => /^(bp\d|ga|dC|dz)/.test(x));
  compileSlp(Q, b.prog, {keep: [...keepC(), 'x0', x0inv]});
  mark(Q, 'q-deep');
  // runtime pick: element `slot` of a list whose first element is `first` and stride `stride`
  const pickRT = (slot, first, stride, out) => {
    const d = Q.depth(first); Q.pick(slot);
    Q.raw([...(stride > 1 ? [stride, 'MUL'] : []), d, 'SWAP', 'SUB', 'PICK'], 1, [out]);
  };
  // layers i >= 1: LAYER<a_i> checks the previous fold against the leaf's slot value, updates the coset bases and folds.
  // Entry: [ .. v_i block (a_i e values) | F (e) xp xbp wp wn slot scale bp (log2 a_i e) ]; exit [ .. F' xinv xb ].
  // Fri leaves were parsed last layer first, so each layer's block is on top when its turn comes.
  let xinv = x0inv, xb = 'x0';
  for (let i = 1; i < r; i++) {
    const ai = a[i], L = Math.log2(ai);
    const bb = new PB(e, F);
    const xp = bb.pow2k(xinv, Math.log2(a[i - 1])), xbp = bb.pow2k(xb, Math.log2(a[i - 1]));
    compileSlp(Q, bb.prog, {keep: keepC()});
    pickRT('sl' + i, `Wp${ai}_0`, 1, 'wp' + i); pickRT('sl' + i, `Wn${ai}_0`, 1, 'wn' + i);
    if (!F['LAYER' + ai]) {
      const sl = new Stk([...Array.from({length: ai}, (_, j) => names(`v${j}_`, e)).flat(), ...names('F', e), 'xp', 'xbp', 'wp', 'wn', 'sl', 'sc', ...Array.from({length: L}, (_, l) => names(`b${l}_`, e)).flat()]);
      const sel = names('sel', e);
      sel.forEach((nm, c) => { const d = sl.depth(`v0_${c}`); sl.pick('sl'); sl.raw([...(e > 1 ? [e, 'MUL'] : []), d, 'SWAP', 'SUB', 'PICK'], 1, [nm]); });
      sl.drop('sl');
      const lb0 = new PB(e, F);
      lb0.call(F.MM, ['xbp', 'wn'], 1, ['xb']);
      compileSlp(sl, lb0.prog);
      sl.raw(['TOALTSTACK'], 1);
      const lb = new PB(e, F);
      sel.forEach((nm, c) => lb.chk(chk('NUMEQUALVERIFY', R(mul(V(nm), V('sc'))), V('F' + c))));
      lb.call(F.MM, ['xp', 'wp'], 1, ['xi']);
      compileSlp(sl, lb.prog);
      sl.raw(['DUP', 'TOALTSTACK'], 0);                  // keep a copy of x_i^-1 for the next layer
      const lb2 = new PB(e, F);
      lb2.call(F['FOLD' + ai], [...Array.from({length: ai}, (_, j) => names(`v${j}_`, e)).flat(), ...Array.from({length: L}, (_, l) => names(`b${l}_`, e)).flat(), 'xi'], e, names('o', e));
      compileSlp(sl, lb2.prog, {keep: names('o', e)});
      sl.raw(['FROMALTSTACK', 'FROMALTSTACK'], 0, ['xi', 'xb']);
      sl.arrange([...names('o', e), 'xi', 'xb']);
      F['LAYER' + ai] = defFn('LAYER' + ai, sl.bytes());
    }
    // arguments directly on top of the v_i block: everything above the block must be an argument
    const block = Array.from({length: ai}, (_, j) => names(`v${i}_${j}_`, e)).flat();
    const args = [...Fv, xp, xbp, 'wp' + i, 'wn' + i, 'sl' + i];
    const stray = Q.st.slice(Q.st.lastIndexOf(block[block.length - 1]) + 1).filter((x) => !args.includes(x));
    if (stray.length) throw new Error('items above the layer block: ' + stray.join(','));
    const lb = new PB(e, F);
    const out = lb.call(F['LAYER' + ai], [...args, K(a[i - 1]), ...Array.from({length: L}, (_, l) => names(`bp${i}_${l}_`, e)).flat()], e + 2);
    compileSlp(Q, lb.prog, {keep: keepC()});
    for (const x of block) Q.st.splice(Q.st.lastIndexOf(x), 1);   // consumed by the call (below its arguments)
    Fv = out.slice(0, e); xinv = out[e]; xb = out[e + 1];
  }
  Q.drop(xinv);   // the last layer's x^-1 is not needed
  mark(Q, 'q-layers');
  // final polynomial: y = xb^(a_{r-1}); y^1..y^G; per group a packed dot product (GRP), then Horner over groups
  {
    const bb = new PB(e, F);
    const y = bb.pow2k(xb, Math.log2(a[r - 1]));
    compileSlp(Q, bb.prog);
    Q.roll(y); Q.raw([F.POWS, 'INVOKE'], 1, Array.from({length: G}, (_, k) => 'Y' + (k + 1)));
    for (let c = 0; c < e; c++) Q.push(0, 'acc' + c);
    if (opts.dbgFinal) Q.emit('NOP');
    // GRP: entry = this shape + [o]; o = depth of the group's first coefficient (counted with o on the stack)
    const g = Q.clone();
    g.st.push('o');
    g.raw(['DUP', 'PICK'], 0, ['pacc']);
    for (let lo = 1; lo < G; lo++) {
      const dY = g.depth('Y' + lo) + 1; // + the coefficient pushed above
      g.raw(['OVER', ...(lo > 1 ? [lo - 1, 'SUB'] : []), 'PICK', dY, 'PICK', 'MUL', 'ADD'], 0);
    }
    g.raw(['NIP'], 0); g.st.splice(g.st.indexOf('o'), 1);
    const idG = defFn('GRP', g.bytes());
    const H = D / G;
    for (let hi = H - 1; hi >= 0; hi--) {
      const o = Q.depth('C' + hi * G) + 1;
      Q.raw([o, idG, 'INVOKE'], 0, ['Pk']);
      if (opts.dbgFinal) Q.emit('NOP');
      Q.pick('Y' + G);
      Q.raw([F.HORN, 'INVOKE'], e + 2, names('acc', e));
    }
    Q.raw([...Array(e).fill('TOALTSTACK'), ...Array(G >> 1).fill('2DROP'), ...(G & 1 ? ['DROP'] : []), ...Array(e).fill('FROMALTSTACK')], G + e, names('acc', e));
    const cb = new PB(e);
    names('acc', e).forEach((x, c) => cb.chk(chk('NUMEQUALVERIFY', R(mul(V(x), K(a[r - 1]))), V(Fv[c]))));
    compileSlp(Q, cb.prog);
  }
  mark(Q, 'q-final');
}

export function buildB(prm, statement, opts = {}) {
  const c = makeCtx(prm, opts);
  const {e, s, h, r, a, D, sizes, trees, G, SLOT, fns, defFn, sizes_, mark, trunc, F} = c;
  void e; void h; void a; void D; void F;
  defineShared(c);

  // ---------------- initial stack ----------------
  const init = [];
  const RG = opts.recGroup ?? 2;          // Merkle records per push (consecutive records of one tree)
  const nRec = Math.ceil(s / RG);
  trees.forEach((_, ti) => { for (let i = 0; i < nRec; i++) init.push(`R${ti}_${i}`); });
  for (let q = 0; q < s; q++) init.push(`L${q}`);
  const rF = Array.from({length: r - 1}, (_, i) => 'rF' + (i + 1));
  const pt = ['rT', 'rC', 'OOD', ...rF, 'FIN', 'NONCE'];   // the statement is baked into the code
  init.push(...pt);
  if (opts.padSlot) init.push('PAD');   // TXv5-as-written grading variant: a zero pad the script ignores
  const S = new Stk(init);
  S.emit('DEPTH', init.length, 'NUMEQUALVERIFY');
  if (opts.padSlot) S.drop('PAD');
  mark(S, 'entry');

  emitTranscript(c, S, statement);
  mark(S, 'transcript');

  emitAirConsts(c, S, statement);
  emitLiftTables(c, S, 'idx' + (s - 1), /^(R\d|L\d|FIN|rT|rC|rF\d)/);
  mark(S, 'air+consts');

  // ---------------- phase 2: Merkle (LIFO programs) ----------------
  const MARKER = Uint8Array.of(0x00, 0x80); // non-minimal number: can never pass as a parked index
  const roots = ['rT', 'rC', ...rF];
  // one record function for all trees; per-tree parameters (leaf-index modulus, 2^depth, leaf offset and length, tag)
  // sit below root/acc/cnt; roots are copied, so every tree sees the same stack shape
  let idREC = null;
  trees.forEach((tree, ti) => {
    S.raw([MARKER, 'TOALTSTACK'], 0);
    S.push(sizes[tree.layer + 1], 'pM'); S.push(1 << tree.depth, 'pK'); S.push(tree.off, 'pO'); S.push(tree.leaf_bytes, 'pN'); S.push(Uint8Array.of(tree.tag), 'pT');
    S.push(0, 'rbc'); S.pick(roots[ti], 'root'); S.push(0, 'acc'); S.push(s, 'cnt');
    if (idREC === null) {
      const m = S.clone();
      // the current group blob; when it is used up, the next one comes from the bottom of the stack
      m.roll('rbc'); m.raw(['SIZE', 'NOT', 'IF', 'DROP', 'DEPTH', '1SUB', 'ROLL', 'ENDIF'], 1, ['rb']);
      m.raw([1, 'SPLIT', 'SWAP', 'BIN2NUM'], 1, ['rb', 'sg']);
      m.push(1); m.pick('sg'); m.raw(['LSHIFTNUM'], 2, ['pw']); m.roll('acc'); m.raw(['ADD'], 2, ['acc']);
      { const d0 = m.depth('idx0'); m.pick('sg'); m.raw([d0, 'ADD', 'PICK'], 1, ['idx']); }
      m.pick('pM'); m.raw(['MOD'], 2, ['idx']); m.pick('pK'); m.raw(['ADD'], 2, ['k']);
      { m.roll('sg'); const dl = m.depth('L' + (s - 1)) - 1 + s - 1; m.raw([dl, 'SWAP', 'SUB', 'PICK'], 1, ['Lc']); }
      m.pick('pO'); m.raw(['SPLIT', 'NIP'], 2, ['Lc']); m.pick('pN'); m.raw(['SPLIT', 'DROP'], 2, ['Lc']);
      m.pick('pT'); m.raw(['SWAP', 'CAT', 'SHA256', ...trunc], 2, ['cur']);
      m.arrange([...m.st.filter((x) => !['root', 'acc', 'k', 'cur', 'rb'].includes(x)), 'root', 'acc', 'k', 'cur', 'rb']);
      m.raw(['BEGIN', 1, 'SPLIT', 'SWAP', 'DUP', 10, 'LESSTHAN', 'VERIFY', 'INVOKE', 'UNTIL'], 3, ['rbc']);
      m.arrange(S.st);
      idREC = defFn('REC', m.bytes());
    }
    S.raw(['BEGIN', idREC, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
    S.st.splice(0, nRec);
    S.roll('acc'); S.raw([(1n << BigInt(s)) - 1n, 'NUMEQUALVERIFY'], 1);
    S.roll('rbc'); S.raw([0, 'EQUALVERIFY'], 1);   // the tree's records are consumed exactly
    S.raw(['FROMALTSTACK', MARKER, 'EQUALVERIFY'], 0);
    S.raw(['2DROP', '2DROP', '2DROP'], 6);
  });
  for (const x of roots) S.drop(x);
  mark(S, 'merkle');

  // ---------------- phase 3: final polynomial unpack ----------------
  emitUnpack(c, S);
  mark(S, 'unpack');

  // ---------------- phase 3: the query function ----------------
  {
    S.push(s, 'qcnt');
    const Q = S.clone();
    Q.bottom(); Q.rename(Q.top(), 'L');
    Q.raw(['SIZE', prm.leafBytes + 8, 'NUMEQUALVERIFY'], 0);
    Q.roll('idx0'); Q.rename(Q.top(), 'idx');
    emitQuery(c, Q);
    const want = S.st.filter((x) => x !== 'idx0').slice(1);
    if (Q.st.length === want.length && Q.st.every((x) => want.includes(x))) Q.arrange(want);
    if (Q.st.join('|') !== want.join('|')) {
      const extra = Q.st.filter((x) => !want.includes(x)), missing = want.filter((x) => !Q.st.includes(x));
      throw new Error(`query function leaves extra [${extra}] missing [${missing}]`);
    }
    const id = defFn('Q', Q.bytes());
    S.raw(['BEGIN', id, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
    S.st.splice(0, s);
    for (let q = 0; q < s; q++) S.st.splice(S.st.indexOf('idx' + q), 1);
  }
  // ---------------- cleanup ----------------
  {
    if (S.st.some((x) => /^(R\d|L\d|idx)/.test(x))) throw new Error('unconsumed witness items');
    S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length);
    S.push(1);
  }
  mark(S, 'end');
  return {main: S.bytes(), fns, init, G, SLOT, codeSizes: sizes_};
}

export function redeemB(built) {
  const pro = [];
  for (const [, f] of built.fns) pro.push(...asm(f.body, f.id, 'DEFINE'));
  return Uint8Array.from([...pro, ...built.main]);
}
