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
  call(id, args, nout) { const outs = Array.from({length: nout}, () => fresh('f')); this.prog.push([outs, call(id, args.map(ex))]); return outs; }
  mul(A, B) { return this.fn ? this.call(this.fn.MULE, [...A, ...B], this.e) : mulE(this.e, A, B).map((x) => this.red(x)); }
  sq(A) { return this.fn ? this.call(this.fn.SQE, A, this.e) : sqE(this.e, A).map((x) => this.red(x)); }
  mulF(A, s) { return this.fn ? this.call(this.fn.MULF, [...A, s], this.e) : A.map((a) => this.red(mul(ex(a), ex(s)))); }
  mm(a, b) { return this.fn ? this.call(this.fn.MM, [a, b], 1)[0] : this.red(mul(ex(a), ex(b))); }
  add(A, B) { return A.map((a, i) => this.red(add(ex(a), ex(B[i])))); }
  // A - B for B < 2^64 (raw or canonical): + 2p keeps the dividend positive
  sub(A, B) { return A.map((a, i) => this.red(add(sub(ex(a), ex(B[i])), K(2n * P)))); }
  subBase0(A, c) { return [this.red(add(sub(ex(A[0]), ex(c)), K(2n * P))), ...A.slice(1)]; }
  pow2k(x, k) { for (let i = 0; i < k; i++) x = this.mm(x, x); return x; }
}

// compile a local function: args (bottom first) -> outs (bottom first)
function localFn(args, build) {
  const s = new Stk(args);
  const outs = build(s);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length) throw new Error('local function leaves ' + extra.join(','));
  s.arrange(outs);
  return s.bytes();
}
const slpFn = (args, prog, outs) => localFn(args, (s) => { compileSlp(s, prog); return outs; });

export function buildB(prm, statement, opts = {}) {
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

  // ---------------- shared functions ----------------
  F.MM = defFn('MM', asm('MUL', P, 'MOD'));
  { const b = new PB(e); mulE(e, names('a', e), names('b', e)).forEach((x, i) => b.red(x, 'c' + i)); F.MULE = defFn('MULE', slpFn([...names('a', e), ...names('b', e)], b.prog, names('c', e))); }
  { const b = new PB(e); sqE(e, names('a', e)).forEach((x, i) => b.red(x, 'c' + i)); F.SQE = defFn('SQE', slpFn(names('a', e), b.prog, names('c', e))); }
  { const b = new PB(e); names('a', e).forEach((x, i) => b.red(mul(V(x), V('s')), 'c' + i)); F.MULF = defFn('MULF', slpFn([...names('a', e), 's'], b.prog, names('c', e))); }
  const Ecode = e === 3
    ? [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD']
    : [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD'];
  F.E = defFn('E', asm(Ecode));
  // PAIR: u + v + g (u - v) for u, v < 2^64, g canonical
  {
    const b = new PB(e);
    const d = Array.from({length: e}, (_, c) => add(sub(V('u' + c), V('v' + c)), K(2n * P)));
    const gd = mulE(e, names('g', e), d);
    for (let c = 0; c < e; c++) b.red(add(add(V('u' + c), V('v' + c)), gd[c]), 'o' + c);
    F.PAIR = defFn('PAIR', slpFn([...names('u', e), ...names('v', e), ...names('g', e)], b.prog, names('o', e)));
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
    const b = new PB(e);
    const i1 = names('a', e).map((x) => b.red(mul(V(x), V('n1')))), i2 = names('b', e).map((x) => b.red(mul(V(x), V('n2'))));
    const p4 = mulE(e, names('g4_', e), names('H', e)), p5 = mulE(e, names('g5_', e), names('J', e));
    const nn = Array.from({length: e}, (_, c) => b.let(sum(mul(V('g1_' + c), V('X')), mul(V('g2_' + c), V('Y')), p4[c], p5[c], sub(K(P), V('C' + c)))));
    const mm = Array.from({length: e}, (_, c) => b.let(add(mul(V('g3_' + c), V('X')), sub(K(P), V('D' + c)))));
    const t1 = mulE(e, nn, i1), t2 = mulE(e, mm, i2);
    t1.forEach((x, c) => b.red(add(x, t2[c]), 'f' + c));
    F.DEEPPT = defFn('DEEPPT', slpFn(deepArgs, b.prog, names('f', e)));
  }
  // HORN: acc' = acc * YG + unpack(P) (P packs e slots of SLOT bits)
  F.HORN = defFn('HORN', localFn([...names('a', e), 'P', 'Y'], (st) => {
    st.roll('P');
    for (let c = 0; c < e - 1; c++) st.raw(['DUP', 1n << BigInt(SLOT), 'MOD', 'SWAP', SLOT, 'RSHIFTNUM'], 1, ['u' + c, 'P']);
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

  // ---------------- initial stack ----------------
  const init = [];
  trees.forEach((_, ti) => { for (let i = 0; i < s; i++) init.push(`R${ti}_${i}`); });
  for (let q = 0; q < s; q++) init.push(`L${q}`);
  const rF = Array.from({length: r - 1}, (_, i) => 'rF' + (i + 1));
  const pt = ['ST', 'rT', 'rC', 'OOD', ...rF, 'FIN', 'NONCE'];
  init.push(...pt);
  const S = new Stk(init);
  S.emit('DEPTH', init.length, 'NUMEQUALVERIFY');
  mark(S, 'entry');

  // ---------------- phase 1: transcript ----------------
  S.roll('ST'); S.raw([statement, 'EQUALVERIFY'], 1);
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
  {
    const mask = ((1n << BigInt(prm.g)) - 1n) << BigInt(32 - prm.g);
    const mb = Uint8Array.of(Number(mask >> 24n) & 255, Number(mask >> 16n) & 255, Number(mask >> 8n) & 255, Number(mask) & 255);
    S.pick('G'); S.raw([4, 'SPLIT', 'DROP', mb, 'AND', new Uint8Array(4), 'EQUALVERIFY'], 1);
  }
  // indices idx_q = LE(SHA256(G ‖ u16 q)[0:3]) mod N_1, q = s-1 .. 0 (idx_0 ends on top of the list)
  const N1 = sizes[1];
  if (N1 > 1 << 24) throw new Error('N1 too large for a 3-byte index');
  S.roll('G');
  S.raw([s - 1, 'BEGIN', '2DUP', 2, 'NUM2BIN', 'CAT', 'SHA256', 3, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', N1, 'MOD', 'ROT', 'ROT',
    '1SUB', 'DUP', 0, 'LESSTHAN', 'UNTIL', '2DROP'], 1, Array.from({length: s}, (_, k) => 'idx' + (s - 1 - k)));
  mark(S, 'transcript');

  // ---------------- phase 1: AIR identity at z, per-proof constants ----------------
  const gam = (j) => names(`ga${j}_`, e);
  {
    S.roll('OODc');
    const ood = ['oX', 'oY', 'oW', 'oA', 'oB'].flatMap((x) => names(x, e));
    S.raw([...Array.from({length: ood.length - 1}, () => [8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP']), B0, 'CAT', 'BIN2NUM'], 1, ood);
    const b = new PB(e, F);
    const [X, Y, W, A, Bv] = ['oX', 'oY', 'oW', 'oA', 'oB'].map((x) => names(x, e).map((nm) => b.red(V(nm))));
    const n = BigInt(prm.n), wl = powp(prm.wn, n - 1n);
    let zz = names('z', e);
    for (let i = 0; i < 13; i++) zz = b.sq(zz);
    const zp = zz; for (let i = 0; i < 3; i++) zz = b.sq(zz); const zn = zz;
    // c(z) = Pc(zp): Horner with base coefficients
    let cz = [b.red(add(mul(V(zp[0]), K(prm.Pc[7])), K(prm.Pc[6]))), ...zp.slice(1).map((x) => b.red(mul(V(x), K(prm.Pc[7]))))];
    for (let k = 5; k >= 0; k--) { const m = b.mul(cz, zp); cz = [b.red(add(V(m[0]), K(prm.Pc[k]))), ...m.slice(1)]; }
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
    lhs.forEach((x, i) => b.chk(chk('NUMEQUALVERIFY', V(x), V(rhs[i]))));
    // DEEP constants at z: C1 = g1 X + g2 Y + g4 H0 + g5 H1, C2 = g3 X(wz)
    const p1 = b.mul(gam(1), X), p2 = b.mul(gam(2), Y), p4 = b.mul(gam(4), A), p5 = b.mul(gam(5), Bv);
    p1.forEach((x, i) => b.red(sum(V(x), V(p2[i]), V(p4[i]), V(p5[i])), 'dC1_' + i));
    b.mul(gam(3), W).forEach((x, i) => b.red(V(x), 'dC2_' + i));
    // norm/adjugate constants of (x - z) and (x - wz) for base-field x
    for (const [zi, zs] of [[0, names('z', e).map(V)], [1, names('z', e).map((x) => mul(V(x), K(prm.wn)))]]) {
      const zc = zs.map((x) => b.red(x));
      const pfx = `dz${zi}_`;
      b.red(sub(K(P), V(zc[0])), pfx + 'm0');
      if (e === 3) {
        b.red(V(zc[1]), pfx + 'z1'); b.red(V(zc[2]), pfx + 'z2');
        b.red(mul(mul(V(zc[1]), V(zc[2])), K(P - 7n)), pfx + 'K0');
        b.red(mul(mul(V(zc[2]), V(zc[2])), K(7)), pfx + 'K1');
        b.red(mul(V(zc[1]), V(zc[1])), pfx + 'K2');
        b.red(mul(mul(V(zc[1]), V(zc[2])), K(P - 21n)), pfx + 'cA');
        const z2c = b.red(mul(mul(V(zc[2]), V(zc[2])), V(zc[2]))), z1c = b.red(mul(mul(V(zc[1]), V(zc[1])), V(zc[1])));
        b.red(add(mul(V(z2c), K(P - 49n)), mul(V(z1c), K(P - 7n))), pfx + 'cB');
      } else {
        b.red(V(zc[1]), pfx + 'z1');
        b.red(mul(mul(V(zc[1]), V(zc[1])), K(P - 7n)), pfx + 'cN');
      }
    }
    // beta powers bp<i>_<l>_<c> = beta_i^(2^l)
    for (let i = 0; i < r; i++) {
      let bp = names(`be${i}_`, e);
      for (let l = 0; (1 << l) < a[i]; l++) {
        if (l > 0) bp = b.sq(bp);
        bp.forEach((x, c) => b.red(V(x), `bp${i}_${l}_${c}`));
      }
    }
    compileSlp(S, b.prog, {keep: [1, 2, 3, 4, 5].flatMap(gam)});
    for (const x of [...S.st]) if (/^(al\d_\d|z\d|be\d_\d|o[XYWAB]\d)$/.test(x)) S.drop(x);
  }
  // everything the query function reads must sit above the index list
  { const lo = S.st.indexOf('idx' + (s - 1)); for (const x of S.st.slice(0, lo)) if (!/^(R\d|L\d|FIN|rT|rC|rF\d)/.test(x)) S.roll(x); }
  // runtime-indexed tables per distinct arity a_i (i >= 1): Wp<a>_<j> = w_a^j, Wn<a>_<j> = w_a^-j (loops)
  const arities = [...new Set(a.slice(1))];
  for (const ai of arities) {
    for (const [nm, w] of [['Wp', rou(ai)], ['Wn', invp(rou(ai))]]) {
      S.raw([1, ai - 1, 'BEGIN', 'OVER', w, 'MUL', P, 'MOD', 'SWAP', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0, Array.from({length: ai}, (_, j) => `${nm}${ai}_${j}`));
    }
  }
  mark(S, 'air+consts');

  // ---------------- phase 2: Merkle (LIFO programs) ----------------
  const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256', ...trunc];
  const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
  defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4); defFn('F8', freshRun(8), OPS.F8);
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
  const MARKER = Uint8Array.of(0x00, 0x80); // non-minimal number: can never pass as a parked index
  const roots = ['rT', 'rC', ...rF];
  trees.forEach((tree, ti) => {
    S.raw([MARKER, 'TOALTSTACK'], 0);
    S.roll(roots[ti]); S.rename(S.top(), 'root'); S.push(0, 'acc'); S.push(s, 'cnt');
    const m = S.clone();
    m.bottom(); m.rename(m.top(), 'rb');
    m.raw([1, 'SPLIT', 'SWAP', 'BIN2NUM'], 1, ['rb', 'sg']);
    m.push(1); m.pick('sg'); m.raw(['LSHIFTNUM'], 2, ['pw']); m.roll('acc'); m.raw(['ADD'], 2, ['acc']);
    { const d0 = m.depth('idx0'); m.pick('sg'); m.raw([d0, 'ADD', 'PICK'], 1, ['idx']); }
    if (tree.layer > 0) m.raw([sizes[tree.layer + 1], 'MOD'], 1, ['idx']);
    m.raw([1 << tree.depth, 'ADD'], 1, ['k']);
    { m.roll('sg'); const dl = m.depth('L' + (s - 1)) - 1 + s - 1; m.raw([dl, 'SWAP', 'SUB', 'PICK'], 1, ['Lc']); }
    m.raw([...(tree.off ? [tree.off, 'SPLIT', 'NIP'] : []), tree.leaf_bytes, 'SPLIT', 'DROP', Uint8Array.of(tree.tag), 'SWAP', 'CAT', 'SHA256', ...trunc], 1, ['cur']);
    m.arrange([...m.st.filter((x) => !['root', 'acc', 'k', 'cur', 'rb'].includes(x)), 'root', 'acc', 'k', 'cur', 'rb']);
    m.raw(['BEGIN', 1, 'SPLIT', 'SWAP', 'DUP', 10, 'LESSTHAN', 'VERIFY', 'INVOKE', 'UNTIL'], 3, ['rb']);
    m.raw([0, 'EQUALVERIFY'], 1);
    m.arrange(S.st.slice(1));
    const id = defFn('REC' + ti, m.bytes());
    S.raw(['BEGIN', id, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
    S.st.splice(0, s);
    S.roll('acc'); S.raw([(1n << BigInt(s)) - 1n, 'NUMEQUALVERIFY'], 1);
    S.raw(['FROMALTSTACK', MARKER, 'EQUALVERIFY'], 0);
    S.drop('root');
  });
  mark(S, 'merkle');

  // ---------------- phase 3: final polynomial unpack ----------------
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
  mark(S, 'unpack');

  // ---------------- phase 3: the query function ----------------
  {
    S.push(s, 'qcnt');
    const Q = S.clone();
    const k0 = a[0];
    Q.bottom(); Q.rename(Q.top(), 'L');
    Q.raw(['SIZE', prm.leafBytes + 8, 'NUMEQUALVERIFY'], 0);
    Q.roll('idx0'); Q.rename(Q.top(), 'idx');
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
    for (let c = 0; c < nch; c++) { Q.roll('ch' + c); Q.raw([F.PARSE8, 'INVOKE'], 1, vals.slice(8 * c, 8 * c + 8)); }
    mark(Q, 'q-parse');
    // DEEP: norms/adjugates, one Montgomery batch with the hinted inverse T, then f0 at the k0 coset points
    const b = new PB(e, F);
    const w0 = rou(k0);
    const xs = Array.from({length: k0}, (_, j) => (j === 0 ? 'x0' : b.red(mul(V('x0'), K(powp(w0, j))))));
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
    // binary fold i of `cur` (list of extension operands) with x^-1 = X: pairs (j, j + half), g = beta^(2^l) x_j^-1
    const foldB = (bb, i, cur, X) => {
      const wai = invp(rou(a[i]));
      for (let l = 0; cur.length > 1; l++) {
        if (l > 0) X = bb.mm(X, X);
        const half = cur.length / 2, nxt = [];
        for (let j = 0; j < half; j++) {
          const xj = j === 0 ? X : bb.red(mul(V(X), K(powp(wai, BigInt(j << l)))));
          const g = bb.mulF(names(`bp${i}_${l}_`, e), xj);
          nxt.push(bb.call(F.PAIR, [...cur[j], ...cur[j + half], ...g], e));
        }
        cur = nxt;
      }
      return cur[0];
    };
    let Fv = foldB(b, 0, f0, x0inv);
    const keepC = () => Q.st.filter((x) => /^(bp\d|ga|dC|dz)/.test(x));
    compileSlp(Q, b.prog, {keep: [...keepC(), 'x0', x0inv]});
    mark(Q, 'q-deep');
    // runtime pick: element `slot` of a list whose first element is `first` and stride `stride`
    const pickRT = (slot, first, stride, out) => {
      const d = Q.depth(first); Q.pick(slot);
      Q.raw([...(stride > 1 ? [stride, 'MUL'] : []), d, 'SWAP', 'SUB', 'PICK'], 1, [out]);
    };
    let xinv = x0inv, xb = 'x0';
    for (let i = 1; i < r; i++) {
      const sel = names(`sel${i}_`, e);
      sel.forEach((nm, c) => pickRT('sl' + i, `v${i}_0_${c}`, e, nm));
      pickRT('sl' + i, `Wp${a[i]}_0`, 1, 'wp' + i); pickRT('sl' + i, `Wn${a[i]}_0`, 1, 'wn' + i); Q.drop('sl' + i);
      const bb = new PB(e, F);
      // a_{i-1} * (leaf value at the slot) == the unscaled fold of layer i-1
      sel.forEach((nm, c) => bb.chk(chk('NUMEQUALVERIFY', R(mul(V(nm), K(a[i - 1]))), V(Fv[c]))));
      xinv = bb.mm(bb.pow2k(xinv, Math.log2(a[i - 1])), 'wp' + i);
      xb = bb.mm(bb.pow2k(xb, Math.log2(a[i - 1])), 'wn' + i);
      Fv = foldB(bb, i, Array.from({length: a[i]}, (_, j) => names(`v${i}_${j}_`, e)), xinv);
      compileSlp(Q, bb.prog, {keep: [...keepC(), ...(i < r - 1 ? [xinv] : [])]});
    }
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
      for (let k = 1; k <= G; k++) Q.drop('Y' + k);
      const cb = new PB(e);
      names('acc', e).forEach((x, c) => cb.chk(chk('NUMEQUALVERIFY', R(mul(V(x), K(a[r - 1]))), V(Fv[c]))));
      compileSlp(Q, cb.prog);
    }
    mark(Q, 'q-final');
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
    const n = S.st.length;
    S.raw([Array.from({length: n >> 1}, () => '2DROP'), ...(n & 1 ? ['DROP'] : [])], n);
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
