// Code generator for the pq-hash STARK verifier on CashVM (BCH 2026 opcodes: OP_DEFINE/OP_INVOKE, loops, shifts).
//
// buildB(prm, statement, opts) returns the layout (b) program: functions defined with OP_DEFINE plus a main program,
// and the symbolic stack names expected at entry (unlocking push order, bottom first).
//
// Layout (b) unlocking (bottom -> top):
//   R<t>_<i>  record blobs, tree by tree, records in sorted leaf order (sigma ‖ Merkle program)
//   L<q>      leaf blobs in query order: trace ‖ comp ‖ fri1 ‖ ... ‖ T_q (8 B hint)
//   ST rT rC OOD rF1.. FIN NONCE   the public transcript
// Phases: (1) transcript, grinding, indices, AIR at z, per-proof constants; (2) Merkle authentication of all trees
// (LIFO programs, parked nodes on the altstack); (3) final polynomial unpack, then one query function call per
// query (DEEP, folds, final polynomial check). Unlocking data is consumed from the bottom of the stack
// (DEPTH 1SUB ROLL), so every other item keeps a fixed depth at each program point.
import {asm, fresh, Stk} from './lib/asm.mjs';
import {compileSlp, V, K, chk, add, sub, mul, modp, sum, ex} from './lib/slp.mjs';
import {P, powp, invp, rou, le8, sha, cat, leNum, u16} from './field.mjs';
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

export class PB {
  constructor(e) { this.e = e; this.prog = []; }
  let(expr, name) { const nm = name ?? fresh('v'); this.prog.push([nm, expr]); return nm; }
  red(expr, name) { return this.let(R(expr), name); }
  chk(expr) { this.prog.push([null, expr]); }
  mul(A, B, out) { return mulE(this.e, A, B).map((x, i) => this.red(x, out && out + i)); }
  sq(A, out) { return sqE(this.e, A).map((x, i) => this.red(x, out && out + i)); }
  add(A, B, out) { return A.map((a, i) => this.red(add(ex(a), ex(B[i])), out && out + i)); }
  // A - B for B < 2^64 (raw or canonical): + 2p keeps the dividend positive
  sub(A, B, out) { return A.map((a, i) => this.red(add(sub(ex(a), ex(B[i])), K(2n * P)), out && out + i)); }
  // A - c in coefficient 0 only (c a base constant)
  subBase0(A, c) { return [this.red(add(sub(ex(A[0]), ex(c)), K(2n * P))), ...A.slice(1)]; }
  pow2k(x, k) { for (let i = 0; i < k; i++) x = this.red(mul(V(x), V(x))); return x; }
}

// window exponentiation x0 = 7 * w_N^v (4-bit windows, tables in code), from the kernels' K4
function windowCode(N, bits) {
  const w = rou(N), windows = Math.ceil(bits / 4);
  const tables = Array.from({length: windows}, (_, k) => cat(...Array.from({length: 16}, (_, j) => le8((k === 0 ? 7n : 1n) * powp(w, BigInt(j) << BigInt(4 * k)) % P))));
  return asm(
    'DUP', 16, 'MOD', 8, 'MUL', tables[0], 'SWAP', 'SPLIT', 'NIP', 8, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', 'SWAP', 4, 'RSHIFTNUM', 'SWAP',
    tables.slice(1).map((t, k) => ['OVER', 16, 'MOD', 8, 'MUL', t, 'SWAP', 'SPLIT', 'NIP', 8, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', 'MUL', P, 'MOD', ...(k < windows - 2 ? ['SWAP', 4, 'RSHIFTNUM', 'SWAP'] : [])]),
    'NIP');
}

export function buildB(prm, statement, opts = {}) {
  const {e, s, h, r, a, D, sizes, trees} = prm;
  const e8 = 8 * e;
  const G = Math.min(opts.group ?? 32, D);   // final polynomial: group size of the packed dot products
  const SLOT = 136;                          // packed slot width (sum of 32 products of 64-bit values < 2^133)
  const fns = new Map();
  let nextId = 16;
  const defFn = (name, body, id) => { id ??= nextId++; fns.set(name, {id, body: Uint8Array.from(body)}); return id; };
  const sizes_ = [];
  const mark = (stk, label) => { sizes_.push([label ?? '?', stk === S ? 'main' : 'Q', stk.code.length]); if (opts.markers) stk.emit('NOP'); };
  const trunc = h < 32 ? [h, 'SPLIT', 'DROP'] : [];

  // ---------------- initial stack ----------------
  const init = [];
  trees.forEach((_, ti) => { for (let i = 0; i < s; i++) init.push(`R${ti}_${i}`); });
  for (let q = 0; q < s; q++) init.push(`L${q}`);
  const rF = Array.from({length: r - 1}, (_, i) => 'rF' + (i + 1));
  const pt = ['ST', 'rT', 'rC', 'OOD', ...rF, 'FIN', 'NONCE'];
  init.push(...pt);
  const S = new Stk(init);
  S.emit('DEPTH', init.length, 'NUMEQUALVERIFY');
  mark(S);

  // ---------------- phase 1: transcript ----------------
  const Ecode = e === 3
    ? [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD']
    : [B0, 'CAT', 'BIN2NUM', 'DUP', P, 'MOD', 'SWAP', P, 'DIV', P, 'MOD'];
  // statement: the redeem is built for one statement (x_in, y_out); the proof's copy must match it
  S.roll('ST'); S.raw([statement, 'EQUALVERIFY'], 1);
  const t0 = sha(prm.TAG, statement);
  const absorb = (prev, item, keepItem, len) => {
    if (keepItem) S.pick(item); else S.roll(item);
    S.raw(['SIZE', len, 'NUMEQUALVERIFY'], 0);
    if (prev instanceof Uint8Array) S.raw([prev, 'SWAP', 'CAT', 'SHA256'], 1, [fresh('t')]);
    else { S.roll(prev); S.raw(['SWAP', 'CAT', 'SHA256'], 2, [fresh('t')]); }
    return S.top();
  };
  const challenge = (t, tag, out) => { S.pick(t); S.raw([tag, 'CAT', 'SHA256', Ecode], 1, names(out, e)); };
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
  const N1 = sizes[1];
  if (N1 > 1 << 24) throw new Error('N1 too large for a 3-byte index');
  for (let q = s - 1; q >= 0; q--) { S.pick('G'); S.raw([u16(q), 'CAT', 'SHA256', 3, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', N1, 'MOD'], 1, ['idx' + q]); }
  S.drop('G');
  mark(S);

  // ---------------- phase 1: AIR identity at z, per-proof constants ----------------
  const gam = (j) => names(`ga${j}_`, e);
  {
    S.roll('OODc');
    const ood = ['oX', 'oY', 'oW', 'oA', 'oB'].flatMap((x) => names(x, e));
    ood.forEach((nm, i) => {
      if (i < ood.length - 1) S.raw([8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP'], 1, [nm, 'oodrest']);
      else S.raw([B0, 'CAT', 'BIN2NUM'], 1, [nm]);
    });
    const b = new PB(e);
    // OOD values are raw (< 2^64): reduce once
    const [X, Y, W, A, Bv] = ['oX', 'oY', 'oW', 'oA', 'oB'].map((x) => names(x, e).map((nm) => b.red(V(nm))));
    const n = BigInt(prm.n), wl = powp(prm.wn, n - 1n);
    let zz = names('z', e);
    for (let i = 0; i < 13; i++) zz = b.sq(zz);
    const zp = zz; for (let i = 0; i < 3; i++) zz = b.sq(zz); const zn = zz;
    let cz = [b.red(add(mul(V(zp[0]), K(prm.Pc[7])), K(prm.Pc[6]))), ...zp.slice(1).map((x) => b.red(mul(V(x), K(prm.Pc[7]))))];
    for (let k = 5; k >= 0; k--) { const m = mulE(e, cz, zp); cz = m.map((x, i) => b.red(i === 0 ? add(x, K(prm.Pc[k])) : x)); }
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
    // DEEP: C1 = g1 X + g2 Y + g4 H0 + g5 H1 and C2 = g3 X(wz) at z (all extension products)
    const p1 = mulE(e, gam(1), X), p2 = mulE(e, gam(2), Y), p4 = mulE(e, gam(4), A), p5 = mulE(e, gam(5), Bv);
    p1.forEach((x, i) => b.red(sum(x, p2[i], p4[i], p5[i]), 'dC1_' + i));
    mulE(e, gam(3), W).forEach((x, i) => b.red(x, 'dC2_' + i));
    // norm/adjugate constants of (x - z) and (x - wz) for base-field x
    for (const [zi, zs] of [[0, names('z', e).map(V)], [1, names('z', e).map((x) => mul(V(x), K(prm.wn)))]]) {
      const zc = zs.map((x) => b.red(x));
      const pfx = `dz${zi}_`;
      b.red(sub(K(P), V(zc[0])), pfx + 'm0');
      if (e === 3) {
        b.red(mul(V(zc[1]), K(1)), pfx + 'z1'); b.red(mul(V(zc[2]), K(1)), pfx + 'z2');
        b.red(mul(mul(V(zc[1]), V(zc[2])), K(P - 7n)), pfx + 'K0');
        b.red(mul(mul(V(zc[2]), V(zc[2])), K(7)), pfx + 'K1');
        b.red(mul(V(zc[1]), V(zc[1])), pfx + 'K2');
        b.red(mul(mul(V(zc[1]), V(zc[2])), K(P - 21n)), pfx + 'cA');
        const z2c = b.red(mul(mul(V(zc[2]), V(zc[2])), V(zc[2])));
        const z1c = b.red(mul(mul(V(zc[1]), V(zc[1])), V(zc[1])));
        b.red(add(mul(V(z2c), K(P - 49n)), mul(V(z1c), K(P - 7n))), pfx + 'cB');
      } else {
        b.red(mul(V(zc[1]), K(1)), pfx + 'z1');
        b.red(mul(mul(V(zc[1]), V(zc[1])), K(P - 7n)), pfx + 'cN');
      }
    }
    // fold constants B<i>_<l>_<j>_<c> = beta_i^(2^l) * w_{a_i}^(-j 2^l)
    for (let i = 0; i < r; i++) {
      let bp = names(`be${i}_`, e);
      const wai = invp(rou(a[i]));
      for (let l = 0; (1 << l) < a[i]; l++) {
        if (l > 0) bp = b.sq(bp);
        for (let j = 0; j < a[i] >> (l + 1); j++) {
          const c = powp(wai, BigInt(j << l));
          bp.forEach((x, k) => b.red(mul(V(x), K(c)), `B${i}_${l}_${j}_${k}`));
        }
      }
    }
    compileSlp(S, b.prog, {keep: [1, 2, 3, 4, 5].flatMap(gam)});
    for (const x of [...S.st]) if (/^(al\d_\d|z\d|be\d_\d|o[XYWAB]\d)$/.test(x)) S.drop(x);
  }
  // everything the query function reads must sit above the index list (the list shrinks by one per query)
  { const lo = S.st.indexOf('idx' + (s - 1)); for (const x of S.st.slice(0, lo)) if (!/^(R\d|L\d|FIN|rT|rC|rF\d)/.test(x)) S.roll(x); }
  // runtime-indexed tables for the coset-base updates (i >= 1): Wp<i>_<j> = w_{a_i}^j, Wn<i>_<j> = w_{a_i}^-j
  for (let i = 1; i < r; i++) {
    const w = rou(a[i]), wi = invp(w);
    for (let j = 0; j < a[i]; j++) S.push(powp(w, j), `Wp${i}_${j}`);
    for (let j = 0; j < a[i]; j++) S.push(powp(wi, j), `Wn${i}_${j}`);
  }
  mark(S);

  // ---------------- phase 2: Merkle (LIFO programs) ----------------
  // op functions on [root acc k cur rb] (rb on top). Non-terminal ops leave [.. k' cur' rb' 0]; PARK/ROOT leave
  // [.. rb' 1]. Parked nodes live on the altstack as (cur, k) pairs, k on top.
  // fresh level on [cur] with alt [.. rb k] -> same shape
  const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256', ...trunc];
  const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
  defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4); defFn('F8', freshRun(8), OPS.F8);
  defFn('F16', asm(OPS.F8, 'INVOKE', 'DROP', OPS.F8, 'INVOKE'), OPS.F16);
  {
    // MERGE: (pk, pd) from the altstack; require pk + k == 4 (k >> 1) + 1 (pk is the sibling of k)
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
    // DUPM: the parked node is the same node (duplicate leaf): equal index and digest
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
    S.roll(roots[ti]); S.rename(S.top(), 'root'); S.push(0, 'acc');
    // record function for this tree: entry shape = S now (the bottom item is this record's blob)
    const m = S.clone();
    m.bottom(); m.rename(m.top(), 'rb');
    m.raw([1, 'SPLIT', 'SWAP', 'BIN2NUM'], 1, ['rb', 'sg']);
    m.push(1); m.pick('sg'); m.raw(['LSHIFTNUM'], 2, ['pw']); m.roll('acc'); m.raw(['ADD'], 2, ['acc']);
    { const d0 = m.depth('idx0'); m.pick('sg'); m.raw([d0, 'ADD', 'PICK'], 1, ['idx']); }
    if (tree.layer > 0) m.raw([sizes[tree.layer + 1], 'MOD'], 1, ['idx']);
    m.raw([1 << tree.depth, 'ADD'], 1, ['k']);
    { m.roll('sg'); const dl = m.depth('L' + (s - 1)) - 1 + s - 1; m.raw([dl, 'SWAP', 'SUB', 'PICK'], 1, ['Lc']); }
    m.raw([...(tree.off ? [tree.off, 'SPLIT', 'NIP'] : []), tree.leaf_bytes, 'SPLIT', 'DROP', Uint8Array.of(tree.tag), 'SWAP', 'CAT', 'SHA256', ...trunc], 1, ['cur']);
    m.arrange([...m.st.filter((x) => !['acc', 'k', 'cur', 'rb'].includes(x)), 'acc', 'k', 'cur', 'rb']);
    m.raw(['BEGIN', 1, 'SPLIT', 'SWAP', 'DUP', 10, 'LESSTHAN', 'VERIFY', 'INVOKE', 'UNTIL'], 3, ['rb']);
    m.raw([0, 'EQUALVERIFY'], 1);
    const exit = m.st.join('|'), want = S.st.slice(1).join('|');
    if (exit !== want) throw new Error('record function changes the stack shape');
    const id = defFn('REC' + ti, m.bytes());
    for (let i = 0; i < s; i++) { S.raw([id, 'INVOKE'], 0); S.st.shift(); }
    S.roll('acc'); S.raw([(1n << BigInt(s)) - 1n, 'NUMEQUALVERIFY'], 1);
    S.raw(['FROMALTSTACK', MARKER, 'EQUALVERIFY'], 0);
    S.drop('root');
  });
  mark(S);

  // ---------------- phase 3: final polynomial unpack ----------------
  {
    const Z9 = new Uint8Array(9);
    const pack = e === 3
      ? [8, 'SPLIT', 8, 'SPLIT', B0, 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'BIN2NUM']
      : [8, 'SPLIT', B0, 'CAT', 'SWAP', Z9, 'CAT', 'SWAP', 'CAT', 'BIN2NUM'];
    const CH = Math.min(16, D);
    // UNP: [chunk of CH coefficients] -> CH packed numbers (first coefficient deepest)
    const unp = asm(Array.from({length: CH}, (_, i) => (i < CH - 1 ? [e8, 'SPLIT', 'SWAP', pack, 'SWAP'] : [pack])));
    const idU = defFn('UNP', unp);
    S.roll('FIN');
    const nch = D / CH;
    for (let c = 0; c < nch - 1; c++) S.raw([CH * e8, 'SPLIT'], 1, ['fch' + c, 'FIN']);
    S.rename('FIN', 'fch' + (nch - 1));
    // unpack chunks from the top (last chunk first)
    for (let c = nch - 1; c >= 0; c--) {
      S.roll('fch' + c);
      S.raw([idU, 'INVOKE'], 1, Array.from({length: CH}, (_, i) => 'C' + (c * CH + i)));
    }
  }
  mark(S);

  // ---------------- phase 3: the query function ----------------
  {
    const Q = S.clone();
    const k0 = a[0];
    Q.bottom(); Q.rename(Q.top(), 'L');
    Q.raw(['SIZE', prm.leafBytes + 8, 'NUMEQUALVERIFY'], 0);
    Q.roll('idx0'); Q.rename(Q.top(), 'idx');
    Q.pick('idx'); Q.raw([{raw: windowCode(sizes[0], Math.log2(sizes[1]))}], 1, ['x0']);
    for (let i = 1; i < r; i++) {
      Q.pick('idx');
      Q.raw([...(i > 1 ? [sizes[i], 'MOD'] : []), Math.log2(sizes[i + 1]), 'RSHIFTNUM'], 1, ['sl' + i]);
    }
    Q.drop('idx');
    mark(Q);
    // parse the leaf blob (all values raw, < 2^64)
    const vals = [];
    for (let j = 0; j < k0; j++) vals.push('tX' + j, 'tY' + j);
    for (let j = 0; j < k0; j++) vals.push(...names(`cA${j}_`, e), ...names(`cB${j}_`, e));
    for (let i = 1; i < r; i++) for (let j = 0; j < a[i]; j++) vals.push(...names(`v${i}_${j}_`, e));
    vals.push('T');
    Q.roll('L');
    vals.forEach((nm, i) => {
      if (i < vals.length - 1) Q.raw([8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP'], 1, [nm, 'L']);
      else Q.raw([B0, 'CAT', 'BIN2NUM'], 1, [nm]);
    });
    mark(Q);
    // DEEP: inverses of (x_j - z), (x_j - wz) and x0 by one Montgomery batch with the hinted inverse T
    const b = new PB(e);
    const w0 = rou(k0);
    const xs = Array.from({length: k0}, (_, j) => (j === 0 ? 'x0' : b.red(mul(V('x0'), K(powp(w0, j))))));
    const na = xs.map((x) => [0, 1].map((zi) => {
      const p = `dz${zi}_`;
      const w = b.let(add(V(x), V(p + 'm0')));
      if (e === 3) {
        const w2 = b.let(mul(V(w), V(w)));
        return {
          N: b.red(add(mul(V(w), add(V(w2), V(p + 'cA'))), V(p + 'cB'))),
          adj: [b.red(add(V(w2), V(p + 'K0'))), b.red(add(mul(V(w), V(p + 'z1')), V(p + 'K1'))), b.red(add(mul(V(w), V(p + 'z2')), V(p + 'K2')))],
        };
      }
      return {N: b.red(add(mul(V(w), V(w)), V(p + 'cN'))), adj: [b.red(V(w)), p + 'z1']};
    }));
    const E = [...na.flatMap(([u, v]) => [u.N, v.N]), 'x0'];
    const pre = [E[0]];
    for (let m = 1; m < E.length; m++) pre.push(b.red(mul(V(pre[m - 1]), V(E[m]))));
    b.chk(chk('NUMEQUALVERIFY', R(mul(V(pre[E.length - 1]), V('T'))), K(1)));
    const inv = new Array(E.length);
    let Tm = 'T';
    for (let m = E.length - 1; m >= 1; m--) { inv[m] = b.red(mul(V(Tm), V(pre[m - 1]))); Tm = b.red(mul(V(Tm), V(E[m]))); }
    inv[0] = Tm;
    const x0inv = inv[E.length - 1];
    const f0 = xs.map((_, j) => {
      const i1 = na[j][0].adj.map((x) => b.red(mul(V(x), V(inv[2 * j])))), i2 = na[j][1].adj.map((x) => b.red(mul(V(x), V(inv[2 * j + 1]))));
      const p4 = mulE(e, gam(4), names(`cA${j}_`, e)), p5 = mulE(e, gam(5), names(`cB${j}_`, e));
      const nn = Array.from({length: e}, (_, c) => b.let(sum(mul(V(gam(1)[c]), V('tX' + j)), mul(V(gam(2)[c]), V('tY' + j)), p4[c], p5[c], sub(K(P), V('dC1_' + c)))));
      const mm = Array.from({length: e}, (_, c) => b.let(add(mul(V(gam(3)[c]), V('tX' + j)), sub(K(P), V('dC2_' + c)))));
      const t1 = mulE(e, nn, i1), t2 = mulE(e, mm, i2);
      return t1.map((x, c) => b.red(add(x, t2[c])));
    });
    // binary fold of `cur` (list of extension operands) with x^-1 = X (base name) for fold i; values u, v < 2^64
    const foldB = (i, cur, X) => {
      for (let l = 0; cur.length > 1; l++) {
        if (l > 0) X = b.red(mul(V(X), V(X)));
        const half = cur.length / 2, nxt = [];
        for (let j = 0; j < half; j++) {
          const u = cur[j], v = cur[j + half];
          const g = Array.from({length: e}, (_, c) => b.red(mul(V(`B${i}_${l}_${j}_${c}`), V(X))));
          const d = Array.from({length: e}, (_, c) => add(sub(V(u[c]), V(v[c])), K(2n * P)));
          const gd = mulE(e, g, d);
          nxt.push(Array.from({length: e}, (_, c) => b.red(add(add(V(u[c]), V(v[c])), gd[c]))));
        }
        cur = nxt;
      }
      return cur[0];
    };
    let F = foldB(0, f0, x0inv);
    compileSlp(Q, b.prog, {keep: [...[1, 2, 3, 4, 5].flatMap(gam), ...names('dC1_', e), ...names('dC2_', e),
      ...['dz0_', 'dz1_'].flatMap((p) => (e === 3 ? ['m0', 'z1', 'z2', 'K0', 'K1', 'K2', 'cA', 'cB'] : ['m0', 'z1', 'cN']).map((x) => p + x)),
      ...Q.st.filter((x) => /^B\d/.test(x)), 'x0', x0inv]});
    mark(Q);
    // runtime pick helpers: element `slot` of a list whose first element is `first` and stride `stride`
    const pickRT = (slot, first, stride, out) => {
      const d = Q.depth(first); Q.pick(slot);
      Q.raw([...(stride > 1 ? [stride, 'MUL'] : []), d, 'SWAP', 'SUB', 'PICK'], 1, [out]);
    };
    let xinv = x0inv, xb = 'x0';
    for (let i = 1; i < r; i++) {
      // check the folded value against slot sl_i of the fri_i leaf: a_{i-1} * leaf value == unscaled fold
      const sel = names(`sel${i}_`, e);
      sel.forEach((nm, c) => pickRT('sl' + i, `v${i}_0_${c}`, e, nm));
      pickRT('sl' + i, `Wp${i}_0`, 1, 'wp' + i); pickRT('sl' + i, `Wn${i}_0`, 1, 'wn' + i); Q.drop('sl' + i);
      const bb = new PB(e);
      sel.forEach((nm, c) => bb.chk(chk('NUMEQUALVERIFY', R(mul(V(nm), K(a[i - 1]))), V(F[c]))));
      xinv = bb.red(mul(V(bb.pow2k(xinv, Math.log2(a[i - 1]))), V('wp' + i)));
      xb = bb.red(mul(V(bb.pow2k(xb, Math.log2(a[i - 1]))), V('wn' + i)));
      const cur = Array.from({length: a[i]}, (_, j) => names(`v${i}_${j}_`, e));
      const saveProg = b.prog; b.prog = bb.prog;
      F = foldB(i, cur, xinv);
      b.prog = saveProg;
      compileSlp(Q, bb.prog, {keep: [...Q.st.filter((x) => /^(B\d|ga|dC|dz)/.test(x)), ...(i < r - 1 ? [xinv] : [])]});
      if (i === r - 1) void 0;
    }
    mark(Q);
    // final polynomial: y = xb^(a_{r-1}); packed dot products of G coefficients with y^0..y^(G-1), Horner over groups
    {
      const bb = new PB(e);
      const y = bb.pow2k(xb, Math.log2(a[r - 1]));
      const Y = [null, y];
      for (let k = 2; k <= G; k++) Y.push(bb.red(mul(V(Y[k - 1]), V(y))));
      compileSlp(Q, bb.prog, {keep: Y.slice(1)});
      const H = D / G;
      let acc = null;
      for (let hi = H - 1; hi >= 0; hi--) {
        Q.pick('C' + hi * G); Q.rename(Q.top(), 'pacc');
        for (let lo = 1; lo < G; lo++) {
          Q.pick('C' + (hi * G + lo)); Q.pick(Y[lo]); Q.raw(['MUL'], 2, ['pp']); Q.raw(['ADD'], 2, ['pacc']);
        }
        // unpack e slots of SLOT bits
        const cs = names(`u${hi}_`, e);
        for (let c = 0; c < e - 1; c++) Q.raw(['DUP', 1n << BigInt(SLOT), 'MOD', 'SWAP', SLOT, 'RSHIFTNUM'], 1, [cs[c], 'pacc']);
        Q.rename('pacc', cs[e - 1]);
        const hb = new PB(e);
        acc = acc === null ? cs.map((x) => hb.red(V(x))) : cs.map((x, c) => hb.red(add(mul(V(acc[c]), V(Y[G])), V(x))));
        compileSlp(Q, hb.prog, {keep: [Y[G]]});
      }
      for (let k = 1; k <= G; k++) Q.drop(Y[k]);
      const cb = new PB(e);
      acc.forEach((x, c) => cb.chk(chk('NUMEQUALVERIFY', R(mul(V(x), K(a[r - 1]))), V(F[c]))));
      compileSlp(Q, cb.prog);
    }
    const want = S.st.filter((x) => x !== 'idx0').slice(1);
    if (Q.st.join('|') !== want.join('|')) {
      const extra = Q.st.filter((x) => !want.includes(x)), missing = want.filter((x) => !Q.st.includes(x));
      throw new Error(`query function leaves extra [${extra}] missing [${missing}]`);
    }
    const id = defFn('Q', Q.bytes());
    for (let q = 0; q < s; q++) {
      S.raw([id, 'INVOKE'], 0);
      // the function consumes the bottom leaf blob and the topmost index (positionally the same at every call)
      S.st.shift(); S.st.splice(S.st.indexOf('idx' + q), 1);
    }
  }
  mark(S);
  // ---------------- cleanup ----------------
  {
    let n = S.st.length;
    if (S.st.some((x) => /^(R\d|L\d|idx)/.test(x))) throw new Error('unconsumed witness items: ' + S.st.filter((x) => /^(R\d|L\d|idx)/.test(x)));
    for (; n >= 2; n -= 2) S.emit('2DROP');
    if (n) S.emit('DROP');
    S.st = [];
    S.push(1);
  }
  return {main: S.bytes(), fns, init, G, SLOT, codeSizes: sizes_};
}

export function redeemB(built) {
  const pro = [];
  for (const [, f] of built.fns) pro.push(...asm(f.body, f.id, 'DEFINE'));
  return Uint8Array.from([...pro, ...built.main]);
}
