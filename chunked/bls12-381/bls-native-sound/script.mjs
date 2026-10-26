// BLS12-381 SI-GLS on bch-2026, 4 inputs: the uniform redeem R (pins + loader) and the shared program blob.
// See README.md for the protocol, the role table and the spec rules. Every item is named on the assembler's
// symbolic stack (asm.mjs); shared code is a function (OP_DEFINE / OP_INVOKE), and a function that is shared by
// several roles is compiled once against one canonical named layout that every role re-creates before the call.
//
//   R (every input, identical):  input count = 4; every input's locking == this input's locking;
//     blob = INPUTBYTECODE(carrier)[off, off + len); SHA256(blob) == H_blob; OP_DEFINE it as function 0; invoke.
//   blob (function 0): defines every function, then invokes the role body INPUTINDEX + 1.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {p, r, ETA, GAMMA1, AX, NE, VKC} from './math.mjs';
import {TAG, NIN, ROLES, PLACE, pushesOf, offsetOf, hdrLen, STMT, STMT_SIZE, NQ_MAX, N_MIN, K_IDS, K_HASH, isBoundary, isAdd, blobParts} from './protocol.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const sha256 = (b) => createHash('sha256').update(b).digest();

// ---------------- kernels (DAGs over named stack items) ----------------
const kit = () => { const k = new Kernel(); return {k, I: (n, s) => k.in(n, s), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)}; };
const sch = (k, a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];          // Fp2 schoolbook (u^2 = -1)
const kar = (k, a0, a1, b0, b1) => { const u0 = k.mul(a0, b0), u1 = k.mul(a1, b1), u2 = k.mul(k.add(a0, a1), k.add(b0, b1)); return [k.sub(u0, u1), k.sub(k.sub(u2, u0), u1)]; };
// affine line (c, -l, 1) at P0 = (xP, yP) = (xA, -yA), times w^3: L(+-z) = e +- oP, e = c0 + t c1 - xz2 l0 - xz2t l1
// (xz2 = xA z^2, oP = -yA z^3, t = z^6 - 1). B affine doubling with the witnessed slope l: residues
// d = 2 y l - 3 x^2 (must be 0, reduced), x3 = l^2 - 2x, y3 = l (x - x3) - y, F+- <- F+-^2 L(+-z). env: t xz2 xz2t oP
export function kAffDbl() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const d0 = m(sub(k.small(sub(mul(l0, y0), mul(l1, y1)), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(add(mul(l0, y1), mul(l1, y0)), 2), k.small(mul(x0, x1), 6)));
  const nx0 = m(sub(mul(add(l0, l1), sub(l0, l1)), k.small(x0, 2))), nx1 = m(sub(k.small(mul(l0, l1), 2), k.small(x1, 2)));
  const [a0, a1] = sch(k, l0, l1, sub(x0, nx0), sub(x1, nx1)); const ny0 = m(sub(a0, y0)), ny1 = m(sub(a1, y1));
  const [c0_, c1_] = sch(k, l0, l1, x0, x1); const c0 = sub(c0_, y0), c1 = sub(c1_, y1);
  const e = m(k.sum(c0, mul(E('t'), m(c1)), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(nx0, nx1, ny0, ny1, m(mul(mul(Fp, Fp), add(e, E('oP')))), m(mul(mul(Fm, Fm), sub(e, E('oP')))), d0, d1);
  return k;
}
// B affine addition with +B and the witnessed slope l: ex = xB - x (reduced; must be nonzero), residue d = l ex - (yB - y)
// (must be 0); x3 = l^2 - x - xB, y3 = l (x - x3) - y; F+- <- F+- L(+-z) c+-, c+ = S_c(-z), c- = S_c(z).
// env: t xz2 xz2t oP xB0 xB1 yB0 yB1 Scp Scm
export function kAffAdd() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const [xq0, xq1, yq0, yq1] = ['xB0', 'xB1', 'yB0', 'yB1'].map(E);
  const ex0 = m(sub(xq0, x0)), ex1 = m(sub(xq1, x1));
  const [u0, u1] = sch(k, l0, l1, ex0, ex1); const d0 = m(sub(u0, sub(yq0, y0))), d1 = m(sub(u1, sub(yq1, y1)));
  const nx0 = m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), xq0)), nx1 = m(sub(sub(k.small(mul(l0, l1), 2), x1), xq1));
  const [a0, a1] = sch(k, l0, l1, sub(x0, nx0), sub(x1, nx1)); const ny0 = m(sub(a0, y0)), ny1 = m(sub(a1, y1));
  const [c0_, c1_] = sch(k, l0, l1, x0, x1); const c0 = sub(c0_, y0), c1 = sub(c1_, y1);
  const e = m(k.sum(c0, mul(E('t'), m(c1)), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  k.output(nx0, nx1, ny0, ny1, m(mul(mul(I('Fp'), add(e, E('oP'))), E('Scm'))), m(mul(mul(I('Fm'), sub(e, E('oP'))), E('Scp'))), d0, d1, ex0, ex1);
  return k;
}
// delta step j: n = lambda_j (baked, read), c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}, line (c_j, -lambda_j, 1) at C:
// e = c_j0 + t c_j1 - cz2 n0 - cz2t n1, L(+-z) = e +- oC; x_{j+1} = lambda_j^2 - x_j - s. env: t cz2 cz2t oC
export function kDStep() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map((n) => I(n));
  const [u0, u1] = kar(k, add(l0, n0), add(l1, n1), x0, x1); const nc0 = m(sub(u0, c0)), nc1 = m(sub(u1, c1));
  const e = m(k.sum(nc0, mul(E('t'), nc1), k.neg(mul(E('cz2'), n0)), k.neg(mul(E('cz2t'), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(k.small(mul(n0, n1), 2), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, E('oC')))), m(mul(I('Fm'), sub(e, E('oC')))));
  return k;
}
// monic degree-6 evaluation at +-x: (Ev + Od, Ev - Od) from s0..s5 and x..x6 (all consumed)
function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
// 16-entry subset table from v0..v3 (consumed): T[n] = prod (or sum) over bits of n; outputs T[15] .. T[0]
function kTable(mult) {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(mult ? 1n : 0n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : mult ? k.mod(k.mul(T[n ^ lo], v[b])) : k.add(T[n ^ lo], v[b]); }
  return k.output(...T.slice().reverse());
}

// event flags (one byte per event): 1 = addition, 2 = state boundary after the event
export const FLAGS = Array.from({length: NE}, (_, e) => (isAdd(e) ? 1 : 0) | (isBoundary(e) ? 2 : 0));
const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
// canonical frame: every role re-creates exactly this main stack (alt empty) before SETUP
const FRAME = ['CL', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'z', 'rho', 'xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC',
  'sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5', 'N0', 'N1', 'X0', 'X1', 'Y0', 'Y1', 'SL', 'ST', 'SCH', 'f'];
const HOT = ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'Scp', 'Scm', 'oC', 'cz2', 'cz2t', 'oP', 'xz2', 'xz2t', 't', 'p'];
const STATE = ['N0', 'N1', 'SCH', 'SL', 'X0', 'X1', 'Y0', 'Y1', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm', 'f'];

// ---------------- the redeem R (identical for every input) ----------------
export function buildR({parts, hash}) {
  const rd = parts.flatMap(({carrier, off, len}, j) => [...pushNum(carrier), OP.INPUTBYTECODE, ...pushNum(off), OP.SPLIT, OP.NIP, ...pushNum(len), OP.SPLIT, OP.DROP, ...(j ? [OP.CAT] : [])]);
  return Uint8Array.from([
    OP.TXINPUTCOUNT, ...pushNum(NIN), OP.NUMEQUALVERIFY,
    ...pushNum(0), OP.BEGIN, OP.DUP, OP.UTXOBYTECODE, OP.INPUTINDEX, OP.UTXOBYTECODE, OP.EQUALVERIFY, OP.ADD1, OP.DUP, ...pushNum(NIN), OP.NUMEQUAL, OP.UNTIL, OP.DROP,
    ...rd, OP.DUP, OP.SHA256, ...pushData(hash), OP.EQUALVERIFY, ...pushNum(0), OP.DEFINE, ...pushNum(0), OP.INVOKE,
  ]);
}

// ---------------- program ----------------
export function buildProgram() {
  let L0 = null, blobLen = 6000;
  const lensOf = (n) => [...PLACE.blobLens, n - PLACE.blobLens.reduce((a, b) => a + b, 0)];
  for (let attempt = 0; attempt < 12; attempt++) {
    let out;
    try { out = gen(L0, lensOf(blobLen)); } catch (e) { if (e.retryL0) { L0 = e.retryL0; continue; } throw e; }
    if (out.blob.length !== blobLen) { blobLen = out.blob.length; continue; }
    return out;
  }
  throw new Error('program layout did not converge');
}

function gen(L0guess, BLOB_LENS) {
  const ctx = {funcs: new Map(), nextId: 1 + NIN, defs: []};   // ids 1..NIN: the role bodies (dispatch: INPUTINDEX + 1)
  const info = {roles: [], marks: []};
  const U = (a, x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x); // unsigned LE decode of the top item
  const top = new Asm([], ctx);
  // ---- local functions ----
  top.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  // RD: [blob] -> [v, rest]: split one 48-byte LE word, decode unsigned (BIN2NUM(w || 0x00)), require v < p
  top.defLocal('RD', 1, 2, (s) => { s.push(48).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  top.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  top.defLocal('TM', 4, 16, (s) => s.kernel(kTable(true), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  top.defLocal('TA', 4, 16, (s) => s.kernel(kTable(false), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  top.defLocal('G1C', 2, 0, (s) => { const k = new Kernel(); const x = k.in('in0'), y = k.in('in1'); k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(4n))))); s.kernel(k, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  // C48: x in (-p, p) (every value it is applied to is the output of a MOD p) -> its canonical residue in [0, p) as 48 bytes LE
  top.defLocal('C48', 1, 1, (s) => { s.op(OP.DUP, 1, 'x', 'xc').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse((t) => { t.invoke('P', ['p']).op(OP.ADD, 2, 'x'); }); s.push(48).op(OP.NUM2BIN, 2, 'w'); });
  // READ0 (Miller inputs 1..3): z~, rho~, the statement and s^c from input 0 by introspection (every word < p);
  // out (17): z rho xA yA xB0 xB1 yB0 yB1 xC yC NB(128 nibble bytes) sc0..sc5
  top.defLocal('READ0', 0, 17, (s) => {
    const oZR = offsetOf(0, 'ZR'), oG = offsetOf(0, 'G');
    s.push(0).op(OP.INPUTBYTECODE, 1, 'u').push(oZR).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(oG + STMT_SIZE - oZR).op(OP.SPLIT, 2, 'u', 'x').drop('x');
    // u = ZR (96) | G header | statement (864)
    for (const n of ['z', 'rho']) s.invoke('RD', [n, 'u']);
    s.push(oG - oZR - 96).op(OP.SPLIT, 2, 'x', 'u').drop('x');
    for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) s.invoke('RD', [n, 'u']);
    s.push(64).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(128).op(OP.SPLIT, 2, 'NB', 'u');
    for (let j = 0; j < 6; j++) s.invoke('RD', ['sc' + j, 'u']);
    s.op(OP.SIZE, 1, 'u', 'n').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('u');
  });

  // ---- shared bound functions (compiled once, at the first call, against the canonical layout) ----
  top.defBound('SETUP', (a) => {
    a.invoke('P', ['p']);
    // powers of z and eta z; t = z^6 - 1
    { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
      const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); // eta^2 = eta - 1, eta^3 = -1
      k.output(z2, z3, z4, z5, z6, k.sub(z6, k.c(1n)), m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))));
      a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 't', 'ez', 'ez2', 'ez3', 'ez4', 'ez5'], {iters: 1500}); }
    for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of ZP) a.pick(n); a.invoke('EV', ['Scp', 'Scm']);
    // GT-GLS tables: TP_k[n] = prod_{i in n} factor_{k,i}(z), TM_k at -z (factor_{k,i}(X) = R_{k,i%2}((-1)^i eta^[i>=2] X))
    for (const k of [0, 1]) {
      for (const i of [0, 1]) for (let j = 0; j < 6; j++) a.push(VKC.R[k][i][j], `R${i}_${j}`);
      for (const n of [...ZP, ...EZP.slice(0, 5)]) a.pick(n);
      a.invoke('TBL', [...Array.from({length: 16}, (_, n) => `TP${k}_${15 - n}`), ...Array.from({length: 16}, (_, n) => `TM${k}_${15 - n}`)]);
    }
    { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const t = k.env('t'), z2 = k.env('z2'), z3 = k.env('z3');
      const xz2 = m(mul(k.env('xA'), z2)), oP = m(mul(k.neg(k.env('yA')), z3)), cz2 = m(mul(k.env('xC'), z2));
      k.output(xz2, m(mul(xz2, t)), oP, cz2, m(mul(cz2, t)), m(mul(k.env('yC'), z3)));
      a.kernel(k, ['xz2', 'xz2t', 'oP', 'cz2', 'cz2t', 'oC'], {iters: 500}); }
    a.push(VKC.deltaAff.x.c0, 'xd0').push(VKC.deltaAff.x.c1, 'xd1');
  });
  // TBL: [R_0 (6), R_1 (6), z..z6, ez..ez5] -> TP[15..0], TM[15..0] for one digit group: factor_i(X) = R_{i%2}((-1)^i eta^[i>=2] X);
  // at +z: R0(z), R1(-z), R0(eta z), R1(-eta z); at -z: R0(-z), R1(z), R0(-eta z), R1(eta z)
  top.defLocal('TBL', 23, 32, (a, ins) => {
    const nm = [...['R0', 'R1'].flatMap((r) => [0, 1, 2, 3, 4, 5].map((j) => `${r}_${j}`)), ...ZP, ...EZP.slice(0, 5)];
    ins.forEach((x, i) => a.rename(x, nm[i]));
    for (const i of [0, 1, 2, 3]) {
      for (let j = 0; j < 6; j++) (i < 2 ? a.pick.bind(a) : a.roll.bind(a))(`R${i % 2}_${j}`);
      for (const n of i < 2 ? ZP : EZP) (i === 3 ? a.roll.bind(a) : a.pick.bind(a))(n);
      a.invoke('EV', [`vp${i}`, `vm${i}`]);
    }
    for (const n of ZP.slice(0, 5)) a.drop(n);
    a.arrange(['vp0', 'vm1', 'vp2', 'vm3']).invoke('TM', Array.from({length: 16}, (_, n) => `TP_${15 - n}`));
    a.arrange(['vm0', 'vp1', 'vm2', 'vp3']).invoke('TM', Array.from({length: 16}, (_, n) => `TM_${15 - n}`));
  });
  // WSTART (inputs 1..3): F+- = S_start(+-z), S_start = the first state of ST (the predecessor's last state)
  top.defBound('WSTART', (a) => {
    a.roll('ST').push(288).op(OP.SPLIT, 2, 'S', 'ST');
    a.roll('S'); for (let j = 0; j < 6; j++) a.invoke('RD', ['s' + j, 'S']); a.drop('S');
    for (const n of ZP) a.pick(n); a.invoke('EV', ['Fp', 'Fm']);
  });
  const lookup = (s, tbl, idx, out) => {
    assert.equal(s.top(), idx); s.st.pop(); const d0 = s.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(s.depth(`${tbl}_${n}`), d0 + n, 'table layout ' + tbl);
    s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push(out);
  };
  // the event loop (bound; every IF body is a function, so a skipped branch costs two instructions)
  top.defBound('DSTEP', (s) => {
    s.roll('D').push(96).op(OP.SPLIT, 2, 'lb', 'D').roll('lb').push(48).op(OP.SPLIT, 2, 'w0', 'w1');
    s.op(OP.BIN2NUM, 1, 'n1').roll('w0').op(OP.BIN2NUM, 1, 'n0'); // baked slopes: < p < 2^381, so the LE word is a nonnegative number
    s.kernel(kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS});
  });
  const slope = (s) => { s.roll('SL').push(96).op(OP.SPLIT, 2, 'lw', 'SL').roll('lw'); s.invoke('RD', ['l0', 'lw']).invoke('RD', ['l1', 'lw']).drop('lw'); };
  top.defBound('AFFDBL', (t) => { slope(t); t.kernel(kvDblC(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'd0', 'd1'], {iters: ITERS});
    t.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  top.defBound('AFFADD', (u) => { slope(u); u.kernel(kvAddB(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'd0', 'd1', 'ex0', 'ex1'], {iters: ITERS});
    u.op(OP.BOOLOR, 2, 'nz').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
    u.pick('xd0', 's0').pick('xd1', 's1').invoke('DSTEP', undefined, {arrange: true}); });
  top.defBound('BND', (t) => {
    t.fromAlt('R').fromAlt('ST').push(288).op(OP.SPLIT, 2, 'S', 'ST').toAlt('ST');
    for (let j = 0; j < 6; j++) t.invoke('RD', ['s' + j, 'S']);
    t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
    const k = new Kernel(); const R = k.in('R');
    k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
    t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500}); t.toAlt('R');
  });
  top.defBound('LOOP', (a) => {
    const L0 = a.st.slice();
    a.loop((s) => {
      s.invoke('AFFDBL');
      s.pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP');
      // flags f in 16..19 (0x10 | flags: a minimally encoded one-byte number): bit 0 addition, bit 1 boundary after the event
      s.pick('f').push(2).op(OP.MOD, 2, 'odd').ifElse((t) => t.invoke('AFFADD'));
      s.roll('f').push(2).op(OP.DIV, 2, 'f2').push(2).op(OP.MOD, 2, 'bnd');
      s.roll('SCH').push(1).op(OP.SPLIT, 2, 'f', 'SCH').roll('f');
      // GT-GLS: one nibble per digit group from the hashed strings
      s.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
      s.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
      for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
        s.pick('i0', 'x'); lookup(s, T + '0', 'x', 'u'); s.pick('i1', 'x'); lookup(s, T + '1', 'x', 'v');
        s.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
      }
      s.drop('i0').drop('i1');
      s.roll('bnd').ifElse((t) => t.invoke('BND'));
      s.roll('SCH').emit(OP.SIZE); s.st.push('m'); s.op(OP.NOT, 1, 'last');
    }, {onExit: (nat) => { if (nat.join() !== L0.join()) throw {retryL0: nat}; }});
  });
  // FINW (inputs 0..2): every string consumed; the claims R~ | T~ equal the computed values (canonical, 48 B each)
  top.defBound('FINW', (a) => {
    a.fromAlt('R').fromAlt('ST');
    for (const n of ['ST', 'N0', 'N1', 'SL', 'D']) a.roll(n).op(OP.SIZE, 1, n, 'n').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop(n);
    a.roll('R').invoke('C48', ['cw']); for (const n of ['X0', 'X1', 'Y0', 'Y1']) { a.roll(n).invoke('C48', ['w']).op(OP.CAT, 2, 'cw'); }
    a.roll('CL').op(OP.EQUALVERIFY, 2);
    clean(a);
  });

  // clean stack: every check is a VERIFY, so drop everything (2 items per instruction) and leave TRUE
  const clean = (a) => { assert.equal(a.alt.length, 0, 'altstack not empty'); const n = a.st.length; for (let k = 0; k + 1 < n; k += 2) a.emit(OP.TWODROP); if (n % 2) a.emit(OP.DROP); a.emit(OP.TRUE); a.st = ['ok']; };
  const toLoop = (a, L0g) => {
    a.toAlt('ST').push(0, 'R').toAlt();
    const moved = new Set([...HOT, ...STATE]);
    a.arrangeAll(L0g ?? [...a.st.filter((x) => !moved.has(x)), ...HOT, ...STATE]);
  };
  // WORK (inputs 1..3): z~ rho~ and the statement from input 0; this input's nibble slices; the predecessor's last state and
  // T~; own states | slopes; then the setup, the start value F+- = S_start(+-z) and the event loop
  top.defBound('WORK', (a) => {
    a.invoke('READ0', ['z', 'rho', 'xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC', 'NB', 'sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5']);
    // nibble slices of this input's events (event e uses nibble e + 1): bytes [pE0, pE0 + pNE) of N0 and of N1
    a.roll('NB').push(64).op(OP.SPLIT, 2, 'N0', 'N1');
    for (const n of ['N0', 'N1']) a.roll(n).pick('pE0').op(OP.SPLIT, 2, 'x', n).drop('x').roll(n).pick('pNE').op(OP.SPLIT, 2, n, 'x').drop('x');
    a.drop('pE0').drop('pNE');
    // the predecessor: its last state (the start of this input's first identity) and its B-walk end point T~
    a.roll('pH').op(OP.INPUTBYTECODE, 1, 'u').roll('pOS').op(OP.SPLIT, 2, 'x', 'u').drop('x').push(288).op(OP.SPLIT, 2, 'S0', 'u')
      .roll('pOT').op(OP.SPLIT, 2, 'x', 'u').drop('x').push(192).op(OP.SPLIT, 2, 'Tt', 'x').drop('x');
    a.roll('Tt'); for (const n of ['X0', 'X1', 'Y0', 'Y1']) a.invoke('RD', [n, 'Tt']); a.drop('Tt');
    // own region: states | slopes
    a.roll('G').roll('pNS').op(OP.SPLIT, 2, 'STo', 'SL');
    a.roll('S0').roll('STo').op(OP.CAT, 2, 'ST');
    a.arrangeAll(FRAME); assert.equal(a.alt.length, 0);
    a.invoke('SETUP');
    a.invoke('WSTART');
    toLoop(a, L0guess);
    a.invoke('LOOP');
  });

  // ---- role bodies ----
  const roleCode = [];
  const stats = {};
  for (const i of [1, 2, 3, 0]) {
    const ro = ROLES[i]; const ps = pushesOf(i);
    const a = new Asm(ps.map((x) => x.name), ctx);
    let mark = 0; const sect = (name) => { stats[`${i}:${name}`] = a.code.length - mark; mark = a.code.length; a.mark(`r${i}:end:${name}`); };
    // 1. layout pin: item count and the exact size of every push (WQ: its own rules below)
    a.emit(OP.DEPTH, ...pushNum(ps.length), OP.NUMEQUALVERIFY);
    for (const x of ps) { if (x.name === 'WQ') continue; a.roll(x.name).emit(OP.SIZE); a.st.push('sz'); a.push(x.size ?? BLOB_LENS[x.part]).op(OP.NUMEQUALVERIFY, 2); }
    // pushes held for other inputs (their constant pieces, the blob) are not used here
    // a filler push must be all zero bytes (no malleable content)
    for (const x of ps) if (x.name === 'PAD') { a.roll('PAD').push(0).push(x.size).op(OP.NUM2BIN, 2, 'z').op(OP.EQUALVERIFY, 2); }
    for (const x of ps) if (x.name === 'BLOB' || (x.role !== undefined && x.role !== i)) a.drop(x.name);
    // 2. the constant block K_i: pieces in order (own stack or introspection), SHA256 == K_HASH[i]
    PLACE.K[i].forEach(([h, len], j) => {
      const nm = `K${i}_${j}`;
      if (h === i) a.roll(nm); else { a.push(h).op(OP.INPUTBYTECODE, 1, 'u').push(offsetOf(h, nm)).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(len).op(OP.SPLIT, 2, nm, 'x').drop('x'); }
      if (j > 0) a.op(OP.CAT, 2, `K${i}_${j}`);
      a.rename(`K${i}_${j}`, 'K');
    });
    a.pick('K', 'Kc').op(OP.SHA256, 1, 'kh').pushBytes(K_HASH[i]).op(OP.EQUALVERIFY, 2);
    // delta start: (x_j, y_j), resumed as (x, c, l) = (x_j, y_j, 0)
    a.roll('K').push(192).op(OP.SPLIT, 2, 'ks', 'D').roll('ks');
    for (const n of ['dx0', 'dx1', 'dc0', 'dc1']) { a.push(48).op(OP.SPLIT, 2, 'w', 'ks').roll('w'); U(a, n); a.roll('ks'); }
    a.drop('ks').push(0, 'dl0').push(0, 'dl1');
    sect('pin+K');
    if (i === 0) {
      head(a, U, lookup);
      a.pushBytes(Buffer.from([...FLAGS.slice(ro.e0 + 1, ro.e1 + 1), 0].map((x) => x | 16)), 'SCH').push(FLAGS[ro.e0] | 16, 'f');
      a.arrangeAll(FRAME); assert.equal(a.alt.length, 0);
      a.invoke('SETUP');
      sect('setup');
      // initial value: F+ = S_c(-z) Rc'(z) TP0[N0[0]] TP1[N1[0]], F- = S_c(z) Rc'(-z) TM0[..] TM1[..]
      for (let j = 0; j < 6; j++) a.push(VKC.Rconst[j]); for (const n of ZP) a.pick(n); a.invoke('EV', ['rcp', 'rcm']);
      a.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
      a.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
      for (const [F, T, S, Rc] of [['Fp', 'TP', 'Scm', 'rcp'], ['Fm', 'TM', 'Scp', 'rcm']]) {
        a.pick('i0', 'x'); lookup(a, T + '0', 'x', 'u'); a.pick('i1', 'x'); lookup(a, T + '1', 'x', 'v');
        a.op(OP.MUL, 2, 'uv').pick('p').op(OP.MOD, 2, 'uv').pick(S, 'sv').roll(Rc).op(OP.MUL, 2, 'sr').op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
      }
      a.drop('i0').drop('i1');
      toLoop(a, L0guess);
      sect('start');
      a.invoke('LOOP');
      sect('loop');
    } else {
      // role parameters, then the shared worker body: reads, setup, start, the event loop
      const h = i - 1, ph = ROLES[h]; const oS = offsetOf(h, 'G') + (h === 0 ? STMT_SIZE : 0) + 288 * (ph.states.length - 1), oT = offsetOf(h, 'CL') + 48;
      assert.ok(oT > oS + 288);
      a.push(ro.e0 + 1, 'pE0').push(ro.e1 - ro.e0 + 1, 'pNE').push(h, 'pH').push(oS, 'pOS').push(oT - oS - 288, 'pOT').push(288 * ro.states.length, 'pNS');
      a.pushBytes(Buffer.from([...FLAGS.slice(ro.e0 + 1, ro.e1 + 1), 0].map((x) => x | 16)), 'SCH').push(FLAGS[ro.e0] | 16, 'f');
      a.arrangeAll(['CL', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'G', 'pE0', 'pNE', 'pH', 'pOS', 'pOT', 'pNS', 'SCH', 'f']);
      sect('params');
      a.invoke('WORK');
      sect('work');
    }
    if (i < NIN - 1) a.invoke('FINW');
    else { terminal(a); clean(a); }
    sect('fin');
    roleCode[i] = Uint8Array.from(a.code);
    info.marks.push(...a.marks.map((m) => ({...m, role: i})));
  }

  // ---- the head (input 0): pins, transcript, challenges, statement checks, binding, quotient, final identity ----
  function head(a, U, lookup) {
    const ro = ROLES[0];
    let mark = a.code.length; const sect = (name) => { stats[`0:${name}`] = a.code.length - mark; mark = a.code.length; a.mark(`r0:end:${name}`); };
    // WQ: 48 N_MIN <= SIZE <= 48 NQ_MAX, SIZE = 0 (mod 48); canonical: SIZE == 48 N_MIN or the leading word != 0
    a.roll('WQ').emit(OP.SIZE); a.st.push('qsz');
    a.pick('qsz').push(48).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'qok').op(OP.VERIFY, 1);
    a.pick('qsz').push(48 * N_MIN).push(48 * NQ_MAX + 1).op(OP.WITHIN, 3, 'qin').op(OP.VERIFY, 1);
    a.push(48 * N_MIN).op(OP.NUMEQUAL, 2, 'qfloor');
    a.pick('WQ', 'WQs').push(48).op(OP.SPLIT, 2, 'q0', 'qr').drop('qr'); U(a, 'q0'); a.op(OP.ZERONOTEQUAL, 1, 'nz').op(OP.BOOLOR, 2, 'canon').op(OP.VERIFY, 1);
    // siblings: region G_i and the partial-sum claim R~_i, at their pinned offsets
    for (let h = 1; h < NIN; h++) {
      const oG = offsetOf(h, 'G'), oC = offsetOf(h, 'CL'), gs = ROLES[h].regionSize;
      a.push(h).op(OP.INPUTBYTECODE, 1, 'u').push(oG).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(gs).op(OP.SPLIT, 2, 'g', 'u')
        .push(oC - oG - gs).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(48).op(OP.SPLIT, 2, 'Rw' + h, 'x').drop('x');
      a.roll('g').op(OP.SHA256, 1, 'H' + h);
    }
    a.pick('G', 'gc').op(OP.SHA256, 1, 'H0');
    a.pushBytes(TAG, 'tag'); for (let h = 0; h < NIN; h++) a.roll('H' + h).op(OP.CAT, 2, 'tag');
    a.op(OP.SHA256, 1, 'h0');
    a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
    a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').pick('WQ', 'WQc').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
    // challenges: unsigned 256-bit integers (< p, no reduction); z != 0; the claim z~ | rho~ is their exact encoding
    a.roll('zRaw'); U(a, 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
    a.roll('rhoRaw'); U(a, 'rho');
    a.pick('z', 'zz').push(48).op(OP.NUM2BIN, 2, 'zb').pick('rho', 'rr').push(48).op(OP.NUM2BIN, 2, 'rb').op(OP.CAT, 2, 'zr').roll('ZR').op(OP.EQUALVERIFY, 2);
    sect('transcript');
    // statement: coordinates, n_k < r, nibbles (each <= 0x0f), s^c; then states | slopes of input 0
    a.roll('G').push(STMT_SIZE).op(OP.SPLIT, 2, 'u', 'Gr');
    a.roll('u'); for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) a.invoke('RD', [n, 'u']);
    a.push(r, 'r');
    for (const n of ['n0', 'n1']) { a.roll('u').push(32).op(OP.SPLIT, 2, 'w', 'u').roll('w'); U(a, n); a.pick(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
    a.drop('r');
    a.roll('u').push(128).op(OP.SPLIT, 2, 'NB', 'u').roll('NB').pick('NB', 'NBc');
    a.pushBytes(Buffer.alloc(128, 0x0f), 'mk').op(OP.AND, 2, 'NBm').pick('NB', 'NBc2').op(OP.EQUALVERIFY, 2);
    a.roll('u'); for (let j = 0; j < 6; j++) a.invoke('RD', ['sc' + j, 'u']);
    a.op(OP.SIZE, 1, 'u', 'n').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('u');
    a.roll('Gr').push(288 * ro.states.length).op(OP.SPLIT, 2, 'ST', 'SL');
    // curve checks: A, C on y^2 = x^3 + 4; B on y^2 = x^3 + 4(1 + u) (reduced residues)
    a.pick('xA').pick('yA').invoke('G1C', []); a.pick('xC').pick('yC').invoke('G1C', []);
    { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
      const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.small(k.mul(x0, x1), 2));
      const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
      k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(4n))), m(k.sub(k.sub(k.small(k.mul(y0, y1), 2), c1), k.c(4n))));
      a.kernel(k, ['tw0', 'tw1'], {iters: 300}); a.op(OP.NOT, 1, 'ok1').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok0').op(OP.VERIFY, 1); }
    sect('statement');
    // GT-GLS binding over the integers: acc_k = sum_g 2^(63-g) TB[N_k[g]] == n_k, TB[m] = sum_{i in m} |x|^i
    a.push(1, 'T0').push(AX, 'T1').push(AX * AX, 'T2').push(AX * AX * AX, 'T3').invoke('TA', Array.from({length: 16}, (_, n) => `TB_${15 - n}`));
    a.pick('NB', 'Nb').push(64).op(OP.SPLIT, 2, 'Na', 'Nb').push(0, 'acc0').push(0, 'acc1');
    a.loop((s) => {
      for (const [N, acc] of [['Nb', 'acc1'], ['Na', 'acc0']]) {
        s.roll(N).push(1).op(OP.SPLIT, 2, 'b', N).roll('b').op(OP.BIN2NUM, 1, 'x'); lookup(s, 'TB', 'x', 'tb');
        s.roll(acc).op(OP.DUP, 1, acc, acc + 'c').op(OP.ADD, 2, 'a2').op(OP.ADD, 2, acc);
      }
      s.roll('Na').emit(OP.SIZE); s.st.push('m'); s.op(OP.NOT, 1, 'done');
    });
    a.drop('Na').drop('Nb'); a.roll('acc0').roll('n0').op(OP.NUMEQUALVERIFY, 2); a.roll('acc1').roll('n1').op(OP.NUMEQUALVERIFY, 2);
    for (let n = 0; n < 16; n++) a.drop(`TB_${n}`);
    sect('binding');
    // quotient: Q(z) = z q(z^2), Horner over WQ (highest first) 4 words per step, each word < p
    a.push(0).push(144).op(OP.NUM2BIN, 2, 'zeros').push(192).pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(192).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
      .push(192).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
    { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const z2 = m(mul(z, z)), z4 = m(mul(z2, z2)), z6 = m(mul(z4, z2));
      k.output(z2, z4, z6, m(mul(z4, z4)), m(k.add(k.sub(mul(z6, z6), k.small(z6, 2)), k.c(2n)))); a.kernel(k, ['hz2', 'hz4', 'hz6', 'hz8', 'Mz'], {iters: 100}); }
    a.invoke('P', ['p']);
    a.push(0, 'acc');
    a.loop((s) => {
      s.roll('WQ').push(192).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
      for (let j = 0; j < 4; j++) s.invoke('RD', ['q' + j, 'Q4']);
      s.drop('Q4');
      const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
      k.output(k.mod(k.sum(k.mul(I('acc'), E('hz8')), k.mul(I('q0'), E('hz6')), k.mul(I('q1'), E('hz4')), k.mul(I('q2'), E('hz2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
      s.roll('WQ').emit(OP.SIZE); s.st.push('qs'); s.op(OP.NOT, 1, 'done');
    });
    a.drop('WQ');
    // final identity: sum_i rho^(K - c1_i) R~_i == z q(z^2) M(z) (mod p); R~_0 from this input's own claim
    a.pick('CL', 'c0').push(48).op(OP.SPLIT, 2, 'Rw0', 'x').drop('x');
    for (let h = 0; h < NIN; h++) { a.roll('Rw' + h); a.invoke('RD', ['Rt' + h, 'e']); a.op(OP.SIZE, 1, 'e', 'n').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).drop('e'); }
    { const k = new Kernel(); const rho = k.env('rho'); const m = (x) => k.mod(x); const pw = new Map([[1, rho]]);
      const pow = (n) => { if (pw.has(n)) return pw.get(n); const h = Math.floor(n / 2); const v = m(k.mul(pow(h), pow(n - h))); pw.set(n, v); return v; };
      let lhs = k.in('Rt0'); for (let h = 1; h < NIN; h++) lhs = k.add(m(k.mul(lhs, pow(ROLES[h].c1 - ROLES[h - 1].c1))), k.in('Rt' + h));
      k.output(m(k.sub(lhs, k.mul(m(k.mul(k.env('z'), k.in('acc'))), k.in('Mz'))))); a.kernel(k, ['fin'], {iters: 300}); }
    a.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
    for (const n of ['hz2', 'hz4', 'hz6', 'hz8', 'p']) a.drop(n);
    sect('quotient+final');
    // this input's Miller part: nibbles 0 .. e1 + 1 (byte 0: the initial value), B start = B
    a.roll('NB').push(64).op(OP.SPLIT, 2, 'N0', 'N1');
    for (const n of ['N0', 'N1']) a.roll(n).push(ro.e1 + 2).op(OP.SPLIT, 2, n, 'x').drop('x');
    a.pick('xB0', 'X0').pick('xB1', 'X1').pick('yB0', 'Y0').pick('yB1', 'Y1');
  }

  // ---- terminal (input 3): R <- R rho + F+ W(-z) - F- W(z), W = Frob(S_c); endpoint [|x|]B = -psi(B); claim R~_3 ----
  function terminal(a) {
    a.fromAlt('R').fromAlt('ST');
    for (const n of ['ST', 'N0', 'N1', 'SL', 'D']) a.roll(n).op(OP.SIZE, 1, n, 'n').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop(n);
    // gamma1^j and the Frobenius coefficients c_j = Phi(gamma1^j)(z) = g_j0 + g_j1 t
    { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y); const t = k.env('t');
      const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]]; const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
      for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
      const cj = g.map(([g0, g1]) => m(k.add(g0, mul(g1, t))));
      k.output(...g[1], ...g[2], ...cj); a.kernel(k, ['g20', 'g21', 'g30', 'g31', 'c1', 'c2', 'c3', 'c4', 'c5'], {iters: 1000}); }
    // endpoint (affine, exact, reduced): X gamma1^2 - conj(xB) == 0, Y gamma1^3 + conj(yB) == 0
    { const k = new Kernel(); const [X0, X1, Y0, Y1] = ['X0', 'X1', 'Y0', 'Y1'].map((n) => k.in(n));
      const [x0, x1, y0, y1, g20, g21, g30, g31] = ['xB0', 'xB1', 'yB0', 'yB1', 'g20', 'g21', 'g30', 'g31'].map((n) => k.in(n));
      const fs = (a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
      const [u0, u1] = fs(X0, X1, g20, g21), [w0, w1] = fs(Y0, Y1, g30, g31);
      k.output(k.mod(k.sub(u0, x0)), k.mod(k.add(u1, x1)), k.mod(k.add(w0, y0)), k.mod(k.sub(w1, y1)));
      a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1'], {iters: 1000});
      for (let q = 0; q < 4; q++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
    // W(+-z) = Frob(S_c)(+-z): Frob(S_c)(x) = s0 + 2 - x^6 + sum_j s_j c_j x^j
    { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j)); const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], I('c' + j))))];
      const ev = m(k.sum(sc[0], k.c(2n), k.neg(E('z6')), mul(sj[2], E('z2')), mul(sj[4], E('z4'))));
      const od = m(k.sum(mul(sj[1], E('z')), mul(sj[3], E('z3')), mul(sj[5], E('z5'))));
      k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), k.sub(ev, od))), mul(I('Fm'), k.add(ev, od)))));
      a.kernel(k, ['R'], {iters: 1500}); }
    a.roll('R').invoke('C48', ['cw']).roll('CL').op(OP.EQUALVERIFY, 2);
  }

  // ---- blob: definitions (kernels, shared functions, role bodies) + dispatch on the input index ----
  const defs = [...ctx.defs].sort((x, y) => x.id - y.id);
  const pro = [];
  for (const f of defs) pro.push(...pushData(f.code), ...pushNum(f.id), OP.DEFINE);
  for (let i = 0; i < NIN; i++) pro.push(...pushData(roleCode[i]), ...pushNum(1 + i), OP.DEFINE);
  const blob = Uint8Array.from([...pro, OP.INPUTINDEX, OP.ADD1, OP.INVOKE]);
  info.funcs = Object.fromEntries(defs.map((f) => [[...ctx.funcs].find(([, g]) => g === f)[0], f.code.length]));
  info.roles = roleCode.map((c) => c.length); info.sections = stats; info.prologue = pro.length; info.ctx = ctx; info.roleCode = roleCode;
  return {blob, info, L0: L0guess};
}

// ---------------- assemble: blob, R, lockings ----------------
export function buildAll() {
  const prog = buildProgram();
  const blob = prog.blob; const pieces = blobParts(blob);
  // each part is the last push before R in its carrier: its data offset is the fixed prefix plus its own header
  const parts = PLACE.blob.map((carrier, j) => { let off = 0; for (const x of pushesOf(carrier)) { if (x.name === 'BLOB') { off += hdrLen(pieces[j].length); break; } off += hdrLen(x.size) + x.size; } return {carrier, off, len: pieces[j].length}; });
  const R = buildR({parts, hash: sha256(blob)});
  return {...prog, R, parts};
}

// ---------------- kernel variants under evaluation (kbench) ----------------
// B: Karatsuba products sharing (l0 + l1); y3 = c - l x3 with c = l x - y (unreduced); x^2 in 2 products
export function kvDblB() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const ls = add(l0, l1);
  const nx0 = m(sub(mul(ls, sub(l0, l1)), k.small(x0, 2))), nx1 = m(sub(k.small(mul(l0, l1), 2), k.small(x1, 2)));
  const u0 = mul(l0, x0), u1 = mul(l1, x1), u2 = mul(ls, add(x0, x1));
  const c0 = sub(sub(u0, u1), y0), c1 = sub(sub(sub(u2, u0), u1), y1);
  const v0 = mul(l0, nx0), v1 = mul(l1, nx1), v2 = mul(ls, add(nx0, nx1));
  const ny0 = m(sub(c0, sub(v0, v1))), ny1 = m(sub(c1, sub(sub(v2, v0), v1)));
  const w0 = mul(l0, y0), w1 = mul(l1, y1), w2 = mul(ls, add(y0, y1));
  const d0 = m(sub(k.small(sub(w0, w1), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(sub(sub(w2, w0), w1), 2), k.small(mul(x0, x1), 6)));
  const e = m(k.sum(c0, mul(E('t'), m(c1)), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(nx0, nx1, ny0, ny1, m(mul(mul(Fp, Fp), add(e, E('oP')))), m(mul(mul(Fm, Fm), sub(e, E('oP')))), d0, d1);
  return k;
}
kvDblB.sig = ['B', ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'l0', 'l1'], ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'd0', 'd1']];
// C: as B, t * c1 unreduced
export function kvDblC() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const ls = add(l0, l1);
  const nx0 = m(sub(mul(ls, sub(l0, l1)), k.small(x0, 2))), nx1 = m(sub(k.small(mul(l0, l1), 2), k.small(x1, 2)));
  const u0 = mul(l0, x0), u1 = mul(l1, x1), u2 = mul(ls, add(x0, x1));
  const c0 = sub(sub(u0, u1), y0), c1 = sub(sub(sub(u2, u0), u1), y1);
  const v0 = mul(l0, nx0), v1 = mul(l1, nx1), v2 = mul(ls, add(nx0, nx1));
  const ny0 = m(sub(c0, sub(v0, v1))), ny1 = m(sub(c1, sub(sub(v2, v0), v1)));
  const w0 = mul(l0, y0), w1 = mul(l1, y1), w2 = mul(ls, add(y0, y1));
  const d0 = m(sub(k.small(sub(w0, w1), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(sub(sub(w2, w0), w1), 2), k.small(mul(x0, x1), 6)));
  const e = m(k.sum(c0, mul(E('t'), c1), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(nx0, nx1, ny0, ny1, m(mul(mul(Fp, Fp), add(e, E('oP')))), m(mul(mul(Fm, Fm), sub(e, E('oP')))), d0, d1);
  return k;
}
kvDblC.sig = kvDblB.sig;
// D: e = l0 A + l1 B - (y0 + t y1) with A = x0 + t x1 - xz2, B = t x0 - x1 - xz2t (no c); y3 = 3 l x - l^3 - y via l x and l l^2
export function kvDblD() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const ls = add(l0, l1);
  const L0 = m(mul(ls, sub(l0, l1))), L1 = m(k.small(mul(l0, l1), 2)); // l^2
  const nx0 = sub(L0, k.small(x0, 2)), nx1 = sub(L1, k.small(x1, 2));
  const u0 = mul(l0, x0), u1 = mul(l1, x1), u2 = mul(ls, add(x0, x1)); // l x
  const q0 = mul(l0, L0), q1 = mul(l1, L1), q2 = mul(ls, add(L0, L1)); // l l^2
  const ny0 = m(sub(sub(k.small(sub(u0, u1), 3), sub(q0, q1)), y0)), ny1 = m(sub(sub(k.small(sub(sub(u2, u0), u1), 3), sub(sub(q2, q0), q1)), y1));
  const w0 = mul(l0, y0), w1 = mul(l1, y1), w2 = mul(ls, add(y0, y1));
  const d0 = m(sub(k.small(sub(w0, w1), 2), k.small(mul(add(x0, x1), sub(x0, x1)), 3)));
  const d1 = m(sub(k.small(sub(sub(w2, w0), w1), 2), k.small(mul(x0, x1), 6)));
  const t = E('t');
  const A = sub(add(x0, mul(t, x1)), E('xz2')), B = sub(sub(mul(t, x0), x1), E('xz2t'));
  const e = m(sub(add(mul(l0, m(A)), mul(l1, m(B))), add(y0, mul(t, y1))));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(m(nx0), m(nx1), ny0, ny1, m(mul(mul(Fp, Fp), add(e, E('oP')))), m(mul(mul(Fm, Fm), sub(e, E('oP')))), d0, d1);
  return k;
}
kvDblD.sig = kvDblB.sig;
// AFFADD B: Karatsuba with (l0 + l1) shared; d = l ex - (yB - y); y3 = c - l x3, c = l x - y
export function kvAddB() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, y0, y1, l0, l1] = ['X0', 'X1', 'Y0', 'Y1', 'l0', 'l1'].map((n) => I(n));
  const [xq0, xq1, yq0, yq1] = ['xB0', 'xB1', 'yB0', 'yB1'].map(E);
  const ls = add(l0, l1);
  const ex0 = m(sub(xq0, x0)), ex1 = m(sub(xq1, x1));
  const w0 = mul(l0, ex0), w1 = mul(l1, ex1), w2 = mul(ls, add(ex0, ex1));
  const d0 = m(sub(sub(w0, w1), sub(yq0, y0))), d1 = m(sub(sub(sub(w2, w0), w1), sub(yq1, y1)));
  const nx0 = m(sub(sub(mul(ls, sub(l0, l1)), x0), xq0)), nx1 = m(sub(sub(k.small(mul(l0, l1), 2), x1), xq1));
  const u0 = mul(l0, x0), u1 = mul(l1, x1), u2 = mul(ls, add(x0, x1));
  const c0 = sub(sub(u0, u1), y0), c1 = sub(sub(sub(u2, u0), u1), y1);
  const v0 = mul(l0, nx0), v1 = mul(l1, nx1), v2 = mul(ls, add(nx0, nx1));
  const ny0 = m(sub(c0, sub(v0, v1))), ny1 = m(sub(c1, sub(sub(v2, v0), v1)));
  const e = m(k.sum(c0, mul(E('t'), c1), k.neg(mul(E('xz2'), l0)), k.neg(mul(E('xz2t'), l1))));
  k.output(nx0, nx1, ny0, ny1, m(mul(mul(I('Fp'), add(e, E('oP'))), E('Scm'))), m(mul(mul(I('Fm'), sub(e, E('oP'))), E('Scp'))), d0, d1, ex0, ex1);
  return k;
}
kvAddB.sig = ['AB', ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'l0', 'l1'], ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'd0', 'd1', 'ex0', 'ex1']];
// DSTEP B: c recursion with Karatsuba on (l + n) x; e via cz2 (n0 + t n1)
export function kvDsB() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map((n) => I(n));
  const [u0, u1] = kar(k, add(l0, n0), add(l1, n1), x0, x1); const nc0 = m(sub(u0, c0)), nc1 = m(sub(u1, c1));
  const e = m(sub(add(nc0, mul(E('t'), nc1)), mul(E('cz2'), add(n0, mul(E('t'), n1)))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(k.small(mul(n0, n1), 2), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, E('oC')))), m(mul(I('Fm'), sub(e, E('oC')))));
  return k;
}
kvDsB.sig = ['DB', ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm', 'n0', 'n1', 's0', 's1'], ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm']];
