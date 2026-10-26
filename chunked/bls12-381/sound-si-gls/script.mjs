// BLS12-381 SI-GLS redeem script generator (bch-spec). See README.md for the protocol and the spec rules.
// Unlocking: <WQ> <WS> <redeem>. Every item is named on the assembler's symbolic stack.
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum} from './asm.mjs';
import {p, r, ETA, GAMMA1, AX, BITS, NE, VKC} from './math.mjs';
import {TAG, WS_SIZE, WS_LAYOUT, NQ_MAX, NSTATES, NSLOPES, E_A, isBoundary, isAdd, W48} from './protocol.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const D_PIECE = Number(process.env.SIGLS_DPIECE ?? 4);   // delta slopes per pile piece (96 B each)
const WS_PIECE = Number(process.env.SIGLS_WSPIECE ?? 4); // states per altstack piece (288 B each)

// ---------------- kernels (DAGs over named stack items) ----------------
const kit = () => { const k = new Kernel(); return {k, I: (n, s) => k.in(n, s), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)}; };
const sch = (k, a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];          // Fp2 schoolbook (u^2 = -1)
const kar = (k, a0, a1, b0, b1) => { const u0 = k.mul(a0, b0), u1 = k.mul(a1, b1), u2 = k.mul(k.add(a0, a1), k.add(b0, b1)); return [k.sub(u0, u1), k.sub(k.sub(u2, u0), u1)]; };
// affine line (c, -l, 1) at P0 = (xP, yP), times w^3: L(+-z) = e +- oP, e = c0 + t c1 - xz2 l0 - xz2t l1 (xz2 = xP z^2, oP = yP z^3)
// B affine doubling with the witnessed slope l: residues d = 2 y l - 3 x^2 (must be 0), x3 = l^2 - 2x, y3 = l (x - x3) - y,
// F+- <- F+-^2 L(+-z). Z0, Z1 pass through (unused in the affine segment). env: t xz2 xz2t oP
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
  k.output(nx0, nx1, ny0, ny1, I('Z0', 1n), I('Z1', 0n), m(mul(mul(Fp, Fp), add(e, E('oP')))), m(mul(mul(Fm, Fm), sub(e, E('oP')))), d0, d1);
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
  k.output(nx0, nx1, ny0, ny1, I('Z0', 1n), I('Z1', 0n), m(mul(mul(I('Fp'), add(e, E('oP'))), E('Scm'))), m(mul(mul(I('Fm'), sub(e, E('oP'))), E('Scp'))), d0, d1, ex0, ex1);
  return k;
}
// B projective doubling (homogeneous) + line (B - E, -3X^2, H) + F^2; 3b' = 12 + 12u:
//   L(+-z) = [(l00 + t l01) - 3 (xz2 X20 + xz2t X21)] +- [oP H0 + oPt H1]. SL passes through. env: t xz2 xz2t oP oPt
export function kProjDbl() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => I(n));
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(k.small(mul(Y0, Y1), 2));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(k.small(mul(Z0, Z1), 2));
  const E0 = k.small(sub(C0, C1), 12), E1 = k.small(add(C0, C1), 12); // 3b' C, left unreduced (|E| < 24p)
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const [xy0, xy1] = kar(k, X0, X1, Y0, Y1); const XY0 = m(xy0), XY1 = m(xy1);
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const [x30, x31] = kar(k, XY0, XY1, D0, D1);
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(k.small(mul(S0, S1), 2), B1), C1));
  const [z30, z31] = kar(k, k.small(B0, 4), k.small(B1, 4), H0, H1);
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = k.small(mul(X0, X1), 2);
  const e = m(k.sum(sub(B0, E0), mul(E('t'), sub(B1, E1)), k.neg(k.small(k.sum(mul(E('xz2'), X20), mul(E('xz2t'), X21)), 3))));
  const o = m(add(mul(E('oP'), H0), mul(E('oPt'), H1)));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(I('SL', 0n), m(x30), m(x31), Y30, Y31, m(z30), m(z31), m(mul(mul(Fp, Fp), add(e, o))), m(mul(mul(Fm, Fm), sub(e, o))));
  return k;
}
// B projective mixed addition with +B + line (th xB - la yB, -th, la) + c-multiply. SL passes through.
// env: t xz2 xz2t oP oPt xB0 xB1 yB0 yB1 Scp Scm
export function kProjAdd() {
  const {k, I, E, m, mul, add, sub} = kit();
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => I(n));
  const [xq0, xq1, yq0, yq1] = ['xB0', 'xB1', 'yB0', 'yB1'].map(E);
  const [qz0, qz1] = sch(k, yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = sch(k, xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(k.small(mul(th0, th1), 2));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(k.small(mul(la0, la1), 2));
  const [e0, e1] = kar(k, la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = kar(k, Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = kar(k, X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = kar(k, la0, la1, H0, H1);
  const [a0, a1] = sch(k, th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = sch(k, Y0, Y1, E0, E1);
  const [z30, z31] = kar(k, Z0, Z1, E0, E1);
  const [tx0, tx1] = sch(k, th0, th1, xq0, xq1), [ly0, ly1] = sch(k, la0, la1, yq0, yq1);
  const e = m(k.sum(sub(tx0, ly0), mul(E('t'), m(sub(tx1, ly1))), k.neg(mul(E('xz2'), th0)), k.neg(mul(E('xz2t'), th1))));
  const o = m(add(mul(E('oP'), la0), mul(E('oPt'), la1)));
  k.output(I('SL', 0n), m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31), m(mul(mul(I('Fp'), add(e, o)), E('Scm'))), m(mul(mul(I('Fm'), sub(e, o)), E('Scp'))));
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

// ---------------- program ----------------
// Layout during the event loop (bottom -> top):
//   main: [Dp (pile of delta-slope pieces) | setup/terminal env | GT-GLS tables | hot env | loop state]
//   alt:  [WQ | WSp (pile of state pieces) | WSr (current state piece) | R | SCH N0 N1 acc0 acc1 f]
// Loop state: [SL X0 X1 Y0 Y1 Z0 Z1 D dx0 dx1 dc0 dc1 dl0 dl1 Fp Fm] (the fixed point of the event body; the
// affine/projective branches end in the same layout because the projective kernels pass SL through, which is
// empty by then, and the affine ones pass Z through).
export function buildRedeem({stop} = {}) {
  let L0 = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    try { return gen(L0, stop); } catch (e) { if (e.retryL0) { L0 = e.retryL0; continue; } throw e; }
  }
  throw new Error('loop layout did not converge');
}
// event flags (one byte per event): 1 = addition, 2 = state boundary after the event, 4 = affine B step
export const FLAGS = Array.from({length: NE}, (_, e) => (isAdd(e) ? 1 : 0) | (isBoundary(e) ? 2 : 0) | (e < E_A ? 4 : 0));
function gen(L0guess, stop) {
  const a = new Asm(['WQ', 'WS']);
  const info = {sections: {}}; let mark = 0; const section = (name) => { info.sections[name] = (info.sections[name] ?? 0) + a.code.length - mark; mark = a.code.length; a.mark('end:' + name); };
  const STOP = (label) => { if (stop === label) throw {stopAt: label, asm: a}; };
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x); // unsigned LE decode of the top item
  // ---- functions ----
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  // RD: [blob] -> [v, rest]: split one 48-byte LE word, decode unsigned (BIN2NUM(w || 0x00)), require v < p
  a.defLocal('RD', 1, 2, (s) => { s.push(48).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  a.defLocal('TM', 4, 16, (s) => s.kernel(kTable(true), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('TA', 4, 16, (s) => s.kernel(kTable(false), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('G1C', 2, 0, (s) => { const k = new Kernel(); const x = k.in('in0'), y = k.in('in1'); k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(4n))))); s.kernel(k, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('DSTEP', (s) => {
    s.roll('D').emit(OP.SIZE); s.st.push('dsz'); s.op(OP.NOT, 1, 'dempty').ifElse((t) => { t.drop('D').pileTake('Dp', 'D'); });
    s.push(96).op(OP.SPLIT, 2, 'lb', 'D').roll('lb').push(48).op(OP.SPLIT, 2, 'w0', 'w1');
    s.op(OP.BIN2NUM, 1, 'n1').roll('w0').op(OP.BIN2NUM, 1, 'n0'); // baked slopes: < p < 2^381, so the LE word is a nonnegative number
    s.kernel(kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS});
  });
  section('init');

  // ---- 1. layout pin; WQ to the altstack; the delta-slope pile at the bottom; transcript and challenges ----
  a.emit(OP.DEPTH, ...pushNum(2), OP.NUMEQUALVERIFY); // exactly two witness items (with clean stack: layout pinned)
  a.roll('WQ').pick('WQ', 'WQc').roll('WQ').toAlt();  // alt: [WQ]
  const dlams = VKC.lams; assert.equal(dlams.length, 68);
  const pieces = []; for (let i = 0; i < dlams.length; i += D_PIECE) pieces.push(Buffer.concat(dlams.slice(i, i + D_PIECE).flatMap((l) => [W48(l.c0), W48(l.c1)])));
  a.pushPile('Dp', pieces.reverse()); // the first piece on top
  a.roll('WS').roll('WQc');
  a.pick('WS').emit(OP.SIZE); a.st.push('sz'); a.push(WS_SIZE).op(OP.NUMEQUALVERIFY, 2).drop();
  a.pushBytes(TAG, 'tag').pick('WS').op(OP.CAT, 2, 'tw').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.pick('WQc', 'WQs').emit(OP.SIZE); a.st.push('qsz'); a.drop('WQs');
  a.pick('qsz').push(48).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'qok').op(OP.VERIFY, 1);
  a.push(1).push(48 * NQ_MAX + 1).op(OP.WITHIN, 3, 'qin').op(OP.VERIFY, 1);
  // canonical n_q: the leading (highest) quotient word is nonzero (unsigned decode; < p is enforced by the Horner loop)
  a.pick('WQc', 'WQs').push(48).op(OP.SPLIT, 2, 'q0', 'qr').drop('qr'); U('q0'); a.op(OP.ZERONOTEQUAL, 1, 'nz').op(OP.VERIFY, 1);
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').roll('WQc').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
  // challenges: unsigned 256-bit integers (< p, no reduction); z != 0
  a.roll('zRaw'); U('z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rho');
  a.invoke('P', ['p']);
  section('transcript');
  STOP('transcript');

  // ---- 2. parse WS: statement, public inputs, GLS strings, residue root, states, slopes; checks ----
  a.roll('WS');
  for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) a.invoke('RD', [n, 'WS']);
  a.push(r, 'r');
  for (const n of ['n0', 'n1']) { a.roll('WS').push(32).op(OP.SPLIT, 2, 'w', 'WS').roll('w'); U(n); a.pick(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
  a.drop('r');
  // nibble strings: 128 bytes & 0x0f (canonical: every nibble < 16)
  a.roll('WS').push(128).op(OP.SPLIT, 2, 'G', 'WS').roll('G').pick('G', 'Gc');
  a.pushBytes([0x0f, 0x0f], 'mk'); for (let i = 0; i < 6; i++) a.pick('mk', 'mk2').op(OP.CAT, 2, 'mk');
  a.op(OP.AND, 2, 'Gm').pick('G', 'Gc2').op(OP.EQUALVERIFY, 2);
  a.roll('G').push(64).op(OP.SPLIT, 2, 'N0', 'N1');
  a.roll('WS'); for (let j = 0; j < 6; j++) a.invoke('RD', ['sc' + j, 'WS']);
  // states | slopes
  a.push(288 * NSTATES).op(OP.SPLIT, 2, 'WS', 'SL');
  // the 32 states: pieces of WS_PIECE states to the altstack, last piece first (the first piece ends on top)
  { const cuts = []; for (let k = 0; k < NSTATES; k += WS_PIECE) cuts.push(k * 288);
    a.roll('WS');
    for (let i = cuts.length - 1; i >= 1; i--) { a.push(cuts[i]).op(OP.SPLIT, 2, 'WS', 'tail').toAlt(); a.alt.pop(); }
    a.toAlt(); a.alt.pop(); a.pushAltPile('WSp', cuts.length); }
  a.push(0, 'WSr').toAlt().push(0, 'R').toAlt(); // alt: [WQ, WSp, WSr, R]
  // curve checks: A, C on y^2 = x^3 + 4; B on y^2 = x^3 + 4(1 + u)
  a.pick('xA').pick('yA').invoke('G1C', []); a.pick('xC').pick('yC').invoke('G1C', []);
  { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
    const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.small(k.mul(x0, x1), 2));
    const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
    k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(4n))), m(k.sub(k.sub(k.small(k.mul(y0, y1), 2), c1), k.c(4n))));
    a.kernel(k, ['tw0', 'tw1'], {iters: 300}); a.op(OP.NOT, 1, 'ok1').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok0').op(OP.VERIFY, 1); }
  section('parse+checks');
  STOP('parsed');

  // ---- 3. powers of z and eta z; t = z^6 - 1; gamma1^j and the Frobenius coefficients c_j = Phi(gamma1^j)(z) ----
  { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
    const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); // eta^2 = eta - 1, eta^3 = -1
    const t = k.sub(z6, k.c(1n)); const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]];
    const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
    for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
    const cj = g.map(([g0, g1]) => m(k.add(g0, mul(g1, t))));
    k.output(z2, z3, z4, z5, z6, t, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))), ...g[1], ...g[2], ...cj);
    a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 't', 'ez', 'ez2', 'ez3', 'ez4', 'ez5', 'g20', 'g21', 'g30', 'g31', 'c1', 'c2', 'c3', 'c4', 'c5'], {iters: 1500}); }
  const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of ZP) a.pick(n); a.invoke('EV', ['Scp', 'Scm']);
  for (let j = 0; j < 6; j++) a.push(VKC.Rconst[j]); for (const n of ZP) a.pick(n); a.invoke('EV', ['rcp', 'rcm']);
  section('powers');
  // ---- 4. GT-GLS tables: TP_k[n] = prod_{i in n} factor_{k,i}(z), TM_k at -z, TB[n] = sum_{i in n} T^i (exact integers) ----
  // factor_{k,i}(X) = R_{k,i%2}((-1)^i eta^[i>=2] X): at +z: R0(z), R1(-z), R0(eta z), R1(-eta z); at -z: R0(-z), R1(z), R0(-eta z), R1(eta z)
  a.push(1, 'T0').push(AX, 'T1').pick('T1', 'q').pick('T1', 'q2').op(OP.MUL, 2, 'T2').pick('T2', 'q').pick('T1', 'q2').op(OP.MUL, 2, 'T3').invoke('TA', Array.from({length: 16}, (_, n) => `TB_${15 - n}`));
  for (const k of [0, 1]) {
    for (const i of [0, 1]) for (let j = 0; j < 6; j++) a.push(VKC.R[k][i][j], `R${k}${i}_${j}`);
    for (const i of [0, 1, 2, 3]) {
      for (let j = 0; j < 6; j++) (i < 2 ? a.pick.bind(a) : a.roll.bind(a))(`R${k}${i % 2}_${j}`);
      for (const n of i < 2 ? ZP : EZP) a.pick(n);
      a.invoke('EV', [`vp${i}`, `vm${i}`]);
    }
    a.arrange(['vp0', 'vm1', 'vp2', 'vm3']).invoke('TM', Array.from({length: 16}, (_, n) => `TP${k}_${15 - n}`));
    a.arrange(['vm0', 'vp1', 'vm2', 'vp3']).invoke('TM', Array.from({length: 16}, (_, n) => `TM${k}_${15 - n}`));
  }
  section('gls-tables');
  STOP('tables');

  // ---- 5. loop environment and state ----
  const lookup = (s, tbl, idx, out) => {
    assert.equal(s.top(), idx); s.st.pop(); const d0 = s.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(s.depth(`${tbl}_${n}`), d0 + n, 'table layout ' + tbl);
    s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push(out);
  };
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const t = k.env('t'), z2 = k.env('z2'), z3 = k.env('z3');
    const xz2 = m(mul(k.env('xA'), z2)), oP = m(mul(k.neg(k.env('yA')), z3)), cz2 = m(mul(k.env('xC'), z2));
    k.output(xz2, m(mul(xz2, t)), oP, m(mul(oP, t)), cz2, m(mul(cz2, t)), m(mul(k.env('yC'), z3)));
    a.kernel(k, ['xz2', 'xz2t', 'oP', 'oPt', 'cz2', 'cz2t', 'oC'], {iters: 500}); }
  // initial values: F+ = S_c(-z) Rc'(z) TP0[N0[0]] TP1[N1[0]], F- = S_c(z) Rc'(-z) TM0[..] TM1[..]; acc_k = TB[N_k[0]]
  a.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
  a.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
  for (const k of [0, 1]) { a.pick('i' + k, 'x'); lookup(a, 'TB', 'x', 'acc' + k); }
  for (const [F, T, S, Rc] of [['Fp', 'TP', 'Scm', 'rcp'], ['Fm', 'TM', 'Scp', 'rcm']]) {
    a.pick('i0', 'x'); lookup(a, T + '0', 'x', 'u'); a.pick('i1', 'x'); lookup(a, T + '1', 'x', 'v');
    a.op(OP.MUL, 2, 'uv').pick('p').op(OP.MOD, 2, 'uv').pick(S, 'sv').roll(Rc).op(OP.MUL, 2, 'sr').op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
  }
  a.drop('i0').drop('i1');
  // GLS/flag group lives on the altstack between events: alt = [WQ, WSp, WSr, R, SCH, N0, N1, acc0, acc1, f]
  a.pushBytes(Buffer.from([...FLAGS.slice(1), 0]), 'SCH').toAlt('SCH').toAlt('N0').toAlt('N1').toAlt('acc0').toAlt('acc1').push(FLAGS[0], 'f').toAlt();
  a.pick('xB0', 'X0').pick('xB1', 'X1').pick('yB0', 'Y0').pick('yB1', 'Y1').push(1, 'Z0').push(0, 'Z1');
  a.push(VKC.deltaAff.x.c0, 'xd0').push(VKC.deltaAff.x.c1, 'xd1');
  a.push(0, 'D').pick('xd0', 'dx0').pick('xd1', 'dx1').push(VKC.deltaAff.y.c0, 'dc0').push(VKC.deltaAff.y.c1, 'dc1').push(0, 'dl0').push(0, 'dl1');
  const HOT = ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'Scp', 'Scm', 'oC', 'cz2', 'cz2t', 'oPt', 'oP', 'xz2', 'xz2t', 't', 'p'];
  const STATE = ['SL', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'];
  const moved = new Set([...HOT, ...STATE]);
  const L0 = L0guess ?? [...a.st.filter((x) => !moved.has(x)), ...HOT, ...STATE];
  a.arrangeAll(L0);
  a.piles.set('Dp', null); a.piles.set('WSp', null); // pile sizes vary inside the loop
  section('loop-setup');
  STOP('preloop');

  // ---- 6. the event loop (63 events) ----
  const affine = (s) => s.peekAlt('ft').push(4).op(OP.GREATERTHANOREQUAL, 2, 'aff');
  const slope = (s) => { s.roll('SL'); s.invoke('RD', ['l0', 'SL']).invoke('RD', ['l1', 'SL']); };
  // every IF body is a function (OP_INVOKE): a skipped branch then costs two instructions instead of its whole body
  a.defBound('AFFDBL', (t) => { slope(t); t.kernel(kAffDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm', 'd0', 'd1'], {iters: ITERS});
    t.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('PROJDBL', (t) => { t.kernel(kProjDbl(), ['SL', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS}); });
  a.defBound('AFFADD', (u) => { slope(u); u.kernel(kAffAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm', 'd0', 'd1', 'ex0', 'ex1'], {iters: ITERS});
    u.op(OP.BOOLOR, 2, 'nz').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('PROJADD', (u) => { u.kernel(kProjAdd(), ['SL', 'X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS}); });
  a.defBound('BND', (t) => {
    t.fromAlt('R').fromAlt('WSr').emit(OP.SIZE); t.st.push('wsz'); t.op(OP.NOT, 1, 'wempty').ifElse((u) => { u.drop('WSr').altPileTake('WSr'); });
    t.push(288).op(OP.SPLIT, 2, 'S', 'WSr').toAlt('WSr');
    for (let j = 0; j < 6; j++) t.invoke('RD', ['s' + j, 'S']);
    t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
    const k = new Kernel(); const R = k.in('R');
    k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
    t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500}); t.toAlt('R');
  });
  a.loop((s) => {
    s.mark('bdbl'); affine(s);
    s.ifElse((t) => t.invoke('AFFDBL'), (t) => t.invoke('PROJDBL'));
    s.mark('dstep').pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP');
    s.mark('add'); s.peekAlt('ft').push(2).op(OP.MOD, 2, 'odd').ifElse((t) => {
      affine(t);
      t.ifElse((u) => u.invoke('AFFADD'), (u) => u.invoke('PROJADD'));
      t.pick('xd0', 's0').pick('xd1', 's1').invoke('DSTEP');
    });
    // GLS/flag group out of the altstack; this event's boundary bit; next flag (SCH: flags of events 1..62 and a dummy)
    s.mark('digit'); for (const n of ['f', 'acc1', 'acc0', 'N1', 'N0', 'SCH']) s.fromAlt(n);
    s.roll('f').push(2).op(OP.DIV, 2, 'f2').push(2).op(OP.MOD, 2, 'bnd');
    s.roll('SCH').push(1).op(OP.SPLIT, 2, 'fb', 'SCH').roll('fb').op(OP.BIN2NUM, 1, 'f');
    // GT-GLS: one nibble per digit group from the hashed strings; binding accumulators, then F
    s.mark('gls');
    s.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
    s.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
    for (const k of [0, 1]) { s.roll('acc' + k).pick('acc' + k, 'accc').op(OP.ADD, 2, 'a2').pick('i' + k, 'x'); lookup(s, 'TB', 'x', 'tb'); s.op(OP.ADD, 2, 'acc' + k); }
    for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
      s.pick('i0', 'x'); lookup(s, T + '0', 'x', 'u'); s.pick('i1', 'x'); lookup(s, T + '1', 'x', 'v');
      s.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
    }
    s.drop('i0').drop('i1');
    s.mark('bnd'); s.roll('bnd');
    s.ifElse((t) => t.invoke('BND'));
    s.mark('loopend').pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
    for (const n of ['SCH', 'N0', 'N1', 'acc0', 'acc1', 'f']) s.toAlt(n);
    s.roll('last');
  }, {onExit: (nat) => { if (nat.join() !== L0.join()) throw {retryL0: nat}; }});
  section('loop');
  STOP('postloop');

  // ---- 7. terminal ----
  // all affine slopes and all 68 delta slopes consumed
  a.roll('SL').op(OP.SIZE, 1, 'SL', 'sl').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('SL');
  a.roll('D').op(OP.SIZE, 1, 'D', 'dl').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('D'); a.pileDone('Dp');
  // endpoint [T]B = -psi(B): X gamma1^2 - conj(xB) Z == 0, Y gamma1^3 + conj(yB) Z == 0 (Fp2, reduced), Z != 0
  { const k = new Kernel(); const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => k.in(n));
    const [x0, x1, y0, y1, g20, g21, g30, g31] = ['xB0', 'xB1', 'yB0', 'yB1', 'g20', 'g21', 'g30', 'g31'].map((n) => k.env(n));
    const fs = (a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
    const conjMul = (a0, a1, b0, b1) => [k.add(k.mul(a0, b0), k.mul(a1, b1)), k.sub(k.mul(a0, b1), k.mul(a1, b0))]; // conj(a) b
    const [u0, u1] = fs(X0, X1, g20, g21), [v0, v1] = conjMul(x0, x1, Z0, Z1);
    const [w0, w1] = fs(Y0, Y1, g30, g31), [q0, q1] = conjMul(y0, y1, Z0, Z1);
    k.output(k.mod(k.sub(u0, v0)), k.mod(k.sub(u1, v1)), k.mod(k.add(w0, q0)), k.mod(k.add(w1, q1)), k.mod(Z0), k.mod(Z1));
    a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1', 'ez0', 'ez1'], {iters: 1000});
    a.op(OP.BOOLOR, 2, 'znz').op(OP.VERIFY, 1); for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
  a.fromAlt('f').fromAlt('acc1').fromAlt('acc0').fromAlt('N1').fromAlt('N0').fromAlt('SCH');
  for (const n of ['f', 'N1', 'N0', 'SCH']) a.drop(n);
  a.fromAlt('R').fromAlt('WSr').drop('WSr'); a.pileDone('WSp'); a.fromAlt('WQ'); // all 32 states consumed (WS size pinned)
  // W(+-z) = Frob(S_c)(+-z) = [c^p]: Frob(S_c)(x) = s0 + 2 - x^6 + sum_j s_j c_j x^j;  R <- R rho + F+ W(-z) - F- W(z)
  { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j)); const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], E('c' + j))))];
    const ev = m(k.sum(sc[0], k.c(2n), k.neg(E('z6')), mul(sj[2], E('z2')), mul(sj[4], E('z4'))));
    const od = m(k.sum(mul(sj[1], E('z')), mul(sj[3], E('z3')), mul(sj[5], E('z5'))));
    k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), k.sub(ev, od))), mul(I('Fm'), k.add(ev, od)))));
    a.kernel(k, ['R'], {iters: 1500}); }
  // GT-GLS binding (exact integers): acc_k = sum_i a_{k,i} T^i == n_k
  for (const k of [0, 1]) a.roll('acc' + k).roll('n' + k).op(OP.NUMEQUALVERIFY, 2);
  section('terminal');
  // ---- 8. quotient: Q(z) = z q(z^2), Horner over WQ (highest first) 4 words per step, each word < p ----
  // left-pad WQ with zero words to a multiple of 4 words (does not change the polynomial)
  a.push(0).push(144).op(OP.NUM2BIN, 2, 'zeros').push(192).pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(192).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
    .push(192).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
  { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
  a.push(0, 'acc');
  a.loop((s) => {
    s.roll('WQ').push(192).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
    for (let j = 0; j < 4; j++) s.invoke('RD', ['q' + j, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQ', 'WQc').op(OP.SIZE, 1, 'WQc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQ');
  { const k = new Kernel(); const z6 = k.env('z6');
    const Mz = k.add(k.sub(k.mul(z6, z6), k.small(z6, 2)), k.c(2n)); // M(z) = z^12 - 2 z^6 + 2
    k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
  a.op(OP.NOT, 1, 'result');
  section('final');
  // clean stack: drop everything below the result (the entry DEPTH check pins the item count)
  assert.equal(a.alt.length, 0, 'altstack not empty');
  a.op(OP.TOALT, 1); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result'];
  section('cleanup');
  const code = Uint8Array.from([...a.prologue(), ...a.code]);
  info.marks = a.marks.map((m) => ({name: m.name, off: m.off + a.prologue().length}));
  info.prologue = a.prologue().length; info.funcs = Object.fromEntries([...a.ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]));
  info.L0 = L0;
  return {redeem: code, info};
}

// assemble a partial program for debugging: everything up to a STOP label (stack left as is)
export function buildPartial(label) {
  try { buildRedeem({stop: label}); } catch (e) { if (!e.stopAt) throw e; return {code: Uint8Array.from([...e.asm.prologue(), ...e.asm.code]), names: e.asm.st.slice()}; }
  throw new Error('label not reached: ' + label);
}
