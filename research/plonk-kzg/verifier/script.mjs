// Single-input CashVM verifier for gnark v0.16.4 PLONK/KZG proofs (BN254, SHA-256 transcript, no BSB22),
// generated per verifying key (the VK is baked in, as in the Groth16 entries). See README.md.
//
// Unlocking (bottom -> top): <SL_1> .. <SL_m> <WQ> <WS> <X> <PI> <PROOF> [<PAD>] <redeem>
//   SL_i  : the MSM slope stream (32-byte LE words, < p), m >= 1 pieces, each a nonzero multiple of 32 B; SL_1 first
//   WQ, WS: the SI quotient and the SI states (residue root + 33 states), as in SI-GLS
//   X     : Lambda' (64 B, gnark raw BE: hashed into v) || Fr batch inverse (32 B LE, < r) || zi_R || zi_L (32 B LE, < p,
//           present when the P_right / P* chain starts in Jacobian)
//   PI    : the public inputs, 32 B BE each (gnark Marshal); PROOF: 768 B (gnark MarshalSolidity layout)
//   PAD   : the 100 KB regime only: an ignored push that buys op-cost budget (DROPped first)
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {p, r, mod, ETA, GAMMA1, DIGITS, NE, GLV, OFFSET, aff} from './math.mjs';
import {W, TBL, NW, NWR, baseNames, corr, le32, PROOF_PTS} from './plonk.mjs';
import {TAG, WS_SIZE, NQ_MAX, NSTATES, chains} from './si.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 2500);
export const SL_PIECE = 16; // slopes per stream piece (512 B)
export const D_PIECE = 4;   // chain steps per pile piece (4 x 128 B)
const WS_PIECE = 4;

// ---------------- kernels ----------------
const ops = (k) => ({I: (n) => k.in(n), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)});
// affine add with witnessed slope l: l (x2 - x1) == y2 - y1, x2 != x1
function kAffAdd() { const k = new Kernel(); const {I, m, mul, sub} = ops(k); const [x1, y1, x2, y2, l] = ['in0', 'in1', 'in2', 'in3', 'l'].map(I);
  const x3 = m(sub(sub(mul(l, l), x1), x2)); return k.output(x3, m(sub(mul(l, sub(x1, x3)), y1)), m(sub(mul(l, sub(x2, x1)), sub(y2, y1))), m(sub(x2, x1))); }
// affine doubling with witnessed slope l: 2 y l == 3 x^2 (y != 0 on G1)
function kAffDbl() { const k = new Kernel(); const {I, m, mul, sub} = ops(k); const [x, y, l] = ['in0', 'in1', 'l'].map(I);
  const x3 = m(sub(mul(l, l), k.small(x, 2))); return k.output(x3, m(sub(mul(l, sub(x, x3)), y)), m(sub(k.small(mul(y, l), 2), k.small(mul(x, x), 3)))); }
// Jacobian doubling (dbl-2009-l) and mixed addition (madd-2007-bl); Z = 0 is absorbing (exceptional cases end at Z = 0)
function kJDbl() { const k = new Kernel(); const {I, m, mul, add, sub} = ops(k); const [X, Y, Z] = ['in0', 'in1', 'in2'].map(I);
  const A = m(mul(X, X)), B = m(mul(Y, Y)), C = m(mul(B, B)); const xb = add(X, B); const D = m(k.small(sub(sub(mul(xb, xb), A), C), 2));
  const E = k.small(A, 3); const F = m(mul(E, E)); const X3 = m(sub(F, add(D, D)));
  return k.output(X3, m(sub(mul(E, sub(D, X3)), k.small(C, 8))), m(k.small(mul(Y, Z), 2))); }
function kJMAdd() { const k = new Kernel(); const {I, m, mul, add, sub} = ops(k); const [X1, Y1, Z1, x2, y2] = ['in0', 'in1', 'in2', 'in3', 'in4'].map(I);
  const Z1Z1 = m(mul(Z1, Z1)); const U2 = m(mul(x2, Z1Z1)); const S2 = m(mul(mul(y2, Z1), Z1Z1));
  const H = m(sub(U2, X1)); const HH = m(mul(H, H)); const I4 = k.small(HH, 4); const J = m(mul(H, I4));
  const rr = k.small(sub(S2, Y1), 2); const V = m(mul(X1, I4)); const X3 = m(sub(sub(mul(rr, rr), J), add(V, V)));
  const zh = add(Z1, H); return k.output(X3, m(sub(mul(rr, sub(V, X3)), k.small(mul(Y1, J), 2))), m(sub(sub(mul(zh, zh), Z1Z1), HH))); }
// Jacobian -> affine with witnessed zi: Z zi == 1
function kConv() { const k = new Kernel(); const {I, m, mul, sub} = ops(k); const [X, Y, Z, zi] = ['in0', 'in1', 'in2', 'in3'].map(I);
  const z2 = m(mul(zi, zi)); return k.output(m(mul(X, z2)), m(mul(Y, m(mul(z2, zi)))), m(sub(mul(Z, zi), k.c(1n)))); }
// KZG event: both fixed chains (state x, c, l; slope n; x-shift s), lines at P* (chain a) and P_right (chain b), F update
function chainPart(k, t) {
  const {I, E, m, mul, add, sub} = ops(k); const nm = (s) => s + t;
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map((s) => I(nm(s)));
  const a0 = add(l0, n0), a1 = add(l1, n1); const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const o = m(sub(add(mul(E('z3'), nc0), mul(E('z3t'), nc1)), add(mul(E(nm('cz')), n0), mul(E(nm('czt')), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  return {state: [nx0, nx1, nc0, nc1, n0, n1], Lp: add(E(nm('y')), o), Lm: sub(E(nm('y')), o)};
}
export const EV_OUTS = ['dx0a', 'dx1a', 'dc0a', 'dc1a', 'dl0a', 'dl1a', 'dx0b', 'dx1b', 'dc0b', 'dc1b', 'dl0b', 'dl1b', 'Fp', 'Fm'];
function kEvent(dbl) {
  const k = new Kernel(); const {I, m, mul} = ops(k); const a = chainPart(k, 'a'), b = chainPart(k, 'b'); const Fp = I('Fp'), Fm = I('Fm');
  const fp = dbl ? m(mul(m(mul(mul(Fp, Fp), a.Lp)), b.Lp)) : m(mul(m(mul(mul(Fp, a.Lp), b.Lp)), I('cp')));
  const fm = dbl ? m(mul(m(mul(mul(Fm, Fm), a.Lm)), b.Lm)) : m(mul(m(mul(mul(Fm, a.Lm), b.Lm)), I('cm')));
  return k.output(...a.state, ...b.state, fp, fm);
}
function kEval() { const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5])); const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od)); }

// ---------------- program ----------------
export function buildRedeem(vk, opts = {}) {
  let L0 = null;
  for (let attempt = 0; attempt < 8; attempt++) { try { return gen(vk, opts, L0); } catch (e) { if (e.retryL0) { L0 = e.retryL0; continue; } throw e; } }
  throw new Error('loop layout did not converge');
}
export const xSize = ({J = 0, JR = 0} = {}) => 96 + (JR > 0 ? 32 : 0) + (J > 0 ? 32 : 0);

function gen(vk, {J = 0, JR = 0, pad = false, stop} = {}, L0guess) {
  const names = baseNames(vk), NB = names.length, nbm = NB - 1, k = vk.nbPublic;
  const CH = chains(vk);
  const a = new Asm(['SLb', 'WQ', 'WS', 'X', 'PI', 'PROOF', ...(pad ? ['PAD'] : [])]);
  const info = {sections: {}}; let mark = 0; const section = (name) => { info.sections[name] = (info.sections[name] ?? 0) + a.code.length - mark; mark = a.code.length; a.mark('end:' + name); };
  const STOP = (label) => { if (stop === label) throw {stopAt: label, asm: a}; };
  const raw = (st, ...b) => { st.emit(...b); };
  // ---- local functions ----
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  a.defLocal('R', 0, 1, (s) => s.push(r, 'r'));
  const dec = (s, lim, be) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w'); if (be) s.op(OP.REVERSEBYTES, 1, 'w'); s.pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke(lim, ['m']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); };
  a.defLocal('DBP', 1, 2, (s) => dec(s, 'P', true));  // BE word < p from the front: [blob] -> [v, rest]
  a.defLocal('DBR', 1, 2, (s) => dec(s, 'R', true));  // BE word < r
  a.defLocal('DLP', 1, 2, (s) => dec(s, 'P', false)); // LE word < p
  a.defLocal('DLR', 1, 2, (s) => dec(s, 'R', false)); // LE word < r
  a.defLocal('BMR', 1, 1, (s) => { s.op(OP.REVERSEBYTES, 1, 'w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v').invoke('R', ['r']).op(OP.MOD, 2, 'x'); }); // digest -> BE mod r
  a.defLocal('G1C', 2, 0, (s) => { const kk = new Kernel(); const x = kk.in('in0'), y = kk.in('in1'); kk.output(kk.mod(kk.sub(kk.mul(y, y), kk.add(kk.mul(kk.mul(x, x), x), kk.c(3n))))); s.kernel(kk, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  // slope from the stream (altstack top = current piece; refill from the next piece; the bottom sentinel is empty, so
  // reading past the end fails at SPLIT); the slope must be < p
  const slope = (s) => { s.emit(OP.FROMALT, OP.SIZE, OP.NOT, OP.IF, OP.DROP, OP.FROMALT, OP.ENDIF, ...pushNum(32), OP.SPLIT, OP.TOALT); s.st.push('lw');
    s.pushBytes([0]).op(OP.CAT, 2, 'lw0').op(OP.BIN2NUM, 1, 'l').pick('l').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); };
  a.defLocal('ADD', 4, 2, (s) => { slope(s); s.kernel(kAffAdd(), ['x3', 'y3', 'chk', 'ex'], {iters: ITERS}); s.op(OP.ZERONOTEQUAL, 1, 'q').op(OP.VERIFY, 1).op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  a.defLocal('DBL', 2, 2, (s) => { slope(s); s.kernel(kAffDbl(), ['x3', 'y3', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  a.defLocal('JDBL', 3, 3, (s) => s.kernel(kJDbl(), ['X', 'Y', 'Z'], {iters: ITERS}));
  a.defLocal('JMADD', 5, 3, (s) => s.kernel(kJMAdd(), ['X', 'Y', 'Z'], {iters: ITERS}));
  a.defLocal('CONV', 4, 2, (s) => { s.kernel(kConv(), ['x', 'y', 'chk'], {iters: 300}); s.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  a.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  section('init');

  // ---- 1. layout: pad, slope stream to the altstack over an empty sentinel ----
  const nFixed = 5;
  a.emit(OP.DEPTH, ...pushNum(nFixed + 1 + (pad ? 1 : 0)), OP.GREATERTHANOREQUAL, OP.VERIFY);
  if (pad) a.drop('PAD');
  a.emit(OP['0'], OP.TOALT, OP.BEGIN, ...pushNum(nFixed), OP.ROLL, OP.SIZE, OP.DUP, OP.ZERONOTEQUAL, OP.VERIFY, ...pushNum(32), OP.MOD, OP.NOT, OP.VERIFY, OP.TOALT,
    OP.DEPTH, ...pushNum(nFixed), OP.NUMEQUAL, OP.UNTIL);
  a.st.splice(a.st.indexOf('SLb'), 1); a.alt.push('SLSTREAM');
  section('layout');

  // ---- 2. statement: sizes, decoding, curve checks ----
  a.pick('PROOF').op(OP.SIZE, 1, 'PROOF_', 'sz').op(OP.NIP, 2, 'sz').push(768).op(OP.NUMEQUALVERIFY, 2);
  a.pick('PI').op(OP.SIZE, 1, 'PI_', 'sz').op(OP.NIP, 2, 'sz').push(32 * k).op(OP.NUMEQUALVERIFY, 2);
  a.pick('X').op(OP.SIZE, 1, 'X_', 'sz').op(OP.NIP, 2, 'sz').push(xSize({J, JR})).op(OP.NUMEQUALVERIFY, 2);
  a.pick('PROOF', 'pb');
  const PN = ['Lx', 'Ly', 'Rx', 'Ry', 'Ox', 'Oy', 'H0x', 'H0y', 'H1x', 'H1y', 'H2x', 'H2y'];
  for (const n of PN) a.invoke('DBP', [n, 'pb']);
  for (const n of ['l', 'rr', 'o', 's1', 's2']) a.invoke('DBR', [n, 'pb']);
  a.invoke('DBP', ['Zx', 'pb']).invoke('DBP', ['Zy', 'pb']).invoke('DBR', ['zu', 'pb']);
  for (const n of ['Wzx', 'Wzy', 'Wzwx', 'Wzwy']) a.invoke('DBP', [n, 'pb']);
  a.drop('pb');
  a.pick('PI', 'pib'); for (let i = 0; i < k; i++) a.invoke('DBR', ['pub' + i, 'pib']); a.drop('pib');
  a.pick('X', 'xb'); a.invoke('DBP', ['Lamx', 'xb']).invoke('DBP', ['Lamy', 'xb']).invoke('DLR', ['invP', 'xb']);
  if (JR > 0) a.invoke('DLP', ['ziR', 'xb']); if (J > 0) a.invoke('DLP', ['ziL', 'xb']); a.drop('xb');
  for (const P of ['L', 'R', 'O', 'H0', 'H1', 'H2', 'Z', 'Wz', 'Wzw', 'Lam']) a.pick(P + 'x').pick(P + 'y').invoke('G1C', []);
  section('decode');
  STOP('decode');

  // ---- 3. gnark transcript ----
  const vkBytes = Buffer.concat([Buffer.from('gamma'), vk.rawAll]);
  a.pushBytes(vkBytes, 'GV').pick('GV', 'h').pick('PI').op(OP.CAT, 2, 'h').pick('PROOF').push(192).op(OP.SPLIT, 2, 'lro', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'gRaw');
  a.pushBytes(Buffer.from('beta')).pick('gRaw').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'bRaw');
  a.pushBytes(Buffer.from('alpha')).pick('bRaw').op(OP.CAT, 2, 'h').pick('PROOF').push(544).op(OP.SPLIT, 2, 'x', 'zz').drop('x').push(64).op(OP.SPLIT, 2, 'zr', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'aRaw');
  a.pushBytes(Buffer.from('zeta')).pick('aRaw').op(OP.CAT, 2, 'h').pick('PROOF').push(192).op(OP.SPLIT, 2, 'x', 'hh').drop('x').push(192).op(OP.SPLIT, 2, 'hr', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'zRaw');
  a.roll('gRaw').invoke('BMR', ['gamma']).roll('bRaw').invoke('BMR', ['beta']).roll('aRaw').invoke('BMR', ['alpha']).roll('zRaw').invoke('BMR', ['zeta']);
  section('transcript');
  STOP('transcript');

  // ---- 4. Fr block 1: zeta^n, batch inverse check, PI(zeta), r0 = lin, s1c, s2c, zh, zeta^(n+2) ----
  a.invoke('R', ['r']);
  { const kk = new Kernel(); const E = (n) => kk.env(n), I = (n) => kk.in(n), M = (x) => kk.modr(x), mul = (x, y) => kk.mul(x, y), add = (x, y) => kk.add(x, y), sub = (x, y) => kk.sub(x, y), c = (v) => kk.c(v);
    const canon = (x) => M(add(M(x), E('r')));
    const zeta = E('zeta'), alpha = E('alpha'), beta = E('beta'), gamma = E('gamma');
    let zn = zeta; for (let i = 0; i < vk.log2n; i++) zn = M(mul(zn, zn));
    const zh = sub(zn, c(1n));
    const dens = vk.omegaPow.map((w) => sub(zeta, c(w)));
    let prod = dens[0]; for (let i = 1; i < k; i++) prod = M(mul(prod, dens[i]));
    const invP = I('invP'); const chk = M(sub(mul(prod, invP), c(1n)));
    const invDens = dens.map((_, i) => { let x = invP; dens.forEach((d, j) => { if (j !== i) x = M(mul(x, d)); }); return x; });
    const zhn = M(mul(zh, c(vk.nInv)));
    let pi = null; for (let i = 0; i < k; i++) { const tI = M(mul(M(mul(zhn, invDens[i])), c(vk.omegaPow[i]))); const term = mul(tI, E('pub' + i)); pi = pi ? add(pi, term) : term; }
    pi = M(pi);
    const a2l1 = M(mul(M(mul(alpha, alpha)), M(mul(zhn, invDens[0]))));
    const t1 = add(add(E('l'), M(mul(beta, E('s1')))), gamma), t2 = add(add(E('rr'), M(mul(beta, E('s2')))), gamma);
    const t12 = M(mul(t1, t2));
    const r0 = canon(sub(sub(a2l1, pi), M(mul(M(mul(M(mul(t12, add(E('o'), gamma))), alpha)), E('zu')))));
    const s1c = M(mul(M(mul(M(mul(t12, beta)), alpha)), E('zu')));
    const bz = M(mul(beta, zeta));
    const f1 = add(add(E('l'), bz), gamma), f2v = add(add(E('rr'), M(mul(bz, c(vk.k)))), gamma), f3 = add(add(E('o'), M(mul(bz, c(mod(vk.k * vk.k, r))))), gamma);
    const s2c = M(sub(a2l1, M(mul(M(mul(M(mul(f1, f2v)), f3)), alpha))));
    const zn2 = M(mul(zn, M(mul(zeta, zeta))));
    kk.output(chk, r0, s1c, s2c, M(zh), zn2);
    a.kernel(kk, ['chkInv', 'r0', 's1c', 's2c', 'zh', 'zn2'], {iters: 3000}); }
  a.roll('chkInv').op(OP.NOT, 1, 'q').op(OP.VERIFY, 1);
  section('fr1');
  STOP('fr1');

  // ---- 5. v (kzg.FoldProof transcript), e; ours: uRaw -> u1, u2, t' ----
  const be32 = (n) => { a.pick(n).push(32).op(OP.NUM2BIN, 2, 'b').op(OP.REVERSEBYTES, 1, n + 'BE'); };
  a.pushBytes(Buffer.from('gamma')); be32('zeta'); a.op(OP.CAT, 2, 'h').pick('X').push(64).op(OP.SPLIT, 2, 'lam', 'x').drop('x').op(OP.CAT, 2, 'h');
  a.pick('PROOF').push(192).op(OP.SPLIT, 2, 'lro', 'x').drop('x').op(OP.CAT, 2, 'h');
  a.pick('GV', 's12').push(5).op(OP.SPLIT, 2, 'x', 's12').drop('x').push(128).op(OP.SPLIT, 2, 's12', 'x').drop('x').op(OP.CAT, 2, 'h');
  be32('r0'); a.op(OP.CAT, 2, 'h').pick('PROOF').push(384).op(OP.SPLIT, 2, 'x', 'ev').drop('x').push(160).op(OP.SPLIT, 2, 'ev', 'x').drop('x').op(OP.CAT, 2, 'h');
  a.pick('PROOF').push(608).op(OP.SPLIT, 2, 'x', 'zub').drop('x').push(32).op(OP.SPLIT, 2, 'zub', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'vRaw');
  a.pick('vRaw').invoke('BMR', ['v']);
  a.pushBytes(Buffer.from('u')).roll('vRaw').op(OP.CAT, 2, 'h').pick('PROOF').push(640).op(OP.SPLIT, 2, 'x', 'ww').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'uRaw');
  a.pick('uRaw', 'ub').push(8).op(OP.SPLIT, 2, 'b1', 'ub').roll('b1').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'u1');
  a.roll('ub').push(8).op(OP.SPLIT, 2, 'b2', 'ub').roll('b2').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'u2');
  a.roll('ub').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'tp');
  section('v-u');
  // ---- 6. Fr block 2: the MSM scalars (plan B), canonical in [0, r) ----
  { const kk = new Kernel(); const E = (n) => kk.env(n), M = (x) => kk.modr(x), mul = (x, y) => kk.mul(x, y), add = (x, y) => kk.add(x, y), sub = (x, y) => kk.sub(x, y), c = (v) => kk.c(v);
    const canon = (x) => M(add(M(x), E('r')));
    const v = E('v'), tp = E('tp'), u = M(add(E('u1'), mul(c(GLV.lambda), E('u2')))), nt = sub(c(0n), tp);
    const vs = [c(1n), v]; for (let i = 2; i < 6; i++) vs.push(M(mul(vs[i - 1], v)));
    const e = M(kk.sum(E('r0'), mul(v, E('l')), mul(vs[2], E('rr')), mul(vs[3], E('o')), mul(vs[4], E('s1')), mul(vs[5], E('s2'))));
    const zh = E('zh'), zn2 = E('zn2'), zz = M(mul(zh, zn2));
    const S = {Ql: mul(nt, E('l')), Qr: mul(nt, E('rr')), Qm: mul(nt, M(mul(E('l'), E('rr')))), Qo: mul(nt, E('o')), Qk: nt, S3: mul(nt, E('s1c')), Z: add(mul(nt, E('s2c')), u),
      H0: mul(tp, zh), H1: mul(tp, zz), H2: mul(tp, M(mul(zz, zn2))), Lam: add(c(1n), tp), L: v, R: vs[2], O: vs[3], S1: vs[4], S2: vs[5],
      G: sub(c(0n), add(e, M(mul(u, E('zu'))))), Wz: E('zeta'), Wzw: mul(M(mul(u, E('zeta'))), c(vk.omega))};
    kk.output(...names.slice(0, nbm).map((nm) => canon(S[nm])));
    a.kernel(kk, names.slice(0, nbm).map((nm) => 'sc_' + nm), {iters: 3000}); }
  section('fr2');
  STOP('fr2');

  // ---- 7. signed base-32 recoding of the scalar queue into one digit string (byte = d + 16, MSB window first) ----
  const recode = (n, nw, out) => {
    a.pushBytes([], out);
    a.emit(OP.BEGIN, ...pushNum(n), OP.ROLL, OP.DUP, ...pushNum(32), OP.MOD, ...pushNum(16), OP.ADD, ...pushNum(32), OP.MOD, OP.TUCK, OP.SUB, ...pushNum(16), OP.ADD,
      ...pushNum(32), OP.DIV, OP.ROT, OP.ROT, OP.TRUE, OP.NUM2BIN, OP.SWAP, OP.CAT, OP.SIZE, ...pushNum(n * nw), OP.NUMEQUAL, OP.UNTIL);
    const q = a.st.splice(a.st.length - 1 - n, n); a.st.splice(a.st.length - 1, 0, ...q); // symbolic: the queue keeps its names (all now 0)
    for (let i = 0; i < n; i++) { a.emit(OP.SWAP, OP.NOT, OP.VERIFY); a.st.splice(a.st.length - 2, 1); } // every scalar fully consumed
  };
  a.arrange(names.slice(0, nbm).map((nm) => 'sc_' + nm)); recode(nbm, NW, 'ROWS');
  a.pick('u1').pick('u2'); recode(2, NWR, 'ROWSR');
  section('recode');
  STOP('recode');

  // ---- 8. tables: T[b][k] = k B_b (k = 1..16), affine with witnessed slopes; phi table from the Wzw table ----
  // bases block, bottom -> top: B_{nbm-1} .. B_0 (B_0 on top; tables are built for b = 0, 1, ..)
  const vkPt = (nm) => { const i = ['S1', 'S2', 'S3', 'Ql', 'Qr', 'Qm', 'Qo', 'Qk'].indexOf(nm); a.pick('GV', 'vb').push(5 + 64 * i).op(OP.SPLIT, 2, 'x', 'vb').drop('x').invoke('DBP', [nm + 'x', 'vb']).invoke('DBP', [nm + 'y', 'vb']).drop('vb'); };
  for (let b = nbm - 1; b >= 0; b--) { const nm = names[b];
    if (nm === 'G') a.push(1, 'Gx').push(2, 'Gy'); else if (['Ql', 'Qr', 'Qm', 'Qo', 'Qk', 'S1', 'S2', 'S3'].includes(nm)) vkPt(nm); else { a.pick(nm + 'x', 'b' + nm + 'x').pick(nm + 'y', 'b' + nm + 'y'); } }
  const nBelowBases = a.st.length - 2 * nbm;
  a.push(0, 'ti');
  { const body = [];
    // [.., x_i, y_i, TB(32 i), i] -> roll the base up, build 16 entries, put i back on top, i + 1
    body.push(OP.DUP, ...pushNum(32), OP.MUL, ...pushNum(2), OP.ADD, OP.ROLL, OP.OVER, ...pushNum(32), OP.MUL, ...pushNum(2), OP.ADD, OP.ROLL);
    const call = (n) => a.invokeBytes(n);
    body.push(OP.TWODUP, ...call('DBL'));
    for (let kx = 3; kx <= TBL; kx++) { const d = 2 * (kx - 1) + 1; body.push(OP.TWODUP, ...pushNum(d), OP.PICK, ...pushNum(d), OP.PICK, ...call('ADD')); }
    body.push(...pushNum(2 * TBL), OP.ROLL, OP.ADD1, OP.DUP, ...pushNum(nbm), OP.NUMEQUAL);
    a.emit(OP.BEGIN, ...body, OP.UNTIL, OP.DROP);
    a.st.splice(nBelowBases); }
  // phi table: (beta x_k, y_k) of the Wzw table (the top table): x_k at depth 31 before each push
  a.defLocal('BETA', 0, 1, (s) => s.push(GLV.beta, 'beta'));
  { const one = [...pushNum(31), OP.PICK, ...a.invokeBytes('BETA'), OP.MUL, ...a.invokeBytes('P'), OP.MOD, ...pushNum(31), OP.PICK];
    for (let kx = 0; kx < TBL; kx++) a.emit(...one); }
  a.st.push('TB'); a.piles.set('TB', 2 * TBL * NB);
  section('tables');
  STOP('tables');

  // ---- 9. MSM loops (Straus over shared doublings; signed digits; zero digits skipped) ----
  // tables at bd = 32 (NB - 1 - b) below the top of TB; entry k of table b: x at depth(TB) + bd + 2 (16 - k) + 1
  const msm = (rows, bdStart, bdEnd, nw, jw, ziName, accName) => {
    const X = (jac) => (jac ? ['aX', 'aY', 'aZ'] : ['ax', 'ay']);
    const windowLoop = (jac, untilRows) => a.loop((s) => {
      for (let i = 0; i < W; i++) { s.arrange(X(jac)); s.invoke(jac ? 'JDBL' : 'DBL', X(jac)); }
      s.push(bdStart, 'bd');
      s.loop((t) => {
        t.roll(rows).push(1).op(OP.SPLIT, 2, 'db', rows).roll('db').op(OP.BIN2NUM, 1, 'b').push(16).op(OP.SUB, 2, 'd');
        t.pick('d').op(OP.ZERONOTEQUAL, 1, 'nz').ifElse((u) => {
          u.pick('d').push(0).op(OP.LESSTHAN, 2, 'neg').roll('d').op(OP.ABS, 1, 'k');
          u.emit(OP.DUP, OP.ADD); u.st[u.st.length - 1] = 'k2'; u.pick('bd').op(OP.SWAP, 2, 'bd_', 'k2').op(OP.SUB, 2, 'off');
          const dTB = u.depth('TB'); u.push(dTB + 2 * TBL + 1).op(OP.ADD, 2, 'dep'); // depth of x after 'dep' is popped
          u.emit(OP.DUP, OP.PICK, OP.SWAP, OP.SUB1, OP.PICK); u.st.splice(u.st.length - 1, 1, 'tx', 'ty');
          u.roll('neg').ifElse((v) => { v.invoke('P', ['p']).roll('ty').op(OP.SUB, 2, 'ty'); });
          u.arrange([...X(jac), 'tx', 'ty']).invoke(jac ? 'JMADD' : 'ADD', X(jac));
        }, (u) => { u.drop('d'); });
        t.roll('bd').push(32).op(OP.ADD, 2, 'bd').pick('bd').push(bdEnd).op(OP.NUMEQUAL, 2, 'done');
      });
      s.drop('bd');
      s.pick(rows, 'rc').op(OP.SIZE, 1, 'rc', 'sz').op(OP.NIP, 2, 'sz').push(untilRows).op(OP.NUMEQUAL, 2, 'done');
    });
    const nb = (bdEnd - bdStart) / 32;
    const off = aff(OFFSET);
    if (jw > 0) { a.push(off[0], 'aX').push(off[1], 'aY').push(1, 'aZ'); windowLoop(true, nb * (nw - jw)); a.roll(ziName).arrange(['aX', 'aY', 'aZ', ziName]).invoke('CONV', ['ax', 'ay']); }
    else a.push(off[0], 'ax').push(off[1], 'ay');
    if (jw < nw) windowLoop(false, 0);
    a.roll(rows).op(OP.SIZE, 1, rows, 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1); // rows fully consumed
    const cr = aff(corr(nw)); a.push(cr[0], 'cx').push(cr[1], 'cy').arrange(['ax', 'ay', 'cx', 'cy']).invoke('ADD', [accName + 'x', accName + 'y']);
  };
  a.roll('ROWSR'); msm('ROWSR', 0, 64, NWR, JR, 'ziR', 'PR0');
  STOP('msmR0');
  a.pick('Wzx').pick('Wzy').arrange(['PR0x', 'PR0y', 'Wzx', 'Wzy']).invoke('ADD', ['PRx', 'PRy0']);
  a.invoke('P', ['p']).roll('PRy0').op(OP.SUB, 2, 'PRy');
  section('msm-right');
  STOP('msmR');
  a.roll('ROWS'); msm('ROWS', 32, 32 * NB, NW, J, 'ziL', 'PL');
  // the slope stream is fully consumed: current piece empty, next is the empty sentinel
  a.emit(OP.FROMALT, OP.SIZE, OP.NOT, OP.VERIFY, OP.DROP, OP.FROMALT, OP.SIZE, OP.NOT, OP.VERIFY, OP.DROP); a.alt.pop();
  section('msm-left');
  STOP('msm');

  // ---- 10. SI pairing check: Miller(P*, [1]_2) Miller(P_right, [x]_2) = [c]^lambda ----
  si(a, {CH, section, STOP, L0guess, info});
  const code = Uint8Array.from([...a.prologue(), ...a.code]);
  info.marks = a.marks.map((m) => ({name: m.name, off: m.off + a.prologue().length}));
  info.prologue = a.prologue().length; info.funcs = Object.fromEntries([...a.ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]));
  return {redeem: code, info};
}

// The SI part (fork of the SI-GLS program sections 1-8 without the B walk and the GT-GLS fold).
function si(a, {CH, section, STOP, L0guess, info}) {
  const le = (x) => le32(mod(x));
  // chain slope pile (both chains interleaved: 4 LE words per step), first piece on top
  const steps = []; for (let j = 0; j < 88; j++) steps.push(Buffer.concat([CH.a.lams[j], CH.b.lams[j]].flatMap((l) => [le(l.c0), le(l.c1)])));
  const pieces = []; for (let i = 0; i < 88; i += D_PIECE) pieces.push(Buffer.concat(steps.slice(i, i + D_PIECE)));
  a.pushPile('Dp', pieces.reverse()); // below every item the event loop reads (its size varies inside the loop)
  // WQ / WS checks and the SI transcript h0 = SHA256(TAG || uRaw || WS)
  a.pick('WS').op(OP.SIZE, 1, 'WS_', 'sz').op(OP.NIP, 2, 'sz').push(WS_SIZE).op(OP.NUMEQUALVERIFY, 2);
  a.pushBytes(TAG, 'tag').roll('uRaw').op(OP.CAT, 2, 'h').pick('WS').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.pick('WQ', 'WQs').op(OP.SIZE, 1, 'WQs', 'qsz').drop('WQs');
  a.pick('qsz').push(32).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'qok').op(OP.VERIFY, 1);
  a.push(1).push(32 * NQ_MAX + 1).op(OP.WITHIN, 3, 'qin').op(OP.VERIFY, 1);
  a.pick('WQ', 'WQs').push(32).op(OP.SPLIT, 2, 'q0', 'qr').drop('qr').op(OP.BIN2NUM, 1, 'q0').op(OP.ZERONOTEQUAL, 1, 'nz').op(OP.VERIFY, 1);
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').pick('WQ').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRawS');
  a.invoke('P', ['p']);
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  a.roll('zRawS'); U('zRawS'); a.pick('p').op(OP.MOD, 2, 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  a.roll('WQ').toAlt();
  a.roll('WS'); for (let j = 0; j < 6; j++) a.invoke('DLP', ['sc' + j, 'WS']);
  { const cuts = []; for (let kk = 0; kk < NSTATES; kk += WS_PIECE) cuts.push(kk * 192);
    for (let i = cuts.length - 1; i >= 1; i--) { a.push(cuts[i]).op(OP.SPLIT, 2, 'WS', 'tail').toAlt(); a.alt.pop(); }
    a.toAlt(); a.alt.pop(); a.pushAltPile('WSp', cuts.length); }
  a.push(0, 'WSr').toAlt().push(0, 'R').toAlt();
  section('si-transcript');
  // powers of z, gamma^j, c_j
  { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
    const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); const t = k.sub(z6, k.c(9n)); const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]];
    const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
    for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
    const cj = g.map(([g0, g1]) => m(k.add(g0, mul(g1, t))));
    k.output(z2, z3, z4, z5, z6, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))), ...cj, m(mul(z3, t)));
    a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 'ez', 'ez2', 'ez3', 'ez4', 'ez5', 'c1', 'c2', 'c3', 'c4', 'c5', 'z3t'], {iters: 1500}); }
  const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of ZP) a.pick(n); a.invoke('EV', ['Scp', 'Scm']);
  // line environments of both chains: y, x z, x z t
  for (const n of ['PLx', 'PLy', 'PRx', 'PRy']) a.roll(n);
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y); const t = k.sub(k.env('z6'), k.c(9n)), z = k.env('z');
    const cza = m(mul(k.in('PLx'), z)), czb = m(mul(k.in('PRx'), z));
    k.output(k.in('PLy'), cza, m(mul(cza, t)), k.in('PRy'), czb, m(mul(czb, t)));
    a.kernel(k, ['ya', 'cza', 'czta', 'yb', 'czb', 'cztb'], {iters: 300}); }
  a.push(CH.a.aff.x.c0, 'xqa0').push(CH.a.aff.x.c1, 'xqa1').push(CH.b.aff.x.c0, 'xqb0').push(CH.b.aff.x.c1, 'xqb1');
  a.push(0, 'D');
  for (const [t, C] of [['a', CH.a], ['b', CH.b]]) a.push(C.aff.x.c0, 'dx0' + t).push(C.aff.x.c1, 'dx1' + t).push(C.aff.y.c0, 'dc0' + t).push(C.aff.y.c1, 'dc1' + t).push(0, 'dl0' + t).push(0, 'dl1' + t);
  a.pick('Scm', 'Fp').pick('Scp', 'Fm');
  // EVT: read the next step's 4 slope words, then the fused event kernel
  const readStep = (s) => {
    s.roll('D').emit(OP.SIZE); s.st.push('dsz'); s.op(OP.NOT, 1, 'dempty').ifElse((t) => { t.drop('D').pileTake('Dp', 'D'); });
    s.push(128).op(OP.SPLIT, 2, 'lb', 'D').roll('lb');
    for (const n of ['n0a', 'n1a', 'n0b']) { s.push(32).op(OP.SPLIT, 2, n + 'w', 'lb').roll(n + 'w').op(OP.BIN2NUM, 1, n); s.roll('lb'); }
    s.op(OP.BIN2NUM, 1, 'n1b');
  };
  a.defBound('EVD', (s) => { readStep(s); s.kernel(kEvent(true), EV_OUTS, {iters: ITERS}); });
  a.defBound('EVA', (s) => { readStep(s); s.kernel(kEvent(false), EV_OUTS, {iters: ITERS}); });
  const HOT = ['xqa0', 'xqa1', 'xqb0', 'xqb1', 'Scp', 'Scm', 'ya', 'cza', 'czta', 'yb', 'czb', 'cztb', 'z3', 'z3t', 'p'];
  const STATE = ['D', ...EV_OUTS];
  const moved = new Set([...HOT, ...STATE]);
  const L0 = L0guess ?? [...a.st.filter((x) => !moved.has(x)), ...HOT, ...STATE];
  a.arrangeAll(L0);
  a.pushBytes(Buffer.from(DIGITS.slice(1).map((d) => (d < 0 ? 0x81 : d)).concat([0])), 'SCH').toAlt('SCH');
  a.push(DIGITS[0], 'd').toAlt();
  a.piles.set('Dp', null); a.piles.set('WSp', null);
  section('si-setup');
  STOP('preloop');
  a.loop((s) => {
    s.mark('evd'); s.pick('dx0a', 's0a').pick('dx1a', 's1a').pick('dx0b', 's0b').pick('dx1b', 's1b').invoke('EVD');
    s.mark('eva'); s.peekAlt('dt').ifElse((t) => {
      t.peekAlt('dt').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse((u) => { u.pick('Scp', 'cp').pick('Scm', 'cm'); }, (u) => { u.pick('Scm', 'cp').pick('Scp', 'cm'); });
      t.pick('xqa0', 's0a').pick('xqa1', 's1a').pick('xqb0', 's0b').pick('xqb1', 's1b').invoke('EVA');
    });
    s.mark('digit'); s.fromAlt('d').fromAlt('SCH').drop('d').roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
    s.mark('bnd');
    s.pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').pick('m').push(2).op(OP.MOD, 2, 'odd').roll('m').op(OP.NOT, 1, 'last').op(OP.BOOLOR, 2, 'bnd');
    s.ifElse((t) => {
      t.fromAlt('R').fromAlt('WSr').emit(OP.SIZE); t.st.push('wsz'); t.op(OP.NOT, 1, 'wempty').ifElse((u) => { u.drop('WSr').altPileTake('WSr'); });
      t.push(192).op(OP.SPLIT, 2, 'S', 'WSr').toAlt('WSr');
      for (let j = 0; j < 6; j++) t.invoke('DLP', ['s' + j, 'S']);
      t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
      const k = new Kernel(); const R = k.in('R');
      k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
      t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500}); t.toAlt('R');
    });
    s.mark('loopend').pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
    s.toAlt('SCH').toAlt('d'); s.roll('last');
  }, {onExit: (nat) => { if (nat.join() !== L0.join()) throw {retryL0: nat}; }});
  section('si-loop');
  STOP('postloop');
  // ---- terminal: the two Frobenius steps of each chain (s = x(psi(Q)), then any s), times 1 ----
  a.push(1, 'cp').push(1, 'cm').push(CH.a.psi1x.c0, 's0a').push(CH.a.psi1x.c1, 's1a').push(CH.b.psi1x.c0, 's0b').push(CH.b.psi1x.c1, 's1b').invoke('EVA');
  a.push(1, 'cp').push(1, 'cm').pick('dx0a', 's0a').pick('dx1a', 's1a').pick('dx0b', 's0b').pick('dx1b', 's1b').invoke('EVA');
  a.roll('D').op(OP.SIZE, 1, 'D', 'dl').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('D'); a.pileDone('Dp');
  // F *= S_c(+-eta z) = [c^(p^2)]
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of EZP) a.pick(n); a.invoke('EV', ['ep', 'em']);
  { const k = new Kernel(); k.output(k.mod(k.mul(k.in('Fp'), k.in('ep'))), k.mod(k.mul(k.in('Fm'), k.in('em')))); a.kernel(k, ['Fp', 'Fm'], {iters: 100}); }
  a.fromAlt('d').fromAlt('SCH').drop('d').drop('SCH');
  a.fromAlt('R').fromAlt('WSr').drop('WSr'); a.pileDone('WSp'); a.fromAlt('WQ');
  // W(+-z) = Frob(S_c)(+-z) Frob(S_c)(+-eta z);  R <- R rho + F+ W(-z) - F- W(+z)
  { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j)); const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], E('c' + j))))];
    const fr = (x) => { const ev = m(k.sum(sc[0], k.c(18n), k.neg(E(x[5])), mul(sj[2], E(x[1])), mul(sj[4], E(x[3])))); const od = m(k.sum(mul(sj[1], E(x[0])), mul(sj[3], E(x[2])), mul(sj[5], E(x[4])))); return [k.add(ev, od), k.sub(ev, od)]; };
    const [a1, a2] = fr(ZP), [b1, b2] = fr(EZP);
    k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), m(mul(a2, b2)))), mul(I('Fm'), m(mul(a1, b1))))));
    a.kernel(k, ['R'], {iters: 1500}); }
  section('si-terminal');
  // ---- quotient: Q(z) = z q(z^2), Horner over WQ (highest first), 4 words per step, each word < p ----
  a.push(0).push(96).op(OP.NUM2BIN, 2, 'zeros').push(128).pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(128).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
    .push(128).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
  { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
  a.push(0, 'acc');
  a.loop((s) => {
    s.roll('WQ').push(128).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
    for (let j = 0; j < 4; j++) s.invoke('DLP', ['q' + j, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQ', 'WQc').op(OP.SIZE, 1, 'WQc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQ');
  { const k = new Kernel(); const z6 = k.env('z6'); const Mz = k.add(k.sub(k.mul(z6, z6), k.mul(k.c(18n), z6)), k.c(82n));
    k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
  a.op(OP.NOT, 1, 'result');
  section('si-final');
  assert.equal(a.alt.length, 0, 'altstack not empty');
  a.op(OP.TOALT, 1); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result'];
  section('cleanup');
  info.L0 = L0;
}
