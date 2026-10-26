// Measured kernels: each kernel is scheduled by the SI-GLS assembler (asm.mjs, exact bch-spec cost model),
// executed in the libauth bch-spec VM, and its outputs are checked against the reference polynomials of
// protocol.mjs / math.mjs (the B kernels against projDbl/projAdd + linePoly at +-z, the delta step against the
// baked trajectory). The same harness measures the BN254 kernels of the built sound-si-gls verifier, so
// that BLS costs can be calibrated against that verifier's measured section profile.
//   node kernels.mjs [ITERS]        -> kernels.json
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {Asm, Kernel, OP, setPrime, pushNum} from './asm.mjs';
import {bare, num} from './vm.mjs';
import {p, mod, F2, f2, B3, G1P, G2P, VKC, linePoly, projDbl, projAdd, peval, pneg, ETA, GAMMA_POW, frob1Monic, Phi} from './math.mjs';
import * as BN from '../../chunked/bn254/sound-si-gls/script.mjs';

const ITERS = Number(process.argv[2] ?? process.env.ITERS ?? 4000);
const PBN = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const vmNum = (v) => { const b = []; let x = v < 0n ? -v : v; while (x > 0n) { b.push(Number(x & 255n)); x >>= 8n; } if (b.length && b.at(-1) & 0x80) b.push(0); if (v < 0n && b.length) b[b.length - 1] |= 0x80; return b; };

// run kernel K with the stack [p, ...env..., ...inputs] (bottom -> top); returns op cost of the kernel alone and its outputs
export function measure(K, {P, env, ins, outs, extraDepth = 0}) {
  setPrime(P);
  const pad = Array.from({length: extraDepth}, (_, i) => 'pad' + i); // realistic depth of the environment
  const names = ['p', ...pad, ...Object.keys(env), ...Object.keys(ins)];
  const vals = [P, ...pad.map(() => 1n), ...Object.values(env), ...Object.values(ins)];
  const a = new Asm(names); const res = a.kernel(K, outs, {iters: ITERS});
  const pushes = vals.map(vmNum);
  const run = bare(a.code, pushes); assert.ok(run.error === undefined || /unexpected number of items/.test(run.error), 'kernel error ' + run.error);
  const base = bare([OP.NOP], pushes);
  const got = run.stack.slice(-outs.length).map(num);
  return {op: run.opCost - base.opCost + 100, bytes: a.code.length, est: res.cost, got};
}
const rnd = (() => { let s = 987654321n; return (m) => { s = (s * 6364136223846793005n + 1442695040888963407n) % (1n << 512n); return s % m; }; })();

// ---------------- BLS kernels ----------------
// Line at +-z in the M-twist slots: L(+-z) = E +- O, E = c0(t) + xP z^2 c1(t), O = yP z^3 c2(t), c(t) = c_0 + c_1 t, t = z^6 - 1.
// env: t, xz2 = xP z^2, xz2t, yz3 = yP z^3, yz3t (P = -A: yP = -yA).
export function kBDblBLS() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(mul(add(Y0, Y0), Y1));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(mul(add(Z0, Z0), Z1));
  // E = 3b' C = 12 (1 + u) C = 12 ((C0 - C1) + (C0 + C1) u)
  const E0 = k.small(sub(C0, C1), 12), E1 = k.small(add(C0, C1), 12);
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const t0 = mul(X0, Y0), t1 = mul(X1, Y1), t2 = mul(add(X0, X1), add(Y0, Y1));
  const XY0 = m(sub(t0, t1)), XY1 = m(sub(sub(t2, t0), t1));
  const D0 = m(k.small(sub(B0, F0), 2)), D1 = m(k.small(sub(B1, F1), 2));
  const X30 = m(sub(mul(XY0, D0), mul(XY1, D1))), X31 = m(add(mul(XY0, D1), mul(XY1, D0)));
  const G0 = m(add(B0, F0)), G1 = m(add(B1, F1)); const Em0 = m(E0), Em1 = m(E1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(Em0, Em1), sub(Em0, Em1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(Em0, Em1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(mul(add(S0, S0), S1), B1), C1));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const Z30 = m(sub(mul(B40, H0), mul(B41, H1))), Z31 = m(add(mul(B40, H1), mul(B41, H0)));
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = mul(add(X0, X0), X1);
  // line (c0, c1, c2) = (B - E, -3X^2, H): E-part = (B0-E0) + t (B1-E1) - 3 (xz2 X2_0 + xz2t X2_1); O-part = yz3 H0 + yz3t H1
  const e = m(sub(add(sub(B0, E0), mul(E('t'), m(sub(B1, E1)))), k.small(m(add(mul(E('xz2'), m(X20)), mul(E('xz2t'), m(X21)))), 3)));
  const o = m(add(mul(E('yz3'), H0), mul(E('yz3t'), H1)));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(X30, X31, Y30, Y31, Z30, Z31, m(mul(mul(Fp, Fp), add(e, o))), m(mul(mul(Fm, Fm), sub(e, o))));
  return k;
}
// mixed addition with B (env xB0..yB1, always +B for |x|) + line + c^-1 factor (env Scm = S_c(-z) for F+, Scp for F-)
export function kBAddBLS() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I); const [xq0, xq1, yq0, yq1] = ['xB0', 'xB1', 'yB0', 'yB1'].map(E);
  const fm = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const fs = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const [qz0, qz1] = fs(yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = fs(xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(mul(add(th0, th0), th1));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(mul(add(la0, la0), la1));
  const [e0, e1] = fm(la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = fm(Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = fm(X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = fm(la0, la1, H0, H1);
  const [a0, a1] = fs(th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = fs(Y0, Y1, E0, E1);
  const [z30, z31] = fm(Z0, Z1, E0, E1);
  // line (c0, c1, c2) = (theta xq - lam yq, -theta, lam)
  const [tx0, tx1] = fs(th0, th1, xq0, xq1), [ly0, ly1] = fs(la0, la1, yq0, yq1);
  const e = m(sub(add(m(sub(tx0, ly0)), mul(E('t'), m(sub(tx1, ly1)))), add(mul(E('xz2'), th0), mul(E('xz2t'), th1))));
  const o = m(add(mul(E('yz3'), la0), mul(E('yz3t'), la1)));
  k.output(m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31), m(mul(mul(I('Fp'), add(e, o)), E('Scm'))), m(mul(mul(I('Fm'), sub(e, o)), E('Scp'))));
  return k;
}
// delta step j (BN recursion): c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}; line (c_j, -lambda_j, 1) at C:
// E = c_j0 + t c_j1 - cz2 n0 - cz2t n1, O = yCz3 (constant per proof); x_{j+1} = lambda_j^2 - x_j - s
export function kDStepBLS() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const a0 = add(l0, n0), a1 = add(l1, n1);
  const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const e = m(sub(add(nc0, mul(E('t'), nc1)), add(mul(E('cz2'), n0), mul(E('cz2t'), n1))));
  const o = E('yCz3');
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(e, o))), m(mul(I('Fm'), sub(e, o))));
  return k;
}
// monic degree-6 evaluation at +-x (the same as BN's EV)
export function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
export function kTable(mult) {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(mult ? 1n : 0n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : mult ? k.mod(k.mul(T[n ^ lo], v[b])) : k.add(T[n ^ lo], v[b]); }
  return k.output(...T.slice().reverse());
}
export function kFold() { const k = new Kernel(); const R = k.in('R'); k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp'))))); return k; }
export function kHorner4() { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n); k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); return k; }
// GLS per event, value part only: F+ <- F+ TP0 TP1 mod p, F- likewise
export function kGlsMul() { const k = new Kernel(); k.output(k.mod(k.mul(k.mul(k.in('u0'), k.in('u1')), k.in('Fp'))), k.mod(k.mul(k.mul(k.in('v0'), k.in('v1')), k.in('Fm')))); return k; }

// ---------------- measurements ----------------
const out = {};
const R = (P) => rnd(P);
// BLS B doubling: real point, random projective scale; check against projDbl + linePoly at +-z
{
  const Bp = G2P.BASE.multiply(1234567n).toAffine(), A = G1P.BASE.multiply(777n).toAffine(); const s = f2(R(p), R(p));
  const Tin = [F2.mul(Bp.x, s), F2.mul(Bp.y, s), s];
  const z = R(1n << 256n), t = mod(z ** 6n - 1n), yP = mod(-A.y); const Fp0 = R(p), Fm0 = R(p);
  const env = {t, xz2: mod(A.x * z * z), xz2t: mod(A.x * z * z * t), yz3: mod(yP * z ** 3n), yz3t: mod(yP * z ** 3n * t)};
  const ins = {X0: Tin[0].c0, X1: Tin[0].c1, Y0: Tin[1].c0, Y1: Tin[1].c1, Z0: Tin[2].c0, Z1: Tin[2].c1, Fp: Fp0, Fm: Fm0};
  const r1 = measure(kBDblBLS(), {P: p, env, ins, outs: ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], extraDepth: 30});
  const o = projDbl(Tin); const L = linePoly(A.x, yP, ...o.line);
  const want = [o.T[0].c0, o.T[0].c1, o.T[1].c0, o.T[1].c1, o.T[2].c0, o.T[2].c1, mod(Fp0 * Fp0 * peval(L, z)), mod(Fm0 * Fm0 * peval(L, mod(-z)))];
  assert.deepEqual(r1.got.map((x) => mod(x)), want, 'BLS B doubling kernel');
  out.blsBDbl = {op: r1.op, bytes: r1.bytes};
  // BLS B addition with +B and c^-1
  const Bq = Bp; const Scp = R(p), Scm = R(p);
  const env2 = {...env, xB0: Bq.x.c0, xB1: Bq.x.c1, yB0: Bq.y.c0, yB1: Bq.y.c1, Scp, Scm};
  const T2 = G2P.BASE.multiply(1234567n * 5n).toAffine(); const s2 = f2(R(p), R(p)); const Tin2 = [F2.mul(T2.x, s2), F2.mul(T2.y, s2), s2];
  const ins2 = {X0: Tin2[0].c0, X1: Tin2[0].c1, Y0: Tin2[1].c0, Y1: Tin2[1].c1, Z0: Tin2[2].c0, Z1: Tin2[2].c1, Fp: Fp0, Fm: Fm0};
  const r2 = measure(kBAddBLS(), {P: p, env: env2, ins: ins2, outs: ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], extraDepth: 30});
  const o2 = projAdd(Tin2, [Bq.x, Bq.y]); const L2 = linePoly(A.x, yP, ...o2.line);
  const want2 = [o2.T[0].c0, o2.T[0].c1, o2.T[1].c0, o2.T[1].c1, o2.T[2].c0, o2.T[2].c1, mod(Fp0 * peval(L2, z) * Scm), mod(Fm0 * peval(L2, mod(-z)) * Scp)];
  assert.deepEqual(r2.got.map((x) => mod(x)), want2, 'BLS B addition kernel');
  out.blsBAdd = {op: r2.op, bytes: r2.bytes};
  // BLS delta step j = 5 (a doubling), against the baked trajectory's line at C
  const C = G1P.BASE.multiply(13n).toAffine(); const lams = VKC.lams; const j = 5;
  // reconstruct x_j, c_{j-1} from the trajectory
  let x = VKC.deltaAff.x, c = VKC.deltaAff.y, l = F2.ZERO; const dAff = VKC.deltaAff;
  const BITSj = []; // the schedule's s for steps 0..j-1: doublings at 0..4 except additions; use math's schedule
  const {BITS} = await import('./math.mjs'); const sched = []; for (let e = 0; e < BITS.length; e++) { sched.push('d'); if (BITS[e]) sched.push('a'); }
  for (let i = 0; i < j; i++) { const cj = F2.sub(F2.mul(F2.add(l, lams[i]), x), c); const sv = sched[i] === 'a' ? dAff.x : x; const nx = F2.sub(F2.sub(F2.sqr(lams[i]), x), sv); c = cj; l = lams[i]; x = nx; }
  const env3 = {t, cz2: mod(C.x * z * z), cz2t: mod(C.x * z * z * t), yCz3: mod(C.y * z ** 3n)};
  const sv = sched[j] === 'a' ? dAff.x : x;
  const ins3 = {dx0: x.c0, dx1: x.c1, dc0: c.c0, dc1: c.c1, dl0: l.c0, dl1: l.c1, n0: lams[j].c0, n1: lams[j].c1, s0: sv.c0, s1: sv.c1, Fp: Fp0, Fm: Fm0};
  const r3 = measure(kDStepBLS(), {P: p, env: env3, ins: ins3, outs: ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], extraDepth: 30});
  const cj = F2.sub(F2.mul(F2.add(l, lams[j]), x), c); const L3 = linePoly(C.x, C.y, cj, F2.neg(lams[j]), F2.ONE);
  const nx = F2.sub(F2.sub(F2.sqr(lams[j]), x), sv);
  assert.deepEqual(r3.got.map((v) => mod(v)), [nx.c0, nx.c1, cj.c0, cj.c1, lams[j].c0, lams[j].c1, mod(Fp0 * peval(L3, z)), mod(Fm0 * peval(L3, mod(-z)))], 'BLS delta step');
  out.blsDStep = {op: r3.op, bytes: r3.bytes};
}
// generic kernels at both primes
for (const [tag, P] of [['bls', p], ['bn', PBN]]) {
  const zz = R(P); const xs = [zz]; for (let i = 1; i < 6; i++) xs.push(mod(xs[i - 1] * zz, P));
  const sc = Array.from({length: 6}, () => R(P));
  const ins = Object.fromEntries([...sc, ...xs].map((v, i) => ['in' + i, v]));
  const re = measure(kEval(), {P, env: {}, ins, outs: ['vp', 'vm'], extraDepth: 20});
  const ev = (sgn) => { let a = 0n; for (let i = 0; i < 6; i++) a += sc[i] * (sgn < 0 && i % 2 ? -1n : 1n) * (i ? xs[i - 1] : 1n); a += xs[5]; return mod(a, P); };
  assert.deepEqual(re.got.map((v) => mod(v, P)), [ev(1), ev(-1)], 'EV');
  out[tag + 'Eval'] = {op: re.op, bytes: re.bytes};
  const vs = Array.from({length: 4}, () => R(P)); const rt = measure(kTable(true), {P, env: {}, ins: Object.fromEntries(vs.map((v, i) => ['in' + i, v])), outs: Array.from({length: 16}, (_, i) => 'T' + i), extraDepth: 10});
  out[tag + 'TableMul'] = {op: rt.op, bytes: rt.bytes};
  const rf = measure(kFold(), {P, env: {rho: R(1n << 256n)}, ins: {R: R(P), Fp: R(P), Fm: R(P), Sp: R(P), Sm: R(P)}, outs: ['Fp', 'Fm', 'R'], extraDepth: 20});
  out[tag + 'Fold'] = {op: rf.op, bytes: rf.bytes};
  const rh = measure(kHorner4(), {P, env: {z8: R(P), z6b: R(P), z4: R(P), z2: R(P)}, ins: {acc: R(P), q0: R(P), q1: R(P), q2: R(P), q3: R(P)}, outs: ['acc'], extraDepth: 20});
  out[tag + 'Horner4'] = {op: rh.op, bytes: rh.bytes};
  const rg = measure(kGlsMul(), {P, env: {}, ins: {Fp: R(P), Fm: R(P), u0: R(P), u1: R(P), v0: R(P), v1: R(P)}, outs: ['Fp', 'Fm'], extraDepth: 20});
  out[tag + 'GlsMul'] = {op: rg.op, bytes: rg.bytes};
}
// BN kernels of the built verifier (script.mjs), same harness (outputs not checked here: that verifier is checked by its own build)
{
  const P = PBN; const env = {b30: R(P), b31: R(P), z3t: R(P), yP: R(P), yPt: R(P), xz: R(P), xzt: R(P), xz3: R(P), xz3t: R(P), z3: R(P), cz: R(P), czt: R(P), yC: R(P)};
  const st = Object.fromEntries(['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'].map((n) => [n, R(P)]));
  out.bnBDbl = (({op, bytes}) => ({op, bytes}))(measure(BN.kBDbl(), {P, env, ins: st, outs: ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], extraDepth: 30}));
  const st2 = {...st, xq0: R(P), xq1: R(P), yq0: R(P), yq1: R(P), cp: R(P), cm: R(P)};
  out.bnBAdd = (({op, bytes}) => ({op, bytes}))(measure(BN.kBAdd(), {P, env, ins: st2, outs: ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], extraDepth: 30}));
  const st3 = Object.fromEntries(['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1', 'Fp', 'Fm'].map((n) => [n, R(P)]));
  out.bnDStep = (({op, bytes}) => ({op, bytes}))(measure(BN.kDStep(), {P, env, ins: st3, outs: ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], extraDepth: 30}));
}
for (const [k, v] of Object.entries(out)) console.log(k.padEnd(16), String(v.op).padStart(9), String(v.bytes).padStart(5) + ' B');
const ratio = (a, b) => +(out[a].op / out[b].op).toFixed(3);
out.ratios = {BDbl: ratio('blsBDbl', 'bnBDbl'), BAdd: ratio('blsBAdd', 'bnBAdd'), DStep: ratio('blsDStep', 'bnDStep'), Eval: ratio('blsEval', 'bnEval'), TableMul: ratio('blsTableMul', 'bnTableMul'),
  Fold: ratio('blsFold', 'bnFold'), Horner4: ratio('blsHorner4', 'bnHorner4'), GlsMul: ratio('blsGlsMul', 'bnGlsMul')};
console.log(out.ratios);
writeFileSync(new URL('./kernels.json', import.meta.url), JSON.stringify({iters: ITERS, ...out}, null, 1) + '\n');
