// End-to-end VM measurement of the Miller-fold section of commit-all: the full 6x+2 NAF schedule
// (65 events, 21 NAF additions, 2 Frobenius additions), the B walk (projective from the payload
// B, or affine with witnessed+checked slopes), the delta walk (baked lambda / baked (lambda,b) /
// projective), the per-event fold squaring at +-z, every line multiplied in at +-z, the chat
// multiplications for nonzero 6x+2 digits (swapped values for -1 digits: conj(chat) ~ chat^-1),
// psi(B), -psi^2(B), and the final tie/subgroup check T == -psi^3(B) with Z_T != 0.
// Kernels are OP_DEFINE'd functions; main is the unrolled event schedule with the baked delta
// constants inline. VM output is checked against a BigInt simulation of the same kernels, and
// the simulation's final points against noble.
// Usage: node miller.mjs [B=proj|aff] [D=lam|lamb|proj] [pMode=pick|inline]
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {psiFrobenius} from '@noble/curves/abstract/tower.js';
import {builder, evaluator, compile, run, mod, P, num, push, pushNum, OP, defineFn, invoke, vmNum, opCounts} from './lib.mjs';
import {projDbl, projAdd, affStep, bakedLine, psiK, foldSq, foldMul} from './kern.mjs';
const F2 = bn254.fields.Fp2, Fp = bn254.fields.Fp;
const {psi} = psiFrobenius(Fp, F2, F2.NONRESIDUE);
const [BV = 'proj', DV = 'lam', pMode = 'pick'] = process.argv.slice(2);
const X_BN = 4965661367192848881n;
const digits = []; for (let n = 6n * X_BN + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) digits.unshift(0); else if ((n & 3n) === 3n) { digits.unshift(-1); n++; } else digits.unshift(1); }
const NE = digits.length;
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const g1 = (q) => bn254.G1.Point.fromAffine({x: BigInt(q.x), y: BigInt(q.y)});
const g2 = (q) => bn254.G2.Point.fromAffine({x: {c0: BigInt(q.x.c0), c1: BigInt(q.x.c1)}, y: {c0: BigInt(q.y.c0), c1: BigInt(q.y.c1)}});
const pr = fx.fixtures[0].proof;
const negA = g1(pr.a).negate().toAffine(), Ca = g1(pr.c).toAffine(), Bpt = g2(pr.b), Ba = Bpt.toAffine(), Dpt = g2(fx.vk.delta), Da = Dpt.toAffine();
const f2 = (a) => [a.c0, a.c1];
// psi constants
const q0 = psi(Ba.x, Ba.y);
const PX = F2.div(q0[0], {c0: Ba.x.c0, c1: mod(-Ba.x.c1)}), PY = F2.div(q0[1], {c0: Ba.y.c0, c1: mod(-Ba.y.c1)});
// ---- affine reference walk (slopes, b) for B and delta
function walk(Qa) {
  let T = Qa; const out = [];
  const step = (lam, x2) => { const x = F2.sub(F2.sub(F2.sqr(lam), T.x), x2); const b = F2.sub(F2.mul(lam, T.x), T.y); T = {x, y: F2.sub(b, F2.mul(lam, x))}; return {lam, b}; };
  const dbl = () => step(F2.div(F2.mul(F2.sqr(T.x), {c0: 3n, c1: 0n}), F2.add(T.y, T.y)), T.x);
  const add = (S) => step(F2.div(F2.sub(S.y, T.y), F2.sub(S.x, T.x)), S.x);
  const q1 = psi(Qa.x, Qa.y), q2 = psi(q1[0], q1[1]);
  const Q1 = {x: q1[0], y: q1[1]}, Q2 = {x: q2[0], y: F2.neg(q2[1])};
  for (let e = 0; e < NE; e++) {
    const ev = {dbl: dbl()};
    if (digits[e]) ev.add = add(digits[e] > 0 ? Qa : {x: Qa.x, y: F2.neg(Qa.y)});
    if (e === NE - 1) { ev.f1 = add(Q1); ev.f2 = add(Q2); }
    out.push(ev);
  }
  return {ev: out, T, Q1, Q2};
}
const BW = walk(Ba), DW = walk(Da);
// ---- per-proof constants (setup outputs)
const z = mod(BigInt('0x' + 'c0ffee'.repeat(10)) * 31337n), u = mod(z ** 6n - 9n);
const pairC = (Pt) => ({yP: Pt.y, yPu: mod(Pt.y * u), xz: mod(Pt.x * z), xzu: mod(Pt.x * z * u), xz3: mod(3n * Pt.x * z), xz6u: mod(6n * Pt.x * z * u)});
const cB = pairC(negA), cD = pairC(Ca);
const vals = {P, z3: mod(z ** 3n), z3u: mod(z ** 3n * u), chp: mod(z * 1234567n + 99n), chm: mod(z * 7654321n + 5n),
  Bx0: Ba.x.c0, Bx1: Ba.x.c1, By0: Ba.y.c0, By1: Ba.y.c1, dQx0: Da.x.c0, dQx1: Da.x.c1, dQy0: Da.y.c0, dQy1: Da.y.c1};
for (const [kk, v] of Object.entries(cB)) vals['b_' + kk] = v;
for (const [kk, v] of Object.entries(cD)) vals['d_' + kk] = v;
const keepNames = ['P', ...Object.keys(cB).map((x) => 'b_' + x), ...Object.keys(cD).map((x) => 'd_' + x), 'z3', 'z3u', 'chp', 'chm', 'Bx0', 'Bx1', 'By0', 'By1',
  ...(DV === 'lamb' ? [] : DV === 'proj' ? ['dQx0', 'dQx1', 'dQy0', 'dQy1'] : ['dQx0', 'dQx1'])];
const cOf = (pre) => ({yP: pre + 'yP', yPu: pre + 'yPu', xz: pre + 'xz', xzu: pre + 'xzu', xz3: pre + 'xz3', xz6u: pre + 'xz6u', z3: 'z3', z3u: 'z3u'});
const Bst = BV === 'proj' ? ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'] : ['x0', 'x1', 'y0', 'y1'];
const Dst = DV === 'lam' ? ['dx0', 'dx1', 'dy0', 'dy1'] : DV === 'proj' ? ['DX0', 'DX1', 'DY0', 'DY1', 'DZ0', 'DZ1'] : [];
const mutNames = [...Bst, ...Dst, 'Up', 'Um'];
const frame = [...keepNames, ...mutNames];
// ---- kernel bodies over abstract ops; `S` maps frame names -> handles
const stB = (S) => (BV === 'proj' ? {X: [S.X0, S.X1], Y: [S.Y0, S.Y1], Z: [S.Z0, S.Z1]} : {x: [S.x0, S.x1], y: [S.y0, S.y1]});
const putB = (r) => (BV === 'proj' ? [...r.X, ...r.Y, ...r.Z] : [...r.x, ...r.y]);
const stD = (S) => (DV === 'proj' ? {X: [S.DX0, S.DX1], Y: [S.DY0, S.DY1], Z: [S.DZ0, S.DZ1]} : {x: [S.dx0, S.dx1], y: [S.dy0, S.dy1]});
const putD = (r) => (DV === 'proj' ? [...r.X, ...r.Y, ...r.Z] : DV === 'lam' ? [...r.x, ...r.y] : []);
const cmap = (S, c) => Object.fromEntries(Object.entries(c).map(([a, b]) => [a, S[b]]));
const evIn = [...(BV === 'aff' ? ['s0', 's1'] : []), ...(DV === 'lam' ? ['L0', 'L1'] : DV === 'lamb' ? ['L0', 'L1', 'b0', 'b1'] : [])];
const adIn = ['qx0', 'qx1', 'qy0', 'qy1', ...(BV === 'aff' ? ['s0', 's1'] : []), ...(DV === 'lam' ? ['L0', 'L1', 'qdx0', 'qdx1'] : DV === 'lamb' ? ['L0', 'L1', 'b0', 'b1'] : ['qdx0', 'qdx1', 'qdy0', 'qdy1'])];
function kEV(k, S) {
  let [Up, Um] = foldSq(k, S.Up, S.Um);
  const rb = BV === 'proj' ? projDbl(k, stB(S), cmap(S, cOf('b_'))) : affStep(k, stB(S), [S.s0, S.s1], cmap(S, cOf('b_')), {check: 'dbl'});
  [Up, Um] = foldMul(k, Up, Um, rb.lp, rb.lm);
  const cd = cmap(S, cOf('d_'));
  const rd = DV === 'proj' ? projDbl(k, stD(S), cd) : DV === 'lam' ? affStep(k, stD(S), [S.L0, S.L1], cd) : bakedLine(k, [S.L0, S.L1], [S.b0, S.b1], cd);
  [Up, Um] = foldMul(k, Up, Um, rd.lp, rd.lm);
  return [...putB(rb), ...putD(rd), Up, Um];
}
function kAD(k, S) {
  const Q = {x: [S.qx0, S.qx1], y: [S.qy0, S.qy1]};
  const rb = BV === 'proj' ? projAdd(k, stB(S), Q, cmap(S, cOf('b_'))) : affStep(k, stB(S), [S.s0, S.s1], cmap(S, cOf('b_')), {check: 'add', Q});
  let [Up, Um] = foldMul(k, S.Up, S.Um, rb.lp, rb.lm);
  const cd = cmap(S, cOf('d_'));
  const rd = DV === 'proj' ? projAdd(k, stD(S), {x: [S.qdx0, S.qdx1], y: [S.qdy0, S.qdy1]}, cd)
    : DV === 'lam' ? affStep(k, stD(S), [S.L0, S.L1], cd, {qx: [S.qdx0, S.qdx1]}) : bakedLine(k, [S.L0, S.L1], [S.b0, S.b1], cd);
  [Up, Um] = foldMul(k, Up, Um, rd.lp, rd.lm);
  return [...putB(rb), ...putD(rd), Up, Um];
}
const kCP = (k, S) => [...Bst.map((n) => S[n]), ...Dst.map((n) => S[n]), ...foldMul(k, S.Up, S.Um, S.chp, S.chm)];
const kCM = (k, S) => [...Bst.map((n) => S[n]), ...Dst.map((n) => S[n]), ...foldMul(k, S.Up, S.Um, S.chm, S.chp)];
const kPS = (k, S) => { const r = psiK(k, {x: [S.px0, S.px1], y: [S.py0, S.py1]}, PX, PY); return [...r.x, ...r.y]; };
function kTIE(k, S) { // T == (x3, -y3)
  if (BV === 'proj') {
    const Z = [S.Z0, S.Z1];
    const xz = [k.sub(k.mul(S.px0, Z[0]), k.mul(S.px1, Z[1])), k.add(k.mul(S.px0, Z[1]), k.mul(S.px1, Z[0]))];
    const yz = [k.sub(k.mul(S.py0, Z[0]), k.mul(S.py1, Z[1])), k.add(k.mul(S.py0, Z[1]), k.mul(S.py1, Z[0]))];
    k.eqz(k.sub(S.X0, xz[0])); k.eqz(k.sub(S.X1, xz[1])); k.eqz(k.add(S.Y0, yz[0])); k.eqz(k.add(S.Y1, yz[1])); k.nz2(S.Z0, S.Z1);
  } else { k.eqz(k.sub(S.x0, S.px0)); k.eqz(k.sub(S.x1, S.px1)); k.eqz(k.add(S.y0, S.py0)); k.eqz(k.add(S.y1, S.py1)); }
  return [];
}
// ---- compile functions
const FN = {};
const mk = (name, id, inNames, body, outExtra = null) => {
  const k = builder(); const S = Object.fromEntries([...frame, ...inNames].map((n) => [n, n]));
  const outs = body(k, S);
  const outFrame = outExtra ? [...frame, ...outs] : [...keepNames, ...outs];
  const code = compile({frame: [...frame, ...inNames], prog: k.prog, out: outFrame, pMode});
  FN[name] = {id, code, body, inNames, outExtra, counts: opCounts(k.prog)};
};
mk('EV', 1, evIn, kEV); mk('AD', 2, adIn, kAD); mk('CP', 3, [], kCP); mk('CM', 4, [], kCM);
mk('PS', 5, ['px0', 'px1', 'py0', 'py1'], kPS, true); mk('TIE', 6, ['px0', 'px1', 'py0', 'py1'], kTIE, true);
// ---- main + BigInt simulation side by side
const ev = evaluator();
let sim = {...vals};
const initB = BV === 'proj' ? [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, 1n, 0n] : [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1];
const initD = DV === 'proj' ? [Da.x.c0, Da.x.c1, Da.y.c0, Da.y.c1, 1n, 0n] : DV === 'lam' ? [Da.x.c0, Da.x.c1, Da.y.c0, Da.y.c1] : [];
[...Bst, ...Dst].forEach((n, i) => (sim[n] = [...initB, ...initD][i])); sim.Up = vals.chp; sim.Um = vals.chm;
const setup = frame.flatMap((n) => pushNum(sim[n]));   // setup outputs, pushed (baseline subtracts them)
const main = []; let extra = []; // names above the frame in main
const depth = (n) => { const st = [...frame, ...extra]; return st.length - 1 - st.lastIndexOf(n); };
const pk = (n, as) => { main.push(...pushNum(depth(n)), OP.PICK); extra.push(as); return sim[n]; };
let constBytes = 0, witnessBytes = 0, callBytes = 0;
const pc = (v, as, kind = 'const') => { const b = pushNum(mod(v)); main.push(...b); if (kind === 'const') constBytes += b.length; else witnessBytes += b.length; extra.push(as); return mod(v); };
const call = (name) => {
  const f = FN[name]; const inV = Object.fromEntries(f.inNames.map((n, i) => [n, simExtra[i]]));
  const S = {...sim, ...inV}; const outs = f.body(ev, S);
  if (f.outExtra) { simExtra = outs; extra = outs.map((_, i) => 'o' + i); } else { mutNames.forEach((n, i) => (sim[n] = outs[i])); simExtra = []; extra = []; }
  const b = invoke(f.id); main.push(...b); callBytes += b.length;
};
let simExtra = [];
const ext = (v, as, kind) => { simExtra.push(pc(v, as, kind)); };
const pkx = (n) => { simExtra.push(pk(n, n)); };
const negTop2 = () => { main.push(OP.NEGATE, OP.SWAP, OP.NEGATE, OP.SWAP); simExtra[simExtra.length - 1] = -simExtra.at(-1); simExtra[simExtra.length - 2] = -simExtra.at(-2); };
const dIn = (l, kind, qx) => { // delta inputs for a step
  if (DV === 'lam') { ext(l.lam.c0, 'L0'); ext(l.lam.c1, 'L1'); if (kind !== 'dbl') { if (qx) { ext(qx.c0, 'qdx0'); ext(qx.c1, 'qdx1'); } else { pkx('dQx0'); pkx('dQx1'); } } }
  else if (DV === 'lamb') { ext(l.lam.c0, 'L0'); ext(l.lam.c1, 'L1'); ext(l.b.c0, 'b0'); ext(l.b.c1, 'b1'); }
  else if (kind !== 'dbl') { if (qx) { ext(qx.x.c0, 'q'); ext(qx.x.c1, 'q'); ext(qx.y.c0, 'q'); ext(qx.y.c1, 'q'); } else { pkx('dQx0'); pkx('dQx1'); pkx('dQy0'); pkx('dQy1'); if (kind === 'addm') negTop2(); } }
};
const bIn = (l) => { if (BV === 'aff') { ext(l.lam.c0, 's0', 'wit'); ext(l.lam.c1, 's1', 'wit'); } };
const pickB = () => { pkx('Bx0'); pkx('Bx1'); pkx('By0'); pkx('By1'); };
for (let e = 0; e < NE; e++) {
  bIn(BW.ev[e].dbl); dIn(DW.ev[e].dbl, 'dbl'); call('EV');
  if (digits[e]) {
    pickB(); if (digits[e] < 0) negTop2();
    bIn(BW.ev[e].add); dIn(DW.ev[e].add, digits[e] > 0 ? 'add' : 'addm'); call('AD');
    call(digits[e] > 0 ? 'CP' : 'CM');
  }
  if (e === NE - 1) {
    pickB(); call('PS'); bIn(BW.ev[e].f1); dIn(DW.ev[e].f1, 'add', DV === 'proj' ? DW.Q1 : DW.Q1.x); call('AD');
    pickB(); call('PS'); call('PS'); negTop2(); bIn(BW.ev[e].f2); dIn(DW.ev[e].f2, 'add', DV === 'proj' ? DW.Q2 : DW.Q2.x); call('AD');
    pickB(); call('PS'); call('PS'); call('PS'); call('TIE');
  }
}
// ---- simulation vs noble: final points
if (BV === 'proj') { const x = F2.div({c0: mod(sim.X0), c1: mod(sim.X1)}, {c0: mod(sim.Z0), c1: mod(sim.Z1)}); assert(F2.eql(x, BW.T.x), 'B walk end'); }
else assert(F2.eql({c0: mod(sim.x0), c1: mod(sim.x1)}, BW.T.x));
if (DV === 'lam') assert(F2.eql({c0: mod(sim.dx0), c1: mod(sim.dx1)}, DW.T.x), 'delta walk end');
if (DV === 'proj') assert(F2.eql(F2.div({c0: mod(sim.DX0), c1: mod(sim.DX1)}, {c0: mod(sim.DZ0), c1: mod(sim.DZ1)}), DW.T.x), 'delta walk end');
// ---- VM
const defs = Object.values(FN).flatMap((f) => defineFn(f.id, f.code));
const PAD = 40000;
const full = run({code: [...defs, ...setup, ...main], pad: PAD});
const base = run({code: [...defs, ...setup], pad: PAD});
for (const r of [full, base]) for (const m of ['consensus', 'standard']) { const er = r['err_' + m]; if (er && !/clean|exactly one|unexpected number/i.test(String(er))) throw new Error(m + ': ' + er); }
const top = full.stack.slice(-mutNames.length).map(vmNum);
mutNames.forEach((n, i) => assert.equal(mod(top[i]), mod(sim[n]), 'VM vs sim ' + n));
// isolated per-call op-cost of EV and AD (first event's inputs)
const iso = {};
for (const [name, ins] of [['EV', evIn], ['AD', adIn], ['PS', ['px0', 'px1', 'py0', 'py1']]]) {
  const inPush = ins.flatMap((n, i) => pushNum(mod(BigInt(i + 1) * 0x1234567890abcdefn * z)));
  // EV/AD read the frame; inputs only need to be field-sized (slopes are not checked for proj/lam; aff checks would fail -> use isolated only for proj/lam)
  const a = run({code: [...defs, ...setup, ...inPush, ...invoke(FN[name].id)], pad: 0}), b = run({code: [...defs, ...setup, ...inPush], pad: 0});
  const failed = a['err_consensus'] && !/clean|exactly one|unexpected number/i.test(String(a['err_consensus']));
  // affine EV/AD check the witnessed slope, which these dummy inputs do not satisfy: no isolated figure for them
  iso[name] = failed && BV === 'aff' && name !== 'PS' ? 'n/a (affine: needs a valid witness slope)' : failed ? 'n/a (' + String(a['err_consensus']).slice(0, 40) + ')' : a.consensus - b.consensus;
}
const fnBytes = Object.fromEntries(Object.entries(FN).map(([n, f]) => [n, f.code.length]));
const res = {variant: {B: BV, D: DV, pMode}, opConsensus: full.consensus - base.consensus, opStandard: full.standard - base.standard,
  codeBytes: {functions: fnBytes, defsTotal: defs.length, main: main.length, mainConstPushes: constBytes, mainCalls: callBytes, mainOther: main.length - constBytes - witnessBytes - callBytes},
  witnessBytes, isolatedOpPerCall: iso, kernelOps: Object.fromEntries(Object.entries(FN).map(([n, f]) => [n, f.counts]))};
console.log(JSON.stringify(res));
export default res;
