// End-to-end prototype of the hybrid-direct hot section on the bch-spec VM, one input, one stack:
//   setup (range + curve checks for A, B, C and the pushed vk_x; exact blob lengths; transcript
//   T0 -> g, z; z powers, per-pair line precomputes, c^-1(+-z); STATES split into 36 chunks)
//   -> 65 unrolled events via OP_DEFINE'd kernels (B step, F2 fixed steps for gamma and delta,
//   SZ line accumulation at +-z, c-folds, Frobenius lines, K fold) -> 36 segment closes from the
//   STATES chunks -> exact B endpoint T_B == -psi^3(B) (+ Z != 0) -> Horner over QBLOB ->
//   batched check S == Q(z) M(z).
// NOT included (measured separately): vk_x MSM (msm.mjs; vk_x is pushed here instead), the
// terminal torus verdict (verdict.mjs).
// Usage: node hotloop.mjs [proj|aff|K] [fixture] [--f1=E] [--breakdown]
//   K = number of leading events whose B step is affine with a witnessed slope; --f1=E bakes
//   (lambda, beta) for the gamma/delta lines of events >= E (F1) instead of lambda only (F2).
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {SSA, compile, run, asm, P, mod, vmStd, vmCons, num, vmToBig, L} from './sscomp.mjs';
import {makeWitness, digits, EVENTS, LAST, le32, DOMAIN, BTW, PSI, f2} from './witness.mjs';

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// opts: pOnStack (p kept on the stack, PICKed instead of 33-byte pushes),
// f1From (fixed-pair lines of events >= f1From use baked (lambda, beta): F1), nQ (quotient length).
// w.bMode: 'proj' | 'aff' | K (B steps of events < K affine with witnessed slopes, the rest projective).
export function build(w, {pOnStack = true, f1From = EVENTS, nQ: nQopt} = {}) {
  const PV = pOnStack ? 'P' : P;
  const KS = w.bMode === 'proj' ? 0 : w.bMode === 'aff' ? EVENTS : w.bMode;
  const hasProj = KS < EVENTS, allAff = KS >= EVENTS, hasAff = KS > 0;
  const proj = hasProj;
  const affE = (e) => e < KS;
  let zt = 0; while (w.Qodd[w.Qodd.length - 1 - zt] === 0n) zt++;
  const nQ = nQopt ?? (w.Qodd.length - zt); // structurally zero top coefficients dropped
  const QBLOB = w.QBLOB.subarray(w.QBLOB.length - 32 * nQ); // descending order: drop the leading zeros
  assert.ok(w.Qodd.slice(nQ).every((x) => x === 0n));
  const TB = hasProj ? ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'] : ['X0', 'X1', 'Y0', 'Y1'];
  const core = [...(pOnStack ? ['P'] : []), 'z3', 'z3s', 'a1_0', 'a2_0', 'yP_0', ...(proj ? ['yPs_0'] : []), 'a1_1', 'a2_1', 'yP_1', 'a1_2', 'a2_2', 'yP_2', 'zU',
    'Bx0', 'Bx1', 'By0', 'By1', 'z', 'b1', 'b2', 'b3', 'b4', 'b5', 'g', 'gj', 'S',
    'Tg0', 'Tg1', 'Tg2', 'Tg3', 'Td0', 'Td1', 'Td2', 'Td3', ...TB, 'accP', 'accM'];
  // kernel compiler: fn(b, v) mutates the slot map v (slot -> SSA name); extra = names on top
  const kernel = (fn, extra = []) => {
    const b = new SSA('k', PV);
    assert.ok(extra.every((n) => !core.includes(n)), 'extra input name collides with a core slot');
    const v = Object.fromEntries(core.map((n) => [n, n]));
    const ex = Object.fromEntries(extra.map((n) => [n, n]));
    const outExtra = fn(b, v, ex) ?? [];
    const inputs = [...core, ...extra], outputs = [...core.map((n) => v[n]), ...outExtra];
    const code = compile({inputs, prog: b.prog, outputs});
    return {code, bytes: asm(code).length, prog: b.prog, inputs, outputs};
  };
  // shared pieces
  const lineAcc = (b, v, j, cy, cl, cb) => {
    // even part e = y_P * E(c_y), odd part o = <a1,a2,z3,z3s> . <cl0,cl1,cb0,cb1>
    const e = cy ? b.md(b.add(b.mul(v['yP_' + j], cy[0]), b.mul(v.yPs_0, cy[1]))) : v['yP_' + j];
    const o = b.md(b.add(b.add(b.mul(v['a1_' + j], cl[0]), b.mul(v['a2_' + j], cl[1])), b.add(b.mul(v.z3, cb[0]), b.mul(v.z3s, cb[1]))));
    v.accP = b.mulm(v.accP, b.add(e, o)); v.accM = b.mulm(v.accM, b.sub(e, o));
  };
  const K = {};
  // ---- B doubling (+ square both accumulators) ----
  if (hasAff) K.SQ = kernel((b, v) => { v.accP = b.mulm(v.accP, v.accP); v.accM = b.mulm(v.accM, v.accM); });
  if (hasProj) K.BDBL = kernel((b, v) => {
    v.accP = b.mulm(v.accP, v.accP); v.accM = b.mulm(v.accM, v.accM);
    if (proj) {
      const X = [v.X0, v.X1], Y = [v.Y0, v.Y1], Z = [v.Z0, v.Z1];
      const XX = b.f2sqr(X, false), YY = b.f2sqr(Y), ZZ = b.f2sqr(Z);
      const E = b.f2red(b.f2mul(ZZ, [3n * BTW[0], 3n * BTW[1]], false, false));
      const E3 = b.f2scale(E, 3n);
      // X3 = 2XY(YY - 3E), Y3 = (YY + 3E)^2 - 12E^2, Z3 = 8 YY YZ; line (c_y, c_lambda, c_beta) = (2YZ, 3XX, YY - E)
      const XY = b.f2mul(X, Y), YZ = b.f2mul(Y, Z);
      const X3 = b.f2red(b.f2scale(b.f2mul(XY, b.f2sub(YY, E3), false), 2n));
      const Y3 = b.f2red(b.f2sub(b.f2sqr(b.f2add(YY, E3), false), b.f2scale(b.f2sqr(E), 12n)));
      const Z3 = b.f2red(b.f2scale(b.f2mul(YY, YZ, false), 8n));
      const cy = b.f2scale(YZ, 2n);
      lineAcc(b, v, 0, cy, b.f2scale(XX, 3n), b.f2sub(YY, E));
      [v.X0, v.X1, v.Y0, v.Y1, v.Z0, v.Z1] = [...X3, ...Y3, ...Z3];
    }
  });
  // affine B doubling with witnessed slope (aff mode): extra = slope limbs l0 l1 on top
  if (hasAff) K.ABDBL = kernel((b, v, ex) => {
    const l = [b.range(ex.l0), b.range(ex.l1)], x = [v.X0, v.X1], y = [v.Y0, v.Y1];
    // 2y*l == 3x^2
    const lhs = b.f2mul(b.f2scale(y, 2n), l, false), rhs = b.f2scale(b.f2sqr(x, false), 3n);
    b.zeroModP(b.sub(lhs[0], rhs[0])); b.zeroModP(b.sub(lhs[1], rhs[1]));
    const beta = b.f2red(b.f2sub(b.f2mul(l, x, false), y));
    const x3 = b.f2red(b.f2sub(b.f2sqr(l, false), b.f2scale(x, 2n)));
    const y3 = b.f2red(b.f2sub(beta, b.f2mul(l, x3, false)));
    lineAcc(b, v, 0, null, l, beta);
    [v.X0, v.X1, v.Y0, v.Y1] = [...x3, ...y3];
  }, ['l0', 'l1']);
  // ---- B mixed addition with Q = (xq, yq) affine on top ----
  if (!allAff) K.BADD = kernel((b, v, ex) => {
    const xq = [ex.xq0, ex.xq1], yq = [ex.yq0, ex.yq1];
    if (proj) {
      const X = [v.X0, v.X1], Y = [v.Y0, v.Y1], Z = [v.Z0, v.Z1];
      const th = b.f2sub(Y, b.f2mul(yq, Z)), la = b.f2sub(X, b.f2mul(xq, Z));
      const C = b.f2sqr(th), D = b.f2sqr(la), E = b.f2mul(la, D), F = b.f2mul(Z, C), G = b.f2mul(X, D);
      const Hh = b.f2sub(b.f2add(E, F), b.f2scale(G, 2n));
      const X3 = b.f2mul(la, Hh), Y3 = b.f2red(b.f2sub(b.f2mul(th, b.f2sub(G, Hh), false), b.f2mul(Y, E, false)));
      const Z3 = b.f2mul(Z, E);
      const cb = b.f2red(b.f2sub(b.f2mul(th, xq, false), b.f2mul(la, yq, false)));
      lineAcc(b, v, 0, la, th, cb);
      [v.X0, v.X1, v.Y0, v.Y1, v.Z0, v.Z1] = [...X3, ...Y3, ...Z3];
    }
  }, ['xq0', 'xq1', 'yq0', 'yq1']);
  if (hasAff) K.ABADD = kernel((b, v, ex) => {
    const xq = [ex.xq0, ex.xq1], yq = [ex.yq0, ex.yq1], l = [b.range(ex.l0), b.range(ex.l1)], x = [v.X0, v.X1], y = [v.Y0, v.Y1];
    const dx = b.f2sub(xq, x);
    // nonzero denominator: dx != 0 (Fp2)
    b.nonzero2(dx);
    const lhs = b.f2mul(l, dx, false), rhs = b.f2sub(yq, y);
    b.zeroModP(b.sub(lhs[0], rhs[0])); b.zeroModP(b.sub(lhs[1], rhs[1]));
    const beta = b.f2red(b.f2sub(b.f2mul(l, x, false), y));
    const x3 = b.f2red(b.f2sub(b.f2sub(b.f2sqr(l, false), x), xq));
    const y3 = b.f2red(b.f2sub(beta, b.f2mul(l, x3, false)));
    lineAcc(b, v, 0, null, l, beta);
    [v.X0, v.X1, v.Y0, v.Y1] = [...x3, ...y3];
  }, ['xq0', 'xq1', 'yq0', 'yq1', 'l0', 'l1']);
  // ---- c-fold by sign s (top) and push Q = (Bx, s*By) for BADD ----
  K.CF = kernel((b, v, ex) => {
    const szU = b.mul(ex.s, v.zU);
    v.accP = b.mulm(v.accP, b.sub(1n, szU)); v.accM = b.mulm(v.accM, b.add(1n, szU));
    return [b.copy(v.Bx0), b.copy(v.Bx1), b.mul(ex.s, v.By0), b.mul(ex.s, v.By1)];
  }, ['s']);
  // ---- F2 fixed steps: baked lambda on top (and xq for FADDX) ----
  const fstep = (pair, kind, xqLit) => kernel((b, v, ex) => {
    const T = pair === 1 ? ['Tg0', 'Tg1', 'Tg2', 'Tg3'] : ['Td0', 'Td1', 'Td2', 'Td3'];
    const x = [v[T[0]], v[T[1]]], y = [v[T[2]], v[T[3]]], l = [ex.l0, ex.l1];
    const beta = b.f2red(b.f2sub(b.f2mul(l, x, false), y));
    const xq = kind === 'dbl' ? x : kind === 'addx' ? [ex.xq0, ex.xq1] : xqLit;
    const x3 = b.f2red(b.f2sub(b.f2sub(b.f2sqr(l, false), x), xq));
    // y is kept unreduced (|y| < 2^513); it only enters the next beta = lambda*x - y, which is reduced
    const y3 = b.f2sub(beta, b.f2mul(l, x3, false));
    lineAcc(b, v, pair, null, l, beta);
    [v[T[0]], v[T[1]], v[T[2]], v[T[3]]] = [...x3, ...y3];
  }, kind === 'addx' ? ['l0', 'l1', 'xq0', 'xq1'] : ['l0', 'l1']);
  K.FDBL_G = fstep(1, 'dbl'); K.FDBL_D = fstep(2, 'dbl');
  K.FADD_G = fstep(1, 'add', w.gammaQ[0]); K.FADD_D = fstep(2, 'add', w.deltaQ[0]);
  K.FADDX_G = fstep(1, 'addx'); K.FADDX_D = fstep(2, 'addx');
  if (f1From < EVENTS) for (const [pair, k] of [[1, 'FLINE_G'], [2, 'FLINE_D']]) K[k] = kernel((b, v, ex) => { lineAcc(b, v, pair, null, [ex.l0, ex.l1], [ex.be0, ex.be1]); }, ['l0', 'l1', 'be0', 'be1']);
  if (f1From === 0) for (const k of ['FDBL_G', 'FDBL_D', 'FADD_G', 'FADD_D', 'FADDX_G', 'FADDX_D']) delete K[k];
  // ---- segment close: 192-byte chunk on top ----
  K.SC = kernel((b, v, ex) => {
    let rest = ex.ch; const limbs = [];
    for (let i = 0; i < 6; i++) {
      let limb;
      if (i < 5) [limb, rest] = b.op([32n, 'SPLIT'], (c) => [c.subarray(0, 32), c.subarray(32)], [rest], {nout: 2});
      else limb = rest;
      limbs.push(b.range(b.op(['BIN2NUM'], (c) => vmToBig(c), [limb]), 1n)); // [1,p): canonical, rejects negative zero
    }
    const basis = [null, v.b1, v.b2, v.b3, v.b4, v.b5];
    let acc = limbs[0];
    for (let i = 1; i < 6; i++) acc = b.add(acc, b.mul(limbs[i], basis[i]));
    const t = b.mulm(v.z, b.md(acc));
    const tP = b.add(1n, t), tM = b.sub(1n, t);
    const Rp = b.mul(v.accP, tM), Rm = b.mul(v.accM, tP);
    v.S = b.md(b.add(v.S, b.mul(v.gj, b.md(b.sub(Rp, Rm)))));
    v.gj = b.mulm(v.gj, v.g);
    v.accP = tP; v.accM = tM;
  }, ['ch']);

  // ---------------- setup (inline) ----------------
  const pushes = []; // unlocking pushes bottom -> top
  const slopeItems = [];
  for (const l of w.slopes) slopeItems.push(l[0], l[1]);
  // slopes pushed so that slope 0 is nearest the top of the deep region
  const deep = []; // bottom -> top labels of the deep region
  for (let i = slopeItems.length - 1; i >= 0; i--) { pushes.push(slopeItems[i]); deep.push('sl' + i); }
  const setupIn = ['QBLOB', 'STATES', 'u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'n0', 'n1', 'vx', 'vy', 'Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy'];
  const pv = w.proofVals;
  const setupVals = {QBLOB, STATES: w.STATES, u0: w.u[0], u1: w.u[1], u2: w.u[2], u3: w.u[3], u4: w.u[4], u5: w.u[5], n0: w.n[0], n1: w.n[1], vx: w.vkx.x, vy: w.vkx.y, ...pv};
  for (const n of setupIn) pushes.push(setupVals[n]);
  const S = new SSA('s'); const v = Object.fromEntries(setupIn.map((n) => [n, n]));
  const Pn = S.lit(P); if (pOnStack) S.pv = Pn;
  // exact blob lengths
  const sizeChk = (name, len) => { v[name] = S.op(['SIZE', BigInt(len), 'NUMEQUALVERIFY'], (x) => { assert.equal(x.length, len); return x; }, [v[name]]); };
  sizeChk('STATES', 6912); sizeChk('QBLOB', 32 * nQ);
  for (const n of ['u0', 'u1', 'u2', 'u3', 'u4', 'u5', 'vx', 'vy', 'Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy']) v[n] = S.range(v[n]);
  for (const n of ['n0', 'n1']) v[n] = S.op(['DUP', 0n, R, 'WITHIN', 'VERIFY'], (x) => { assert.ok(x >= 0n && x < R); return x; }, [v[n]]);
  // curve checks: y^2 - x^3 - 3 == 0 (A, C, vk_x); B on the twist
  for (const [x, y] of [['Ax', 'Ay'], ['Cx', 'Cy'], ['vx', 'vy']]) S.zeroModP(S.sub(S.sub(S.mul(v[y], v[y]), S.mul(S.mulm(v[x], v[x]), v[x])), 3n));
  { const Bx = [v.Bx0, v.Bx1], By = [v.By0, v.By1];
    const lhs = S.f2sqr(By, false), x3 = S.f2mul(S.f2sqr(Bx), Bx, false);
    S.zeroModP(S.sub(S.sub(lhs[0], x3[0]), BTW[0])); S.zeroModP(S.sub(S.sub(lhs[1], x3[1]), BTW[1])); }
  // transcript
  const enc = (x) => S.op([32n, 'NUM2BIN'], (a) => le32(a), [x]);
  const cat = (a, b2) => S.op(['CAT'], (p, q) => Buffer.concat([p, q]), [a, b2]);
  let tr = S.lit(DOMAIN);
  for (const n of ['n0', 'n1', 'Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy', 'u0', 'u1', 'u2', 'u3', 'u4', 'u5']) tr = cat(tr, enc(v[n]));
  tr = cat(tr, v.STATES);
  const sha = (x) => S.op(['SHA256'], (a) => L.sha256.hash(a), [x]);
  const T0 = sha(tr);
  const toF = (h) => S.md(S.op([Uint8Array.of(0), 'CAT', 'BIN2NUM'], (a) => vmToBig(Buffer.concat([a, Buffer.from([0])])), [h]));
  const g = toF(sha(cat(T0, S.lit(Uint8Array.of(1)))));
  const z = toF(sha(cat(cat(T0, S.lit(Uint8Array.of(2))), v.QBLOB)));
  // powers and basis
  const z2 = S.mulm(z, z), z3 = S.mulm(z2, z), z4 = S.mulm(z2, z2), z6 = S.mulm(z3, z3), s = S.sub(z6, 9n);
  const o = {P: Pn, z, z3, z3s: S.mulm(z3, s), b1: s, b2: z2, b3: S.mulm(s, z2), b4: z4, b5: S.mulm(s, z4), g, gj: S.lit(1n), S: S.lit(0n)};
  const pairP = [['Ax', 'Ay', true], ['vx', 'vy', false], ['Cx', 'Cy', false]];
  pairP.forEach(([x, y, negY], j) => {
    o['a1_' + j] = S.md(S.neg(S.mul(v[x], z))); o['a2_' + j] = S.mulm(o['a1_' + j], s);
    o['yP_' + j] = negY ? S.neg(v[y]) : v[y];
  });
  if (proj) o.yPs_0 = S.mulm(o.yP_0, s);
  let U = v.u0; [v.u1, v.u2, v.u3, v.u4, v.u5].forEach((ui, i) => { U = S.add(U, S.mul(ui, o['b' + (i + 1)])); });
  o.zU = S.mulm(z, S.md(U));
  o.accP = S.sub(1n, o.zU); o.accM = S.add(1n, o.zU);
  for (const n of ['Bx0', 'Bx1', 'By0', 'By1']) o[n] = v[n];
  [o.Tg0, o.Tg1, o.Tg2, o.Tg3] = [...w.gammaQ[0], ...w.gammaQ[1]].map((x) => S.lit(x));
  [o.Td0, o.Td1, o.Td2, o.Td3] = [...w.deltaQ[0], ...w.deltaQ[1]].map((x) => S.lit(x));
  if (proj) [o.X0, o.X1, o.Y0, o.Y1, o.Z0, o.Z1] = [S.copy(v.Bx0), S.copy(v.Bx1), S.copy(v.By0), S.copy(v.By1), S.lit(1n), S.lit(0n)];
  else [o.X0, o.X1, o.Y0, o.Y1] = [S.copy(v.Bx0), S.copy(v.Bx1), S.copy(v.By0), S.copy(v.By1)];
  // split STATES into 36 chunks (chunk 0 deepest)
  let rest = v.STATES; const chunks = [];
  for (let j = 0; j < 35; j++) { let c; [c, rest] = S.op([192n, 'SPLIT'], (a) => [a.subarray(0, 192), a.subarray(192)], [rest], {nout: 2}); chunks.push(c); }
  chunks.push(rest);
  const setupOut = [v.QBLOB, ...chunks, ...core.map((n) => o[n])];
  const setupCode = compile({inputs: setupIn, prog: S.prog, outputs: setupOut});
  deep.push('QBLOB', ...chunks.map((_, j) => 'ch' + j));

  // ---------------- glue ----------------
  const fnIds = Object.keys(K);
  const inv = (k) => [BigInt(fnIds.indexOf(k) + 1), 'INVOKE'];
  const counts = Object.fromEntries(fnIds.map((k) => [k, 0]));
  const glue = []; const inline = {};
  const marks = [];
  const call = (k) => { counts[k]++; const a = glue.length; glue.push(...inv(k)); marks.push({k, a, b: glue.length}); };
  const rollDeep = (label) => { const i = deep.indexOf(label); assert.ok(i >= 0, label); const d = core.length + (deep.length - 1 - i); deep.splice(i, 1); glue.push(BigInt(d), 'ROLL'); };
  // the deep ROLL happens while `extraAbove` items sit above the core: account for them
  const rollDeepWith = (label, extraAbove) => { const i = deep.indexOf(label); const d = core.length + extraAbove + (deep.length - 1 - i); deep.splice(i, 1); glue.push(BigInt(d), 'ROLL'); };
  const lamOf = (e, pair, kind) => w.events[e].filter((x) => x.pair === pair && x.kind === kind);
  const ends = new Map(w.segs.map(([, bb], j) => [bb, j]));
  let slopeIdx = 0;
  const pushSlope = (extraAbove) => { rollDeepWith('sl' + (2 * slopeIdx), extraAbove); rollDeepWith('sl' + (2 * slopeIdx + 1), extraAbove + 1); slopeIdx++; };
  const inlineSSA = (name, fn, extraIn = [], extraOutN = 0) => {
    const b = new SSA(name, PV); const vv = Object.fromEntries(core.map((n) => [n, n])); const ex = Object.fromEntries(extraIn.map((n) => [n, n]));
    const outEx = fn(b, vv, ex) ?? [];
    const code = compile({inputs: [...core, ...extraIn], prog: b.prog, outputs: [...core.map((n) => vv[n]), ...outEx]});
    const a0 = glue.length; glue.push(...code); marks.push({k: name, a: a0, b: glue.length}); inline[name] = asm(code).length; assert.equal(outEx.length, extraOutN);
  };
  for (let e = 0; e < EVENTS; e++) {
    const f1 = e >= f1From;
    const fixed = (pair, kind, k2, i = 0) => {
      const L1 = lamOf(e, pair, kind)[i];
      if (f1) { glue.push(L1.lam[0], L1.lam[1], L1.cb[0], L1.cb[1]); call(pair === 1 ? 'FLINE_G' : 'FLINE_D'); }
      else { glue.push(L1.lam[0], L1.lam[1]); if (kind === 'frob') glue.push(L1.xq[0], L1.xq[1]); call(k2); }
    };
    if (!affE(e)) call('BDBL'); else { call('SQ'); pushSlope(0); call('ABDBL'); }
    fixed(1, 'dbl', 'FDBL_G'); fixed(2, 'dbl', 'FDBL_D');
    if (digits[e]) {
      glue.push(BigInt(digits[e])); call('CF');
      if (!affE(e)) call('BADD'); else { pushSlope(4); call('ABADD'); }
      fixed(1, 'add', 'FADD_G'); fixed(2, 'add', 'FADD_D');
    }
    if (e === LAST) {
      // Frobenius: Q1 = psi(B), Q2 = -psi^2(B) computed on-chain from B
      for (let fi = 0; fi < 2; fi++) {
        inlineSSA('frobQ' + fi, (b, vv) => {
          const x = [vv.Bx0, vv.Bx1], y = [vv.By0, vv.By1];
          if (fi === 0) { const xc = [x[0], b.neg(x[1])], yc = [y[0], b.neg(y[1])]; return [...b.f2mul(xc, PSI.PSI_X), ...b.f2mul(yc, PSI.PSI_Y)]; }
          return [...b.f2mul(x, PSI.PSI2_X), b.copy(y[0]), b.copy(y[1])];
        }, [], 4);
        if (!allAff) call('BADD'); else { pushSlope(4); call('ABADD'); }
        fixed(1, 'frob', 'FADDX_G', fi); fixed(2, 'frob', 'FADDX_D', fi);
      }
      // K fold: K(+-z) = 1 +- z*kappa(z^2)
      inlineSSA('kfold', (b, vv) => {
        const bs = [null, vv.b1, vv.b2, vv.b3, vv.b4, vv.b5]; let acc = b.lit(w.kappa[0]);
        for (let i = 1; i < 6; i++) acc = b.add(acc, b.mul(bs[i], w.kappa[i]));
        const zK = b.mulm(vv.z, b.md(acc));
        vv.accP = b.mulm(vv.accP, b.add(1n, zK)); vv.accM = b.mulm(vv.accM, b.sub(1n, zK));
      });
      // exact B endpoint: T_B == -psi^3(B)  (psi^3 = psi o psi^2), plus Z != 0 in projective form
      inlineSSA('endpoint', (b, vv) => {
        const x = [vv.Bx0, vv.Bx1], y = [vv.By0, vv.By1];
        const x2 = b.f2mul(x, PSI.PSI2_X), y2 = [b.neg(y[0]), b.neg(y[1])];
        const x3 = b.f2mul([x2[0], b.neg(x2[1])], PSI.PSI_X), y3 = b.f2mul([y2[0], b.neg(y2[1])], PSI.PSI_Y);
        if (!allAff) {
          const Z = [vv.Z0, vv.Z1];
          b.nonzero2(Z);
          const xz = b.f2mul(x3, Z, false), yz = b.f2mul(y3, Z, false);
          b.zeroModP(b.sub(vv.X0, xz[0])); b.zeroModP(b.sub(vv.X1, xz[1]));
          b.zeroModP(b.add(vv.Y0, yz[0])); b.zeroModP(b.add(vv.Y1, yz[1]));
        } else {
          b.zeroModP(b.sub(vv.X0, x3[0])); b.zeroModP(b.sub(vv.X1, x3[1]));
          b.zeroModP(b.add(vv.Y0, y3[0])); b.zeroModP(b.add(vv.Y1, y3[1]));
        }
      });
    }
    if (ends.has(e)) { rollDeep('ch' + ends.get(e)); call('SC'); }
  }
  // ---------------- final: Horner over QBLOB, S == Q(z) M(z) ----------------
  const defs = fnIds.flatMap((k, i) => (counts[k] ? [asm(K[k].code), BigInt(i + 1), 'DEFINE'] : [])); // unused kernels are not defined
  rollDeep('QBLOB');
  assert.equal(deep.length, 0);
  const hornerBody = new SSA('h');
  // Horner step as a function: [z2 ... acc blob] -> [acc' blob']: compiled over a 3-item region
  {
    const hb = hornerBody;
    const [q, r] = hb.op([32n, 'SPLIT'], (c) => [c.subarray(0, 32), c.subarray(32)], ['blob'], {nout: 2});
    const qn = hb.range(hb.op(['BIN2NUM'], (c) => vmToBig(c), [q]), 1n);
    const a2 = hb.md(hb.add(hb.mul('acc', 'z2'), qn));
    K.HSTEP = {code: compile({inputs: ['z2', 'acc', 'blob'], prog: hb.prog, outputs: ['z2', a2, r]})};
    K.HSTEP.bytes = asm(K.HSTEP.code).length;
  }
  // region for the final: core + QBLOB. Bring b2 (z^2) and an accumulator above QBLOB.
  const fin = [];
  // stack: core..., QBLOB  -> [core..., QBLOB, z2, acc, blob]
  fin.push(BigInt(core.length - core.indexOf('b2')), 'PICK', 0n, 2n, 'ROLL');
  const hId = BigInt(fnIds.length + 1);
  for (let i = 0; i < nQ; i++) fin.push(hId, 'INVOKE');
  fin.push(0n, 'NUMEQUALVERIFY', 'NIP'); // blob empty; drop z2 -> [core..., acc]
  {
    const b = new SSA('fin', PV); const vv = Object.fromEntries(core.map((n) => [n, n]));
    const Qz = b.mulm('accQ', vv.z), z6 = b.mulm(vv.b2, vv.b4);
    const Mz = b.add(b.sub(b.mul(z6, z6), b.mul(z6, 18n)), 82n);
    b.zeroModP(b.sub(vv.S, b.mul(Qz, b.md(Mz))));
    fin.push(...compile({inputs: [...core, 'accQ'], prog: b.prog, outputs: []}), 1n, 'NIP');
  }
  const hDef = [asm(K.HSTEP.code), hId, 'DEFINE'];
  const lock = asm(...defs, ...hDef, ...setupCode, ...glue, ...fin);
  const sec = {defs: asm(...defs, ...hDef).length, setup: asm(setupCode).length, glue: asm(glue).length, final: asm(fin).length};
  const prefix = (gi) => asm(...defs, ...hDef, ...setupCode, ...glue.slice(0, gi));
  return {lock, pushes, sec, K, counts, inline, nQ, QBLOB, layout: core, marks, prefix, setupOnly: asm(...defs, ...hDef, ...setupCode), defsOnly: asm(...defs, ...hDef), glueLen: glue.length};
}

const fmtM = (x) => (x / 1e6).toFixed(3) + 'M';
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const m0 = process.argv[2] ?? 'proj', mode = /^\d+$/.test(m0) ? Number(m0) : m0;
  const fi = Number(process.argv[3] ?? 0);
  const f1From = Number((process.argv.find((x) => x.startsWith('--f1=')) ?? '--f1=' + EVENTS).slice(5));
  const w = makeWitness(fi, mode);
  const B = build(w, {f1From});
  const r = run(B.pushes, B.lock, {pad: 60000});
  const rc = run(B.pushes, B.lock, {pad: 60000, vm: vmCons});
  const r0 = run(B.pushes, asm('1'), {pad: 60000});
  console.log({mode, fixture: fi, accepted: !r.err && !rc.err, error: r.err ?? null, consensusError: rc.err ?? null});
  const witnessBytes = B.pushes.reduce((a, x) => a + (x instanceof Uint8Array ? L.encodeDataPush(x).length : L.encodeDataPush(num(x)).length), 0);
  const out = {mode, fixture: fi, opStandard: r.cost - r0.cost, opConsensus: rc.cost - run(B.pushes, asm('1'), {pad: 60000, vm: vmCons}).cost,
    lockBytes: B.lock.length, sections: B.sec, witnessBytes, kernelBytes: Object.fromEntries(Object.entries(B.K).map(([k, x]) => [k, x.bytes])),
    calls: B.counts, inlineBytes: B.inline, nQ: B.nQ, coreSlots: B.layout.length};
  console.log(JSON.stringify(out));
  if (process.argv.includes('--breakdown')) {
    const c = (lk) => run(B.pushes, lk, {pad: 60000}).cost - r0.cost;
    const bd = {defs: c(B.defsOnly)}; bd.setup = c(B.setupOnly) - bd.defs;
    const seen = {};
    for (const m of B.marks) {
      if (seen[m.k] !== undefined) continue;
      // the slope/chunk/literal pushes immediately before a call are attributed to the call
      const prevEnd = B.marks.filter((x) => x.b <= m.a).at(-1)?.b ?? 0;
      seen[m.k] = c(B.prefix(m.b)) - c(B.prefix(prevEnd));
    }
    bd.perCall = seen;
    bd.loopTotal = c(B.prefix(B.glueLen)) - c(B.setupOnly);
    bd.final = out.opStandard - c(B.prefix(B.glueLen));
    console.log(JSON.stringify(bd));
  }
  console.log('op standard', fmtM(out.opStandard), 'consensus', fmtM(out.opConsensus), 'lock', out.lockBytes, 'witness', witnessBytes);
}
