// Shared reference math + helpers for the chunked BLS12-381 pairing generators
// (Miller loops, combine, final exponentiation). The BLS counterpart of
// chunked/pairing/_millermath.mjs. The per-step math is noble's (which our
// CashScript fp2/fp6/fp12 ops match bit-for-bit, per singleton/bls12-381/*.mjs), so
// the carried limbs equal what the contract computes and the NFT-commitment hashes
// line up. Covenant + 48-byte serialization are reused from _vkxmath.mjs.
//
// BLS12-381 vs BN254 (see singleton/bls12-381/miller_ref.mjs):
//   * multiplicative (M-type) twist -> the line uses mul014, not mul034
//   * G2 b' = 4*(1+u): mulByB(x) = (4 c0 - 4 c1) + (4 c0 + 4 c1) u
//   * ate loop = NAF of |x| (x = -0xd201000000010000), 64 digits; NO 6x+2, NO Q1/Q2
//   * x is NEGATIVE -> the single-pair Miller result is CONJUGATED at the very end
//   * final exponentiation is the BLS/Hayashida-Scott hard part over |x|
import { readFileSync } from 'node:fs';
import {
  P, compileBytecode, OP_BUDGET, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2,
  le48, le48Exact, commit, CATEGORY, commitBin, commitBinExact, covIn, covOut, planChunk, tok, verifierPath,
  measureCovenant as _measureCov, bls12_381,
} from './_vkxmath.mjs';
import { vk, proof, computeVkx, boundaryFor } from '../../singleton/bls12-381/bls_instance.mjs';

export { P, OP_BUDGET, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2, le48, le48Exact, commit, CATEGORY, commitBin, commitBinExact, covIn, covOut, planChunk, tok, verifierPath, compileBytecode, vk, proof, computeVkx, boundaryFor };
export const { Fp, Fp2, Fp6, Fp12 } = bls12_381.fields;

// ---- miller-step math (noble, M-twist) ----
const INV2 = Fp2.div(Fp2.ONE, Fp2.fromBigTuple([2n, 0n]));
const mulByB = (x) => Fp2.fromBigTuple([Fp.sub(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n)), Fp.add(Fp.mul(x.c0, 4n), Fp.mul(x.c1, 4n))]);
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
export function pointDouble(Rx, Ry, Rz) {
  const t0 = Fp2.sqr(Ry), t1 = Fp2.sqr(Rz);
  const t2 = mulByB(Fp2.mul(t1, 3n)), t3 = Fp2.mul(t2, 3n);
  const t4 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Ry, Rz)), t1), t0);
  const c0 = Fp2.sub(t2, t0), c1 = Fp2.mul(Fp2.sqr(Rx), 3n), c2 = Fp2.neg(t4);
  const nx = Fp2.mul(Fp2.mul(Fp2.mul(Fp2.sub(t0, t3), Rx), Ry), INV2);
  const ny = Fp2.sub(Fp2.sqr(Fp2.mul(Fp2.add(t0, t3), INV2)), Fp2.mul(Fp2.sqr(t2), 3n));
  const nz = Fp2.mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
export function pointAdd(Rx, Ry, Rz, Qx, Qy) {
  const t0 = Fp2.sub(Ry, Fp2.mul(Qy, Rz)), t1 = Fp2.sub(Rx, Fp2.mul(Qx, Rz));
  const c0 = Fp2.sub(Fp2.mul(t0, Qx), Fp2.mul(t1, Qy)), c1 = Fp2.neg(t0), c2 = t1;
  const t2 = Fp2.sqr(t1), t3 = Fp2.mul(t2, t1), t4 = Fp2.mul(t2, Rx);
  const t5 = Fp2.add(Fp2.sub(t3, Fp2.mul(t4, 2n)), Fp2.mul(Fp2.sqr(t0), Rz));
  const nx = Fp2.mul(t1, t5);
  const ny = Fp2.sub(Fp2.mul(Fp2.sub(t4, t5), t0), Fp2.mul(t3, Ry));
  const nz = Fp2.mul(Rz, t3);
  return { coeffs: [c0, c1, c2], R: { x: nx, y: ny, z: nz } };
}
const fp6Mul1 = (x, b1) => Fp6.create({ c0: Fp2.mulByNonresidue(Fp2.mul(x.c2, b1)), c1: Fp2.mul(x.c0, b1), c2: Fp2.mul(x.c1, b1) });
function mul014(f, o0, o1, o4) {
  const t0 = Fp6.mul01(f.c0, o0, o1);
  const t1 = fp6Mul1(f.c1, o4);
  return Fp12.create({
    c0: Fp6.add(Fp6.mulByNonresidue(t1), t0),
    c1: Fp6.sub(Fp6.sub(Fp6.mul01(Fp6.add(f.c1, f.c0), o0, Fp2.add(o1, o4)), t0), t1),
  });
}
export const lineFn = (f, c0, c1, c2, Px, Py) => mul014(f, c0, scalarFp2(c1, Px), scalarFp2(c2, Py));

// Identity-complete G1 line coordinates for the BLS M-twist. For a finite
// P=(x,y), u=-x/(2y) and v=-1/(2y). The curve equation becomes
// v=4u^3+16v^3, with the unique v=0 solution (u,v)=(0,0) encoding infinity.
//
// A raw mul014 line is c0 + c1*x*V + c2*y*W*V. Multiplying it by
// -2v/(W*V) gives the sparse (0,4,5) value
//   c2 - (2*c0*v/xi)*W*V - (2*c1*u/xi)*W*V^2,
// where V^3=xi. The removed factor is killed by final exponentiation;
// at (u,v)=(0,0), accepted G2 walks leave a nonzero Fp2 value c2, also killed there.
const XI_INV = Fp2.inv(Fp2.fromBigTuple([1n, 1n]));
export function unitG1(point) {
  if (point.is0()) return { u: 0n, v: 0n };
  const { x, y } = point.toAffine();
  const yInv = Fp.inv(Fp.mul(2n, y));
  return { u: Fp.neg(Fp.mul(x, yInv)), v: Fp.neg(yInv) };
}
export const lineUnitScaledFn = (f, c0, c1, c2, u, v) => {
  const o4 = Fp2.neg(Fp2.mul(scalarFp2(c0, Fp.mul(2n, v)), XI_INV));
  const o5 = Fp2.neg(Fp2.mul(scalarFp2(c1, Fp.mul(2n, u)), XI_INV));
  const sparse = Fp12.create({
    c0: Fp6.create({ c0: c2, c1: Fp2.ZERO, c2: Fp2.ZERO }),
    c1: Fp6.create({ c0: Fp2.ZERO, c1: o4, c2: o5 }),
  });
  return Fp12.mul(f, sparse);
};

// qsplit-only direct eight-Fp2-product fold for a normalized affine G2 line
// d0 - m*x + y = 0. The established shared Miller generators continue to use
// the NAF/mul014 path below; qsplit callers opt into this path explicitly.
export const qsplitLineUnitDirect8Fn = (f, d0, m, u, v) => {
  const oneMinusI = Fp2.fromBigTuple([1n, Fp.neg(1n)]);
  const q = Fp2.mul(
    Fp2.fromBigTuple([Fp.neg(Fp.mul(d0.c0, v)), Fp.neg(Fp.mul(d0.c1, v))]),
    oneMinusI,
  );
  const r = Fp2.mul(
    Fp2.fromBigTuple([Fp.mul(m.c0, u), Fp.mul(m.c1, u)]),
    oneMinusI,
  );
  return Fp12.mul(f, Fp12.create({
    c0: Fp6.ONE,
    c1: Fp6.create({ c0: Fp2.ZERO, c1: q, c2: r }),
  }));
};

export function qsplitNormalizeLine(coeffs) {
  if (Fp2.eql(coeffs[2], Fp2.ZERO)) {
    throw new Error('cannot normalize a Miller line with zero c2');
  }
  const c2Inv = Fp2.inv(coeffs[2]);
  return {
    d0: Fp2.mul(coeffs[0], c2Inv),
    m: Fp2.neg(Fp2.mul(coeffs[1], c2Inv)),
  };
}

// ---- ate loop NAF of |x| (BLS_X), 64 digits, MSB-first ----
const BLS_X = 0xd201000000010000n;
const naf = (a) => { const r = []; for (; a > 1n; a >>= 1n) { if ((a & 1n) === 0n) r.unshift(0); else if ((a & 3n) === 3n) { r.unshift(-1); a += 1n; } else r.unshift(1); } return r; };
export const ATE_NAF = naf(BLS_X);

// one fused NAF step k on (f, R) for pair (Qx,Qy,Px,Py)
export function millerStep(f, R, k, Qx, Qy, negQy, Px, Py) {
  f = Fp12.sqr(f);
  let d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], Px, Py);
  if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, Qx, ATE_NAF[k] === -1 ? negQy : Qy); R = a.R; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], Px, Py); }
  return { f, R };
}
// full single-pair Miller -> { f (Fp12, CONJUGATED for x<0), R (final, unused downstream) }
export function singlePairMiller(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  let f = Fp12.ONE, R = { x: Qa.x, y: Qa.y, z: Fp2.ONE };
  for (let k = 0; k < ATE_NAF.length; k++) ({ f, R } = millerStep(f, R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y));
  return { f: Fp12.conjugate(f), R };
}

// ---- BATCHED multi-pair Miller (one shared fp12Sqr per step) -------------------
// noble's millerLoopBatch: f squared ONCE per NAF step, then each pair's double-line
// (and add-line when the digit is set) multiplied into the SHARED f; each pair's R
// evolves independently. This eliminates 3 of every 4 fp12Sqr vs four single-pair
// chains, AND folds the 4 results so the conjugated f after the loop IS the boundary
// (no separate combine). `pds` = [{Qx,Qy,negQy,Px,Py}] per pair (affine).
export function pairData(pairs) {
  return pairs.map((p) => { const Qa = p.Q.toAffine(), Pa = p.P.toAffine(); return { Qx: Qa.x, Qy: Qa.y, negQy: Fp2.neg(Qa.y), Px: Pa.x, Py: Pa.y }; });
}
export function millerBatchStep(f, Rs, k, pds) {
  f = Fp12.sqr(f);
  const out = [];
  for (let j = 0; j < pds.length; j++) {
    const pd = pds[j]; let R = Rs[j];
    let d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py);
    if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, pd.Qx, ATE_NAF[k] === -1 ? pd.negQy : pd.Qy); R = a.R; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
    out.push(R);
  }
  return { f, Rs: out };
}
// states[k] = { f, Rs:[4] } BEFORE step k; finalF = conjugate(states[64].f) = boundary.
export function millerBatchStates(pairs) {
  const pds = pairData(pairs);
  const states = [{ f: Fp12.ONE, Rs: pds.map((pd) => ({ x: pd.Qx, y: pd.Qy, z: Fp2.ONE })) }];
  for (let k = 0; k < ATE_NAF.length; k++) states.push(millerBatchStep(states[k].f, states[k].Rs, k, pds));
  return { states, finalF: Fp12.conjugate(states[ATE_NAF.length].f) };
}

// FLAT-OP model: one batched step (sqr + 4×(double-line[+add-line])) is ~8 mul014 ≈
// 13M op — too coarse for one BCH input. So expose the loop as a flat op list that can
// be chunked at ANY op boundary, carrying (f + 4 R) as state. Each op updates f and at
// most one Rj. ops[i] = {t:'sqr'} | {t:'dl',j} | {t:'al',j,neg}. states[i] = {f,Rs}
// BEFORE op i; states[ops.length] = the final state (f pre-conjugate). The line
// function is internal here so the op replay matches the contract bit-for-bit.
export function millerBatchOps(pairs, opts = {}) {
  // opts.skipPairs (Set of pair indices): omit those pairs' line-folds entirely. Used by the
  // residue build to drop the fully-constant pair e(alpha,beta) from the loop (its single-pair
  // Miller value is baked and multiplied in once instead). Default = skip none, so every other
  // consumer is unaffected. f then = product over the NON-skipped pairs (pre-conjugate).
  const skip = opts.skipPairs ?? new Set();
  const unitLines = opts.unitLines === true;
  const pds = pairData(pairs).map((pd, j) => unitLines && PT_CFG[j].P
    ? { ...pd, ...unitG1(pairs[j].P) }
    : pd);
  const foldLine = (value, coeffs, pd) => unitLines && pd.u !== undefined
    ? lineUnitScaledFn(value, coeffs[0], coeffs[1], coeffs[2], pd.u, pd.v)
    : lineFn(value, coeffs[0], coeffs[1], coeffs[2], pd.Px, pd.Py);
  const ops = [];
  for (let k = 0; k < ATE_NAF.length; k++) {
    ops.push({ t: 'sqr' });
    for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'dl', j }); if (ATE_NAF[k]) ops.push({ t: 'al', j, neg: ATE_NAF[k] === -1 }); }
  }
  const states = [];
  let f = Fp12.ONE; const Rs = pds.map((pd) => ({ x: pd.Qx, y: pd.Qy, z: Fp2.ONE }));
  // Each non-sqr op also records its line coeffs (`op.coeffs`, a triple of Fp2). For a pair
  // with a FIXED VK G2 point the whole R trajectory is proof-independent, so a generator can
  // BAKE these coeffs and only evaluate the line at the runtime G1 point (no on-chain G2 work).
  for (const op of ops) {
    states.push({ f, Rs: Rs.slice() });
    if (op.t === 'sqr') f = Fp12.sqr(f);
    else if (op.t === 'dl') { const d = pointDouble(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z); Rs[op.j] = d.R; op.coeffs = d.coeffs; f = foldLine(f, d.coeffs, pds[op.j]); }
    else { const pd = pds[op.j]; const a = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[op.j] = a.R; op.coeffs = a.coeffs; f = foldLine(f, a.coeffs, pd); }
  }
  states.push({ f, Rs: Rs.slice() });
  return { ops, states, boundary: f, finalF: Fp12.conjugate(f) };
}

// qsplit uses the ordinary binary expansion of |x| because its affine/direct8
// trace is smaller with five additions. These exports are deliberately separate
// from ATE_NAF and millerBatchOps, preserving every existing generator default.
export const QSPLIT_ATE_LOOP_DIGITS = Array.from(BLS_X.toString(2).slice(1), Number);

const qsplitPairData = (pairs) => pairs.map((pair) => {
  const Q = pair.Q.toAffine();
  const Ppoint = pair.P.toAffine();
  return { Qx: Q.x, Qy: Q.y, Px: Ppoint.x, Py: Ppoint.y };
});

export function qsplitSinglePairMiller(pair) {
  const Q = pair.Q.toAffine();
  const Ppoint = pair.P.toAffine();
  let f = Fp12.ONE;
  let R = { x: Q.x, y: Q.y, z: Fp2.ONE };
  for (let k = 0; k < QSPLIT_ATE_LOOP_DIGITS.length; k++) {
    f = Fp12.sqr(f);
    const doubled = pointDouble(R.x, R.y, R.z);
    R = doubled.R;
    f = lineFn(f, ...doubled.coeffs, Ppoint.x, Ppoint.y);
    if (QSPLIT_ATE_LOOP_DIGITS[k] !== 0) {
      const added = pointAdd(R.x, R.y, R.z, Q.x, Q.y);
      R = added.R;
      f = lineFn(f, ...added.coeffs, Ppoint.x, Ppoint.y);
    }
  }
  return { f: Fp12.conjugate(f), R };
}

export function qsplitMillerBatchOps(pairs, opts = {}) {
  const skip = opts.skipPairs ?? new Set();
  const unitLines = opts.unitLines === true;
  const pds = qsplitPairData(pairs).map((pd, index) => unitLines && PT_CFG[index].P
    ? { ...pd, ...unitG1(pairs[index].P) }
    : pd);
  const foldLine = (value, coeffs, pd) => unitLines && pd.u !== undefined
    ? lineUnitScaledFn(value, coeffs[0], coeffs[1], coeffs[2], pd.u, pd.v)
    : lineFn(value, coeffs[0], coeffs[1], coeffs[2], pd.Px, pd.Py);
  const ops = [];
  for (let k = 0; k < QSPLIT_ATE_LOOP_DIGITS.length; k++) {
    ops.push({ t: 'sqr' });
    for (let index = 0; index < 4; index++) {
      if (skip.has(index)) continue;
      ops.push({ t: 'dl', j: index });
      if (QSPLIT_ATE_LOOP_DIGITS[k] !== 0) {
        ops.push({ t: 'al', j: index, neg: false });
      }
    }
  }
  const states = [];
  let f = Fp12.ONE;
  const Rs = pds.map((pd) => ({ x: pd.Qx, y: pd.Qy, z: Fp2.ONE }));
  for (const op of ops) {
    states.push({ f, Rs: Rs.slice() });
    if (op.t === 'sqr') {
      f = Fp12.sqr(f);
    } else if (op.t === 'dl') {
      const doubled = pointDouble(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z);
      Rs[op.j] = doubled.R;
      op.coeffs = doubled.coeffs;
      f = foldLine(f, doubled.coeffs, pds[op.j]);
    } else {
      const pd = pds[op.j];
      const added = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, pd.Qx, pd.Qy);
      Rs[op.j] = added.R;
      op.coeffs = added.coeffs;
      f = foldLine(f, added.coeffs, pd);
    }
  }
  states.push({ f, Rs: Rs.slice() });
  return { ops, states, boundary: f, finalF: Fp12.conjugate(f) };
}

// Plain prepared-VK Miller trace. Pair 1 = e(alpha,beta) is wholly fixed, so replace its
// 69 sparse line folds with one dense multiplication by its pre-conjugate Miller value.
// Pairs 2 and 3 retain their line folds (their G1 points are runtime), but their fixed-G2
// trajectories expose baked coefficients through `op.coeffs`; only pair 0 needs a runtime R.
const PRECOMPUTED_PAIR = 1;
const PREPARED_G2_PAIRS = [2, 3];
export function millerPreparedOps(pairs) {
  if (pairs.length !== 4 || pairs.map((pair) => pair.name).join(',') !== 'negA_B,alpha_beta,vkx_gamma,C_delta') {
    throw new Error('prepared Miller requires the four ordered Groth16 pairs');
  }
  const base = millerBatchOps(pairs, { skipPairs: new Set([PRECOMPUTED_PAIR]) });
  const fAB = Fp12.conjugate(singlePairMiller(pairs[PRECOMPUTED_PAIR]).f);
  const preparedG2Points = PREPARED_G2_PAIRS.map((pairIndex) => {
    const Q = pairs[pairIndex].Q.toAffine();
    return [Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1];
  });
  const boundary = Fp12.mul(base.boundary, fAB);
  const finalF = Fp12.conjugate(boundary);
  if (!Fp12.eql(finalF, millerBatchOps(pairs).finalF)) {
    throw new Error('prepared Miller boundary does not match the raw four-pair boundary');
  }
  const tail = base.states[base.states.length - 1];
  return {
    ops: [...base.ops, { t: 'cmul1' }],
    states: [...base.states, { f: boundary, Rs: tail.Rs.slice() }],
    boundary,
    finalF,
    fAB,
    precomputedPair: PRECOMPUTED_PAIR,
    preparedG2Pairs: PREPARED_G2_PAIRS,
    preparedG2Points,
  };
}

export function assertPreparedMillerManifest(manifest, trace, { checkReferenceBoundary = true } = {}) {
  const expectedFAB = f12limbs(trace.fAB).map(String);
  const fABMatches = Array.isArray(manifest.precomputedPairMiller)
    && manifest.precomputedPairMiller.length === expectedFAB.length
    && manifest.precomputedPairMiller.every((limb, i) => limb === expectedFAB[i]);
  const preparedG2Matches = Array.isArray(manifest.preparedG2Pairs)
    && manifest.preparedG2Pairs.length === trace.preparedG2Pairs.length
    && manifest.preparedG2Pairs.every((pair, i) => pair === trace.preparedG2Pairs[i]);
  const preparedG2PointsMatch = Array.isArray(manifest.preparedG2Points)
    && manifest.preparedG2Points.length === trace.preparedG2Points.length
    && manifest.preparedG2Points.every((point, i) =>
      Array.isArray(point)
      && point.length === trace.preparedG2Points[i].length
      && point.every((limb, j) => limb === String(trace.preparedG2Points[i][j])));
  const boundary = f12limbs(trace.finalF).map(String);
  const boundaryMatches = Array.isArray(manifest.boundary)
    && manifest.boundary.length === boundary.length
    && manifest.boundary.every((limb, i) => limb === boundary[i]);
  const chunksCoverTrace = Array.isArray(manifest.chunks)
    && manifest.chunks.length > 0
    && manifest.chunks.length === manifest.numChunks
    && manifest.chunks.every((chunk, i) =>
      chunk.idx === i
      && Number.isInteger(chunk.opLo)
      && Number.isInteger(chunk.opHi)
      && chunk.opLo === (i === 0 ? 0 : manifest.chunks[i - 1].opHi)
      && chunk.opHi > chunk.opLo
      && chunk.opHi <= trace.ops.length
      && chunk.final === (chunk.opHi === trace.ops.length))
    && manifest.chunks[manifest.chunks.length - 1].opHi === trace.ops.length;
  if (
    manifest.batched !== true
    || manifest.preparedVk !== true
    || manifest.stageBound !== true
    || manifest.genesisDerived !== true
    || manifest.numPairs !== 4
    || manifest.runtimeRs !== 1
    || manifest.numOps !== trace.ops.length
    || manifest.precomputedPair !== trace.precomputedPair
    || trace.ops[trace.ops.length - 1]?.t !== 'cmul1'
    || !fABMatches
    || !preparedG2Matches
    || !preparedG2PointsMatch
    || (checkReferenceBoundary && !boundaryMatches)
    || !chunksCoverTrace
  ) {
    throw new Error('prepared Miller manifest does not match its trace; regenerate it with gen_miller.mjs');
  }
}

// ---- state serialization (matches the .cash hash256(toPaddedBytes(.,48))) ----
export const f12limbs = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
export const r6limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1];
export const qsplitR4limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1];

// ---- the committed instance's 4 Groth16 pairs ----
export const vkxPoint = (inputs) => computeVkx(inputs.map(BigInt));
export const pairsFor = (inputs, pf = proof) => [
  { name: 'negA_B', P: pf.a.negate(), Q: pf.b },
  { name: 'alpha_beta', P: vk.alpha, Q: vk.beta },
  { name: 'vkx_gamma', P: vkxPoint(inputs), Q: vk.gamma },
  { name: 'C_delta', P: pf.c, Q: vk.delta },
];
export const qsplitVkxMsmPoint = (inputs) => inputs.map(BigInt).reduce(
  (point, scalar, index) => scalar === 0n
    ? point
    : point.add(vk.ic[index + 1].multiply(scalar)),
  bls12_381.G1.Point.ZERO,
);
export const qsplitVkxPoint = (inputs) => vk.ic[0].add(qsplitVkxMsmPoint(inputs));
export const qsplitPairsFor = (inputs, pf = proof, { msmOnly = false } = {}) => [
  { name: 'negA_B', P: pf.a.negate(), Q: pf.b },
  { name: 'alpha_beta', P: vk.alpha, Q: vk.beta },
  { name: 'vkx_gamma', P: msmOnly ? qsplitVkxMsmPoint(inputs) : qsplitVkxPoint(inputs), Q: vk.gamma },
  { name: 'C_delta', P: pf.c, Q: vk.delta },
];
// A canonical B identity is evaluated as e(O,Q*) so the Miller walk remains defined. Q* only
// needs to be fixed, nonzero, and order-r; the certificate pins those properties for this base.
export const B_IDENTITY_SUBSTITUTE = bls12_381.G2.Point.BASE;
// build a proof object {a,b,c} (curve points) from raw limb bigints (replay proof#1)
export const proofFromLimbs = (Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy) => ({
  a: bls12_381.G1.Point.fromAffine({ x: Ax, y: Ay }),
  b: bls12_381.G2.Point.fromAffine({ x: Fp2.fromBigTuple([Bxa, Bxb]), y: Fp2.fromBigTuple([Bya, Byb]) }),
  c: bls12_381.G1.Point.fromAffine({ x: Cx, y: Cy }),
});

// Which of P (G1) and Q (G2) are PROOF-derived (runtime) per pair, vs VK (baked).
// pair0 e(-A,B): both proof. pair1 e(alpha,beta): both VK. pair2 e(vk_x,gamma):
// P=vk_x runtime, Q=gamma VK. pair3 e(C,delta): P=C runtime, Q=delta VK.
export const PT_CFG = [{ P: true, Q: true }, { P: false, Q: false }, { P: true, Q: false }, { P: true, Q: false }];
export const ptLimbs = (pairIdx, P_, Q_) => {
  const o = [], c = PT_CFG[pairIdx];
  if (c.P) o.push(P_.x, P_.y);
  if (c.Q) o.push(Q_.x.c0, Q_.x.c1, Q_.y.c0, Q_.y.c1);
  return o;
};

// ---- finalExp op-DAG trace (BLS hard part; replayable for ANY boundary) ----------
// Same Fp12 primitive set as BN254 (cyc/mul/conj/f1/f2/f3/inv); only the addition
// chain + |x| differ. cycExpX is square-and-multiply over the 64 bits of |x| from ONE
// (faithful to finalexp.cash, including the trivial leading ops -> op-cost matches).
const ABS_X = 15132376222941642752n; // |x|, 64-bit
export function finalexpTrace(boundaryVal) {
  const ops = []; let nextId = 0;
  const Vv = (val) => ({ id: nextId++, val });
  const rec = (op, args, val) => { const v = Vv(val); ops.push({ id: v.id, op, args: args.map((a) => a.id), val }); return v; };
  const cyc = (a) => rec('cyc', [a], Fp12._cyclotomicSquare(a.val));
  const mul = (a, b) => rec('mul', [a, b], Fp12.mul(a.val, b.val));
  const conj = (a) => rec('conj', [a], Fp12.conjugate(a.val));
  const f1 = (a) => rec('f1', [a], Fp12.frobeniusMap(a.val, 1));
  const f2 = (a) => rec('f2', [a], Fp12.frobeniusMap(a.val, 2));
  const f3 = (a) => rec('f3', [a], Fp12.frobeniusMap(a.val, 3));
  const inv = (a) => rec('inv', [a], Fp12.inv(a.val));
  // square-and-multiply for numV^|x|, MSB-first. |x| bit 63 (the MSB) is set, so we
  // seed z = numV (consuming that bit) and loop bits 62..0 -> no ONE constant leaf.
  const cycExpX = (numV) => { let z = numV; for (let i = 62; i >= 0; i--) { z = cyc(z); if ((ABS_X >> BigInt(i)) & 1n) z = mul(z, numV); } return z; };
  const powMinusX = (zV) => conj(cycExpX(zV));
  const fV = Vv(boundaryVal);
  // easy part
  const t0 = mul(conj(fV), inv(fV));
  const t1 = mul(f2(t0), t0);
  // hard part
  const t2 = powMinusX(t1);
  const t3 = mul(conj(cyc(t1)), t2);
  const t4 = powMinusX(t3);
  const t5 = powMinusX(t4);
  const t6 = mul(powMinusX(t5), cyc(t2));
  const t7 = powMinusX(t6);
  const A = f2(mul(t2, t5));
  const B = f3(mul(t4, t1));
  const C = f1(mul(t6, conj(t1)));
  const D = mul(mul(t7, conj(t3)), t1);
  const result = mul(mul(mul(A, B), C), D);
  const valOf = new Map([[fV.id, boundaryVal]]); for (const o of ops) valOf.set(o.id, o.val);
  const def = new Map([[fV.id, -1]]); ops.forEach((o, i) => def.set(o.id, i));
  const lastUse = new Map(); ops.forEach((o, i) => o.args.forEach((a) => lastUse.set(a, i)));
  lastUse.set(result.id, ops.length);
  const liveAt = (cut) => [...def.keys()].filter((id) => def.get(id) < cut && (lastUse.get(id) ?? -1) >= cut).sort((a, b) => a - b);
  const limbs12 = (id) => f12limbs(valOf.get(id));
  return { ops, liveAt, limbs12, resultId: result.id, result: result.val, boundaryId: fV.id };
}

// ---- extract reusable functions from a singleton lib .cash (brace-counted) ----
// The singleton libs are top-level `function`s at column 0 (feat/multi-returns syntax).
export function fnExtractor(cashPath) {
  const src = readFileSync(cashPath, 'utf8').split('\n');
  return (name) => {
    const out = []; let p = false, depth = 0;
    for (const ln of src) {
      if (!p && ln.startsWith(`function ${name}(`)) p = true;
      if (p) {
        out.push(ln);
        depth += (ln.match(/\{/g) || []).length - (ln.match(/\}/g) || []).length;
        if (depth === 0 && ln.includes('}')) break;
      }
    }
    return out.join('\n');
  };
}

// ---- real-VM covenant measurer (state == committed; no extra uncommitted args) ----
export const measureCovenant = (src, inLimbs, outLimbs) => _measureCov(src, inLimbs, inLimbs, outLimbs);

// LAZY reduction (BN254 "option-A"): drop the `% p` in addFp (values only grow inside a
// chunk; mulFp/subFp and the covOut reduction bring them back). subFp keeps the mod but
// with a big K*p bias so a lazily-grown operand never goes negative. Same signatures as
// the singleton's addFp/subFp, so callers are unchanged — the chunk generators just emit
// these instead of extracting the reducing versions. K=64 is well above the deepest
// add-chain bound in the tower (validated by build_vectors accepting on the real VM).
export const lazyArith = (K = 64) =>
  'function addFp(int x, int y) returns (int) { return x + y; }\n' +
  `function subFp(int x, int y) returns (int) { return (x - y + ${(BigInt(K) * P).toString()}) % ${P}; }`;
// 4-arg form for chunks that push UNCOMMITTED witness args (pushed = stateInts,
// committed = commitInts), e.g. the final-exp chunk that supplies f^-1 as a witness.
export const measureCov4 = _measureCov;
export const decl = (names) => names.map((n) => `int ${n}`).join(',');
