// Shared reference math + helpers for the chunked-pairing generators (noble
// Fp2/Fp6/Fp12, matching our CashScript ops bit-for-bit), plus the committed
// instance's 4 Groth16 pairs, state serialization, and a real-VM measurer.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import { bn254 } from '@noble/curves/bn254.js';
export { bn254 };
export const { Fp, Fp2, Fp6, Fp12 } = bn254.fields;

// IN-PROCESS cashc compile (compileString + asmToBytecode) instead of spawning a
// `node cashc-cli` subprocess per candidate chunk — the planner compiles hundreds
// of times, so dropping the spawn + file I/O is a real speedup.
import { compileString, compileFile, utils } from 'cashc';
const { asmToBytecode } = utils;

// Compiled redeems go through the compiler's DAG stack-rescheduling pass (cashc fork
// option `rescheduleStacks`): each straight-line block's schedule is re-derived so
// operands are on top of the stack when needed, and each function's argument order is
// chosen jointly with its schedule, selected by the BCH2026 op-cost meter. Default ON —
// the committed vectors are built this way; set RESCHEDULE=off to A/B the plain compile.
const RESCHED_OPTS = process.env.RESCHEDULE === 'off' ? {} : { rescheduleStacks: true };
/** compile a .cash source string -> redeem bytecode (Uint8Array); throws on compile error */
export const compileBytecode = (src) => asmToBytecode(compileString(src, RESCHED_OPTS).bytecode);
/** compile a .cash FILE -> redeem bytecode. Unlike compileString, compileFile resolves
 * relative `import` statements (it has a base path), so chunks can import the shared
 * singleton library instead of inlining the tower functions. */
export const compileFileBytecode = (path) => asmToBytecode(compileFile(path, RESCHED_OPTS).bytecode);
/** plain-cashc variants (no rescheduling): the vector builders A/B the two redeems per
 * chunk and keep whichever measures better, and the chunk PLANNERS measure candidate
 * windows with these so the generated chunk manifests stay independent of the pass. */
export const compileBytecodeRaw = (src) => asmToBytecode(compileString(src).bytecode);
export const compileFileBytecodeRaw = (path) => asmToBytecode(compileFile(path).bytecode);

// TARGET_UNLOCK is the per-input unlocking-bytecode length the chunk planners/measurers pad to;
// the BCH op-cost budget an input gets is (densityControlBase + unlockingLen) * 800, so OP_BUDGET
// follows from it. Both default to the current-BCH (BCH_2026) reference: base 41, 10 kB unlocking
// => 8,032,800 op. They are env-overridable so the large-script build can plan against the
// PROPOSED bch-spec limits (100 kB scripts; densityControlBaseLength 10,000 => a 100 kB input
// gets (10000+100000)*800 = 88,000,000 op) without touching any other build (default => identical).
export const BCH_SPEC = process.env.BCH_VM === 'spec';
export const DENSITY_BASE = BCH_SPEC ? 10_000 : 41; // libauth ConsensusBch(2026|Spec).densityControlBaseLength
export const TARGET_UNLOCK = Number(process.env.TARGET_UNLOCK ?? 10_000);
export const OP_BUDGET = (DENSITY_BASE + TARGET_UNLOCK) * 800;
export const OP_DROP = 0x75, OP_PUSHDATA2 = 0x4d;

import { hexToBin, bigIntToVmNumber, encodeDataPush, bigIntToBinUintLE, binToFixedLength, numberToBinUint16LE, numberToBinUint32LE, createTestAuthenticationProgramBch, createVirtualMachineBch2026, createVirtualMachineBchSpec } from '@bitauth/libauth';
// BCH_VM=spec selects the PROPOSED bch-spec VM (100 kB scripts, densityControlBase 10,000);
// default is the current-BCH BCH_2026 VM (10 kB scripts). Chunk planners measure against this.
const realVm = (BCH_SPEC ? createVirtualMachineBchSpec : createVirtualMachineBch2026)(false);

// ---- constants ----
export const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n,
]);
export const INV2 = Fp2.inv(Fp2.fromBigTuple([2n, 0n]));
export const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 3n);
export const PSI_Y = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 2n);
export const BN_X = 4965661367192848881n;
const naf = (a) => { const r = []; for (; a > 1n; a >>= 1n) { if ((a & 1n) === 0n) r.unshift(0); else if ((a & 3n) === 3n) { r.unshift(-1); a += 1n; } else r.unshift(1); } return r; };
export const ATE_NAF = naf(6n * BN_X + 2n);

// ---- miller-step math ----
const mulByB = (x) => Fp2.mul(x, Fp2B);
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
function mul034(f, o0, o3, o4) {
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
}
export const lineFn = (f, c0, c1, c2, Px, Py) => mul034(f, scalarFp2(c2, Py), scalarFp2(c1, Px), c0);
export const lineUnitFn = (f, c0, c1, u, v) => mul034(f, Fp2.ONE, scalarFp2(c1, u), scalarFp2(c0, v));
export const psi = (x, y) => [Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y)];

export function millerStep(f, R, k, Qx, Qy, negQy, Px, Py) {
  f = Fp12.sqr(f);
  let d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], Px, Py);
  if (ATE_NAF[k]) { let a = pointAdd(R.x, R.y, R.z, Qx, ATE_NAF[k] === -1 ? negQy : Qy); R = a.R; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], Px, Py); }
  return { f, R };
}
export function postPrecompute(f, R, Qx, Qy, Px, Py) {
  const q1 = psi(Qx, Qy);
  let a1 = pointAdd(R.x, R.y, R.z, q1[0], q1[1]); R = a1.R; f = lineFn(f, a1.coeffs[0], a1.coeffs[1], a1.coeffs[2], Px, Py);
  const q2 = psi(q1[0], q1[1]);
  let a2 = pointAdd(R.x, R.y, R.z, q2[0], Fp2.neg(q2[1])); R = a2.R; f = lineFn(f, a2.coeffs[0], a2.coeffs[1], a2.coeffs[2], Px, Py);
  return { f, R, coeffs: [a1.coeffs, a2.coeffs] };
}
// full single-pair miller -> { f (Fp12), R (final) }
export function singlePairMiller(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  let f = Fp12.ONE, R = { x: Qa.x, y: Qa.y, z: Fp2.ONE };
  for (let k = 0; k < ATE_NAF.length; k++) ({ f, R } = millerStep(f, R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y));
  return postPrecompute(f, R, Qa.x, Qa.y, Pa.x, Pa.y);
}

// ---- BATCHED multi-pair Miller (one shared fp12Sqr per step) -------------------
// noble's millerLoopBatch: f squared ONCE per NAF step, each pair's double-line (+
// add-line) folded into the SHARED f; each pair's R evolves independently; then the
// Q1/Q2 (psi) postPrecompute per pair. The folded f IS the boundary (no separate
// combine). One batched step is ~8 mul034 (too coarse for one BCH input), so the loop
// is exposed as a FLAT op list chunkable at any boundary, carrying (f + 4 R + points).
// ops[i] = {t:'sqr'} | {t:'dl',j} | {t:'al',j,neg} | {t:'pp',j} (postPrecompute pair j).
// states[i] = {f,Rs} BEFORE op i; states[ops.length] = final (f == boundary, BN: no conj).
export function millerBatchOps(pairs, opts = {}) {
  // opts.skipPairs (Set of pair indices): omit those pairs' line-folds entirely. Used by the
  // residue build to drop the fully-constant pair e(alpha,beta) from the loop (its single-pair
  // Miller value f_{alpha,beta} is baked and multiplied in once instead). Default = skip none,
  // so every other consumer is unaffected. f then = product over the NON-skipped pairs.
  const skip = opts.skipPairs ?? new Set();
  const pds = pairs.map((p) => { const Qa = p.Q.toAffine(), Pa = p.P.toAffine(); return { Qx: Qa.x, Qy: Qa.y, negQy: Fp2.neg(Qa.y), Px: Pa.x, Py: Pa.y }; });
  const ops = [];
  for (let k = 0; k < ATE_NAF.length; k++) {
    ops.push({ t: 'sqr' });
    for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'dl', j }); if (ATE_NAF[k]) ops.push({ t: 'al', j, neg: ATE_NAF[k] === -1 }); }
  }
  for (let j = 0; j < 4; j++) { if (skip.has(j)) continue; ops.push({ t: 'pp', j }); }
  const states = [];
  let f = Fp12.ONE; const Rs = pds.map((pd) => ({ x: pd.Qx, y: pd.Qy, z: Fp2.ONE }));
  // Each non-sqr op also records its line-function coeffs (`op.coeffs`). For a pair with a
  // FIXED VK G2 point (PT_CFG[j].Q === false) the whole R trajectory is proof-independent, so
  // these coeffs are constants the generator can BAKE — the chunk then only evaluates the line
  // at the runtime G1 point, skipping all on-chain G2 (pointDouble/pointAdd) work and dropping
  // that pair's R from the carried state. `op.coeffs` is a triple of Fp2 (dl/al) or a pair of
  // such triples (pp's two psi add-lines).
  for (const op of ops) {
    states.push({ f, Rs: Rs.slice() });
    if (op.t === 'sqr') f = Fp12.sqr(f);
    else if (op.t === 'dl') { const d = pointDouble(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z); Rs[op.j] = d.R; op.coeffs = d.coeffs; f = lineFn(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pds[op.j].Px, pds[op.j].Py); }
    else if (op.t === 'al') { const pd = pds[op.j]; const a = pointAdd(Rs[op.j].x, Rs[op.j].y, Rs[op.j].z, pd.Qx, op.neg ? pd.negQy : pd.Qy); Rs[op.j] = a.R; op.coeffs = a.coeffs; f = lineFn(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
    else { const pd = pds[op.j]; const res = postPrecompute(f, Rs[op.j], pd.Qx, pd.Qy, pd.Px, pd.Py); f = res.f; Rs[op.j] = res.R; op.coeffs = res.coeffs; }
  }
  states.push({ f, Rs: Rs.slice() });
  return { ops, states, boundary: f };
}

// ---- Prepared plain Miller ----------------------------------------------------
// Pair 1 is e(alpha,beta): both points are fixed by the VK. Folding its 87 op objects
// (88 line folds; postPrecompute contains two) through the shared loop is therefore
// equivalent to omitting that pair and multiplying its raw single-pair Miller value
// into f once after the loop.
// Keep the raw millerBatchOps trace above for residue/reference math; all plain chunk
// consumers share this trace so their op indices and states stay aligned.
const PRECOMPUTED_PAIR = 1;
export function preparedMillerOps(pairs) {
  if (pairs.length !== 4 || pairs[PRECOMPUTED_PAIR]?.name !== 'alpha_beta') {
    throw new Error('prepared Miller requires the four Groth16 pairs with alpha_beta at index 1');
  }
  const base = millerBatchOps(pairs, { skipPairs: new Set([PRECOMPUTED_PAIR]) });
  const fAB = singlePairMiller(pairs[PRECOMPUTED_PAIR]).f;
  const ops = [...base.ops, { t: 'cmul1' }];
  const states = base.states.slice();
  const finalState = base.states[base.states.length - 1];
  const boundary = Fp12.mul(base.boundary, fAB);
  const rawBoundary = millerBatchOps(pairs).boundary;
  if (!Fp12.eql(boundary, rawBoundary)) {
    throw new Error('prepared Miller boundary does not match the raw four-pair Miller boundary');
  }
  states.push({ f: boundary, Rs: finalState.Rs.slice() });
  return { ops, states, boundary, fAB, precomputedPair: PRECOMPUTED_PAIR };
}

export function assertPreparedMillerManifest(manifest, trace) {
  const expectedFAB = f12limbs(trace.fAB).map(String);
  const manifestFAB = manifest.precomputedPairMiller;
  const fABMatches = Array.isArray(manifestFAB)
    && manifestFAB.length === expectedFAB.length
    && manifestFAB.every((limb, i) => limb === expectedFAB[i]);
  // `manifest.boundary` records the generator's committed proof, so it must not be
  // compared here: the same lockings intentionally verify other proofs and boundaries.
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
    || manifest.numPairs !== 4
    || manifest.numOps !== trace.ops.length
    || manifest.precomputedPair !== trace.precomputedPair
    || !fABMatches
    || !chunksCoverTrace
  ) {
    throw new Error('manifest_miller.json does not match the prepared Miller trace; regenerate it with gen_miller.mjs');
  }
}

// ---- serialization -----------------------------------------------------------
// Canonical BN254 field/scalar values are below 2^254, so their high sign bit is clear
// in a 32-byte Script number. Wider state encoding only adds hashing and handoff cost.
export const STATE_BYTES = 32;
export const f12limbs = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
export const r6limbs = (R) => [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1];
export const le40 = (n) => binToFixedLength(bigIntToBinUintLE(BigInt(n)), 40);
export const leState = (n) => binToFixedLength(bigIntToBinUintLE(BigInt(n)), STATE_BYTES);
const sha256 = (b) => createHash('sha256').update(b).digest();
export const commit = (limbs) => sha256(sha256(Buffer.concat(limbs.map(leState)))).toString('hex');

// ---- the committed instance's 4 pairs ----
const verifierDir = process.env.VERIFIER_DIR;
export const verifierPath = (...parts) => {
  if (!verifierDir) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');
  return join(verifierDir, ...parts);
};
export const vec = JSON.parse(readFileSync(verifierPath('src/checkpoints/pairing-vectors.json'), 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
export const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
export const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
export const vkxPoint = (inputs) => { let x = vk.ic[0]; inputs.map(BigInt).forEach((s, i) => { x = x.add(vk.ic[i + 1].multiply(s)); }); return x; };
/** Point-limb overrides for isolated input-validation rejection fixtures. */
export function invalidG2Overrides(proofValue = proof, offSubgroupCount = 1) {
  if (!Number.isInteger(offSubgroupCount) || offSubgroupCount < 1) {
    throw new Error('offSubgroupCount must be a positive integer');
  }
  const A = proofValue.a.negate().toAffine();
  const C = proofValue.c.toAffine();
  const B = proofValue.b.toAffine();
  const offCurveA = { Ay: (A.y + 1n) % Fp.ORDER };
  const offCurveC = { Cy: (C.y + 1n) % Fp.ORDER };
  const offCurveB = { By: Fp2.create({ c0: (B.y.c0 + 1n) % Fp.ORDER, c1: B.y.c1 }) };
  const b2 = Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n]));
  const offSubgroups = [];
  for (let i = 1n; i < 10_000n && offSubgroups.length < offSubgroupCount; i++) {
    const x = Fp2.fromBigTuple([i, 0n]);
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2);
    let y;
    try { y = Fp2.sqrt(rhs); } catch { continue; }
    if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
    try { bn254.G2.Point.fromAffine({ x, y }).assertValidity(); }
    catch { offSubgroups.push({ Bx: x, By: y }); }
  }
  if (offSubgroups.length !== offSubgroupCount) {
    throw new Error(`failed to construct ${offSubgroupCount} off-subgroup G2 fixtures`);
  }
  return [offCurveA, offCurveC, offCurveB, ...offSubgroups];
}
const G2_STAGE_LAYOUT = ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy'];
/** Fail fast when a builder reads G2 chunks generated for a different state layout. */
export function assertG2StageManifest(manifest, { carriesVkx = false, linkedLayout = false } = {}) {
  const expectedLayout = carriesVkx ? [...G2_STAGE_LAYOUT, 'vkxX', 'vkxY'] : G2_STAGE_LAYOUT;
  if (
    manifest.fastEndo !== true ||
    manifest.canonicalProofCoordinates !== true ||
    manifest.stageBound !== true ||
    manifest.genesisDerived !== true ||
    manifest.carriesVkx !== carriesVkx ||
    manifest.linkedLayout !== linkedLayout ||
    JSON.stringify(manifest.stageLayout) !== JSON.stringify(expectedLayout)
  ) {
    throw new Error(`G2 manifest does not match the expected ${expectedLayout.length}-limb stage layout`);
  }
}
export const pairsFor = (inputs, pf = proof) => [
  { name: 'negA_B', P: pf.a.negate(), Q: pf.b },
  { name: 'alpha_beta', P: vk.alpha, Q: vk.beta },
  { name: 'vkx_gamma', P: vkxPoint(inputs), Q: vk.gamma },
  { name: 'C_delta', P: pf.c, Q: vk.delta },
];
// build a proof object {a,b,c} (curve points) from raw limb bigints — used to
// replay a DIFFERENT proof (proof #1) through the same generic chunk programs.
export const proofFromLimbs = (Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy) => ({
  a: bn254.G1.Point.fromAffine({ x: Ax, y: Ay }),
  b: bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([Bxa, Bxb]), y: Fp2.fromBigTuple([Bya, Byb]) }),
  c: bn254.G1.Point.fromAffine({ x: Cx, y: Cy }),
});

// Which of P (G1) and Q (G2) are PROOF-derived (runtime) per pair, vs VK (baked).
// pair0 e(-A,B): both proof.  pair1 e(alpha,beta): both VK.  pair2 e(vk_x,gamma):
// P=vk_x runtime, Q=gamma VK.  pair3 e(C,delta): P=C runtime, Q=delta VK.
// Runtime points ride in the carried (committed) state so they are bound; baked
// VK points stay literals. This is what makes the chunks proof-agnostic.
export const PT_CFG = [{ P: true, Q: true }, { P: false, Q: false }, { P: true, Q: false }, { P: true, Q: false }];
/** runtime point limbs (declaration order) for a pair's affine P (G1) and Q (G2). */
export const ptLimbs = (pairIdx, P, Q, unitLines = false) => {
  const o = [], c = PT_CFG[pairIdx];
  if (c.P && unitLines) {
    const invY = Fp.inv(P.y);
    o.push(Fp.neg(Fp.mul(P.x, invY)), Fp.neg(invY));
  } else if (c.P) o.push(P.x, P.y);
  if (c.Q) o.push(Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1);
  return o;
};

// ---- finalExp op-DAG trace (replayable for ANY boundary) -----------------------
// Same op structure as gen_finalexp (proof-independent); only the values differ.
// Returns { ops, liveAt(cut), limbs12(id), resultId } so build_vectors can recompute
// a different proof's per-chunk live state at the SAME chunk windows.
const X_LEN_FE = 63;
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
  const cycExp = (numV) => { let z = numV; for (let i = X_LEN_FE - 2; i >= 0; i--) { z = cyc(z); if ((BN_X >> BigInt(i)) & 1n) z = mul(z, numV); } return z; };
  const powMinusX = (xV) => conj(cycExp(xV));
  const fV = Vv(boundaryVal);
  const r0 = mul(conj(fV), inv(fV));
  const r = mul(f2(r0), r0);
  const y1 = cyc(powMinusX(r));
  const y2 = mul(cyc(y1), y1);
  const y4 = powMinusX(y2);
  const y6 = powMinusX(cyc(y4));
  const y8 = mul(mul(conj(y6), y4), conj(y2));
  const y9 = mul(y8, y1);
  const left = f3(mul(conj(r), y9));
  const right = mul(f2(y8), mul(f1(y9), mul(mul(y8, y4), r)));
  const result = mul(left, right);
  const valOf = new Map([[fV.id, boundaryVal]]); for (const o of ops) valOf.set(o.id, o.val);
  const def = new Map([[fV.id, -1]]); ops.forEach((o, i) => def.set(o.id, i));
  const lastUse = new Map(); ops.forEach((o, i) => o.args.forEach((a) => lastUse.set(a, i)));
  lastUse.set(result.id, ops.length);
  const liveAt = (cut) => [...def.keys()].filter((id) => def.get(id) < cut && (lastUse.get(id) ?? -1) >= cut).sort((a, b) => a - b);
  const limbs12 = (id) => f12limbs(valOf.get(id));
  return { ops, liveAt, limbs12, resultId: result.id, result: result.val };
}

// ---- vk_x Jacobian accumulator trace (replayable for ANY public inputs) ---------
const PFP = Fp.ORDER;
const aF = (x, y) => (x + y) % PFP, sF = (x, y) => (x - y + PFP) % PFP, mF = (x, y) => (x * y) % PFP, qF = (x) => (x * x) % PFP;
function jacDouble(X, Y, Z) {
  const a = qF(X), b = qF(Y), c = qF(b);
  const d = mF(2n, sF(sF(qF(aF(X, b)), a), c));
  const e = mF(3n, a), f = qF(e);
  const nx = sF(f, mF(2n, d));
  return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y, Z))];
}
function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  if (aZ === 0n) return [bX, bY, bZ];
  const z1z1 = qF(aZ), z2z2 = qF(bZ);
  const u1 = mF(aX, z2z2), u2 = mF(bX, z1z1);
  const s1 = mF(mF(aY, bZ), z2z2), s2 = mF(mF(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2);
  const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2);
  const nx = sF(sF(qF(rr), j), mF(2n, v));
  return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1z1), z2z2), h)];
}
const _ic1 = vk.ic[1].toAffine(), _ic2 = vk.ic[2].toAffine(), _icT = vk.ic[1].add(vk.ic[2]).toAffine();
/** Shamir/Straus vk_x accumulator after processing windows [0,upto): [rX,rY,rZ]. */
export function vkxStateAt(in0, in1, upto) {
  let X = 0n, Y = 1n, Z = 0n;
  for (let j = 0; j < upto; j++) {
    const i = 253 - j;
    if (Z !== 0n) [X, Y, Z] = jacDouble(X, Y, Z);
    const b0 = (in0 >> BigInt(i)) & 1n, b1 = (in1 >> BigInt(i)) & 1n;
    const ap = b0 && b1 ? [_icT.x, _icT.y] : b0 ? [_ic1.x, _ic1.y] : b1 ? [_ic2.x, _ic2.y] : null;
    if (ap) [X, Y, Z] = jacAdd(X, Y, Z, ap[0], ap[1], 1n);
  }
  return [X, Y, Z];
}
const _ic0 = vk.ic[0].toAffine();
const modpowFp = (b, e) => { let r = 1n; b %= PFP; while (e > 0n) { if (e & 1n) r = (r * b) % PFP; b = (b * b) % PFP; e >>= 1n; } return r; };
/** the final vkx chunk's auxiliary zInv = (Z of (acc + IC0))^-1, supplied in the unlocking. */
export function vkxFinalZinv(in0, in1) {
  const acc = vkxStateAt(in0, in1, 254);
  const [, , fz] = jacAdd(acc[0], acc[1], acc[2], _ic0.x, _ic0.y, 1n);
  return fz === 0n ? 0n : modpowFp(fz, PFP - 2n);
}

// ---- extract reusable functions from a singleton lib .cash (for chunk prologues) ----
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
        if (depth === 0 && ln.includes('}')) break; // matched the function's closing brace (inline braces keep depth>0)
      }
    }
    return out.join('\n');
  };
}

// ---- real-VM measurement (padded like shamir) ----
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
// Zero-pad the unlocking up to `target` bytes. PUSHDATA2 tops out at 65535 data bytes, so
// above that (the 100 kB large-script build) switch to PUSHDATA4; otherwise the uint16 length
// wraps and the push is malformed (VM rejects). Header is 3 B for PUSHDATA2, 5 B for PUSHDATA4.
const OP_PUSHDATA4 = 0x4e;
const padPush = (argLen, target) => {
  const budget = target - argLen;
  if (budget - 3 <= 0xffff) { const N = budget - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); }
  const N = budget - 5; return Uint8Array.from([OP_PUSHDATA4, ...numberToBinUint32LE(N), ...new Uint8Array(N)]);
};
// compile `src` IN-PROCESS, run with `stateInts` (declaration order) on the real
// VM (padded to cap). Returns op-cost + size + accept; a compile error counts as
// "doesn't fit" so the planner just shrinks the window. (3rd arg kept for callers
// that still pass a probe path — ignored.)
export function measureChunk(src, stateInts) {
  let raw;
  try { raw = compileBytecodeRaw(src); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([...raw]); // no OP_DROP: trailing `bytes unused zeroPadding` param
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]); // pad first (pushed first)
  const st = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}
export const decl = (names) => names.map((n) => `int ${n}`).join(',');
export const serExpr = (names) => 'hash256(' + names.map((n) => `toPaddedBytes(${n}, ${STATE_BYTES})`).join(' + ') + ')';

// ---- covenant (token state-threading) helpers ----------------------------------
// A GENERIC (proof-independent) chunk carries NO baked state: the running-state
// HASH lives in the spent/created token's NFT commitment. The unlocking script
// pushes the raw state limbs; the contract checks them against the input token's
// commitment, recomputes, and re-commits to output[0] under the same token thread.
// One fixed locking therefore verifies ANY proof (runtime-general).
export const CATEGORY = new Uint8Array(32).fill(0xcd); // benchmark thread id (32B)
const sha256d = (b) => sha256(sha256(b));
/** 32-byte NFT commitment of a state (decl-order limbs), as bytes. */
export const commitBin = (limbs) => new Uint8Array(sha256d(Buffer.concat(limbs.map(leState))));
/** require: the spent token commits hash(incoming state) (decl-order `names`). */
export const covIn = (names) =>
  `        require(tx.inputs[this.activeInputIndex].nftCommitment == ${serExpr(names)});`;
/** require: output[0] commits hash(outgoing) + perpetuates the token thread. */
export const covOut = (outNames, exactNames = []) => {
  const exact = new Set(exactNames);
  if (exact.size !== exactNames.length || exactNames.some((name) => !outNames.includes(name))) {
    throw new Error('exact covenant outputs must be unique members of the outgoing state');
  }
  // local name `Pmod` (not `P`) avoids colliding with the global `constant P` that the non-lazy
  // library exports (g2check imports it); the lazy-lib consumers have no global P either way.
  const modulus = outNames.some((name) => !exact.has(name))
    ? '        int Pmod = 21888242871839275222246405745257275088696311157297823662689037894645226208583;\n'
    : '';
  return modulus +
    `        require(tx.outputs[0].nftCommitment == hash256(${outNames.map((name) => `toPaddedBytes(${name}${exact.has(name) ? '' : ' % Pmod'}, ${STATE_BYTES})`).join(' + ')}));\n` +
    '        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);';
};

/** Real-VM measurer for a COVENANT chunk: drives it through a synthetic token tx
 * (spent UTXO = hash(incoming), output[0] = hash(outgoing)) so the introspection
 * resolves. `stateInts` contains every pushed declaration-order argument;
 * `committedStateInts` selects the threaded state hashed into the spent NFT and defaults
 * to all arguments. `outLimbs` is already reduced. */
export function measureCovenant(src, stateInts, outLimbs, committedStateInts = stateInts) {
  let raw;
  try { raw = compileBytecodeRaw(src); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  return measureCovenantRaw(raw, stateInts, outLimbs, committedStateInts);
}
/** Like measureCovenant, but compiles `src` from a FILE (written to `probePath`) so its
 * relative library `import` resolves. Used by the prepared-VK Miller planner, whose chunks
 * import the shared singleton library instead of inlining the tower functions. The optional
 * rescheduling and committed-state arguments mirror the final compiler and covenant path. */
export function measureCovenantFile(src, stateInts, outLimbs, probePath, reschedule = false, committedStateInts = stateInts) {
  let raw;
  try {
    writeFileSync(probePath, src);
    raw = reschedule ? compileFileBytecode(probePath) : compileFileBytecodeRaw(probePath);
  }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  return measureCovenantRaw(raw, stateInts, outLimbs, committedStateInts);
}
function measureCovenantRaw(raw, stateInts, outLimbs, committedStateInts = stateInts) {
  const locking = Uint8Array.from([...raw]); // no OP_DROP: trailing `bytes unused zeroPadding` param
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]); // pad first (pushed first)
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(committedStateInts)) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

// Predict-and-adjust greedy window planner. Instead of linear growth (compile
// every candidate from lo+1 upward — most thrown away), estimate the window from
// a running op-cost-per-unit average, compile that, then adjust ±1 to the budget
// boundary. ~2 compiles/chunk vs ~4-10. `state` is a mutable {perUnit:null} that
// the planner calibrates over successive chunks (first chunk falls back to linear
// growth to seed it). `tryAt(hi) -> { fits, operationCost, ... }` builds+measures
// the window [lo,hi); returns the best record (with its `.hi`).
export function planChunk(lo, max, opTarget, tryAt, state) {
  let best = null;
  const consider = (hi) => { const r = tryAt(hi); if (r.fits) best = { hi, ...r }; return r; };
  if (state.perUnit == null) {
    consider(lo + 1);
    for (let hi = lo + 2; hi <= max; hi++) if (!consider(hi).fits) break;
  } else {
    const guess = Math.min(max, lo + Math.max(1, Math.floor(opTarget / state.perUnit)));
    if (consider(guess).fits) { for (let hi = guess + 1; hi <= max; hi++) if (!consider(hi).fits) break; }
    else { for (let hi = guess - 1; hi > lo; hi--) if (consider(hi).fits) break; }
    if (!best) consider(lo + 1); // 1 unit always fits in practice
  }
  if (best) { const u = best.hi - lo, pu = best.operationCost / u; state.perUnit = state.perUnit == null ? pu : 0.5 * state.perUnit + 0.5 * pu; }
  return best;
}
