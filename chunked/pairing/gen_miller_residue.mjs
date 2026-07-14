// Generator for the c^-(6x+2)-FUSED batched BN254 Miller loop (residue method).
// Identical to gen_miller.mjs (prepared-VK, 4 pairs batched, shared f) EXCEPT the loop also
// folds c^-(6x+2) into f so the boundary fF = fRaw * c^-(6x+2). The residue witness (c, cInv)
// is carried as CONSTANT state (12+12 limbs) so each chunk can multiply by it; op 'cf' (c-fold)
// does f = fp12Mul(f, cInv) [NAF digit +1] or fp12Mul(f, c) [digit -1]. The LEADING 'cf' injects
// the loop's implicit MSB (R=Q preload -> 2^65 term). The minimal-weight NAF of 6x+2 (22 c-folds)
// beats a cInv-only binary fold (37 folds) — measured 27 chunks / 194.9M op vs 28 / 201.1M.
// One fixed locking per chunk verifies ANY proof (c,cInv are runtime state, like the rest).
// FUSE_G2_ENDPOINT=1 also validates the proof points at genesis and proves B is in G2 by reusing
// the second runtime-B post-processing line; prove_miller_endpoint_subgroup.mjs proves that the
// line-incidence condition is equivalent to subgroup membership on the complete twist group.
//   node gen_miller_residue.mjs        plan + emit millerres_NN.cash + manifest_millerres.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, BN_X, f12limbs, r6limbs, pairsFor, vec, commit, millerBatchOps, singlePairMiller,
  measureCovenantFile, planChunk, covIn, covOut, PT_CFG, ptLimbs, decl,
  commitBin, compileFileBytecodeRaw, STATE_BYTES,
} from './_millermath.mjs';
import { millerFusedOps, residueWitness, fp12limbsOf, COSET27 } from './_residuemath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const FUSE_G2_ENDPOINT = process.env.FUSE_G2_ENDPOINT === '1';
const LIB_IMPORT = FUSE_G2_ENDPOINT
  ? '../../../singleton/bn254/lib/lazy/Bn254LazyG.cash'
  : '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = join(GEN, '_probe_millerres.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const LINKED_LAYOUT = process.env.MILLER_LINKED_LAYOUT === '1';
const linkedCutsOverride = process.env.MILLER_LINKED_CUTS;
const LINKED_CUTS = !LINKED_LAYOUT || linkedCutsOverride === 'auto'
  ? []
  : linkedCutsOverride === undefined
    ? [18, 32, 50, 68, 86, 104, 122, 140, 158, 176, 194, 212, 230, 249, 266, 285, 303, 320, 338]
    : linkedCutsOverride.split(',').map(Number);
const STAGE_BOUND = process.env.STAGE_BOUND_LAYOUT === '1';
const COVENANT_RESIDUE = STAGE_BOUND && process.env.COVENANT_RESIDUE_LAYOUT === '1';
if (FUSE_G2_ENDPOINT && !STAGE_BOUND) {
  throw new Error('FUSE_G2_ENDPOINT requires STAGE_BOUND_LAYOUT=1');
}

const PAIRS = pairsFor(vec.publicInputs);
const PINFO = PAIRS.map((pair, j) => {
  const Q = pair.Q.toAffine(), Pt = pair.P.toAffine(), cfg = PT_CFG[j], negQ = Fp2.neg(Q.y);
  return {
    j, cfg, negQ,
    Pxe: cfg.P ? `Px${j}` : `${Pt.x}`, Pye: cfg.P ? `Py${j}` : `${Pt.y}`,
    Qxae: cfg.Q ? `Q${j}xa` : `${Q.x.c0}`, Qxbe: cfg.Q ? `Q${j}xb` : `${Q.x.c1}`,
    Qyae: cfg.Q ? `Q${j}ya` : `${Q.y.c0}`, Qybe: cfg.Q ? `Q${j}yb` : `${Q.y.c1}`,
  };
});
const ptParams = [];
PINFO.forEach((pi, j) => { if (pi.cfg.P) ptParams.push(`Px${j}`, `Py${j}`); if (pi.cfg.Q) ptParams.push(`Q${j}xa`, `Q${j}xb`, `Q${j}ya`, `Q${j}yb`); });
const ptL = PAIRS.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
// Keep the proof tuple contiguous at stage genesis so G2-final can bind -A/B/C with one slice.
// Later Miller states retain the generic -A/B, vk_x, C point order.
const stagePtParams = [...ptParams.slice(0, 6), ...ptParams.slice(8, 10), ...ptParams.slice(6, 8)];
const stagePtL = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];

// witness for the committed planning instance (the chunk math is generic; only window
// boundaries come from this instance, like the rest of the generators).
const { boundary: fRawPlan } = millerBatchOps(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN, w: W_PLAN } = residueWitness(fRawPlan);
const { ops, states, boundary } = millerFusedOps(PAIRS, C_PLAN, CINV_PLAN);
if (LINKED_CUTS.some((cut, i) => !Number.isInteger(cut) || cut <= (LINKED_CUTS[i - 1] ?? 0) || cut >= ops.length)) {
  throw new Error('MILLER_LINKED_CUTS must be strictly increasing integer boundaries inside the op range');
}

const endpointOp = ops.findIndex((op) => op.t === 'pp' && op.j === 0);
if (endpointOp < 0) throw new Error('missing runtime-B Miller endpoint');
const firstRuntimeDoubleOp = ops.findIndex((op) => op.t === 'dl' && op.j === 0);
if (firstRuntimeDoubleOp < 0) throw new Error('missing runtime-B Miller genesis double');
const endpointAffine = {
  x: Fp2.div(states[endpointOp].Rs[0].x, states[endpointOp].Rs[0].z),
  y: Fp2.div(states[endpointOp].Rs[0].y, states[endpointOp].Rs[0].z),
};
const expectedEndpoint = PAIRS[0].Q.multiply(6n * BN_X + 2n).toAffine();
if (!Fp2.eql(endpointAffine.x, expectedEndpoint.x) || !Fp2.eql(endpointAffine.y, expectedEndpoint.y)) {
  throw new Error('runtime-B Miller endpoint is not [6x+2]B');
}

// baked constant f_{alpha,beta} (pair 1's single-pair Miller value; VK-only, proof-independent),
// multiplied in once by the 'cmul1' op instead of folding pair 1's ~89 lines through the loop.
const FAB_LIMBS = f12limbs(singlePairMiller(PAIRS[1]).f).map((x) => x.toString());
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
const wNames = Array.from({ length: 12 }, (_, i) => `w${i}`);
const ONE_L = ['1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'];
const W_HASHES = [ONE_L, fp12limbsOf(COSET27[1]).map(String), fp12limbsOf(COSET27[2]).map(String)]
  .map((limbs) => Buffer.from(commitBin(limbs.map(BigInt))).toString('hex'));
// state = f(12) + R0(6) + runtime points + c(12) + cInv(12)
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptL, ...rest]; };
const inState = (i) => STAGE_BOUND && i === 0
  ? [...stagePtL, ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));
// the FINAL chunk hands off only [fF, c, cInv] (36 limbs, contiguous) to the residue tail —
// R0/pts are done with once the loop ends. Non-final hand-offs carry the full 52-limb state.
const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
// withTail (linked layout or FUSE_TAIL, final chunk only): fold the residue final-exp verdict into this chunk so
// the separate ResidueTail input disappears. The chunk computes fF = final f, then runs the
// witnessed-residue verdict inline (w is an extra UNCOMMITTED witness, appended after the state).
function genChunk(opLo, opHi, isFinal, withTail = false) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
  const fullStateParams = [...inF, ...inR0, ...ptParams, ...cNames, ...ciNames];
  const stateParams = STAGE_BOUND && opLo === 0 ? [...stagePtParams, ...cNames, ...ciNames] : fullStateParams;
  const committedParams = COVENANT_RESIDUE && opLo === 0 ? stagePtParams : stateParams;
  const allParams = withTail ? [...stateParams, ...wNames] : stateParams;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// c^-(6x+2)-fused prepared-VK batched BN254 Miller chunk: ops [${opLo},${opHi}).${withTail ? ' [+ residue-tail verdict fused]' : ''}`);
  L.push('// state = f(12) + R0(6) [+ runtime points] + c(12) + cInv(12); c,cInv are constant');
  L.push('// carried witness. cf op folds c^-1/c into f (residue method, ePrint 2024/640).');
  L.push(`contract MillerFused${withTail ? 'Tail' : ''}Chunk() {`);
  L.push(`    function spend(${decl(allParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(committedParams));
  if (FUSE_G2_ENDPOINT && STAGE_BOUND && opLo === 0) {
    const proofNames = ['Px0', 'Py0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Px3', 'Py3'];
    L.push('        int fieldP = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
    L.push('        ' + proofNames.map((name) => `require(within(${name}, 0, fieldP));`).join(' '));
    L.push('        require((mulFp(Py0, Py0) - addFp(mulFp(mulFp(Px0, Px0), Px0), 3)) % fieldP == 0);');
    L.push('        require((mulFp(Py3, Py3) - addFp(mulFp(mulFp(Px3, Px3), Px3), 3)) % fieldP == 0);');
  }
  if (COVENANT_RESIDUE && opLo === 0) {
    L.push('        int residueP = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
    L.push('        ' + [...cNames, ...ciNames].map((n) => `require(within(${n}, 0, residueP));`).join(' '));
  }
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe}, 64);`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  // The fused MSB optimization starts f at cInv and R0 at the runtime B point. Derive both
  // genesis values here instead of accepting independent witness state.
  let f = STAGE_BOUND && opLo === 0 ? ciNames.slice() : inF.slice();
  let r0 = STAGE_BOUND && opLo === 0
    ? [PINFO[0].Qxae, PINFO[0].Qxbe, PINFO[0].Qyae, PINFO[0].Qybe, '1', '0']
    : inR0.slice();
  let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = line(${f.join(',')}, ${coeffs.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q;
    const r0Unused = isFinal && !ops.slice(i + 1, opHi).some((later) =>
      later.j !== undefined && PINFO[later.j].cfg.Q && ['dl', 'al', 'pp'].includes(later.t));
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'cf') { // c-fold: f *= (neg ? c : cInv)
      const g = fresh(12); const m = op.neg ? cNames : ciNames;
      L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${m.join(',')});`); f = g;
    } else if (op.t === 'cmul1') { // f *= baked f_{alpha,beta} (VK constant)
      const g = fresh(12);
      L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${FAB_LIMBS.join(',')});`); f = g;
    } else if (op.t === 'dl') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const dco = fresh(6), dr = fresh(6);
      L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r0.join(',')});`); r0 = dr;
      if (FUSE_G2_ENDPOINT && i === firstRuntimeDoubleOp) {
        const c1x = fresh(2);
        L.push('        // With c0=3*b2-y^2 and c1=3*x^2 from this doubling,');
        L.push('        // c1*x+3*c0=6*b2 is exactly the twist-curve equation.');
        L.push(`        (${decl(c1x)}) = fp2Mul(${dco[2]}, ${dco[3]}, ${pi.Qxae}, ${pi.Qxbe});`);
        L.push(`        require((${c1x[0]} + 3 * ${dco[0]} - 7474034151359752514913406839843947591262155029321208079942598305488613827323) % fieldP == 0);`);
        L.push(`        require((${c1x[1]} + 3 * ${dco[1]} - 1601578746719946967481444322823703055270461791997401731416271065461845820140) % fieldP == 0);`);
      }
      emitLine(dco, pi);
    } else if (op.t === 'al') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r0.join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]});`); r0 = ar;
      emitLine(aco, pi);
    } else { // pp
      if (fixed) { emitLine(bakedCoeffs(op.coeffs[0]), pi); emitLine(bakedCoeffs(op.coeffs[1]), pi); continue; }
      const q1 = fresh(4);
      L.push(`        (${decl(q1)}) = psi(${pi.Qxae}, ${pi.Qxbe}, ${pi.Qyae}, ${pi.Qybe});`);
      const bco = fresh(6), br = fresh(6);
      L.push(`        (${decl([...bco, ...br])}) = pointAdd(${r0.join(',')}, ${q1.join(',')});`); r0 = br;
      emitLine(bco, pi);
      const cco = fresh(6), cr = fresh(6);
      if (r0Unused) {
        // The final handoff drops R0. Emit only pointAdd's line-coefficient prefix so CashScript
        // does not reject the otherwise-dead new-R tuple, and avoid computing state we discard.
        // psi^2(Q) = (KX * Q.x, -Q.y), so the final add by
        // (psi^2(Q).x, -psi^2(Q).y) can use (KX * Q.x, Q.y) directly.
        const q2x = fresh(2);
        L.push(`        (${decl(q2x)}) = fp2Scale(${pi.Qxae}, ${pi.Qxbe}, 21888242871839275220042445260109153167277707414472061641714758635765020556616);`);
        const qyz = fresh(2), t0 = fresh(2), qxz = fresh(2), t1 = fresh(2);
        const t0qx = fresh(2), t1qy = fresh(2);
        L.push(`        (${decl(qyz)}) = fp2Mul(${pi.Qyae}, ${pi.Qybe}, ${r0[4]}, ${r0[5]});`);
        L.push(`        (${decl(t0)}) = fp2Sub(${r0[2]}, ${r0[3]}, ${qyz[0]}, ${qyz[1]}, 0);`);
        L.push(`        (${decl(qxz)}) = fp2Mul(${q2x[0]}, ${q2x[1]}, ${r0[4]}, ${r0[5]});`);
        L.push(`        (${decl(t1)}) = fp2Sub(${r0[0]}, ${r0[1]}, ${qxz[0]}, ${qxz[1]}, 1);`);
        L.push(`        (${decl(t0qx)}) = fp2Mul(${t0[0]}, ${t0[1]}, ${q2x[0]}, ${q2x[1]});`);
        L.push(`        (${decl(t1qy)}) = fp2Mul(${t1[0]}, ${t1[1]}, ${pi.Qyae}, ${pi.Qybe});`);
        L.push(`        (${decl(cco.slice(0, 2))}) = fp2Sub(${t0qx[0]}, ${t0qx[1]}, ${t1qy[0]}, ${t1qy[1]}, 1);`);
        L.push(`        (${decl(cco.slice(2, 4))}) = fp2Neg(${t0[0]}, ${t0[1]}, 64);`);
        L.push(`        int ${cco[4]} = ${t1[0]}; int ${cco[5]} = ${t1[1]};`);
      } else {
        const q2 = fresh(4); L.push(`        (${decl(q2)}) = psi(${q1.join(',')});`);
        const q2ny = fresh(2); L.push(`        (${decl(q2ny)}) = fp2Neg(${q2[2]}, ${q2[3]}, 64);`);
        L.push(`        (${decl([...cco, ...cr])}) = pointAdd(${r0.join(',')}, ${q2[0]}, ${q2[1]}, ${q2ny[0]}, ${q2ny[1]});`); r0 = cr;
      }
      if (FUSE_G2_ENDPOINT && i === endpointOp) {
        const q3x = fresh(2), q3y = fresh(2), lineX = fresh(2), lineY = fresh(2);
        L.push('        // R+psi(B)-psi^2(B)+psi^3(B)=O iff B is in G2; the second add line');
        L.push('        // already passes through R+psi(B), -psi^2(B), and therefore psi^3(B).');
        L.push(`        (${decl(q3x)}) = fp2Scale(${q1[0]}, ${q1[1]}, 21888242871839275220042445260109153167277707414472061641714758635765020556616);`);
        L.push(`        (${decl(q3y)}) = fp2Neg(${q1[2]}, ${q1[3]}, 64);`);
        L.push(`        (${decl(lineX)}) = fp2Mul(${cco[2]}, ${cco[3]}, ${q3x[0]}, ${q3x[1]});`);
        L.push(`        (${decl(lineY)}) = fp2Mul(${cco[4]}, ${cco[5]}, ${q3y[0]}, ${q3y[1]});`);
        L.push('        int subgroupP = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
        L.push(`        require((${cco[0]} + ${lineX[0]} + ${lineY[0]}) % subgroupP == 0);`);
        L.push(`        require((${cco[1]} + ${lineX[1]} + ${lineY[1]}) % subgroupP == 0);`);
      }
      emitLine(cco, pi);
    }
  }
  if (withTail) {
    const pNames = Array.from({ length: 12 }, (_, i) => `tailP${i}`);
    const cqqNames = Array.from({ length: 12 }, (_, i) => `tailCqq${i}`);
    const uNames = Array.from({ length: 12 }, (_, i) => `tailU${i}`);
    const rhsNames = Array.from({ length: 12 }, (_, i) => `tailRhs${i}`);
    const tNames = Array.from({ length: 12 }, (_, i) => `tailT${i}`);
    const lhsNames = Array.from({ length: 12 }, (_, i) => `tailLhs${i}`);
    L.push('        int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
    L.push(`        (${decl(pNames)}) = fp12Mul(${cNames.join(',')}, ${ciNames.join(',')});`);
    L.push('        ' + pNames.map((n, i) => `require(${n} % P == ${ONE_L[i]});`).join(' '));
    L.push(`        bytes wHash = hash256(${wNames.map((n) => `toPaddedBytes(${n}, ${STATE_BYTES})`).join(' + ')});`);
    L.push(`        require(wHash == 0x${W_HASHES[0]} || wHash == 0x${W_HASHES[1]} || wHash == 0x${W_HASHES[2]});`);
    L.push(`        (${decl(cqqNames)}) = fp12Frob2(${cNames.join(',')});`);
    L.push(`        (${decl(uNames)}) = fp12Mul(${cNames.join(',')}, ${cqqNames.join(',')});`);
    L.push(`        (${decl(rhsNames)}) = fp12Frob1(${uNames.join(',')});`);
    L.push(`        (${decl(tNames)}) = fp12Mul(${wNames.join(',')}, ${cqqNames.join(',')});`);
    L.push(`        (${decl(lhsNames)}) = fp12Mul(${f.join(',')}, ${tNames.join(',')});`);
    L.push('        ' + lhsNames.map((n, i) => `require((${n} - ${rhsNames[i]}) % P == 0);`).join(' '));
  } else {
    // final chunk hands off only [fF, c, cInv] to the residue tail; others carry full state.
    const exactState = COVENANT_RESIDUE
      ? (isFinal ? [...cNames, ...ciNames] : [...ptParams, ...cNames, ...ciNames])
      : [];
    L.push(isFinal
      ? covOut([...f, ...cNames, ...ciNames], exactState)
      : covOut([...f, ...r0, ...ptParams, ...cNames, ...ciNames], exactState));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

if (process.argv[2] === 'probe') {
  for (const [a, b] of [[0, 4], [0, 8], [ops.length - 4, ops.length]]) {
    const final = b === ops.length;
    const withTail = final && LINKED_LAYOUT;
    const inL = inState(a);
    const args = withTail ? [...inL, ...fp12limbsOf(W_PLAN)] : inL;
    const committedIn = COVENANT_RESIDUE && a === 0 ? stagePtL : inL;
    const m = measureCovenantFile(genChunk(a, b, final, withTail), args, withTail ? [] : outState(b), PROBE, true, committedIn);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

console.error(`planning FUSED BN254 Miller chunks (${ops.length} flat ops, ${ops.filter(o => o.t === 'cf').length} c-folds)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const committedIn = COVENANT_RESIDUE && lo === 0 ? stagePtL : inL;
  const tryHi = (hi) => {
    const final = hi === ops.length;
    const withTail = final && LINKED_LAYOUT;
    const outL = withTail ? [] : outState(hi);
    const args = withTail ? [...inL, ...fp12limbsOf(W_PLAN)] : inL;
    const src = genChunk(lo, hi, final, withTail);
    const m = measureCovenantFile(src, args, outL, PROBE, true, committedIn);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final, withTail, outgoing: withTail ? null : commit(outL), src, m };
  };
  // The generic covenant layout needs the greedy windows. Linked grouped/intratx packaging
  // has a cheaper handoff prologue, so use the measured 20-window layout selected by sweeping
  // every boundary against the assembled verifier and all official proof runs. Some generic
  // covenant probes exceed OP_TARGET, so keep the complete measured layout opt-in.
  const linkedHi = LINKED_CUTS[chunks.length];
  const best = linkedHi === undefined
    ? planChunk(lo, ops.length, OP_TARGET, tryHi, planState)
    : tryHi(linkedHi);
  if (!best) throw new Error(`no fitting fused window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, tailFused: best.withTail, incoming: commit(inL), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`fused miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);

// FUSE_TAIL=1: fold the residue final-exp verdict into the FINAL Miller chunk (making it TERMINAL),
// so the separate ResidueTail input disappears (-1 input). Only the last chunk's SOURCE is
// regenerated with the verdict inlined; its window/state are unchanged (the verdict replaces the
// [fF,c,cInv] hand-off, and the final op is an f-only c-fold so no R accumulator dangles). The
// consuming build must treat it as terminal and supply the w witness. Default (unset) keeps the
// hand-off form so the flagship builds + the standalone ResidueTail are untouched.
if (process.env.FUSE_TAIL === '1' && chunks[chunks.length - 1].tailFused !== true) {
  const last = chunks[chunks.length - 1];
  const src = genChunk(last.opLo, last.opHi, true, true);
  writeFileSync(join(GEN, `millerres_${String(last.idx).padStart(2, '0')}.cash`), src);
  try { compileFileBytecodeRaw(join(GEN, `millerres_${String(last.idx).padStart(2, '0')}.cash`)); }
  catch (e) { throw new Error(`FUSE_TAIL: fused final Miller+tail chunk does not compile: ${e?.message ?? e}`); }
  last.tailFused = true;
  console.error(`  chunk ${last.idx}: residue-tail verdict FUSED -> terminal (was hand-off + separate tail)`);
}
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify({
  fused: true, linkedLayout: LINKED_LAYOUT, stageBound: STAGE_BOUND,
  covenantResidue: COVENANT_RESIDUE, endpointSubgroup: FUSE_G2_ENDPOINT,
  numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, tailFused: c.tailFused === true, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error('wrote generated/manifest_millerres.json');
