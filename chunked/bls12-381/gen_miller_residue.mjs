// Generator for the c^-|x|-fused batched BLS12-381 Miller loop (residue method).
// The default path uses the four-pair prepared-VK structure: only e(-A,B) runs on-chain G2
// arithmetic, the gamma/delta lines are baked, and e(alpha,beta) is folded once with cmul1.
// Fixed-key collapse mode instead evaluates e(-A,B) * e(D,G2.BASE) with two runtime G1 points;
// affine G2 walks and half-normalized lines remove projective state and fixed-pair folds.
//
// Both paths fold c^-|x| into the shared f so the boundary is fRaw*c^-|x|. The default residue
// state carries f(12) + R_B(6) + runtime points(10) + c(12) + cInv(12), and its final chunk hands
// [fF,c,cInv] to the residue tail. BLS_QUOTIENT_TORUS=1 carries the six-limb finite class
// [c]=[1+u*W] modulo Fp6 and fuses the projective residue verdict into the final chunk.
//   node gen_miller_residue.mjs          covenant plan -> generated/
//   node gen_miller_residue.mjs linked   linked plan   -> generated/linked-residue/
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  B_IDENTITY_SUBSTITUTE, P, Fp2, f12limbs, r6limbs, pairsFor, collapsedPairsFor, singlePairMiller,
  millerBatchOps, millerCollapsedAffineOps, PT_CFG, COLLAPSED_PT_CFG, ptLimbs, unitG1,
} from './_pairingmath.mjs';
import { commit, measureCovenantFile, planChunk, covIn, covOut, PUBLIC_INPUTS } from './_vkxmath.mjs';
import {
  millerFusedOps, millerFusedTorusOps, residueTorusWitness, residueWitness,
  conj, fp12limbsOf,
} from './_residuemath.mjs';
import {
  LINKED_COLLAPSED_TORUS_MILLER_BOUNDS, LINKED_MILLER_BOUNDS, LINKED_RESIDUE_NAMESPACE,
} from './_residue_linked_plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LINKED = process.argv[2] === 'linked';
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
const UNIT_G1 = process.env.BLS_UNIT_G1 === '1';
const FIXED_VK_COLLAPSE = process.env.BLS_FIXED_VK_COLLAPSE === '1';
const AFFINE_G2 = process.env.BLS_AFFINE_G2 === '1';
if (AFFINE_G2 && (!FIXED_VK_COLLAPSE || !UNIT_G1)) {
  throw new Error('BLS_AFFINE_G2 requires the fixed-VK collapse and unit G1 lines');
}
if (QUOTIENT_TORUS && !LINKED && process.env.BLS_QUOTIENT_LARGE !== '1') {
  throw new Error('BLS_QUOTIENT_TORUS is linked-only; pass the linked layout explicitly');
}
const STAGE_BOUND = LINKED || process.env.STAGE_BOUND_LAYOUT === '1';
const COVENANT_RESIDUE = STAGE_BOUND && process.env.COVENANT_RESIDUE_LAYOUT === '1';
const GEN = join(here, 'generated', ...(LINKED ? [LINKED_RESIDUE_NAMESPACE] : []));
mkdirSync(GEN, { recursive: true });
const LIB_IMPORT = LINKED
  ? `../../../../singleton/bls12-381/lib/lazy/Bls12381Lazy${QUOTIENT_TORUS ? 'Torus' : 'G'}.cash`
  : `../../../singleton/bls12-381/lib/lazy/Bls12381Lazy${QUOTIENT_TORUS ? 'Torus' : 'G'}.cash`;
const PROBE = join(GEN, '_probe_millerres.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_880_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const decl = (names) => names.map((n) => `int ${n}`).join(', ');

const PAIRS = FIXED_VK_COLLAPSE ? collapsedPairsFor(PUBLIC_INPUTS) : pairsFor(PUBLIC_INPUTS);
const PAIR_CFG = FIXED_VK_COLLAPSE ? COLLAPSED_PT_CFG : PT_CFG;
const B_IDENTITY_SUBSTITUTE_AFFINE = B_IDENTITY_SUBSTITUTE.toAffine();
const PINFO = PAIRS.map((pair, j) => {
  const Q = pair.Q.toAffine(), Pt = pair.P.toAffine(), cfg = PAIR_CFG[j], negQ = Fp2.neg(Q.y);
  return {
    j, cfg, negQ,
    Pxe: cfg.P ? `${UNIT_G1 ? 'Pu' : 'Px'}${j}` : `${Pt.x}`, Pye: cfg.P ? `${UNIT_G1 ? 'Pv' : 'Py'}${j}` : `${Pt.y}`,
    Qxae: cfg.Q ? `Q${j}xa` : `${Q.x.c0}`, Qxbe: cfg.Q ? `Q${j}xb` : `${Q.x.c1}`,
    Qyae: cfg.Q ? `Q${j}ya` : `${Q.y.c0}`, Qybe: cfg.Q ? `Q${j}yb` : `${Q.y.c1}`,
  };
});
const ptParams = [];
PINFO.forEach((pi, j) => { if (pi.cfg.P) ptParams.push(`${UNIT_G1 ? 'Pu' : 'Px'}${j}`, `${UNIT_G1 ? 'Pv' : 'Py'}${j}`); if (pi.cfg.Q) ptParams.push(`Q${j}xa`, `Q${j}xb`, `Q${j}ya`, `Q${j}yb`); });
const ptL = PAIRS.flatMap((pair, j) => {
  const Q = pair.Q.toAffine();
  const out = [];
  if (PAIR_CFG[j].P) {
    const point = UNIT_G1 ? unitG1(pair.P) : pair.P.toAffine();
    out.push(...(UNIT_G1 ? [point.u, point.v] : [point.x, point.y]));
  }
  if (PAIR_CFG[j].Q) out.push(Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1);
  return out;
});
// Put the hot derived-state sources first at genesis: cInv, c, then B/A/vk_x/C.
const genesisPtParams = [...ptParams.slice(2, 6), ...ptParams.slice(0, 2), ...ptParams.slice(6)];
const genesisPtL = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
// The full-stage GLV predecessor emits [A,B,C,vk_x]. Keep that exact order in the covenant
// commitment even though the Miller function declares its hot arguments as [cInv,c,B,A,vk_x,C].
const stagePtParams = FIXED_VK_COLLAPSE
  ? ptParams
  : [...ptParams.slice(0, 6), ...ptParams.slice(8, 10), ...ptParams.slice(6, 8)];
const stagePtL = FIXED_VK_COLLAPSE
  ? ptL
  : [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];

// witness for the committed planning instance (chunk math is generic; only window boundaries
// come from this instance).
const { boundary: fRawPlan } = AFFINE_G2
  ? millerCollapsedAffineOps(PAIRS)
  : millerBatchOps(PAIRS, { unitLines: UNIT_G1, ptCfg: PAIR_CFG });
const rootPlan = QUOTIENT_TORUS ? residueTorusWitness(fRawPlan) : residueWitness(fRawPlan);
const { c: C_PLAN, cInv: CINV_PLAN } = rootPlan;
const U_PLAN = QUOTIENT_TORUS ? rootPlan.u : null;
const trace = QUOTIENT_TORUS
  ? millerFusedTorusOps(PAIRS, C_PLAN, CINV_PLAN, U_PLAN, {
      unitLines: UNIT_G1, ptCfg: PAIR_CFG, affineG2: AFFINE_G2,
    })
  : millerFusedOps(PAIRS, C_PLAN, CINV_PLAN, {
      unitLines: UNIT_G1, ptCfg: PAIR_CFG, affineG2: AFFINE_G2,
    });
const { ops, states, boundary, fAB } = trace;

// baked constant f_{alpha,beta} (pair 1's UNCONJUGATED single-pair Miller value; VK-only),
// multiplied in once by 'cmul1' instead of folding pair 1's lines through the loop.
const FAB_LIMBS = fAB === null ? [] : fp12limbsOf(fAB).map(String);
const FAB_TORUS = QUOTIENT_TORUS
  ? trace.fAbU
  : null;
const FAB_TORUS_LIMBS = FAB_TORUS === null
  ? []
  : [
      FAB_TORUS.c0.c0, FAB_TORUS.c0.c1,
      FAB_TORUS.c1.c0, FAB_TORUS.c1.c1,
      FAB_TORUS.c2.c0, FAB_TORUS.c2.c1,
    ].map(String);
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
const torusNames = Array.from({ length: 6 }, (_, i) => `u${i}`);
const rootNames = QUOTIENT_TORUS ? torusNames : [...cNames, ...ciNames];
const rootPlanLimbs = QUOTIENT_TORUS
  ? [U_PLAN.c0.c0, U_PLAN.c0.c1, U_PLAN.c1.c0, U_PLAN.c1.c1, U_PLAN.c2.c0, U_PLAN.c2.c1]
  : [...f12limbs(C_PLAN), ...f12limbs(CINV_PLAN)];
// state = f(12) + R_B(6) + runtime points + residue root. Quotient mode carries one
// immutable six-limb u for [c]=[1+u*W], while the legacy path carries c+cInv (24 limbs).
const runtimeRLimbs = (R) => AFFINE_G2
  ? [R.x.c0, R.x.c1, R.y.c0, R.y.c1]
  : r6limbs(R);
const stateLimbs = (s) => [
  ...f12limbs(s.f), ...runtimeRLimbs(s.Rs[0]),
  ...(QUOTIENT_TORUS ? rootPlanLimbs : [...f12limbs(s.c), ...f12limbs(s.cInv)]),
];
const statePrefixLength = 12 + (AFFINE_G2 ? 4 : 6);
const withPts = (limbs) => { const fr = limbs.slice(0, statePrefixLength); const rest = limbs.slice(statePrefixLength); return [...fr, ...ptL, ...rest]; };
const slopeLimbs = (opLo, opHi) => AFFINE_G2
  ? ops.slice(opLo, opHi).flatMap((op) => op.j !== 0 || op.slope === undefined ? [] : [op.slope.c0, op.slope.c1])
  : [];
const inState = (i) => STAGE_BOUND && i === 0
  ? QUOTIENT_TORUS
    ? [...rootPlanLimbs, ...genesisPtL]
    : [...f12limbs(states[i].cInv), ...f12limbs(states[i].c), ...genesisPtL]
  : withPts(stateLimbs(states[i]));
// the FINAL chunk hands off only [fF, c, cInv] (36 limbs, contiguous) to the residue tail —
// R_B/pts are done with once the loop ends. Non-final hand-offs carry the full 52-limb state.
const outState = (i) => i === states.length - 1
  ? QUOTIENT_TORUS
    ? []
    : [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
const bakedUnitCoeffs = (triple) => {
  const inv = Fp2.inv(triple[2]);
  return [Fp2.mul(triple[0], inv), Fp2.mul(triple[1], inv)]
    .flatMap((c) => [`${c.c0}`, `${c.c1}`]);
};
function genChunk(opLo, opHi, isFinal) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = AFFINE_G2
    ? ['R0xa', 'R0xb', 'R0ya', 'R0yb']
    : ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
  const fullStateParams = [...inF, ...inR0, ...ptParams, ...rootNames];
  const stateParams = STAGE_BOUND && opLo === 0
    ? QUOTIENT_TORUS
      ? [...torusNames, ...genesisPtParams]
      : [...ciNames, ...cNames, ...genesisPtParams]
    : fullStateParams;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  if (QUOTIENT_TORUS) {
    L.push(`// c^-|x|-fused prepared-VK batched BLS12-381 Miller chunk: ops [${opLo},${opHi}).${isFinal ? ' Includes the quotient terminal verdict.' : ''}`);
    L.push(`// state = f(12) + R_B(${AFFINE_G2 ? 4 : 6}) [+ runtime points] + torus u(6); root data is constant.`);
    L.push('// cf folds c^-1/c into f modulo Fp6 scaling (residue method, ePrint 2024/640).');
    L.push(`contract MillerFusedBls${isFinal ? 'TorusTerminal' : 'Chunk'}() {`);
  } else {
    L.push(`// c^-|x|-fused prepared-VK batched BLS12-381 Miller chunk: ops [${opLo},${opHi}).`);
    L.push(`// state = f(12) + R_B(${AFFINE_G2 ? 4 : 6}) [+ runtime points] + c(12) + cInv(12); c,cInv are constant`);
    L.push('// carried witness. cf op folds c^-1/c into f (residue method, ePrint 2024/640).');
    L.push('contract MillerFusedBlsChunk() {');
  }
  const slopeNamesByOp = new Map();
  for (let i = opLo; i < opHi; i++) {
    if (ops[i].j === 0 && ops[i].slope !== undefined) slopeNamesByOp.set(i, [`m${i}a`, `m${i}b`]);
  }
  const slopeParams = [...slopeNamesByOp.values()].flat();
  L.push(`    function spend(${decl([...stateParams, ...slopeParams])}, bytes unused zeroPadding) {`);
  L.push(covIn(COVENANT_RESIDUE && opLo === 0 ? stagePtParams : stateParams));
  // Affine G2 arithmetic cannot walk the point at infinity. For the identity B encoding, execute
  // the equivalent neutral pair (P=O,Q=G2.BASE). Static-context chunks reload the raw proof from
  // the genesis input, so every chunk must recreate this effective mapping before using P/Q.
  const identityComplete = UNIT_G1;
  const pairPxe = (pi) => identityComplete && pi.j === 0 ? 'pairPu0' : pi.Pxe;
  const pairPye = (pi) => identityComplete && pi.j === 0 ? 'pairPv0' : pi.Pye;
  const pairQxae = (pi) => identityComplete && pi.j === 0 ? 'pairQ0xa' : pi.Qxae;
  const pairQxbe = (pi) => identityComplete && pi.j === 0 ? 'pairQ0xb' : pi.Qxbe;
  const pairQyae = (pi) => identityComplete && pi.j === 0 ? 'pairQ0ya' : pi.Qyae;
  const pairQybe = (pi) => identityComplete && pi.j === 0 ? 'pairQ0yb' : pi.Qybe;
  if (identityComplete) {
    L.push('        bool bIdentity = Q0xa + Q0xb + Q0ya + Q0yb == 0;');
    L.push('        int pairPu0 = Pu0; int pairPv0 = Pv0;');
    L.push('        int pairQ0xa = Q0xa; int pairQ0xb = Q0xb; int pairQ0ya = Q0ya; int pairQ0yb = Q0yb;');
    L.push('        if (bIdentity) {');
    L.push('            pairPu0 = 0; pairPv0 = 0;');
    L.push(`            pairQ0xa = ${B_IDENTITY_SUBSTITUTE_AFFINE.x.c0}; pairQ0xb = ${B_IDENTITY_SUBSTITUTE_AFFINE.x.c1};`);
    L.push(`            pairQ0ya = ${B_IDENTITY_SUBSTITUTE_AFFINE.y.c0}; pairQ0yb = ${B_IDENTITY_SUBSTITUTE_AFFINE.y.c1};`);
    L.push('        }');
  }
  // FUSED input validation (was the standalone g2check pass): the first Miller chunk checks the
  // prover's points are on-curve (A=-P0 & C=P3 on G1 y^2=x^3+4; B=Q0 on G2 y^2=x^3+(4+4u)); the
  // final chunk's psi(B)==[|x|]B subgroup test reuses R_B (=[|x|]B) that this loop already walks.
  if (opLo === 0) {
    for (const name of ptParams) L.push(`        require(within(${name}, 0, ${P}));`);
    if (STAGE_BOUND) {
      const canonicalRoots = QUOTIENT_TORUS ? rootNames : [...ciNames, ...cNames];
      for (const name of canonicalRoots) L.push(`        require(within(${name}, 0, ${P}));`);
    }
    if (UNIT_G1) {
      L.push('        require(Pv0 == mAdd(mulFp(4, mulFp(mSqr(Pu0), Pu0)), mulFp(16, mulFp(mSqr(Pv0), Pv0))));');
      const derivedPair = FIXED_VK_COLLAPSE ? 1 : 3;
      L.push(`        require(Pv${derivedPair} == mAdd(mulFp(4, mulFp(mSqr(Pu${derivedPair}), Pu${derivedPair})), mulFp(16, mulFp(mSqr(Pv${derivedPair}), Pv${derivedPair}))));`);
    } else {
      L.push('        require(mSqr(Py0) == mAdd(mulFp(mSqr(Px0), Px0), 4));'); // A on G1 (-A shares the curve)
      const derivedPair = FIXED_VK_COLLAPSE ? 1 : 3;
      L.push(`        require(mSqr(Py${derivedPair}) == mAdd(mulFp(mSqr(Px${derivedPair}), Px${derivedPair}), 4));`);
    }
    if (UNIT_G1) {
      L.push('        if (!bIdentity) {');
      L.push('            (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
      L.push('            (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
      L.push('            (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);');
      L.push('            (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
      L.push('            require(by2a == rhsa); require(by2b == rhsb);');
      L.push('        }');
    } else {
      L.push('        (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
      L.push('        (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
      L.push('        (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);'); // b' = 4 + 4u
      L.push('        (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
      L.push('        require(by2a == rhsa); require(by2b == rhsb);');
    }
  }
  // precompute -Q.y for any runtime pair whose add-line in this window is negated
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a, int nq${pi.j}b) = fp2Neg(${pairQyae(pi)}, ${pairQybe(pi)}, 1);`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pairQyae(pi), pairQybe(pi)];
  });
  // Stage-bound genesis derives the fused MSB state from inputs already needed by the loop.
  // In quotient mode [cInv]=[1-u*W], so its high coordinate is the canonical negation of u.
  const negTorusNames = Array.from({ length: 6 }, (_, i) => `nu${i}`);
  const needsNegTorus = QUOTIENT_TORUS && (STAGE_BOUND && opLo === 0 ||
    ops.slice(opLo, opHi).some((op) => op.t === 'cf' && !op.neg));
  if (needsNegTorus) {
    const negRaw = Array.from({ length: 6 }, (_, i) => `nur${i}`);
    L.push(`        (${decl(negRaw)}) = fp6Neg(${torusNames.join(',')}, 1);`);
    negTorusNames.forEach((name, i) => L.push(`        int ${name} = mulFp(${negRaw[i]}, 1);`));
  }
  let f = STAGE_BOUND && opLo === 0
    ? QUOTIENT_TORUS
      ? ['1', '0', '0', '0', '0', '0', ...negTorusNames]
      : ciNames.slice()
    : inF.slice();
  let r0 = STAGE_BOUND && opLo === 0
    ? [pairQxae(PINFO[0]), pairQxbe(PINFO[0]), pairQyae(PINFO[0]), pairQybe(PINFO[0]), ...(AFFINE_G2 ? [] : ['1', '0'])]
    : inR0.slice();
  let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi, normalized = false) => {
    const g = fresh(12);
    const fn = UNIT_G1 && pi.cfg.P
      ? normalized ? 'lineUnitOneRaw' : 'lineUnitScaledRaw'
      : 'line';
    L.push(`        (${decl(g)}) = ${fn}(${f.join(',')}, ${coeffs.join(',')}, ${pairPxe(pi)}, ${pairPye(pi)});`);
    f = g;
  };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q;
    const nextOp = i + 1 < opHi ? ops[i + 1] : null;
    if (AFFINE_G2 && UNIT_G1 && (op.t === 'dl' || op.t === 'al') &&
      nextOp !== null && (nextOp.t === 'dl' || nextOp.t === 'al') &&
      PINFO[op.j].cfg.P && PINFO[nextOp.j].cfg.P) {
      const paired = [];
      for (let pairIndex = i; pairIndex <= i + 1; pairIndex++) {
        const lineOp = ops[pairIndex], linePi = PINFO[lineOp.j];
        let coeffs;
        if (!linePi.cfg.Q) {
          coeffs = bakedCoeffs(lineOp.coeffs).slice(0, 4);
        } else {
          const lineCoeffs = fresh(4), lineR = fresh(4);
          if (lineOp.t === 'dl') {
            L.push(`        (${decl([...lineCoeffs, ...lineR])}) = pointDoubleAffine(${r0.join(',')}, ${slopeNamesByOp.get(pairIndex).join(',')});`);
          } else {
            const lineY = lineOp.neg ? negY[lineOp.j] : [pairQyae(linePi), pairQybe(linePi)];
            L.push(`        (${decl([...lineCoeffs, ...lineR])}) = pointAddAffine(${r0.join(',')}, ${pairQxae(linePi)}, ${pairQxbe(linePi)}, ${lineY[0]}, ${lineY[1]}, ${slopeNamesByOp.get(pairIndex).join(',')});`);
          }
          r0 = lineR;
          coeffs = lineCoeffs;
        }
        paired.push({ coeffs, pi: linePi });
      }
      const pairF = fresh(12);
      L.push(`        (${decl(pairF)}) = lineUnitOnePairKaratsubaRaw(${f.join(',')}, ${paired[0].coeffs.join(',')}, ${pairPxe(paired[0].pi)}, ${pairPye(paired[0].pi)}, ${paired[1].coeffs.join(',')}, ${pairPxe(paired[1].pi)}, ${pairPye(paired[1].pi)});`);
      f = pairF;
      i += 1;
      continue;
    }
    if (op.t === 'sqr') {
      const sf = fresh(12);
      L.push(`        (${decl(sf)}) = ${AFFINE_G2 ? 'fp12SqrRaw' : 'fp12Sqr'}(${f.join(',')});`);
      f = sf;
    }
    else if (op.t === 'cf') { // c-fold: f *= (neg ? c : cInv)
      const g = fresh(12);
      if (QUOTIENT_TORUS) {
        const m = op.neg ? torusNames : negTorusNames;
        L.push(`        (${decl(g)}) = fp12MulTorus(${f.join(',')}, ${m.join(',')});`);
      } else {
        const m = op.neg ? cNames : ciNames;
        L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${m.join(',')});`);
      }
      f = g;
    } else if (op.t === 'cmul1') { // f *= baked f_{alpha,beta} (VK constant)
      const g = fresh(12);
      L.push(QUOTIENT_TORUS
        ? `        (${decl(g)}) = fp12MulTorus(${f.join(',')}, ${FAB_TORUS_LIMBS.join(',')});`
        : `        (${decl(g)}) = fp12Mul(${f.join(',')}, ${FAB_LIMBS.join(',')});`);
      f = g;
    } else if (op.t === 'dl') {
      if (fixed) {
        emitLine(AFFINE_G2 ? bakedCoeffs(op.coeffs).slice(0, 4) : bakedCoeffs(op.coeffs), pi, AFFINE_G2);
        continue;
      }
      const dco = fresh(AFFINE_G2 ? 4 : 6), dr = fresh(AFFINE_G2 ? 4 : 6);
      if (AFFINE_G2) {
        L.push(`        (${decl([...dco, ...dr])}) = pointDoubleAffine(${r0.join(',')}, ${slopeNamesByOp.get(i).join(',')});`);
      } else {
        L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r0.join(',')});`);
      }
      r0 = dr;
      emitLine(dco, pi, AFFINE_G2);
    } else if (op.t === 'al') {
      if (fixed) {
        emitLine(AFFINE_G2 ? bakedCoeffs(op.coeffs).slice(0, 4) : bakedCoeffs(op.coeffs), pi, AFFINE_G2);
        continue;
      }
      const Y = op.neg ? negY[op.j] : [pairQyae(pi), pairQybe(pi)];
      const aco = fresh(AFFINE_G2 ? 4 : 6), ar = fresh(AFFINE_G2 ? 4 : 6);
      if (AFFINE_G2) {
        L.push(`        (${decl([...aco, ...ar])}) = pointAddAffine(${r0.join(',')}, ${pairQxae(pi)}, ${pairQxbe(pi)}, ${Y[0]}, ${Y[1]}, ${slopeNamesByOp.get(i).join(',')});`);
      } else {
        L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r0.join(',')}, ${pairQxae(pi)}, ${pairQxbe(pi)}, ${Y[0]}, ${Y[1]});`);
      }
      r0 = ar;
      emitLine(aco, pi, AFFINE_G2);
    }
  }
  // final chunk: G2 subgroup test on B, fused from the standalone g2check pass. R_B (=r0) is the
  // running pair-0 point, which at loop end equals [|x|]B (homogeneous projective; affine =
  // R/Rz). The membership relation is psi(B) == -[|x|]B (same as g2check), so require
  // Rx == psi(B).x * Rz  and  Ry == -psi(B).y * Rz. Rejects any B outside the prime-order subgroup.
  if (isFinal) {
    if (AFFINE_G2) {
      L.push(`        (int psxa, int psxb, int psya, int psyb) = psi(${pairQxae(PINFO[0])}, ${pairQxbe(PINFO[0])}, ${pairQyae(PINFO[0])}, ${pairQybe(PINFO[0])});`);
      L.push('        (int npya, int npyb) = fp2Neg(psya, psyb, 1);');
      L.push(`        require(redFp(${r0[0]}) == psxa); require(redFp(${r0[1]}) == psxb);`);
      L.push(`        require(redFp(${r0[2]}) == redFp(npya)); require(redFp(${r0[3]}) == redFp(npyb));`);
    } else {
    // GUARD (soundness): reject R_B = O before the cross-multiplied psi compare. |x| has NAF
    // prefix 13 and 13 | h2 (G2 twist cofactor), so an order-13 B (passes the raw on-curve check)
    // walks R_B through O; the homogeneous point ops collapse it to (0:0:0), which would VACUOUSLY
    // satisfy the compare (0 == psi.x*0). gcd(prefix, r)=1 makes order-13 the only collapsing case,
    // so requiring Rz != 0 closes it; non-collapsing walks give the true [|x|]B and gcd(lambda,h2)=1
    // then makes the compare a faithful G2 test. See psi-subgroup-degeneracy.md.
    L.push(`        require(redFp(${r0[4]}) != 0 || redFp(${r0[5]}) != 0);`);
    L.push(`        (int psxa, int psxb, int psya, int psyb) = psi(${pairQxae(PINFO[0])}, ${pairQxbe(PINFO[0])}, ${pairQyae(PINFO[0])}, ${pairQybe(PINFO[0])});`);
    L.push('        (int npya, int npyb) = fp2Neg(psya, psyb, 1);');
    L.push(`        (int exa, int exb) = r2Mul(psxa, psxb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(redFp(${r0[0]}) == exa); require(redFp(${r0[1]}) == exb);`);
    L.push(`        (int eya, int eyb) = r2Mul(npya, npyb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(redFp(${r0[2]}) == eya); require(redFp(${r0[3]}) == eyb);`);
    }
  }
  if (QUOTIENT_TORUS && isFinal) {
    const canonicalF = Array.from({ length: 12 }, (_, i) => `tailF${i}`);
    const frobeniusU = Array.from({ length: 6 }, (_, i) => `tailU${i}`);
    const product = Array.from({ length: 6 }, (_, i) => `tailP${i}`);
    canonicalF.forEach((name, i) => L.push(`        int ${name} = mulFp(${f[i]}, 1);`));
    L.push('        // Reject the vacuous projective value [0:0] before the cross-product test.');
    L.push(`        require(${canonicalF.join(' + ')} != 0);`);
    L.push(`        (${decl(frobeniusU)}) = torusFrob1(${torusNames.join(',')});`);
    L.push(`        (${decl(product)}) = fp6Mul(${canonicalF.slice(0, 6).join(',')}, ${frobeniusU.join(',')});`);
    L.push('        // [fX:fY] == [1:frob1(u)] iff fX*frob1(u) == fY in Fp6.');
    L.push('        ' + product.map((name, i) => `require(mulFp(${name} - ${canonicalF[i + 6]}, 1) == 0);`).join(' '));
  } else {
    // The legacy final chunk hands off [fF,c,cInv] to the separate residue tail; non-final
    // chunks carry the full state. Quotient mode instead verifies inline above.
    const carriedPtParams = identityComplete && opLo === 0
      ? [pairPxe(PINFO[0]), pairPye(PINFO[0]), pairQxae(PINFO[0]), pairQxbe(PINFO[0]), pairQyae(PINFO[0]), pairQybe(PINFO[0]), ...ptParams.slice(6)]
      : ptParams;
    const outNames = isFinal
      ? [...f, ...cNames, ...ciNames]
      : [...f, ...r0, ...carriedPtParams, ...rootNames];
    // Lazy point arithmetic can leave R_B above p, so every computed f/R limb is reduced exactly
    // once at this ownership boundary. Proof coordinates and roots are range-gated at genesis and
    // never reassigned; carrying those byte-for-byte preserves their canonical encoding.
    const exactNames = COVENANT_RESIDUE
      ? isFinal ? [...cNames, ...ciNames] : [...new Set([...carriedPtParams, ...rootNames])]
      : [];
    L.push(covOut(outNames, exactNames));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

if (process.argv[2] === 'probe') {
  for (const [a, b] of [[0, 0], [0, 1], [1, 1], [1, 2], [2, 2], [2, 3], [5, 5], [5, 6], [6, 6], [6, 7], [7, 7], [7, 8], [8, 8], [8, 9], [ops.length - 1, ops.length - 1], [ops.length - 1, ops.length]]) {
    const m = measureCovenantFile(genChunk(a, b, b === ops.length), [...inState(a), ...slopeLimbs(a, b)], inState(a), outState(b), PROBE);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

console.error(`planning FUSED BLS12-381 Miller chunks (${ops.length} flat ops, ${ops.filter((o) => o.t === 'cf').length} c-folds)  deployment=${LINKED ? 'linked' : 'covenant'} OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
const fixedBounds = !LINKED
  ? null
  : QUOTIENT_TORUS && FIXED_VK_COLLAPSE && AFFINE_G2
    ? LINKED_COLLAPSED_TORUS_MILLER_BOUNDS
    : LINKED_MILLER_BOUNDS;
if (fixedBounds !== null && (fixedBounds[0] !== 0 || fixedBounds[fixedBounds.length - 1] !== ops.length)) {
  throw new Error('fixed linked quotient Miller bounds do not span the operation trace');
}
while (lo < ops.length) {
  const inL = inState(lo);
  const inCommit = COVENANT_RESIDUE && lo === 0 ? stagePtL : inL;
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi, hi === ops.length);
    const m = measureCovenantFile(src, [...inL, ...slopeLimbs(lo, hi)], inCommit, outL, PROBE);
    return {
      fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET,
      operationCost: m.operationCost,
      hi,
      final: hi === ops.length,
      outgoing: QUOTIENT_TORUS && hi === ops.length ? null : commit(outL),
      src,
      m,
    };
  };
  const fixedIndex = fixedBounds === null ? -1 : fixedBounds.indexOf(lo);
  const best = fixedBounds === null
    ? planChunk(lo, ops.length, OP_TARGET, tryHi, planState)
    : fixedIndex >= 0 && fixedIndex < fixedBounds.length - 1
      ? tryHi(fixedBounds[fixedIndex + 1])
      : null;
  if (!best || !best.m.accepted || best.operationCost > OP_TARGET ||
    (fixedBounds === null && QUOTIENT_TORUS && !best.fits)) {
    throw new Error(`no fitting Miller window at op ${lo}`);
  }
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: commit(inCommit), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} acceptedAsCovenant=${best.m.accepted} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`fused miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
const manifest = QUOTIENT_TORUS
  ? {
      fused: true, deployment: LINKED ? 'linked-hash-free' : 'covenant', stageBound: STAGE_BOUND,
      covenantResidue: COVENANT_RESIDUE, inputValidationFused: true, unitG1Lines: UNIT_G1,
      affineG2: AFFINE_G2,
      quotientTorus: true, terminalFused: true, genesisRootParams: rootNames,
      numPairs: PAIRS.length, fixedVkCollapse: FIXED_VK_COLLAPSE,
      numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
      chunks: chunks.map((c) => ({
        idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final,
        terminalFused: c.final, incoming: c.incoming, outgoing: c.outgoing,
      })),
    }
  : {
      fused: true, deployment: LINKED ? 'linked-hash-free' : 'covenant', stageBound: STAGE_BOUND,
      covenantResidue: COVENANT_RESIDUE, inputValidationFused: true, unitG1Lines: UNIT_G1,
      affineG2: AFFINE_G2,
      numPairs: PAIRS.length, fixedVkCollapse: FIXED_VK_COLLAPSE,
      numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
      chunks: chunks.map((c) => ({
        idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final,
        incoming: c.incoming, outgoing: c.outgoing,
      })),
    };
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify(manifest, null, 2));
console.error(`wrote ${join(GEN, 'manifest_millerres.json')}`);
