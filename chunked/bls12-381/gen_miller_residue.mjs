// Generator for the c^-|x|-FUSED batched BLS12-381 Miller loop (residue method).
// BLS port of chunked/pairing/gen_miller_residue.mjs. Same prepared-VK batched structure as the
// op-optimized singleton (singleton/bls12-381/gen_singleton_minop.mjs emitMillerTailLazy): only
// the runtime pair 0 = e(-A,B) runs on-chain G2 arithmetic; pairs 2,3 have BAKED line coeffs
// (fixed VK G2 point); pair 1 = e(alpha,beta) is skipped and its UNCONJUGATED single-pair Miller
// value fAB is multiplied in once via the 'cmul1' op. The loop also folds c^-|x| into the shared
// f so the boundary fF = fRaw * c^-|x| (genesis f = cInv folds the 2^63 MSB term; op 'cf' folds
// cInv [NAF digit +1] or c [-1]). The default path carries (c,cInv) as constant state.
// state = f(12) + R_B(6) + runtime points(10) + c(12) + cInv(12) = 52 limbs; stage-bound
// genesis carries only cInv+c+points (34 limbs) and derives f=cInv, R_B=B in-contract. The
// FINAL chunk hands off only [fF, c, cInv] (36 limbs) to the residue tail.
// BLS_QUOTIENT_TORUS=1 instead carries the six-limb finite class [c]=[1+u*W] modulo Fp6,
// specializes constant folds, and fuses the projective residue verdict into the final chunk.
//   node gen_miller_residue.mjs          covenant plan -> generated/
//   node gen_miller_residue.mjs linked   linked plan   -> generated/linked-residue/
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  B_IDENTITY_SUBSTITUTE, P, Fp2, f12limbs, r6limbs, pairsFor, singlePairMiller,
  millerBatchOps, PT_CFG, ptLimbs, unitG1,
} from './_pairingmath.mjs';
import { commit, measureCovenantFile, planChunk, covIn, covOut, PUBLIC_INPUTS } from './_vkxmath.mjs';
import {
  millerFusedOps, millerFusedTorusOps, residueTorusWitness, residueWitness,
  conj, fp12limbsOf,
} from './_residuemath.mjs';
import { LINKED_MILLER_BOUNDS, LINKED_RESIDUE_NAMESPACE } from './_residue_linked_plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LINKED = process.argv[2] === 'linked';
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
const UNIT_G1 = process.env.BLS_UNIT_G1 === '1';
const REPLAN_LINKED = process.env.BLS_REPLAN_LINKED === '1';
if (REPLAN_LINKED && (!LINKED || UNIT_G1)) {
  throw new Error('BLS_REPLAN_LINKED requires the linked affine-G1 layout');
}
// The grouped builder owns a fixed standard-transaction schedule. Only the one-transaction
// affine-G1 path opts into planning against its actual linked-input byte/op-cost context.
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

const PAIRS = pairsFor(PUBLIC_INPUTS);
const B_IDENTITY_SUBSTITUTE_AFFINE = B_IDENTITY_SUBSTITUTE.toAffine();
const PINFO = PAIRS.map((pair, j) => {
  const Q = pair.Q.toAffine(), Pt = pair.P.toAffine(), cfg = PT_CFG[j], negQ = Fp2.neg(Q.y);
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
  if (PT_CFG[j].P) {
    const point = UNIT_G1 ? unitG1(pair.P) : pair.P.toAffine();
    out.push(...(UNIT_G1 ? [point.u, point.v] : [point.x, point.y]));
  }
  if (PT_CFG[j].Q) out.push(Q.x.c0, Q.x.c1, Q.y.c0, Q.y.c1);
  return out;
});
// Put the hot derived-state sources first at genesis: cInv, c, then B/A/vk_x/C.
const genesisPtParams = [...ptParams.slice(2, 6), ...ptParams.slice(0, 2), ...ptParams.slice(6)];
const genesisPtL = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
// The full-stage GLV predecessor emits [A,B,C,vk_x]. Keep that exact order in the covenant
// commitment even though the Miller function declares its hot arguments as [cInv,c,B,A,vk_x,C].
const stagePtParams = [...ptParams.slice(0, 6), ...ptParams.slice(8, 10), ...ptParams.slice(6, 8)];
const stagePtL = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];

// witness for the committed planning instance (chunk math is generic; only window boundaries
// come from this instance).
const { boundary: fRawPlan } = millerBatchOps(PAIRS, { unitLines: UNIT_G1 });
const rootPlan = QUOTIENT_TORUS ? residueTorusWitness(fRawPlan) : residueWitness(fRawPlan);
const { c: C_PLAN, cInv: CINV_PLAN } = rootPlan;
const U_PLAN = QUOTIENT_TORUS ? rootPlan.u : null;
const trace = QUOTIENT_TORUS
  ? millerFusedTorusOps(PAIRS, C_PLAN, CINV_PLAN, U_PLAN, { unitLines: UNIT_G1 })
  : millerFusedOps(PAIRS, C_PLAN, CINV_PLAN, { unitLines: UNIT_G1 });
const { ops, states, boundary, fAB } = trace;

// baked constant f_{alpha,beta} (pair 1's UNCONJUGATED single-pair Miller value; VK-only),
// multiplied in once by 'cmul1' instead of folding pair 1's lines through the loop.
const FAB_LIMBS = fp12limbsOf(fAB).map(String);
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
const stateLimbs = (s) => [
  ...f12limbs(s.f), ...r6limbs(s.Rs[0]),
  ...(QUOTIENT_TORUS ? rootPlanLimbs : [...f12limbs(s.c), ...f12limbs(s.cInv)]),
];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptL, ...rest]; };
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
function genChunk(opLo, opHi, isFinal) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
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
    L.push('// state = f(12) + R_B(6) [+ runtime points] + torus u(6); root data is constant.');
    L.push('// cf folds c^-1/c into f modulo Fp6 scaling (residue method, ePrint 2024/640).');
    L.push(`contract MillerFusedBls${isFinal ? 'TorusTerminal' : 'Chunk'}() {`);
  } else {
    L.push(`// c^-|x|-fused prepared-VK batched BLS12-381 Miller chunk: ops [${opLo},${opHi}).`);
    L.push('// state = f(12) + R_B(6) [+ runtime points] + c(12) + cInv(12); c,cInv are constant');
    L.push('// carried witness. cf op folds c^-1/c into f (residue method, ePrint 2024/640).');
    L.push('contract MillerFusedBlsChunk() {');
  }
  L.push(`    function spend(${decl(stateParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(COVENANT_RESIDUE && opLo === 0 ? stagePtParams : stateParams));
  const identityCompleteGenesis = UNIT_G1 && opLo === 0;
  const pairPxe = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairPu0' : pi.Pxe;
  const pairPye = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairPv0' : pi.Pye;
  const pairQxae = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairQ0xa' : pi.Qxae;
  const pairQxbe = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairQ0xb' : pi.Qxbe;
  const pairQyae = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairQ0ya' : pi.Qyae;
  const pairQybe = (pi) => identityCompleteGenesis && pi.j === 0 ? 'pairQ0yb' : pi.Qybe;
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
      L.push('        require(Pv3 == mAdd(mulFp(4, mulFp(mSqr(Pu3), Pu3)), mulFp(16, mulFp(mSqr(Pv3), Pv3))));');
    } else {
      L.push('        require(mSqr(Py0) == mAdd(mulFp(mSqr(Px0), Px0), 4));'); // A on G1 (-A shares the curve)
      L.push('        require(mSqr(Py3) == mAdd(mulFp(mSqr(Px3), Px3), 4));'); // C on G1
    }
    if (UNIT_G1) {
      L.push('        bool bIdentity = Q0xa + Q0xb + Q0ya + Q0yb == 0;');
      L.push('        if (!bIdentity) {');
      L.push('            (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
      L.push('            (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
      L.push('            (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);');
      L.push('            (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
      L.push('            require(by2a == rhsa); require(by2b == rhsb);');
      L.push('        }');
      L.push('        int pairPu0 = Pu0; int pairPv0 = Pv0;');
      L.push('        int pairQ0xa = Q0xa; int pairQ0xb = Q0xb; int pairQ0ya = Q0ya; int pairQ0yb = Q0yb;');
      L.push('        if (bIdentity) {');
      L.push('            pairPu0 = 0; pairPv0 = 0;');
      L.push(`            pairQ0xa = ${B_IDENTITY_SUBSTITUTE_AFFINE.x.c0}; pairQ0xb = ${B_IDENTITY_SUBSTITUTE_AFFINE.x.c1};`);
      L.push(`            pairQ0ya = ${B_IDENTITY_SUBSTITUTE_AFFINE.y.c0}; pairQ0yb = ${B_IDENTITY_SUBSTITUTE_AFFINE.y.c1};`);
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
    ? [pairQxae(PINFO[0]), pairQxbe(PINFO[0]), pairQyae(PINFO[0]), pairQybe(PINFO[0]), '1', '0']
    : inR0.slice();
  let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = ${UNIT_G1 && pi.cfg.P ? 'lineUnitScaled' : 'line'}(${f.join(',')}, ${coeffs.join(',')}, ${pairPxe(pi)}, ${pairPye(pi)});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q;
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
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
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const dco = fresh(6), dr = fresh(6);
      L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r0.join(',')});`); r0 = dr;
      emitLine(dco, pi);
    } else if (op.t === 'al') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pairQyae(pi), pairQybe(pi)];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r0.join(',')}, ${pairQxae(pi)}, ${pairQxbe(pi)}, ${Y[0]}, ${Y[1]});`); r0 = ar;
      emitLine(aco, pi);
    }
  }
  // final chunk: G2 subgroup test on B, fused from the standalone g2check pass. R_B (=r0) is the
  // running pair-0 point, which at loop end equals [|x|]B (homogeneous projective; affine =
  // R/Rz). The membership relation is psi(B) == -[|x|]B (same as g2check), so require
  // Rx == psi(B).x * Rz  and  Ry == -psi(B).y * Rz. Rejects any B outside the prime-order subgroup.
  if (isFinal) {
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
    const carriedPtParams = identityCompleteGenesis
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
  for (const [a, b] of [[0, 4], [0, 8], [ops.length - 4, ops.length]]) {
    const m = measureCovenantFile(genChunk(a, b, b === ops.length), inState(a), inState(a), outState(b), PROBE);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

if (LINKED && !REPLAN_LINKED && (LINKED_MILLER_BOUNDS[0] !== 0 || LINKED_MILLER_BOUNDS[LINKED_MILLER_BOUNDS.length - 1] !== ops.length ||
  LINKED_MILLER_BOUNDS.some((bound, i) => i > 0 && bound <= LINKED_MILLER_BOUNDS[i - 1]))) {
  throw new Error('invalid linked Miller boundaries');
}
console.error(`planning FUSED BLS12-381 Miller chunks (${ops.length} flat ops, ${ops.filter((o) => o.t === 'cf').length} c-folds)  deployment=${LINKED ? 'linked' : 'covenant'} OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const inCommit = COVENANT_RESIDUE && lo === 0 ? stagePtL : inL;
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi, hi === ops.length);
    const m = measureCovenantFile(src, inL, inCommit, outL, PROBE);
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
  const best = LINKED && !REPLAN_LINKED
    ? tryHi(LINKED_MILLER_BOUNDS[chunks.length + 1])
    : planChunk(lo, ops.length, OP_TARGET, tryHi, planState);
  if (!best || (QUOTIENT_TORUS && !best.fits)) {
    throw new Error(`no fitting quotient-torus window at op ${lo}`);
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
      quotientTorus: true, terminalFused: true, genesisRootParams: rootNames,
      numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
      chunks: chunks.map((c) => ({
        idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final,
        terminalFused: c.final, incoming: c.incoming, outgoing: c.outgoing,
      })),
    }
  : {
      fused: true, deployment: LINKED ? 'linked-hash-free' : 'covenant', stageBound: STAGE_BOUND,
      covenantResidue: COVENANT_RESIDUE, inputValidationFused: true, unitG1Lines: UNIT_G1,
      numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
      chunks: chunks.map((c) => ({
        idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final,
        incoming: c.incoming, outgoing: c.outgoing,
      })),
    };
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify(manifest, null, 2));
console.error(`wrote ${join(GEN, 'manifest_millerres.json')}`);
