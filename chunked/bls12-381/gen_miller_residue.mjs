// Generator for the c^-|x|-FUSED batched BLS12-381 Miller loop (residue method).
// BLS port of chunked/pairing/gen_miller_residue.mjs. Same prepared-VK batched structure as the
// op-optimized singleton (singleton/bls12-381/gen_singleton_minop.mjs emitMillerTailLazy): only
// the runtime pair 0 = e(-A,B) runs on-chain G2 arithmetic; pairs 2,3 have BAKED line coeffs
// (fixed VK G2 point); pair 1 = e(alpha,beta) is skipped and its UNCONJUGATED single-pair Miller
// value fAB is multiplied in once via the 'cmul1' op. The loop also folds c^-|x| into the shared
// f so the boundary fF = fRaw * c^-|x| (genesis f = cInv folds the 2^63 MSB term; op 'cf' folds
// cInv [NAF digit +1] or c [-1]). The residue witness (c, cInv) is carried as CONSTANT state.
// state = f(12) + R_B(6) + runtime points(10) + c(12) + cInv(12) = 52 limbs; stage-bound
// genesis carries only cInv+c+points (34 limbs) and derives f=cInv, R_B=B in-contract. The
// FINAL chunk hands off only [fF, c, cInv] (36 limbs) to the residue tail.
//   node gen_miller_residue.mjs          covenant plan -> generated/
//   node gen_miller_residue.mjs linked   linked plan   -> generated/linked-residue/
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, Fp2, f12limbs, r6limbs, pairsFor, singlePairMiller, millerBatchOps, PT_CFG, ptLimbs,
} from './_pairingmath.mjs';
import { commit, measureCovenantFile, planChunk, covIn, covOut, PUBLIC_INPUTS } from './_vkxmath.mjs';
import { millerFusedOps, residueWitness, conj, fp12limbsOf } from './_residuemath.mjs';
import { LINKED_MILLER_BOUNDS, LINKED_RESIDUE_NAMESPACE } from './_residue_linked_plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LINKED = process.argv[2] === 'linked';
const STAGE_BOUND = LINKED || process.env.STAGE_BOUND_LAYOUT === '1';
const GEN = join(here, 'generated', ...(LINKED ? [LINKED_RESIDUE_NAMESPACE] : []));
mkdirSync(GEN, { recursive: true });
const LIB_IMPORT = LINKED
  ? '../../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash'
  : '../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash';
const PROBE = join(GEN, '_probe_millerres.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_880_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const decl = (names) => names.map((n) => `int ${n}`).join(', ');

const PAIRS = pairsFor(PUBLIC_INPUTS);
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
// Put the hot derived-state sources first at genesis: cInv, c, then B/A/vk_x/C.
const genesisPtParams = [...ptParams.slice(2, 6), ...ptParams.slice(0, 2), ...ptParams.slice(6)];
const genesisPtL = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];

// witness for the committed planning instance (chunk math is generic; only window boundaries
// come from this instance).
const { boundary: fRawPlan } = millerBatchOps(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN } = residueWitness(fRawPlan);
const { ops, states, boundary, fAB } = millerFusedOps(PAIRS, C_PLAN, CINV_PLAN);

// baked constant f_{alpha,beta} (pair 1's UNCONJUGATED single-pair Miller value; VK-only),
// multiplied in once by 'cmul1' instead of folding pair 1's lines through the loop.
const FAB_LIMBS = fp12limbsOf(fAB).map(String);
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
// state = f(12) + R_B(6) + runtime points + c(12) + cInv(12)
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptL, ...rest]; };
const inState = (i) => STAGE_BOUND && i === 0
  ? [...f12limbs(states[i].cInv), ...f12limbs(states[i].c), ...genesisPtL]
  : withPts(stateLimbs(states[i]));
// the FINAL chunk hands off only [fF, c, cInv] (36 limbs, contiguous) to the residue tail —
// R_B/pts are done with once the loop ends. Non-final hand-offs carry the full 52-limb state.
const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
function genChunk(opLo, opHi, isFinal) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
  const fullStateParams = [...inF, ...inR0, ...ptParams, ...cNames, ...ciNames];
  const stateParams = STAGE_BOUND && opLo === 0 ? [...ciNames, ...cNames, ...genesisPtParams] : fullStateParams;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// c^-|x|-fused prepared-VK batched BLS12-381 Miller chunk: ops [${opLo},${opHi}).`);
  L.push('// state = f(12) + R_B(6) [+ runtime points] + c(12) + cInv(12); c,cInv are constant');
  L.push('// carried witness. cf op folds c^-1/c into f (residue method, ePrint 2024/640).');
  L.push('contract MillerFusedBlsChunk() {');
  L.push(`    function spend(${decl(stateParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(stateParams));
  // FUSED input validation (was the standalone g2check pass): the first Miller chunk checks the
  // prover's points are on-curve (A=-P0 & C=P3 on G1 y^2=x^3+4; B=Q0 on G2 y^2=x^3+(4+4u)); the
  // final chunk's psi(B)==[|x|]B subgroup test reuses R_B (=[|x|]B) that this loop already walks.
  if (opLo === 0) {
    for (const name of ptParams) L.push(`        require(within(${name}, 0, ${P}));`);
    L.push('        require(mSqr(Py0) == mAdd(mulFp(mSqr(Px0), Px0), 4));'); // A on G1 (-A shares the curve)
    L.push('        require(mSqr(Py3) == mAdd(mulFp(mSqr(Px3), Px3), 4));'); // C on G1
    L.push('        (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
    L.push('        (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
    L.push('        (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);'); // b' = 4 + 4u
    L.push('        (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
    L.push('        require(by2a == rhsa); require(by2b == rhsb);');
  }
  // precompute -Q.y for any runtime pair whose add-line in this window is negated
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a, int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe});`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  // Stage-bound genesis derives the fused MSB state from inputs already needed by the loop:
  // f starts at cInv and R_B starts at the proof's B point.
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
      emitLine(dco, pi);
    } else if (op.t === 'al') {
      if (fixed) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r0.join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]});`); r0 = ar;
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
    L.push(`        require(${r0[4]} != 0 || ${r0[5]} != 0);`);
    L.push(`        (int psxa, int psxb, int psya, int psyb) = psi(Q0xa, Q0xb, Q0ya, Q0yb);`);
    L.push('        (int npya, int npyb) = fp2Neg(psya, psyb);');
    L.push(`        (int exa, int exb) = r2Mul(psxa, psxb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(${r0[0]} == exa); require(${r0[1]} == exb);`);
    L.push(`        (int eya, int eyb) = r2Mul(npya, npyb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(${r0[2]} == eya); require(${r0[3]} == eyb);`);
  }
  // final chunk hands off only [fF, c, cInv] to the residue tail; others carry full state.
  L.push(isFinal ? covOut([...f, ...cNames, ...ciNames]) : covOut([...f, ...r0, ...ptParams, ...cNames, ...ciNames]));
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

if (LINKED && (LINKED_MILLER_BOUNDS[0] !== 0 || LINKED_MILLER_BOUNDS[LINKED_MILLER_BOUNDS.length - 1] !== ops.length ||
  LINKED_MILLER_BOUNDS.some((bound, i) => i > 0 && bound <= LINKED_MILLER_BOUNDS[i - 1]))) {
  throw new Error('invalid linked Miller boundaries');
}
console.error(`planning FUSED BLS12-381 Miller chunks (${ops.length} flat ops, ${ops.filter((o) => o.t === 'cf').length} c-folds)  deployment=${LINKED ? 'linked' : 'covenant'} OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi, hi === ops.length);
    const m = measureCovenantFile(src, inL, inL, outL, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final: hi === ops.length, outgoing: commit(outL), src, m };
  };
  const best = LINKED
    ? tryHi(LINKED_MILLER_BOUNDS[chunks.length + 1])
    : planChunk(lo, ops.length, OP_TARGET, tryHi, planState);
  if (!best) throw new Error(`no fitting fused window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: commit(inL), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} acceptedAsCovenant=${best.m.accepted} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`fused miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify({
  fused: true, deployment: LINKED ? 'linked-hash-free' : 'covenant', stageBound: STAGE_BOUND,
  numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error(`wrote ${join(GEN, 'manifest_millerres.json')}`);
