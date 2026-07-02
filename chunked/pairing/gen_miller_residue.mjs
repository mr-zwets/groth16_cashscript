// Generator for the c^-(6x+2)-FUSED batched BN254 Miller loop (residue method).
// Identical to gen_miller.mjs (prepared-VK, 4 pairs batched, shared f) EXCEPT the loop also
// folds c^-(6x+2) into f so the boundary fF = fRaw * c^-(6x+2). The residue witness (c, cInv)
// is carried as CONSTANT state (12+12 limbs) so each chunk can multiply by it; op 'cf' (c-fold)
// does f = fp12Mul(f, cInv) [NAF digit +1] or fp12Mul(f, c) [digit -1]. The LEADING 'cf' injects
// the loop's implicit MSB (R=Q preload -> 2^65 term). The minimal-weight NAF of 6x+2 (22 c-folds)
// beats a cInv-only binary fold (37 folds) — measured 27 chunks / 194.9M op vs 28 / 201.1M.
// One fixed locking per chunk verifies ANY proof (c,cInv are runtime state, like the rest).
//   node gen_miller_residue.mjs        plan + emit millerres_NN.cash + manifest_millerres.json
import { hoistSpendConstants } from '../_hoistconsts.mjs';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, f12limbs, r6limbs, pairsFor, vec, commit, millerBatchOps, singlePairMiller,
  measureCovenantFile, planChunk, covIn, covOut, PT_CFG, ptLimbs, decl,
} from './_millermath.mjs';
import { millerFusedOps, residueWitness } from './_residuemath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const LIB_IMPORT = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = join(GEN, '_probe_millerres.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

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

// witness for the committed planning instance (the chunk math is generic; only window
// boundaries come from this instance, like the rest of the generators).
const { boundary: fRawPlan } = millerBatchOps(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN } = residueWitness(fRawPlan);
const { ops, states, boundary } = millerFusedOps(PAIRS, C_PLAN, CINV_PLAN);

// baked constant f_{alpha,beta} (pair 1's single-pair Miller value; VK-only, proof-independent),
// multiplied in once by the 'cmul1' op instead of folding pair 1's ~89 lines through the loop.
const FAB_LIMBS = f12limbs(singlePairMiller(PAIRS[1]).f).map((x) => x.toString());
const cNames = Array.from({ length: 12 }, (_, i) => `c${i}`);
const ciNames = Array.from({ length: 12 }, (_, i) => `ci${i}`);
// state = f(12) + R0(6) + runtime points + c(12) + cInv(12)
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptL, ...rest]; };
const inState = (i) => withPts(stateLimbs(states[i]));
// the FINAL chunk hands off only [fF, c, cInv] (36 limbs, contiguous) to the residue tail —
// R0/pts are done with once the loop ends. Non-final hand-offs carry the full 52-limb state.
const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
function genChunk(opLo, opHi, isFinal) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
  const allParams = [...inF, ...inR0, ...ptParams, ...cNames, ...ciNames];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// c^-(6x+2)-fused prepared-VK batched BN254 Miller chunk: ops [${opLo},${opHi}).`);
  L.push('// state = f(12) + R0(6) [+ runtime points] + c(12) + cInv(12); c,cInv are constant');
  L.push('// carried witness. cf op folds c^-1/c into f (residue method, ePrint 2024/640).');
  L.push('contract MillerFusedChunk() {');
  L.push(`    function spend(${decl(allParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(allParams));
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe}, 64);`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  let f = inF.slice(); let r0 = inR0.slice(); let uid = 0;
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
    } else { // pp
      if (fixed) { emitLine(bakedCoeffs(op.coeffs[0]), pi); emitLine(bakedCoeffs(op.coeffs[1]), pi); continue; }
      const q1 = fresh(4);
      L.push(`        (${decl(q1)}) = psi(${pi.Qxae}, ${pi.Qxbe}, ${pi.Qyae}, ${pi.Qybe});`);
      const bco = fresh(6), br = fresh(6);
      L.push(`        (${decl([...bco, ...br])}) = pointAdd(${r0.join(',')}, ${q1.join(',')});`); r0 = br;
      emitLine(bco, pi);
      const q2 = fresh(4); L.push(`        (${decl(q2)}) = psi(${q1.join(',')});`);
      const q2ny = fresh(2); L.push(`        (${decl(q2ny)}) = fp2Neg(${q2[2]}, ${q2[3]}, 64);`);
      const cco = fresh(6), cr = fresh(6);
      L.push(`        (${decl([...cco, ...cr])}) = pointAdd(${r0.join(',')}, ${q2[0]}, ${q2[1]}, ${q2ny[0]}, ${q2ny[1]});`); r0 = cr;
      emitLine(cco, pi);
    }
  }
  // final chunk hands off only [fF, c, cInv] to the residue tail; others carry full state.
  L.push(isFinal ? covOut([...f, ...cNames, ...ciNames]) : covOut([...f, ...r0, ...ptParams, ...cNames, ...ciNames]));
  L.push('    }');
  L.push('}');
  return hoistSpendConstants(L.join('\n') + '\n');
}

if (process.argv[2] === 'probe') {
  for (const [a, b] of [[0, 4], [0, 8], [ops.length - 4, ops.length]]) {
    const m = measureCovenantFile(genChunk(a, b, b === ops.length), inState(a), outState(b), PROBE);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

console.error(`planning FUSED BN254 Miller chunks (${ops.length} flat ops, ${ops.filter(o => o.t === 'cf').length} c-folds)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi, hi === ops.length);
    const m = measureCovenantFile(src, inL, outL, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final: hi === ops.length, outgoing: commit(outL), src, m };
  };
  const best = planChunk(lo, ops.length, OP_TARGET, tryHi, planState);
  if (!best) throw new Error(`no fitting fused window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `millerres_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: commit(inL), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`fused miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_millerres.json'), JSON.stringify({
  fused: true, numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error('wrote generated/manifest_millerres.json');
