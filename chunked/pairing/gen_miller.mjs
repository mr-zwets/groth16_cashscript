// Generator for the BCH-native, multi-transaction BATCHED BN254 Miller loop.
// All 4 Groth16 pairs in ONE chain: f squared ONCE per NAF step (shared), then each
// pair's double-line (+ add-line when the digit is set) folded into the shared f; each
// pair's R evolves independently; then the Q1/Q2 (psi) postPrecompute per pair. The
// folded f IS the boundary (NO separate combine). Eliminates 3 of every 4 fp12Sqr vs
// four single-pair chains.
//
// One batched step is ~8 mul034 (~too coarse for one BCH input), so the loop is a FLAT
// op list (sqr / double-line / add-line / postPrecompute) chunked at ANY op boundary,
// carrying state = f (12) + R0..R3 (24) + proof-derived points (per PT_CFG), hash256-
// committed (40-byte limbs). Field arithmetic is the lazy addFp/subFp already in
// singleton/bn254/miller.cash. Replaces the previous four-single-pair-chains + combine.
//
//   node gen_miller.mjs            plan + emit miller_NN.cash + manifest_miller.json
//   node gen_miller.mjs probe      fast fixed-window op-cost probe
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, ATE_NAF, millerBatchOps, f12limbs, r6limbs, pairsFor, vec, commit,
  measureCovenantFile, planChunk, covIn, covOut, PT_CFG, ptLimbs, decl,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
// The tower/pairing functions live in the shared singleton library; each chunk imports it
// (resolved by compileFile) instead of inlining the bodies. Path is relative to GEN/.
const LIB_IMPORT = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = join(GEN, '_probe.cash'); // planner writes candidate chunks here to compile-from-file
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const STAGE_BOUND = process.env.STAGE_BOUND_LAYOUT === '1';

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

const { ops, states, boundary } = millerBatchOps(PAIRS);
// Prepared-VK state: only the RUNTIME pair's accumulator R0 (= e(-A,B), PT_CFG[0]) is carried;
// the three fixed-VK pairs (alpha/beta, vk_x/gamma, C/delta) use baked line coeffs, so their R
// is never needed on-chain and never enters the committed state. f(12) + R0(6) [+ runtime points].
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const withPts = (limbs) => [...limbs, ...ptL];
const inState = (i) => STAGE_BOUND && i === 0 ? stagePtL : withPts(stateLimbs(states[i]));
const outState = (i) => withPts(stateLimbs(states[i]));
// Genesis f/R0 are derived in-contract under STAGE_BOUND (f = 1, R0 = runtime B); the literal
// limb strings come from the plan states so the serialization stays canonical.
const F_ONE_L = f12limbs(states[0].f).map(String);

// limbs of a baked line-coeff triple [c0,c1,c2] (each Fp2) in the order `line` expects:
// c0a,c0b,c1a,c1b,c2a,c2b. Reduced (canonical) reps; the lazy line()/mul034 accept any
// representative mod p, and covOut reduces the final f, so baking the reduced value is exact.
const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);
function genChunk(opLo, opHi) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb']; // only the runtime pair's R
  const stateParams = STAGE_BOUND && opLo === 0 ? stagePtParams : [...inF, ...inR0, ...ptParams];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// Prepared-VK batched BN254 Miller chunk: ops [${opLo},${opHi}).`);
  L.push('// state = f(12) + R0(6) [+ runtime points]; lives in the token NFT commitment. The runtime');
  L.push('// pair e(-A,B) keeps on-chain G2 (pointDouble/pointAdd); the fixed-VK pairs (alpha/beta,');
  L.push('// vk_x/gamma, C/delta) fold BAKED line coeffs in — no on-chain G2, no carried R.');
  L.push('contract MillerBatchChunk() {');
  L.push(`    function spend(${decl(stateParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(stateParams));
  // -Qy (bias 64) for the runtime pair's add-line with digit -1 in this window (fixed pairs
  // never do an on-chain add, so only PT_CFG[*].Q===true [pair 0] can need this).
  const negY = PINFO.map((pi) => {
    if (!pi.cfg.Q) return [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
    const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
    if (needs) { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe}, 64);`); return [`nq${pi.j}a`, `nq${pi.j}b`]; }
    return [pi.Qyae, pi.Qybe];
  });
  // Stage-bound genesis derives f = 1 and R0 = the runtime B point in-contract instead of
  // accepting them as independent witness state.
  let f = STAGE_BOUND && opLo === 0 ? F_ONE_L.slice() : inF.slice();
  let r0 = STAGE_BOUND && opLo === 0
    ? [PINFO[0].Qxae, PINFO[0].Qxbe, PINFO[0].Qyae, PINFO[0].Qybe, '1', '0']
    : inR0.slice();
  let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  // fold one line(f, coeffs, Px, Py) into f; `coeffs` is a 6-name/literal array.
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = line(${f.join(',')}, ${coeffs.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    const fixed = pi !== null && !pi.cfg.Q; // fixed VK G2 point -> bake the line coeffs
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'dl') {
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
    } else { // pp: Q1/Q2 postPrecompute (2 psi add-lines) for pair j
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
  L.push(covOut([...f, ...r0, ...ptParams]));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- probe ----
if (process.argv[2] === 'probe') {
  for (const [a, b] of [[0, 4], [0, 8], [ops.length - 4, ops.length]]) {
    const m = measureCovenantFile(genChunk(a, b), inState(a), outState(b), PROBE);
    console.error(`ops [${a},${b}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

// ---- plan + emit ----
console.error(`planning BATCHED BN254 Miller chunks (${ops.length} flat ops)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const tryHi = (hi) => {
    const outL = outState(hi);
    const src = genChunk(lo, hi);
    const m = measureCovenantFile(src, inL, outL, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final: hi === ops.length, outgoing: commit(outL), src, m };
  };
  const best = planChunk(lo, ops.length, OP_TARGET, tryHi, planState);
  if (!best) throw new Error(`no fitting batched window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `miller_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: commit(inL), outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`batched miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_miller.json'), JSON.stringify({
  batched: true, stageBound: STAGE_BOUND, numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(boundary).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error('wrote generated/manifest_miller.json');
