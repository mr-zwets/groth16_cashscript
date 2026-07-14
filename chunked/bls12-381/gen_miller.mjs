// Generator for the BCH-native, multi-transaction PREPARED BLS12-381 Miller loop.
// All 4 Groth16 pairs remain in one shared-squaring product, but only proof-derived B
// walks G2 on-chain. The fixed gamma/delta trajectories use baked line coefficients;
// fully fixed e(alpha,beta) is multiplied once as a baked dense Miller value.
//
// The loop is a FLAT op list chunked at any boundary. Its genesis accepts only the
// contiguous proof tuple (-A,B,C) + vk_x and derives f=1 and R_B=B in-contract. Later
// chunks carry f (12) + R_B (6) + runtime points; the final chunk emits only the
// conjugated 12-limb Miller boundary consumed by final exponentiation. `full` emits a
// separate namespace which fuses G1/G2 input validation into the first/last chunks;
// the ordinary namespace remains explicitly input-unvalidated for pairing-only tracks.
//
//   node gen_miller.mjs            plan + emit miller_NN.cash + manifest_miller.json
//   node gen_miller.mjs full       plan + emit millerfull_NN.cash + manifest_millerfull.json
//   node gen_miller.mjs probe      fast fixed-window op-cost probe
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, Fp2, ATE_NAF, OP_BUDGET, millerPreparedOps, f12limbs, r6limbs, pairsFor, commit,
  planChunk, covIn, covOut, PT_CFG, ptLimbs, decl,
} from './_pairingmath.mjs';
import { measureCovenantFile } from './_vkxmath.mjs';
import { PUBLIC_INPUTS } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const VALIDATED = process.argv[2] === 'full';
const PREFIX = VALIDATED ? 'millerfull' : 'miller';
const MANIFEST = `manifest_${PREFIX}.json`;
const PROBE = join(GEN, `_probe_${PREFIX}_${process.pid}.cash`); // compile candidates from file so the lib import resolves
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const TAIL_OP_TARGET = OP_BUDGET - 100_000;
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

// The lazy tower (lazy addFp/subFp + reducing mulFp and the rest) lives in the shared lazy library;
// each chunk imports it (cashc tree-shakes). Replaces the old fnExtractor-from-singleton + lazyArith,
// which broke when the singleton migrated those functions into its (non-lazy) library layout.
const LIB_IMPORT = VALIDATED
  ? '../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash'
  : '../../../singleton/bls12-381/lib/lazy/Bls12381Lazy.cash';

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
// Genesis order is contiguous proof tuple (-A,B,C), then vk_x. Later states retain
// the ordinary pair order (-A/B, vk_x, C).
const stagePtParams = [...ptParams.slice(0, 6), ...ptParams.slice(8, 10), ...ptParams.slice(6, 8)];
const stagePtL = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];

const trace = millerPreparedOps(PAIRS);
const { ops, states, finalF, fAB } = trace;
const FAB_LIMBS = f12limbs(fAB).map(String);
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const withPts = (limbs) => [...limbs, ...ptL];
const inState = (i) => i === 0 ? stagePtL : withPts(stateLimbs(states[i]));
const finalLimbs = f12limbs(finalF);
const outState = (i, final) => final ? finalLimbs : withPts(stateLimbs(states[i]));
const F_ONE_LIMBS = f12limbs(states[0].f).map(String);

const bakedCoeffs = (triple) => triple.flatMap((c) => [`${c.c0}`, `${c.c1}`]);

function genChunk(opLo, opHi, final) {
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR0 = ['R0xa', 'R0xb', 'R0ya', 'R0yb', 'R0za', 'R0zb'];
  const stateParams = opLo === 0 ? stagePtParams : [...inF, ...inR0, ...ptParams];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// GENERIC batched BLS12-381 Miller covenant chunk: ops [${opLo},${opHi}), final=${final}.`);
  L.push('// genesis derives f=1 and R_B=B; later state = f(12) + R_B(6) + runtime points.');
  L.push(`contract ${VALIDATED ? 'MillerBatchBlsValidatedChunk' : 'MillerBatchBlsChunk'}() {`);
  L.push(`    function spend(${decl(stateParams)}, bytes unused zeroPadding) {`);
  L.push(covIn(stateParams));
  if (VALIDATED && opLo === 0) {
    for (const name of stagePtParams) L.push(`        require(within(${name}, 0, ${P}));`);
    L.push('        require(mSqr(Py0) == mAdd(mulFp(mSqr(Px0), Px0), 4));');
    L.push('        require(mSqr(Py3) == mAdd(mulFp(mSqr(Px3), Px3), 4));');
    L.push('        (int bx2a, int bx2b) = r2Sqr(Q0xa, Q0xb);');
    L.push('        (int bx3a, int bx3b) = r2Mul(bx2a, bx2b, Q0xa, Q0xb);');
    L.push('        (int rhsa, int rhsb) = r2Add(bx3a, bx3b, 4, 4);');
    L.push('        (int by2a, int by2b) = r2Sqr(Q0ya, Q0yb);');
    L.push('        require(by2a == rhsa); require(by2b == rhsb);');
  }
  // -Qy for any runtime-Q pair that does an add-line with digit -1 in this window
  const negY = PINFO.map((pi) => [pi.Qyae, pi.Qybe]);
  for (const pi of PINFO) {
    if (pi.cfg.Q) {
      const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
      negY[pi.j] = needs ? (() => { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe});`); return [`nq${pi.j}a`, `nq${pi.j}b`]; })() : [pi.Qyae, pi.Qybe];
    } else negY[pi.j] = [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
  }
  let f = opLo === 0 ? F_ONE_LIMBS.slice() : inF.slice();
  let r0 = opLo === 0
    ? [PINFO[0].Qxae, PINFO[0].Qxbe, PINFO[0].Qyae, PINFO[0].Qybe, '1', '0']
    : inR0.slice();
  let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const emitLine = (coeffs, pi) => { const g = fresh(12); L.push(`        (${decl(g)}) = line(${f.join(',')}, ${coeffs.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = g; };
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'cmul1') {
      const g = fresh(12); L.push(`        (${decl(g)}) = fp12Mul(${f.join(',')}, ${FAB_LIMBS.join(',')});`); f = g;
    }
    else if (op.t === 'dl') {
      if (!pi.cfg.Q) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const dco = fresh(6), dr = fresh(6);
      // Pairing-only does not consume the terminal R_B. Explicit unused sinks let its final
      // line stay in the tail chunk without adding a fake predicate or an extra state boundary.
      const discardR = final && !VALIDATED && !ops.slice(i + 1, opHi).some((next) => (next.t === 'dl' || next.t === 'al') && PINFO[next.j].cfg.Q);
      if (discardR) L.push(`        ${dr.map((name) => `int unused ${name} = 0;`).join(' ')}`);
      const drDecl = discardR ? dr.join(',') : decl(dr);
      L.push(`        (${decl(dco)},${drDecl}) = pointDouble(${r0.join(',')});`); r0 = dr;
      emitLine(dco, pi);
    } else { // al
      if (!pi.cfg.Q) { emitLine(bakedCoeffs(op.coeffs), pi); continue; }
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(6);
      // Same terminal-R case as pointDouble above (the last runtime op can be either kind).
      const discardR = final && !VALIDATED && !ops.slice(i + 1, opHi).some((next) => (next.t === 'dl' || next.t === 'al') && PINFO[next.j].cfg.Q);
      if (discardR) L.push(`        ${ar.map((name) => `int unused ${name} = 0;`).join(' ')}`);
      const arDecl = discardR ? ar.join(',') : decl(ar);
      L.push(`        (${decl(aco)},${arDecl}) = pointAdd(${r0.join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]});`); r0 = ar;
      emitLine(aco, pi);
    }
  }
  if (VALIDATED && final) {
    L.push(`        require(${r0[4]} != 0 || ${r0[5]} != 0);`);
    L.push('        (int psxa, int psxb, int psya, int psyb) = psi(Q0xa, Q0xb, Q0ya, Q0yb);');
    L.push('        (int npya, int npyb) = fp2Neg(psya, psyb);');
    L.push(`        (int exa, int exb) = r2Mul(psxa, psxb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(${r0[0]} == exa); require(${r0[1]} == exb);`);
    L.push(`        (int eya, int eyb) = r2Mul(npya, npyb, ${r0[4]}, ${r0[5]});`);
    L.push(`        require(${r0[2]} == eya); require(${r0[3]} == eyb);`);
  }
  let outF = f;
  if (final) { outF = f.slice(0, 6); for (let j = 6; j < 12; j++) { const nm = `cj${j}`; L.push(`        int ${nm} = subFp(0, ${f[j]});`); outF.push(nm); } }
  L.push(covOut(final ? outF : [...outF, ...r0, ...ptParams]));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- probe ----
if (process.argv[2] === 'probe') {
  for (const [a, b, fin] of [[0, 4, false], [0, 8, false], [ops.length - 9, ops.length, true], [ops.length - 4, ops.length, true]]) {
    const m = measureCovenantFile(genChunk(a, b, fin), inState(a), inState(a), outState(b, fin), PROBE);
    console.error(`ops [${a},${b}) final=${fin}: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

// ---- plan + emit ----
const measureWindow = (opLo, opHi, final, maxOp) => {
  const inL = inState(opLo);
  const outL = outState(opHi, final);
  const src = genChunk(opLo, opHi, final);
  const m = measureCovenantFile(src, inL, inL, outL, PROBE);
  return {
    fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= maxOp,
    operationCost: m.operationCost, hi: opHi, final, incoming: commit(inL),
    outgoing: commit(outL), src, m,
  };
};

// Reserve the widest consensus-fitting suffix for the dense fAB multiplication. A purely
// forward-greedy plan leaves cmul1 alone in a 31st input; the reverse tail scan fits the same
// work in 30 inputs while retaining >100k op-cost headroom.
let tailLo = ops.length - 1;
let tail = measureWindow(tailLo, ops.length, true, TAIL_OP_TARGET);
for (; tailLo > 0; tailLo--) {
  const wider = measureWindow(tailLo - 1, ops.length, true, TAIL_OP_TARGET);
  if (!wider.fits) break;
  tail = wider;
}
if (!tail.fits) throw new Error('no fitting prepared Miller tail');

console.error(`planning ${VALIDATED ? 'INPUT-VALIDATED ' : ''}PREPARED BLS Miller chunks (${ops.length} flat ops, final suffix [${tailLo},${ops.length}))  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < tailLo) {
  const best = planChunk(lo, tailLo, OP_TARGET, (hi) => measureWindow(lo, hi, false, OP_TARGET), planState);
  if (!best) throw new Error(`no fitting batched window at op ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `${PREFIX}_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: lo, opHi: best.hi, final: best.final, incoming: best.incoming, outgoing: best.outgoing, opCost: best.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  chunk ${idx}: ops[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
const tailIdx = chunks.length;
writeFileSync(join(GEN, `${PREFIX}_${String(tailIdx).padStart(2, '0')}.cash`), tail.src);
chunks.push({ idx: tailIdx, opLo: tailLo, opHi: ops.length, final: true, incoming: tail.incoming, outgoing: tail.outgoing, opCost: tail.operationCost, lockingBytes: tail.m.lockingBytes });
console.error(`  chunk ${tailIdx}: ops[${tailLo},${ops.length}) lock=${tail.m.lockingBytes}B op=${tail.operationCost.toLocaleString()} final=true`);
for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('continuity break at ' + i);
console.error(`batched miller: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.opCost, 0).toLocaleString()}, maxOp=${Math.max(...chunks.map((c) => c.opCost)).toLocaleString()}`);
writeFileSync(join(GEN, MANIFEST), JSON.stringify({
  batched: true, preparedVk: true, stageBound: true, genesisDerived: true,
  inputValidationFused: VALIDATED,
  precomputedPair: trace.precomputedPair, precomputedPairMiller: FAB_LIMBS,
  preparedG2Pairs: trace.preparedG2Pairs,
  preparedG2Points: trace.preparedG2Points.map((point) => point.map(String)),
  numPairs: 4, runtimeRs: 1, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(finalF).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error(`wrote generated/${MANIFEST}`);
