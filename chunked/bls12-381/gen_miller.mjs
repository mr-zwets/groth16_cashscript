// Generator for the BCH-native, multi-transaction BATCHED BLS12-381 Miller loop.
// All 4 Groth16 pairs in ONE chain: f squared ONCE per NAF step (shared), then each
// pair's double-line (+ add-line when the digit is set) multiplied into the shared f;
// each pair's R evolves independently. Eliminates 3 of every 4 fp12Sqr vs four
// single-pair chains, and folds the 4 results so the conjugated f after the loop IS
// the boundary (NO separate combine step).
//
// One batched step is ~8 mul014 (~13M op) — too coarse for one BCH input — so the loop
// is treated as a FLAT op list (sqr / double-line / add-line) chunked at ANY op
// boundary, carrying state = f (12) + R0..R3 (24) + proof-derived points (per PT_CFG),
// hash256-committed (48-byte limbs). The FINAL chunk conjugates f (x<0).
//
//   node gen_miller.mjs            plan + emit miller_NN.cash + manifest_miller.json
//   node gen_miller.mjs probe      fast fixed-window op-cost probe
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, ATE_NAF, millerBatchOps, f12limbs, r6limbs, pairsFor, commit,
  measureCovenant, planChunk, covIn, covOut, PT_CFG, ptLimbs, fnExtractor, decl, lazyArith,
} from './_pairingmath.mjs';
import { PUBLIC_INPUTS } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const MILLER_CASH = join(here, '..', '..', 'singleton', 'bls12-381', 'miller.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

const ext = fnExtractor(MILLER_CASH);
// addFp/subFp are emitted LAZY (lazyArith) instead of extracted; mulFp + the rest reduce.
const BASE_FNS = ['mulFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2Scale', 'fp2MulXi', 'fp2MulByB', 'fp2Half', 'fp6Add', 'fp6Sub', 'fp6MulByV', 'fp6Mul', 'fp6Mul01', 'fp6Mul1', 'fp12Sqr', 'mul014', 'line', 'pointDouble', 'pointAdd'];

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

const { ops, states, finalF } = millerBatchOps(PAIRS);
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];
const withPts = (limbs) => [...limbs, ...ptL];
const inState = (i) => withPts(stateLimbs(states[i]));
// final output: conjugated f + final R's + points (full shape; build_vectors reads 12 f-limbs)
const finalLimbs = withPts([...f12limbs(finalF), ...states[ops.length].Rs.flatMap(r6limbs)]);
const outState = (i, final) => final ? finalLimbs : withPts(stateLimbs(states[i]));

function genChunk(opLo, opHi, final) {
  const fns = lazyArith() + '\n' + BASE_FNS.map(ext).join('\n');
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR = [0, 1, 2, 3].map((j) => [`R${j}xa`, `R${j}xb`, `R${j}ya`, `R${j}yb`, `R${j}za`, `R${j}zb`]);
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// GENERIC batched BLS12-381 Miller covenant chunk: ops [${opLo},${opHi}), final=${final}.`);
  L.push('// state = f(12) + R0..R3(24) [+ runtime points]; lives in the token NFT commitment.');
  L.push('contract MillerBatchBlsChunk() {');
  L.push(fns);
  L.push(`    function spend(${decl([...inF, ...inR.flat(), ...ptParams])}) {`);
  L.push(covIn([...inF, ...inR.flat(), ...ptParams]));
  // -Qy for any runtime-Q pair that does an add-line with digit -1 in this window
  const negY = PINFO.map((pi) => [pi.Qyae, pi.Qybe]);
  for (const pi of PINFO) {
    if (pi.cfg.Q) {
      const needs = ops.slice(opLo, opHi).some((o) => o.t === 'al' && o.neg && o.j === pi.j);
      negY[pi.j] = needs ? (() => { L.push(`        (int nq${pi.j}a,int nq${pi.j}b) = fp2Neg(${pi.Qyae}, ${pi.Qybe});`); return [`nq${pi.j}a`, `nq${pi.j}b`]; })() : [pi.Qyae, pi.Qybe];
    } else negY[pi.j] = [`${pi.negQ.c0}`, `${pi.negQ.c1}`];
  }
  let f = inF.slice(); const r = inR.map((a) => a.slice()); let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  for (let i = opLo; i < opHi; i++) {
    const op = ops[i], pi = op.j !== undefined ? PINFO[op.j] : null;
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'dl') {
      const dco = fresh(6), dr = fresh(6);
      L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r[op.j].join(',')});`); r[op.j] = dr;
      const gf = fresh(12); L.push(`        (${decl(gf)}) = line(${f.join(',')}, ${dco.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = gf;
    } else { // al
      const Y = op.neg ? negY[op.j] : [pi.Qyae, pi.Qybe];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r[op.j].join(',')}, ${pi.Qxae}, ${pi.Qxbe}, ${Y[0]}, ${Y[1]});`); r[op.j] = ar;
      const hf = fresh(12); L.push(`        (${decl(hf)}) = line(${f.join(',')}, ${aco.join(',')}, ${pi.Pxe}, ${pi.Pye});`); f = hf;
    }
  }
  let outF = f;
  if (final) { outF = f.slice(0, 6); for (let j = 6; j < 12; j++) { const nm = `cj${j}`; L.push(`        int ${nm} = subFp(0, ${f[j]});`); outF.push(nm); } }
  L.push(covOut([...outF, ...r.flat(), ...ptParams]));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- probe ----
if (process.argv[2] === 'probe') {
  for (const [a, b, fin] of [[0, 4, false], [0, 8, false], [ops.length - 4, ops.length, true]]) {
    const m = measureCovenant(genChunk(a, b, fin), inState(a), outState(b, fin));
    console.error(`ops [${a},${b}) final=${fin}: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`);
  }
  process.exit(0);
}

// ---- plan + emit ----
console.error(`planning BATCHED BLS Miller chunks (${ops.length} flat ops)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ops.length) {
  const inL = inState(lo);
  const tryHi = (hi) => {
    const final = hi === ops.length;
    const outL = outState(hi, final);
    const src = genChunk(lo, hi, final);
    const m = measureCovenant(src, inL, outL);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, final, outgoing: commit(outL), src, m };
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
  batched: true, numPairs: 4, numOps: ops.length, numChunks: chunks.length, boundary: f12limbs(finalF).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, outgoing: c.outgoing })),
}, null, 2));
console.error('wrote generated/manifest_miller.json');
