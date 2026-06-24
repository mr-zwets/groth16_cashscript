// Generator for the BCH-native, multi-transaction BLS12-381 FINAL EXPONENTIATION
// f^((p^12-1)/r), taking the chunked pairing from the Miller boundary to the verdict.
// finalExp is traced (in _pairingmath) as an SSA op-DAG of Fp12 primitives
// (cyc=cycSqr, mul, conj, frob1/2/3, inv); the 5 cyclotomic-exp ladders over |x|
// unroll into cyc/mul ops. Liveness carries only the LIVE Fp12 values across chunk
// boundaries as hash256-committed state (48-byte limbs); chunks are planned by
// measured real-VM op-cost. The last chunk asserts the result == Fp12 ONE (verdict).
//
//   node gen_finalexp.mjs          plan + emit -> generated/finalexp_NN.cash + manifest
//   node gen_finalexp.mjs probe    feasibility probe (function-set + a few op-costs)
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, finalexpTrace, boundaryFor, pairsFor, planChunk,
  commit, f12limbs, decl, covIn, covOut,
} from './_pairingmath.mjs';
import { measureCovenantFile } from './_vkxmath.mjs';
import { PUBLIC_INPUTS } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, `_probe_finalexp_${process.pid}.cash`); // compile candidates from file so the lib import resolves
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

// The lazy tower comes from the shared lazy library (imported per chunk; cashc tree-shakes the
// unused inverse fns). Replaces the old fnExtractor-from-singleton + lazyArith, which broke when
// the singleton migrated those functions into its (non-lazy) library layout.
const LIB_IMPORT = '../../../singleton/bls12-381/lib/lazy/Bls12381Lazy.cash';
const OP_FN = { cyc: 'cycSqr', mul: 'fp12Mul', conj: 'fp12Conj', f1: 'fp12Frob1', f2: 'fp12Frob2', f3: 'fp12Frob3', inv: 'fp12Inv' };

// boundary (combine output) = noble pre-final-exp product
const boundaryVal = boundaryFor(pairsFor(PUBLIC_INPUTS).map((p) => ({ g1: p.P, g2: p.Q })));
const tr = finalexpTrace(boundaryVal);
const { ops, liveAt, resultId } = tr;
console.error(`traced ${ops.length} ops; finalExp(boundary) computed`);

const vnames = (id) => Array.from({ length: 12 }, (_, j) => `w${id}_${j}`);
const limbsOf = (id) => tr.limbs12(id).map(String);

// emit a chunk for ops [s,e). last chunk (e==ops.length) asserts result==ONE.
// An `inv` op is verified by a WITNESS: f^-1 is pushed UNCOMMITTED in the unlocking
// and checked with one fp12Mul(f, f^-1)==ONE (the 381-iter Fermat inverse on-chain
// would alone exceed one input's op-cost budget). The committed live state is hashed
// by covIn; the inverse witnesses are appended after it (decl order: committed, then
// witnesses) and pushed in the unlocking but NOT committed.
function buildChunkSrc(s, e) {
  const liveIn = liveAt(s);
  const isLast = e === ops.length;
  const liveOut = isLast ? [] : liveAt(e);
  const inLimbs = liveIn.flatMap(limbsOf).map(BigInt);
  const committedParams = liveIn.flatMap(vnames);
  const name = new Map(); liveIn.forEach((id) => name.set(id, vnames(id)));
  const witnessParams = [], witnessLimbs = [];
  let uid = 0; const fresh = () => Array.from({ length: 12 }, () => `t${uid++}`);
  const body = [];
  const hasInv = (() => { for (let i = s; i < e; i++) if (ops[i].op === 'inv') return true; return false; })();
  // lazy add leaves fp12Mul outputs unreduced, so equality vs ONE must compare mod the
  // prime. Named iP (not P) to avoid colliding with covOut's own `int P` declaration.
  if (hasInv) body.push(`        int iP = ${P};`);
  for (let i = s; i < e; i++) {
    const o = ops[i];
    const argVars = o.args.flatMap((a) => name.get(a));
    if (o.op === 'inv') {
      const iv = Array.from({ length: 12 }, (_, j) => `iv${o.id}_${j}`);
      witnessParams.push(...iv); witnessLimbs.push(...limbsOf(o.id).map(BigInt));
      const chk = fresh();
      body.push(`        (${decl(chk)}) = fp12Mul(${argVars.join(',')}, ${iv.join(',')});`);
      body.push(`        require(${chk[0]} % iP == 1); ` + Array.from({ length: 11 }, (_, j) => `require(${chk[j + 1]} % iP == 0);`).join(' '));
      name.set(o.id, iv);
    } else {
      const out = fresh();
      body.push(`        (${decl(out)}) = ${OP_FN[o.op]}(${argVars.join(',')});`);
      name.set(o.id, out);
    }
  }
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// BLS12-381 final-exp chunk ops [${s},${e})  final=${isLast}`);
  L.push('contract FinalExpBlsChunk() {');
  L.push(`    function spend(${decl([...committedParams, ...witnessParams])}, bytes unused zeroPadding) {`);
  L.push(covIn(committedParams)); // ONLY the committed live state is in the NFT commitment
  L.push(...body);
  if (isLast) {
    const rv = name.get(resultId);
    L.push(`        int P = ${P};`);
    L.push(`        require(${rv[0]} % P == 1); ` + Array.from({ length: 11 }, (_, j) => `require(${rv[j + 1]} % P == 0);`).join(' '));
  } else {
    L.push(covOut(liveOut.flatMap((id) => name.get(id))));
  }
  L.push('    }');
  L.push('}');
  const outLimbs = isLast ? [] : liveOut.flatMap(limbsOf).map(BigInt);
  return { src: L.join('\n') + '\n', inLimbs, witnessLimbs, outLimbs, incoming: commit(liveIn.flatMap(limbsOf)), isLast };
}

const measureChunk = (c) => measureCovenantFile(c.src, [...c.inLimbs, ...c.witnessLimbs], c.inLimbs, c.outLimbs, PROBE);

// ---- probe ----
if (process.argv[2] === 'probe') {
  for (const e of [1, 2, 3, 5]) { const c = buildChunkSrc(0, e); const m = measureChunk(c); console.error(`ops[0,${e}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`); }
  process.exit(0);
}

// ---- plan + emit ----
console.error(`planning BLS final-exp chunks  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let s = 0; const planState = { perUnit: null };
while (s < ops.length) {
  const tryAt = (e) => {
    const c = buildChunkSrc(s, e);
    const m = measureChunk(c);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, ...c, m };
  };
  const best = planChunk(s, ops.length, OP_TARGET, tryAt, planState);
  if (!best) throw new Error(`no fitting final-exp window at op ${s}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `finalexp_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: s, opHi: best.hi, incoming: best.incoming, final: best.isLast, lockingBytes: best.m.lockingBytes, operationCost: best.m.operationCost });
  console.error(`  chunk ${idx}: ops[${s},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.isLast}`);
  s = best.hi;
}
console.error(`final-exp: ${chunks.length} chunks, total op=${chunks.reduce((a, c) => a + c.operationCost, 0).toLocaleString()}, max=${Math.max(...chunks.map((c) => c.operationCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_finalexp.json'), JSON.stringify({
  numChunks: chunks.length, numOps: ops.length, boundary: f12limbs(boundaryVal).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming })),
}, null, 2));
console.error('wrote generated/manifest_finalexp.json');
