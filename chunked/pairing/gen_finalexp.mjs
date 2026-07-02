// Generator for the BCH-limit-viable, multi-transaction FINAL EXPONENTIATION
// f^((p^12-1)/r), taking the chunked pairing from the Miller boundary (cp#2) to
// the verdict (cp#3). finalExp is traced as an SSA op-DAG of Fp12 primitives
// (cyc=cyclotomicSquare, mul, conj, frob1/2/3, inv); the three 63-bit cyclotomic-
// exp ladders unroll into cyc/mul ops exactly like the Miller NAF loop. Liveness
// analysis carries only the LIVE Fp12 values across chunk boundaries as
// hash256-committed state (40-byte LE limbs), and chunks are planned by measured
// real-VM op-cost. The last chunk asserts the result == Fp12 ONE (the verdict).
//
//   node gen_finalexp.mjs          full plan + emit -> generated/finalexp_NN.cash + manifest_finalexp.json
//   node gen_finalexp.mjs probe    feasibility: function-set size + a few op-costs
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, Fp2, bn254, vec, measureCovenantFile, planChunk, commit, f12limbs, decl, covIn, covOut, compileFileBytecode,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, `_probe_${process.pid}.cash`);
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_900_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const BN_X = 4965661367192848881n;
const X_LEN = 63;

// Tower/pairing functions come from the shared singleton library; each chunk imports it (cashc
// tree-shakes the unused half). Matches gen_miller.mjs — and tracks the singleton's library
// migration, which moved these out of finalexp.cash (so fnExtractor-inlining no longer resolves).
const LIB_IMPORT = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const OP_FN = { cyc: 'cycSqr', mul: 'fp12Mul', conj: 'fp12Conj', f1: 'fp12Frob1', f2: 'fp12Frob2', f3: 'fp12Frob3', inv: 'fp12Inv' };

// ---- trace finalExp as an op list (values computed with noble) ----
const ops = []; let nextId = 0;
const V = (val) => ({ id: nextId++, val });
const rec = (op, args, val) => { const v = V(val); ops.push({ id: v.id, op, args: args.map((a) => a.id), val }); return v; };
const cyc = (a) => rec('cyc', [a], Fp12._cyclotomicSquare(a.val));
const mul = (a, b) => rec('mul', [a, b], Fp12.mul(a.val, b.val));
const conj = (a) => rec('conj', [a], Fp12.conjugate(a.val));
const f1 = (a) => rec('f1', [a], Fp12.frobeniusMap(a.val, 1));
const f2 = (a) => rec('f2', [a], Fp12.frobeniusMap(a.val, 2));
const f3 = (a) => rec('f3', [a], Fp12.frobeniusMap(a.val, 3));
const inv = (a) => rec('inv', [a], Fp12.inv(a.val));
function cycExp(numV) { let z = numV; for (let i = X_LEN - 2; i >= 0; i--) { z = cyc(z); if ((BN_X >> BigInt(i)) & 1n) z = mul(z, numV); } return z; }
const powMinusX = (xV) => conj(cycExp(xV));
function traceFinalExp(fV) {
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
  return mul(left, right);
}

// boundary (combine output) = noble pre-final-exp product
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
let vkx = vk.ic[0]; vec.publicInputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
const boundaryVal = bn254.pairingBatch([{ g1: proof.a.negate(), g2: proof.b }, { g1: vk.alpha, g2: vk.beta }, { g1: vkx, g2: vk.gamma }, { g1: proof.c, g2: vk.delta }], false);
const boundary = V(boundaryVal); // id 0, leaf (no op)
const result = traceFinalExp(boundary);
if (!Fp12.eql(result.val, Fp12.ONE)) throw new Error('traced finalExp(boundary) != ONE (valid instance should verify)');
console.error(`traced ${ops.length} ops; finalExp(boundary)==ONE OK`);

// value table + liveness
const valOf = new Map([[0, boundaryVal]]); for (const o of ops) valOf.set(o.id, o.val);
const def = new Map([[0, -1]]); ops.forEach((o, i) => def.set(o.id, i));
const lastUse = new Map(); ops.forEach((o, i) => o.args.forEach((a) => lastUse.set(a, i)));
lastUse.set(result.id, ops.length); // result used by the verdict
const liveAt = (cut) => [...def.keys()].filter((id) => def.get(id) < cut && (lastUse.get(id) ?? -1) >= cut).sort((a, b) => a - b);

const vnames = (id) => Array.from({ length: 12 }, (_, j) => `w${id}_${j}`);
const limbsOf = (id) => f12limbs(valOf.get(id)).map(String);

// emit a chunk for ops [s,e). last chunk (e==ops.length) asserts result==ONE.
function buildChunkSrc(s, e) {
  const liveIn = liveAt(s);
  const isLast = e === ops.length;
  const liveOut = isLast ? [] : liveAt(e);
  const inLimbs = liveIn.flatMap(limbsOf).map(BigInt);
  const incoming = commit(liveIn.flatMap(limbsOf));
  const params = liveIn.flatMap(vnames);
  const name = new Map(); liveIn.forEach((id) => name.set(id, vnames(id)));
  let uid = 0; const fresh = () => Array.from({ length: 12 }, () => `t${uid++}`);
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// final-exp chunk ops [${s},${e})  final=${isLast}`);
  L.push('contract FinalExpChunk() {');
  L.push(`    function spend(${decl(params)}, bytes unused zeroPadding) {`);
  L.push(covIn(liveIn.flatMap(vnames))); // incoming live state == spent token commitment
  for (let i = s; i < e; i++) {
    const o = ops[i];
    const argVars = o.args.flatMap((a) => name.get(a));
    const out = fresh();
    L.push(`        (${decl(out)}) = ${OP_FN[o.op]}(${argVars.join(',')});`);
    name.set(o.id, out);
  }
  if (isLast) {
    // terminal verdict: result == Fp12 ONE (no output token; the thread ends here)
    const rv = name.get(result.id);
    L.push('        int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
    L.push(`        require(${rv[0]} % P == 1); ` + Array.from({ length: 11 }, (_, j) => `require(${rv[j + 1]} % P == 0);`).join(' '));
  } else {
    // outgoing live state (lazy, reduced %P) committed to output[0]'s NFT commitment
    L.push(covOut(liveOut.flatMap((id) => name.get(id))));
  }
  L.push('    }');
  L.push('}');
  const outLimbs = isLast ? [] : liveOut.flatMap(limbsOf).map(BigInt);
  return { src: L.join('\n') + '\n', inLimbs, outLimbs, incoming, isLast };
}

// ---------- probe ----------
if (process.argv[2] === 'probe') {
  const fnOnly = `pragma cashscript ^0.14.0;\nimport "${LIB_IMPORT}";\ncontract P(){\n    function spend(int x){ require(x==x); }\n}\n`;
  writeFileSync(PROBE, fnOnly);
  console.error('function-set size:', compileFileBytecode(PROBE).length);
  for (const e of [1, 2, 3, 5]) { const c = buildChunkSrc(0, e); const m = measureCovenantFile(c.src, c.inLimbs, c.outLimbs, PROBE); console.error(`ops[0,${e}): lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted} ${m.error ?? ''}`); }
  try { execFileSync('rm', [PROBE]); } catch {}
  process.exit(0);
}

// ---------- plan + emit (predict-and-adjust by measured op-cost) ----------
console.error(`planning final-exp chunks  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let s = 0; const planState = { perUnit: null };
while (s < ops.length) {
  const tryAt = (e) => {
    const c = buildChunkSrc(s, e);
    const m = measureCovenantFile(c.src, c.inLimbs, c.outLimbs, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, ...c, m };
  };
  const best = planChunk(s, ops.length, OP_TARGET, tryAt, planState);
  const idx = chunks.length;
  writeFileSync(join(GEN, `finalexp_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, opLo: s, opHi: best.hi, incoming: best.incoming, final: best.isLast, incomingLimbs: best.inLimbs.map(String), lockingBytes: best.m.lockingBytes, operationCost: best.m.operationCost });
  console.error(`  chunk ${idx}: ops[${s},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.isLast}`);
  s = best.hi;
}
console.error(`final-exp: ${chunks.length} chunks, total op=${chunks.reduce((a, c) => a + c.operationCost, 0).toLocaleString()}, max=${Math.max(...chunks.map((c) => c.operationCost)).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_finalexp.json'), JSON.stringify({
  numChunks: chunks.length, numOps: ops.length, boundary: f12limbs(boundaryVal).map(String),
  chunks: chunks.map((c) => ({ idx: c.idx, opLo: c.opLo, opHi: c.opHi, final: c.final, incoming: c.incoming, incomingLimbs: c.incomingLimbs })),
}, null, 2));
