// Generator for the witnessed-residue final-exponentiation TAIL (BLS12-381, ePrint 2024/640
// adapted) — replaces the 23-chunk hard-part final exponentiation with a HANDFUL of cheap chunks.
// The fused Miller already folded c^-|x| and multiplied in fAB, so the boundary handed off is the
// UNCONJUGATED fF = g * c^-|x|. The tail reproduces the verified lazy-lib `residueVerdict` body
// (singleton/bls12-381/lib/lazy/Bls12381LazyG.cash). Each lazy fp12 op is ~235K op-cost, so the
// 63-iteration ((w^|x|)*w)^9 mu_(27A) walk (~15M) plus the verdict cannot fit one 8.03M-budget
// input; it is op-budget-planned into WALK chunks (each forwarding the running accumulator t)
// followed by a terminal FINALIZE chunk:
//   walk chunk k:  w^|x| walk iters [lo,hi); forwards [fF,c,cInv,w,t].
//   finalize:      t=w^|x| -> ((t)*w)^9 == ONE, then c canonical + c*cInv == ONE +
//                  verdict fF*w == frob(c,1)  (terminal).
// State from the fused Miller: fF(12), c(12), cInv(12). w(12) enters as an uncommitted witness in
// the first walk chunk and is committed forward (with t) thereafter. lambda = p + |x|.
//   node gen_finalexp_residue.mjs   emit finalexpres_NN.cash + manifest_finalexpres.json
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { measureCovenantFile, covIn, covOut, planChunk, commit, P, PUBLIC_INPUTS } from './_vkxmath.mjs';
import { pairsFor, millerBatchOps, Fp12 } from './_pairingmath.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf } from './_residuemath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, '_probe_finalexpres.cash');
const LIB_IMPORT = '../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash';
const Pstr = P.toString();
const ABS_X = 15132376222941642752n; // |x| MSB-preloaded walk constant (matches the lazy lib)
const NWALK = 63;
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

const decl = (names) => names.map((n) => `int ${n}`).join(', ');
const names12 = (p) => Array.from({ length: 12 }, (_, i) => `${p}${i}`);
const fFn = names12('fF'), cN = names12('c'), ciN = names12('ci'), wN = names12('w'), tN = names12('t');
const eqOne = (p) => Array.from({ length: 12 }, (_, i) => `require(${p}${i} % P == ${i === 0 ? 1 : 0});`).join(' ');
const canon = (names) => names.map((n) => `require(${n} < P);`).join(' ');
const STATE5 = [...fFn, ...cN, ...ciN, ...wN, ...tN]; // 60 forwarded limbs (t = running w^partial)

const walkLoop = (lo, hi) =>
  `        for (int wi = ${lo}; wi < ${hi}; wi = wi + 1) {\n` +
  `            (${tN.join(',')}) = fp12Sqr(${tN.join(',')});\n` +
  `            if (((${ABS_X} >> (62 - wi)) % 2) == 1) {\n` +
  `                (${tN.join(',')}) = fp12Mul(${tN.join(',')}, ${wN.join(',')});\n` +
  '            }\n' +
  '        }';

// walk chunk [lo,hi). first (lo==0): covIn [fF,c,cInv] (36) + w witness, t=w. else: covIn STATE5 (60).
function genWalk(lo, hi) {
  const first = lo === 0;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// residue tail walk: w^|x| iterations [${lo},${hi}); forwards [fF,c,cInv,w,t].`);
  L.push('contract ResidueWalkBls() {');
  const params = first ? [...fFn, ...cN, ...ciN, ...wN] : STATE5;
  L.push(`    function spend(${decl(params)}, bytes unused zeroPadding) {`);
  L.push(covIn(first ? [...fFn, ...cN, ...ciN] : STATE5));
  L.push(`        int P = ${Pstr};`);
  if (first) { L.push('        ' + canon(wN)); L.push(`        ${tN.map((n, i) => `int ${n}=w${i};`).join(' ')}`); }
  else { L.push(`        ${tN.map((n) => `int ${n}=${n}in;`).join(' ')}`); } // rename param tin -> local t
  L.push(walkLoop(lo, hi));
  L.push(covOut(STATE5));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
// non-first walk chunks take t as `tin` params (params can't be reassigned in the loop)
function genWalkNonFirst(lo, hi) {
  const params = [...fFn, ...cN, ...ciN, ...wN, ...names12('tin')];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// residue tail walk: w^|x| iterations [${lo},${hi}); forwards [fF,c,cInv,w,t].`);
  L.push('contract ResidueWalkBls() {');
  L.push(`    function spend(${decl(params)}, bytes unused zeroPadding) {`);
  L.push(covIn([...fFn, ...cN, ...ciN, ...wN, ...names12('tin')]));
  L.push(`        ${tN.map((n, i) => `int ${n}=tin${i};`).join(' ')}`);
  L.push(walkLoop(lo, hi));
  L.push(covOut(STATE5));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// finalize: t=w^|x| in, ((t)*w)^9 == ONE, then c*cInv==ONE + verdict fF*w==frob(c,1). terminal.
function genFinalize() {
  const params = [...fFn, ...cN, ...ciN, ...wN, ...names12('tin')];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push('// residue tail finalize: ((w^|x|)*w)^9 == ONE, c*cInv == ONE, fF*w == frob(c,1).');
  L.push('contract ResidueFinalizeBls() {');
  L.push(`    function spend(${decl(params)}, bytes unused zeroPadding) {`);
  L.push(covIn([...fFn, ...cN, ...ciN, ...wN, ...names12('tin')]));
  L.push(`        int P = ${Pstr};`);
  L.push(`        ${tN.map((n, i) => `int ${n}=tin${i};`).join(' ')}`);
  L.push(`        (${tN.join(',')}) = fp12Mul(${tN.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(names12('s'))}) = fp12Sqr(${tN.join(',')});`);
  L.push(`        (${names12('s').join(',')}) = fp12Sqr(${names12('s').join(',')});`);
  L.push(`        (${names12('s').join(',')}) = fp12Sqr(${names12('s').join(',')});`);
  L.push(`        (${names12('s').join(',')}) = fp12Mul(${names12('s').join(',')}, ${tN.join(',')});`);
  L.push('        ' + eqOne('s'));
  L.push('        ' + canon(cN));
  L.push(`        (${decl(names12('p'))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  L.push('        ' + eqOne('p'));
  L.push(`        (${decl(names12('lhs'))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(names12('rhs'))}) = fp12Frob1(${cN.join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// JS replay of the walk accumulator t after `upto` iterations (for planning + build vectors).
export function residueWalkT(w, upto) {
  let t = w;
  for (let wi = 0; wi < upto; wi++) { t = Fp12.sqr(t); if (((ABS_X >> BigInt(62 - wi)) & 1n) === 1n) t = Fp12.mul(t, w); }
  return t;
}

if (process.argv[1] && process.argv[1].endsWith('gen_finalexp_residue.mjs')) {
  const pairs = pairsFor(PUBLIC_INPUTS);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const fused = millerFusedOps(pairs, c, cInv);
  const fFl = fp12limbsOf(fused.boundary), cl = fp12limbsOf(c), cil = fp12limbsOf(cInv), wl = fp12limbsOf(w);
  const commit36 = [...fFl, ...cl, ...cil];
  const state5At = (upto) => [...fFl, ...cl, ...cil, ...wl, ...fp12limbsOf(residueWalkT(w, upto))];

  console.error(`planning residue tail walk (${NWALK} iters)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
  const chunks = []; let lo = 0; const planState = { perUnit: null };
  while (lo < NWALK) {
    const first = lo === 0;
    const inPush = first ? [...commit36, ...wl] : state5At(lo);
    const inCommit = first ? commit36 : state5At(lo);
    const tryHi = (hi) => {
      const src = first ? genWalk(lo, hi) : genWalkNonFirst(lo, hi);
      const out = state5At(hi);
      const m = measureCovenantFile(src, inPush, inCommit, out, PROBE);
      return { hi, src, m, outgoing: commit(out), fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost };
    };
    const best = planChunk(lo, NWALK, OP_TARGET, tryHi, planState);
    if (!best) throw new Error(`no fitting walk window at ${lo}`);
    const idx = chunks.length;
    writeFileSync(join(GEN, `finalexpres_${String(idx).padStart(2, '0')}.cash`), best.src);
    chunks.push({ idx, role: 'walk', lo, hi: best.hi, final: false, incoming: commit(inCommit), outgoing: best.outgoing });
    console.error(`  walk chunk ${idx}: iters[${lo},${best.hi}) op=${best.operationCost.toLocaleString()} lock=${best.m.lockingBytes}B`);
    lo = best.hi;
  }
  // finalize chunk
  const fin = genFinalize();
  const fidx = chunks.length;
  writeFileSync(join(GEN, `finalexpres_${String(fidx).padStart(2, '0')}.cash`), fin);
  const inFin = state5At(NWALK);
  const mF = measureCovenantFile(fin, inFin, inFin, [], PROBE);
  chunks.push({ idx: fidx, role: 'finalize', final: true, incoming: commit(inFin) });
  console.error(`  finalize chunk ${fidx}: op=${mF.operationCost.toLocaleString()} lock=${mF.lockingBytes}B accepted=${mF.accepted} ${mF.error ?? ''}`);
  for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('tail continuity break at ' + i);
  writeFileSync(join(GEN, 'manifest_finalexpres.json'), JSON.stringify({
    residueTail: true, numChunks: chunks.length, nwalk: NWALK,
    chunks: chunks.map((c) => ({ idx: c.idx, role: c.role, lo: c.lo ?? null, hi: c.hi ?? null, final: c.final })),
  }, null, 2));
  console.error(`residue tail: ${chunks.length} chunks (${chunks.length - 1} walk + 1 finalize)`);
  // negative: tamper fF in finalize verdict -> reject
  const badF = inFin.slice(); badF[0] = badF[0] + 1n;
  console.error(`finalize (tampered fF): accepted=${measureCovenantFile(fin, badF, badF, [], PROBE).accepted} (expect false)`);
}
