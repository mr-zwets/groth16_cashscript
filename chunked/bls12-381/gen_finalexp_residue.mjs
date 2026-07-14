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
//   node gen_finalexp_residue.mjs          covenant plan -> generated/
//   node gen_finalexp_residue.mjs linked   linked plan   -> generated/linked-residue/
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { measureCovenantFile, covIn, covOut, planChunk, commit, P, PUBLIC_INPUTS } from './_vkxmath.mjs';
import { pairsFor, millerBatchOps, Fp12 } from './_pairingmath.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf } from './_residuemath.mjs';
import { LINKED_RESIDUE_NAMESPACE, LINKED_TAIL_BOUNDS } from './_residue_linked_plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LINKED = process.argv[2] === 'linked';
const GEN = join(here, 'generated', ...(LINKED ? [LINKED_RESIDUE_NAMESPACE] : []));
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, '_probe_finalexpres.cash');
const LIB_IMPORT = LINKED
  ? '../../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash'
  : '../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash';
const Pstr = P.toString();
const ABS_X = 15132376222941642752n; // |x| MSB-preloaded walk constant (matches the lazy lib)
const NWALK = 63;
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_880_000);
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

// The finalize verdict body (assumes t/w/c/ci/fF locals in scope and `int P` declared): from the
// t=w^|x| accumulator, check ((t)*w)^9 == ONE, then c canonical + c*cInv == ONE + fF*w == frob(c,1).
// Shared by the standalone finalize chunk and the FUSE_FINAL walk+finalize chunk (byte-identical).
const finalizeLines = () => [
  `        (${tN.join(',')}) = fp12Mul(${tN.join(',')}, ${wN.join(',')});`,
  `        (${decl(names12('s'))}) = fp12Sqr(${tN.join(',')});`,
  `        (${names12('s').join(',')}) = fp12Sqr(${names12('s').join(',')});`,
  `        (${names12('s').join(',')}) = fp12Sqr(${names12('s').join(',')});`,
  `        (${names12('s').join(',')}) = fp12Mul(${names12('s').join(',')}, ${tN.join(',')});`,
  '        ' + eqOne('s'),
  '        ' + canon(cN),
  `        (${decl(names12('p'))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`,
  '        ' + eqOne('p'),
  `        (${decl(names12('lhs'))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`,
  `        (${decl(names12('rhs'))}) = fp12Frob1(${cN.join(',')});`,
  '        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '),
];

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
  for (const ln of finalizeLines()) L.push(ln);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// FUSE_FINAL: one TERMINAL chunk that does the w^|x| walk [lo,hi=NWALK) AND the finalize verdict
// inline (no covOut / no forward hand-off), collapsing the separate finalize input. Byte-identical
// walk loop + finalize body to the split path. Used by the LARGE (bch-spec) build where the whole
// walk fits one 88M-op input with the ~4M-op verdict to spare.
function genWalkFinal(lo, hi, first) {
  const params = first ? [...fFn, ...cN, ...ciN, ...wN] : [...fFn, ...cN, ...ciN, ...wN, ...names12('tin')];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// residue tail walk+finalize (FUSED, terminal): w^|x| iters [${lo},${hi}) then ((t)*w)^9==ONE, c*cInv==ONE, fF*w==frob(c,1).`);
  L.push('contract ResidueWalkFinalBls() {');
  L.push(`    function spend(${decl(params)}, bytes unused zeroPadding) {`);
  L.push(covIn(first ? [...fFn, ...cN, ...ciN] : [...fFn, ...cN, ...ciN, ...wN, ...names12('tin')]));
  L.push(`        int P = ${Pstr};`);
  if (first) { L.push('        ' + canon(wN)); L.push(`        ${tN.map((n, i) => `int ${n}=w${i};`).join(' ')}`); }
  else { L.push(`        ${tN.map((n, i) => `int ${n}=tin${i};`).join(' ')}`); }
  L.push(walkLoop(lo, hi));
  for (const ln of finalizeLines()) L.push(ln);
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

  if (LINKED && (LINKED_TAIL_BOUNDS[0] !== 0 || LINKED_TAIL_BOUNDS[LINKED_TAIL_BOUNDS.length - 1] !== NWALK ||
    LINKED_TAIL_BOUNDS.some((bound, i) => i > 0 && bound <= LINKED_TAIL_BOUNDS[i - 1]))) {
    throw new Error('invalid linked residue-tail boundaries');
  }
  console.error(`planning residue tail walk (${NWALK} iters) deployment=${LINKED ? 'linked' : 'covenant'} OP_TARGET=${OP_TARGET.toLocaleString()}`);
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
    const best = LINKED
      ? tryHi(LINKED_TAIL_BOUNDS[chunks.length + 1])
      : planChunk(lo, NWALK, OP_TARGET, tryHi, planState);
    if (!best) throw new Error(`no fitting walk window at ${lo}`);
    const idx = chunks.length;
    writeFileSync(join(GEN, `finalexpres_${String(idx).padStart(2, '0')}.cash`), best.src);
    chunks.push({ idx, role: 'walk', lo, hi: best.hi, final: false, incoming: commit(inCommit), outgoing: best.outgoing });
    console.error(`  walk chunk ${idx}: iters[${lo},${best.hi}) op=${best.operationCost.toLocaleString()} lock=${best.m.lockingBytes}B`);
    lo = best.hi;
  }
  if (LINKED || process.env.FUSE_FINAL === '1') {
    // Fold the finalize verdict into the LAST walk chunk (terminal), dropping the separate finalize
    // input. Fits only when the last walk window + ~4M-op verdict stay under OP_TARGET (the LARGE
    // bch-spec budget); errors otherwise so a too-tight fusion is caught, not silently mis-planned.
    const last = chunks[chunks.length - 1];
    const first = last.lo === 0;
    const src = genWalkFinal(last.lo, last.hi, first);
    const inPush = first ? [...commit36, ...wl] : state5At(last.lo);
    const inCommit = first ? commit36 : state5At(last.lo);
    const mF = measureCovenantFile(src, inPush, inCommit, [], PROBE); // terminal -> outLimbs []
    if (!LINKED && (!mF.accepted || mF.lockingBytes > BYTE_BUDGET || mF.operationCost > OP_TARGET))
      throw new Error(`FUSE_FINAL: fused walk+finalize does not fit (accepted=${mF.accepted} lock=${mF.lockingBytes} op=${mF.operationCost.toLocaleString()})`);
    writeFileSync(join(GEN, `finalexpres_${String(last.idx).padStart(2, '0')}.cash`), src);
    last.final = true; last.fused = true;
    console.error(`  FUSED walk+finalize chunk ${last.idx}: iters[${last.lo},${last.hi}) op=${mF.operationCost.toLocaleString()} lock=${mF.lockingBytes}B (finalize folded in, terminal)`);
    // negative: tamper fF -> the verdict fF*w==frob(c,1) fails -> reject
    const badPush = inPush.slice(); badPush[0] = badPush[0] + 1n;
    const badCommit = inCommit.slice(); badCommit[0] = badCommit[0] + 1n;
    if (!LINKED) console.error(`  fused finalize (tampered fF): accepted=${measureCovenantFile(src, badPush, badCommit, [], PROBE).accepted} (expect false)`);
  } else {
    // finalize chunk (separate terminal input)
    const fin = genFinalize();
    const fidx = chunks.length;
    writeFileSync(join(GEN, `finalexpres_${String(fidx).padStart(2, '0')}.cash`), fin);
    const inFin = state5At(NWALK);
    const mF = measureCovenantFile(fin, inFin, inFin, [], PROBE);
    chunks.push({ idx: fidx, role: 'finalize', final: true, incoming: commit(inFin) });
    console.error(`  finalize chunk ${fidx}: op=${mF.operationCost.toLocaleString()} lock=${mF.lockingBytes}B accepted=${mF.accepted} ${mF.error ?? ''}`);
    // negative: tamper fF in finalize verdict -> reject
    const badF = inFin.slice(); badF[0] = badF[0] + 1n;
    console.error(`finalize (tampered fF): accepted=${measureCovenantFile(fin, badF, badF, [], PROBE).accepted} (expect false)`);
  }
  for (let i = 1; i < chunks.length; i++) if (chunks[i - 1].outgoing !== chunks[i].incoming) throw new Error('tail continuity break at ' + i);
  writeFileSync(join(GEN, 'manifest_finalexpres.json'), JSON.stringify({
    residueTail: true, deployment: LINKED ? 'linked-hash-free' : 'covenant', numChunks: chunks.length, nwalk: NWALK,
    chunks: chunks.map((c) => ({ idx: c.idx, role: c.role, lo: c.lo ?? null, hi: c.hi ?? null, final: c.final, fused: c.fused ?? false })),
  }, null, 2));
  console.error(`residue tail: ${chunks.length} chunks`);
}
