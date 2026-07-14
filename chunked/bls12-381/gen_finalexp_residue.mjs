// Generator for the witnessed-residue final-exponentiation tail (BLS12-381,
// ePrint 2024/640 adapted). The fused Miller boundary is
//
//   fF = g * c^-|x|,
//
// so the terminal relation is fF*w == frob(c, 1). The witness construction
// produces w in the embedded Fp6*: its upper six Fp12 limbs are zero. This is
// sufficient for soundness because p^6-1 divides h=(p^12-1)/r, so every
// nonzero Fp6 element has order dividing h. c*cInv == ONE and the terminal
// equality exclude zero without a separate w inverse.
//
//   node gen_finalexp_residue.mjs          covenant layout -> generated/
//   node gen_finalexp_residue.mjs linked   linked layout   -> generated/linked-residue/
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { measureCovenantFile, covIn, P, PUBLIC_INPUTS } from './_vkxmath.mjs';
import { pairsFor, millerBatchOps, Fp12 } from './_pairingmath.mjs';
import {
  frob, mk12, residueWitness, millerFusedOps, fp12limbsOf,
} from './_residuemath.mjs';
import { LINKED_RESIDUE_NAMESPACE } from './_residue_linked_plan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LINKED = process.argv[2] === 'linked';
const COVENANT_RESIDUE = !LINKED && process.env.COVENANT_RESIDUE_LAYOUT === '1';
const GEN = join(here, 'generated', ...(LINKED ? [LINKED_RESIDUE_NAMESPACE] : []));
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, '_probe_finalexpres.cash');
const LIB_IMPORT = LINKED
  ? '../../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash'
  : '../../../singleton/bls12-381/lib/lazy/Bls12381LazyG.cash';
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_880_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

const decl = (names) => names.map((name) => `int ${name}`).join(', ');
const names12 = (prefix) => Array.from({ length: 12 }, (_, i) => `${prefix}${i}`);
const fFn = names12('fF');
const cN = names12('c');
const ciN = names12('ci');
const wN = names12('w');
const canon = (names) => names.map((name) => `require(within(${name}, 0, P));`).join(' ');
const eqOne = (prefix) => Array.from(
  { length: 12 },
  (_, i) => `require(${prefix}${i} % P == ${i === 0 ? 1 : 0});`,
).join(' ');

function genFinalize() {
  const lines = [
    'pragma cashscript ^0.14.0;',
    `import "${LIB_IMPORT}";`,
    '// Terminal residue verdict: w in Fp6*, c*cInv == ONE, fF*w == frob(c,1).',
    'contract ResidueFinalizeBls() {',
    `    function spend(${decl([...fFn, ...cN, ...ciN, ...wN])}, bytes unused zeroPadding) {`,
    covIn([...fFn, ...cN, ...ciN]),
    `        int P = ${P};`,
    `        ${canon(cN)}`,
    `        ${canon(wN)}`,
    `        ${wN.slice(6).map((name) => `require(${name} == 0);`).join(' ')}`,
    `        (${decl(names12('p'))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`,
    `        ${eqOne('p')}`,
    `        (${decl(names12('lhs'))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`,
    `        (${decl(names12('rhs'))}) = fp12Frob1(${cN.join(',')});`,
    `        ${Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' ')}`,
    '    }',
    '}',
  ];
  return `${lines.join('\n')}\n`;
}

if (process.argv[1] && process.argv[1].endsWith('gen_finalexp_residue.mjs')) {
  const pairs = pairsFor(PUBLIC_INPUTS);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const fF = millerFusedOps(pairs, c, cInv).boundary;
  const fFl = fp12limbsOf(fF);
  const cl = fp12limbsOf(c);
  const cil = fp12limbsOf(cInv);
  const wl = fp12limbsOf(w);
  const commit36 = [...fFl, ...cl, ...cil];
  const source = genFinalize();
  const measurement = measureCovenantFile(
    source,
    [...commit36, ...wl],
    commit36,
    [],
    PROBE,
  );
  if (!measurement.accepted || measurement.lockingBytes > BYTE_BUDGET || measurement.operationCost > OP_TARGET) {
    throw new Error(
      `residue Fp6 verdict does not fit (accepted=${measurement.accepted} ` +
      `lock=${measurement.lockingBytes} op=${measurement.operationCost.toLocaleString()})`,
    );
  }

  const file = join(GEN, 'finalexpres_00.cash');
  writeFileSync(file, source);
  console.error(
    `  Fp6 residue verdict: op=${measurement.operationCost.toLocaleString()} ` +
    `lock=${measurement.lockingBytes}B accepted=${measurement.accepted}`,
  );

  const badF = [...commit36];
  badF[0] += 1n;
  const badFMeasurement = measureCovenantFile(source, [...badF, ...wl], badF, [], PROBE);
  if (badFMeasurement.accepted) throw new Error('tampered fF passed the residue verdict');
  console.error('  tampered fF rejected');

  for (let upper = 0; upper < 6; upper++) {
    const hi = Array(6).fill(0n);
    hi[upper] = 1n;
    const wBad = mk12([1n, 0n, 0n, 0n, 0n, 0n], hi);
    const fFBad = Fp12.mul(frob(c, 1), Fp12.inv(wBad));
    const badCommit = [...fp12limbsOf(fFBad), ...cl, ...cil];
    const badW = fp12limbsOf(wBad);
    const badMeasurement = measureCovenantFile(
      source,
      [...badCommit, ...badW],
      badCommit,
      [],
      PROBE,
    );
    if (badMeasurement.accepted) throw new Error(`non-Fp6 w limb ${upper + 6} passed the residue verdict`);
    console.error(`  non-Fp6 w limb ${upper + 6} rejected with matching tail relation`);
  }

  writeFileSync(join(GEN, 'manifest_finalexpres.json'), JSON.stringify({
    residueTail: true,
    fp6Membership: true,
    deployment: LINKED ? 'linked-hash-free' : 'covenant',
    covenantResidue: COVENANT_RESIDUE,
    numChunks: 1,
    nwalk: 0,
    chunks: [{ idx: 0, role: 'finalize', final: true, upperZeroLimbs: [6, 7, 8, 9, 10, 11] }],
  }, null, 2));
  console.error('residue tail: 1 chunk');
}
