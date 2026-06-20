// CHECKPOINT #3: grade singleton/bls12-381/finalexp.cash against noble
// Fp12.finalExponentiate on the loosened BCH 2026 VM. Inputs: a random Fp12, the
// VALID Groth16 Miller boundary (-> Fp12.ONE, i.e. proof verifies), and an INVALID
// boundary (tampered public input -> != ONE). Run: node singleton/bls12-381/finalexp.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';
import { bls12_381, Fp12, vkx, grothPairs, boundaryFor, computeVkx, PUBLIC_INPUTS, f12 } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));

const valid = boundaryFor(grothPairs(vkx));
const tampered = [PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]];
const invalid = boundaryFor(grothPairs(computeVkx(tampered)));

const rng = splitmix64(0x66657870n); // "fexp"
const rand = Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));

const inputs = [
  { label: 'random', f: rand },
  { label: 'valid boundary', f: valid },
  { label: 'invalid boundary', f: invalid },
];
const vectors = inputs.map(({ f }) => [...f12(f), ...f12(Fp12.finalExponentiate(f))]);

// sanity: confirm the verdicts before running on-chain
console.log('valid finalExp == ONE   :', Fp12.eql(Fp12.finalExponentiate(valid), Fp12.ONE));
console.log('invalid finalExp != ONE :', !Fp12.eql(Fp12.finalExponentiate(invalid), Fp12.ONE));

const template = compileTemplate(join(here, 'finalexp.cash'));
console.log(`FinalExp (cp#3): contract ${template.length}B (slow)`);
const ok = runVectors('finalExp == noble.finalExponentiate', template, vectors, { tamperIndex: 12 });
process.exit(ok ? 0 : 1);
