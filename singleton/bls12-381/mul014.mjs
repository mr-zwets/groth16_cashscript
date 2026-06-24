// Grade singleton/bls12-381/mul014.cash against noble Fp12.mul014 on the loosened
// BCH 2026 VM. Run: node singleton/bls12-381/mul014.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

import { bls12_381 } from '@noble/curves/bls12-381.js';
const { Fp2, Fp12 } = bls12_381.fields;

const here = dirname(fileURLToPath(import.meta.url));
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];
const randFp12 = (rng) => Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));
const randFp2 = (rng) => Fp2.fromBigTuple([randFp(rng), randFp(rng)]);

const rng = splitmix64(0x303134n); // "014"
const N = 5;
const vectors = [];
for (let i = 0; i < N; i++) {
  const f = randFp12(rng);
  const o0 = randFp2(rng), o1 = randFp2(rng), o4 = randFp2(rng);
  vectors.push([
    ...f12(f),
    o0.c0, o0.c1, o1.c0, o1.c1, o4.c0, o4.c1,
    ...f12(Fp12.mul014(f, o0, o1, o4)),
  ]);
}

const template = compileTemplate(join(here, 'mul014.cash'));
console.log(`mul014: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('mul014', template, vectors, { tamperIndex: 18 });
process.exit(ok ? 0 : 1);
