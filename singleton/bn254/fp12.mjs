// Grade singleton/pairing/fp12.cash against @noble/curves bn254 Fp12 on the
// loosened BCH 2026 VM. Run: node singleton/pairing/fp12.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

import { bn254 } from '@noble/curves/bn254.js';
const Fp12 = bn254.fields.Fp12;

const here = dirname(fileURLToPath(import.meta.url));
// noble Fp12 -> 12 ints in toBytes order (c0.c0.c0 .. c1.c2.c1)
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];
const randFp12 = (rng) => Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));

const rng = splitmix64(0x66703132n); // "fp12"
const N = 5;
const vectors = [];
for (let i = 0; i < N; i++) {
  const a = randFp12(rng);
  const b = randFp12(rng);
  vectors.push([
    ...f12(a), ...f12(b),
    ...f12(Fp12.mul(a, b)),
    ...f12(Fp12.sqr(a)),
    ...f12(Fp12.conjugate(a)),
  ]);
}

const template = compileTemplate(join(here, 'fp12.cash'));
console.log(`Fp12 layer: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('fp12(mul,sqr,conj)', template, vectors, { tamperIndex: 24 });
process.exit(ok ? 0 : 1);
