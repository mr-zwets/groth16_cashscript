// Grade singleton/pairing/miller.cash (single-pair Miller loop) against noble
// bn254.pairing(g1,g2,false) on the loosened BCH 2026 VM. Heavy (~hundreds of M
// op-cost) so few vectors. Run: node singleton/pairing/miller.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors } from './_harness.mjs';

import { bn254 } from '@noble/curves/bn254.js';
const { Fp12 } = bn254.fields;
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];

const here = dirname(fileURLToPath(import.meta.url));

// a couple of (G1, G2) pairs (deterministic scalar multiples of the generators)
const cases = [[1n, 1n], [3n, 5n]];
const vectors = cases.map(([s1, s2]) => {
  const P = bn254.G1.Point.BASE.multiply(s1).toAffine();
  const Q = bn254.G2.Point.BASE.multiply(s2);
  const Qa = Q.toAffine();
  const expected = bn254.pairing(bn254.G1.Point.BASE.multiply(s1), Q, false);
  return [
    Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, P.x, P.y,
    ...f12(expected),
  ];
});

const template = compileTemplate(join(here, 'miller.cash'));
console.log(`Miller single-pair: ${vectors.length} vectors, contract ${template.length}B (this is slow)`);
const ok = runVectors('miller(single-pair)', template, vectors, { tamperIndex: 6 });
process.exit(ok ? 0 : 1);
