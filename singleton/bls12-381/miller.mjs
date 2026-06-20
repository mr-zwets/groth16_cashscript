// Grade singleton/bls12-381/miller.cash (single-pair Miller loop) against noble
// bls12_381.pairing(g1,g2,false) on the loosened BCH 2026 VM. Heavy (~hundreds of M
// op-cost) so few vectors. Run: node singleton/bls12-381/miller.mjs
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bls12-381.js').href;
const { bls12_381 } = await import(NOBLE);
const { Fp12 } = bls12_381.fields;
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];

const here = dirname(fileURLToPath(import.meta.url));

// a couple of (G1, G2) pairs (deterministic scalar multiples of the generators)
const cases = [[1n, 1n], [3n, 5n]];
const vectors = cases.map(([s1, s2]) => {
  const P = bls12_381.G1.Point.BASE.multiply(s1).toAffine();
  const Q = bls12_381.G2.Point.BASE.multiply(s2);
  const Qa = Q.toAffine();
  const expected = bls12_381.pairing(bls12_381.G1.Point.BASE.multiply(s1), Q, false);
  return [
    Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, P.x, P.y,
    ...f12(expected),
  ];
});

const template = compileTemplate(join(here, 'miller.cash'));
console.log(`Miller single-pair: ${vectors.length} vectors, contract ${template.length}B (this is slow)`);
const ok = runVectors('miller(single-pair)', template, vectors, { tamperIndex: 6 });
process.exit(ok ? 0 : 1);
