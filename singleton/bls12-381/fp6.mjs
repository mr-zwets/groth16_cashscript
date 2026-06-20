// Grade singleton/bls12-381/fp6.cash against @noble/curves bls12-381 Fp6 on the
// loosened BCH 2026 VM. Run: node singleton/bls12-381/fp6.mjs
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bls12-381.js').href;
const { bls12_381 } = await import(NOBLE);
const Fp6 = bls12_381.fields.Fp6;

const here = dirname(fileURLToPath(import.meta.url));
const f6 = (x) => [x.c0.c0, x.c0.c1, x.c1.c0, x.c1.c1, x.c2.c0, x.c2.c1];
const randFp6 = (rng) => Fp6.fromBigSix([randFp(rng), randFp(rng), randFp(rng), randFp(rng), randFp(rng), randFp(rng)]);

const rng = splitmix64(0x667036n); // "fp6"
const N = 6;
const vectors = [];
for (let i = 0; i < N; i++) {
  const a = randFp6(rng);
  const b = randFp6(rng);
  vectors.push([
    ...f6(a), ...f6(b),
    ...f6(Fp6.mul(a, b)),
    ...f6(Fp6.sqr(a)),
    ...f6(Fp6.mulByNonresidue(a)), // multiply by v
  ]);
}

const template = compileTemplate(join(here, 'fp6.cash'));
console.log(`Fp6 layer: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('fp6(mul,sqr,mulByV)', template, vectors, { tamperIndex: 12 });
process.exit(ok ? 0 : 1);
