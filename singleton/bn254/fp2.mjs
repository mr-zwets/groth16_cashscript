// Grade singleton/pairing/fp2.cash against @noble/curves bn254 Fp2 on the
// loosened BCH 2026 VM. Each vector = (operand a, operand b) + noble's expected
// outputs for mul/sqr/inv/mulXi/conj. Run: node singleton/pairing/fp2.mjs
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
const { bn254 } = await import(NOBLE);
const Fp2 = bn254.fields.Fp2;
const XI = Fp2.fromBigTuple([9n, 1n]);

const here = dirname(fileURLToPath(import.meta.url));
const f2 = (a) => [a.c0, a.c1]; // noble Fp2 -> [c0,c1] limbs

const rng = splitmix64(0x6670320001n); // "fp2" seed
const N = 8;
const vectors = [];
for (let i = 0; i < N; i++) {
  const a = Fp2.fromBigTuple([randFp(rng), randFp(rng)]);
  const b = Fp2.fromBigTuple([randFp(rng), randFp(rng)]);
  vectors.push([
    a.c0, a.c1, b.c0, b.c1,
    ...f2(Fp2.mul(a, b)),
    ...f2(Fp2.sqr(a)),
    ...f2(Fp2.inv(a)),
    ...f2(Fp2.mul(a, XI)),
    ...f2(Fp2.frobeniusMap(a, 1)), // a^p = conjugate
  ]);
}

const template = compileTemplate(join(here, 'fp2.cash'));
console.log(`Fp2 layer: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('fp2(mul,sqr,inv,mulXi,conj)', template, vectors, { tamperIndex: 4 });
process.exit(ok ? 0 : 1);
