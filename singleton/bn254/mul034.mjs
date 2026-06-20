// Grade singleton/pairing/mul034.cash against noble Fp12.mul034 on the loosened
// BCH 2026 VM. Run: node singleton/pairing/mul034.mjs
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
const { bn254 } = await import(NOBLE);
const { Fp2, Fp12 } = bn254.fields;

const here = dirname(fileURLToPath(import.meta.url));
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];
const randFp12 = (rng) => Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));
const randFp2 = (rng) => Fp2.fromBigTuple([randFp(rng), randFp(rng)]);

const rng = splitmix64(0x303334n); // "034"
const N = 5;
const vectors = [];
for (let i = 0; i < N; i++) {
  const f = randFp12(rng);
  const o0 = randFp2(rng), o3 = randFp2(rng), o4 = randFp2(rng);
  vectors.push([
    ...f12(f),
    o0.c0, o0.c1, o3.c0, o3.c1, o4.c0, o4.c1,
    ...f12(Fp12.mul034(f, o0, o3, o4)),
  ]);
}

const template = compileTemplate(join(here, 'mul034.cash'));
console.log(`mul034: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('mul034', template, vectors, { tamperIndex: 18 });
process.exit(ok ? 0 : 1);
