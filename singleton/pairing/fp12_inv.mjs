// Grade singleton/pairing/fp12_inv.cash against @noble Fp12.inv on the loosened
// BCH 2026 VM. Run: node singleton/pairing/fp12_inv.mjs
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
const { bn254 } = await import(NOBLE);
const Fp12 = bn254.fields.Fp12;

const here = dirname(fileURLToPath(import.meta.url));
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];
const randFp12 = (rng) => Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));

const rng = splitmix64(0x66313276n); // "f12v"
const N = 4;
const vectors = [];
for (let i = 0; i < N; i++) {
  const a = randFp12(rng);
  vectors.push([...f12(a), ...f12(Fp12.inv(a))]);
}

const template = compileTemplate(join(here, 'fp12_inv.cash'));
console.log(`Fp12 inverse: ${vectors.length} vectors, contract ${template.length}B`);
const ok = runVectors('fp12Inv', template, vectors, { tamperIndex: 12 });
process.exit(ok ? 0 : 1);
