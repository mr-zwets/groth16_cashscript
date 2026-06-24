// CHECKPOINT #3: grade singleton/pairing/finalexp.cash against noble
// Fp12.finalExponentiate on the loosened BCH 2026 VM. Inputs: a random Fp12, the
// VALID Groth16 Miller boundary (-> Fp12.ONE, i.e. proof verifies), and the
// INVALID boundary (-> != ONE). Run: node singleton/pairing/finalexp.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors, splitmix64, randFp } from './_harness.mjs';

import { bn254 } from '@noble/curves/bn254.js';
const { Fp2, Fp12 } = bn254.fields;
const here = dirname(fileURLToPath(import.meta.url));
const f12 = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];

// rebuild valid + invalid Miller boundaries from the committed instance
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
const boundary = (inputs) => {
  let vkx = vk.ic[0];
  inputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
  return bn254.pairingBatch([
    { g1: proof.a.negate(), g2: proof.b }, { g1: vk.alpha, g2: vk.beta },
    { g1: vkx, g2: vk.gamma }, { g1: proof.c, g2: vk.delta },
  ], false);
};
const valid = boundary(vec.publicInputs);
const invalid = boundary(vec.invalid.publicInputs);

const rng = splitmix64(0x66657870n); // "fexp"
const rand = Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));

const inputs = [
  { label: 'random', f: rand },
  { label: 'valid boundary', f: valid },
  { label: 'invalid boundary', f: invalid },
];
const vectors = inputs.map(({ f }) => [...f12(f), ...f12(Fp12.finalExponentiate(f))]);

// sanity: confirm the verdicts match golden before running on-chain
console.log('valid finalExp == ONE   :', Fp12.eql(Fp12.finalExponentiate(valid), Fp12.ONE), '(golden', vec.golden.verified + ')');
console.log('invalid finalExp != ONE :', !Fp12.eql(Fp12.finalExponentiate(invalid), Fp12.ONE), '(golden', vec.golden.invalidVerified + ')');

const template = compileTemplate(join(here, 'finalexp.cash'));
console.log(`FinalExp (cp#3): contract ${template.length}B (slow)`);
const ok = runVectors('finalExp == noble.finalExponentiate', template, vectors, { tamperIndex: 12 });
process.exit(ok ? 0 : 1);
