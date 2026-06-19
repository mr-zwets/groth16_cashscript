// CHECKPOINT #2: grade singleton/pairing/miller4.cash (4-pair Groth16 Miller
// boundary) against golden millerHex from pairing-vectors.json, on the loosened
// BCH 2026 VM. Heavy (~950M op-cost). Run: node singleton/pairing/miller4.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, runVectors } from './_harness.mjs';

const NOBLE = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@noble/curves/bn254.js').href;
const { bn254 } = await import(NOBLE);
const { Fp2 } = bn254.fields;
const here = dirname(fileURLToPath(import.meta.url));

const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({
  x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]),
  y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]),
});
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
let vkx = vk.ic[0];
vec.publicInputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });

// 4 Groth16 pairs: (-A,B), (alpha,beta), (vkx,gamma), (C,delta)
const pairs = [
  { P: proof.a.negate(), Q: proof.b },
  { P: vk.alpha, Q: vk.beta },
  { P: vkx, Q: vk.gamma },
  { P: proof.c, Q: vk.delta },
];
const args = [];
for (const { P, Q } of pairs) {
  const Pa = P.toAffine(), Qa = Q.toAffine();
  args.push(Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, Pa.x, Pa.y);
}
// golden millerHex -> 12 limbs (12 x 32-byte big-endian)
const mh = vec.golden.millerHex;
for (let i = 0; i < 12; i++) args.push(BigInt('0x' + mh.slice(i * 64, i * 64 + 64)));

const template = compileTemplate(join(here, 'miller4.cash'));
console.log(`Miller 4-pair (cp#2): contract ${template.length}B (very slow, ~950M op-cost)`);
const ok = runVectors('miller4 boundary == golden millerHex', template, [args], { tamperIndex: 24 });
process.exit(ok ? 0 : 1);
