// End-to-end: grade singleton/pairing/verify.cash (full Groth16 pairing verdict,
// 4 pairs -> boundary -> finalExp -> require ==1) on the loosened BCH 2026 VM.
// Valid instance must ACCEPT; invalid (tampered public input) must REJECT.
// Run: node singleton/pairing/verify.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, evalArgs } from './_harness.mjs';

import { bn254 } from '@noble/curves/bn254.js';
const { Fp2 } = bn254.fields;
const here = dirname(fileURLToPath(import.meta.url));
const verifierDir = process.env.VERIFIER_DIR;
if (!verifierDir) throw new Error('VERIFIER_DIR must point to the zk-verifier-bench checkout');

const vec = JSON.parse(readFileSync(join(verifierDir, 'src', 'checkpoints', 'pairing-vectors.json'), 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };

const pairsArgs = (inputs) => {
  let vkx = vk.ic[0];
  inputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
  const pairs = [
    { P: proof.a.negate(), Q: proof.b }, { P: vk.alpha, Q: vk.beta },
    { P: vkx, Q: vk.gamma }, { P: proof.c, Q: vk.delta },
  ];
  const args = [];
  for (const { P, Q } of pairs) {
    const Pa = P.toAffine(), Qa = Q.toAffine();
    args.push(Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, Pa.x, Pa.y);
  }
  return args;
};

const template = compileTemplate(join(here, 'verify.cash'));
console.log(`verify.cash: ${template.length}B locking (singleton, very slow ~1.2B op-cost)`);

const validRes = evalArgs(template, pairsArgs(vec.publicInputs));
console.log(`VALID   instance: accepted=${validRes.accepted}  op-cost=${validRes.opCost.toLocaleString()}  ${validRes.error ?? ''}`);
const invalidRes = evalArgs(template, pairsArgs(vec.invalid.publicInputs));
console.log(`INVALID instance: accepted=${invalidRes.accepted}  (must be false)  ${invalidRes.error ?? ''}`);

const ok = validRes.accepted && !invalidRes.accepted;
console.log(ok ? 'PASS  full Groth16 pairing verdict (accept valid, reject invalid)' : 'FAIL');
process.exit(ok ? 0 : 1);
