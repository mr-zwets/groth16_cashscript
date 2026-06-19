// End-to-end: grade singleton/pairing/groth16.cash -- the SOUND singleton Groth16
// verifier. Runtime inputs = proof (A,B,C) + public inputs (in0,in1); vk_x is
// computed ON-CHAIN from the hardcoded IC. Valid public inputs must ACCEPT; the
// tampered public input (in1+1) must REJECT (different vk_x -> product != 1).
// Run: node singleton/pairing/groth16.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, evalArgs } from './_harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));

// spend(Ax,Ay, Bxa,Bxb,Bya,Byb, Cx,Cy, in0,in1) -- A is the raw proof point (negated in-script)
const A = vec.proof.a, B = vec.proof.b, C = vec.proof.c;
const proofArgs = (inputs) => [
  BigInt(A.x), BigInt(A.y),
  BigInt(B.x.c0), BigInt(B.x.c1), BigInt(B.y.c0), BigInt(B.y.c1),
  BigInt(C.x), BigInt(C.y),
  ...inputs.map(BigInt),
];

const template = compileTemplate(join(here, 'groth16.cash'));
console.log(`groth16.cash: ${template.length}B locking (sound singleton: vk_x on-chain + pairing; very slow)`);

const valid = evalArgs(template, proofArgs(vec.publicInputs));
console.log(`VALID   (inputs ${vec.publicInputs.join(',')}): accepted=${valid.accepted}  op-cost=${valid.opCost.toLocaleString()}  ${valid.error ?? ''}`);
const invalid = evalArgs(template, proofArgs(vec.invalid.publicInputs));
console.log(`INVALID (inputs ${vec.invalid.publicInputs.join(',')}): accepted=${invalid.accepted}  (must be false)  ${invalid.error ?? ''}`);

const ok = valid.accepted && !invalid.accepted;
console.log(ok ? 'PASS  sound Groth16 verifier (vk_x computed on-chain; accept valid, reject tampered input)' : 'FAIL');
process.exit(ok ? 0 : 1);
