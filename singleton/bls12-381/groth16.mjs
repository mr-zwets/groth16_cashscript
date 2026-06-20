// Grade singleton/bls12-381/groth16.cash: the COMPLETE BLS12-381 Groth16 verifier
// in one contract. Computes vk_x on-chain from runtime inputs, runs the pairing,
// require()s == 1. Valid proof+inputs -> ACCEPT; tampered input -> REJECT. Very
// slow (~1.5B op-cost). Run: node singleton/bls12-381/groth16.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, evalArgs } from './_harness.mjs';
import { proof, PUBLIC_INPUTS } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const template = compileTemplate(join(here, 'groth16.cash'));
console.log(`Groth16Verify (BLS12-381, full): contract ${template.length}B (very slow)`);

const A = proof.a.toAffine(), B = proof.b.toAffine(), C = proof.c.toAffine();
// spend(Ax,Ay, Bxa,Bxb,Bya,Byb, Cx,Cy, in0,in1)
const baseArgs = [
  A.x, A.y,
  B.x.c0, B.x.c1, B.y.c0, B.y.c1,
  C.x, C.y,
];
const validArgs = [...baseArgs, PUBLIC_INPUTS[0], PUBLIC_INPUTS[1]];
const invalidArgs = [...baseArgs, PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]]; // tampered input0

const v = evalArgs(template, validArgs);
const x = evalArgs(template, invalidArgs);
console.log(`valid   -> accepted=${v.accepted}  op-cost~${v.opCost.toLocaleString()}`);
console.log(`invalid -> accepted=${x.accepted} (want false)  ${x.error ? 'rejected' : ''}`);

const ok = v.accepted && !x.accepted;
console.log(`${ok ? 'PASS' : 'FAIL'}  groth16(valid accepts, tampered rejects)`);
process.exit(ok ? 0 : 1);
