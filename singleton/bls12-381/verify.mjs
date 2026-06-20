// Grade singleton/bls12-381/verify.cash: the full BLS12-381 pairing verdict in one
// contract. Valid Groth16 instance -> ACCEPT (finalExp == ONE); tampered public
// input -> the pairing product != ONE -> REJECT. Very slow (~1.4B op-cost).
// Run: node singleton/bls12-381/verify.mjs
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compileTemplate, evalArgs } from './_harness.mjs';
import { vkx, grothPairs, pairRow, computeVkx, PUBLIC_INPUTS } from './bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const template = compileTemplate(join(here, 'verify.cash'));
console.log(`GrothVerify (BLS12-381 pairing verdict): contract ${template.length}B (very slow)`);

const validArgs = grothPairs(vkx).flatMap(pairRow);
const tampered = computeVkx([PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]]);
const invalidArgs = grothPairs(tampered).flatMap(pairRow);

const v = evalArgs(template, validArgs);
const x = evalArgs(template, invalidArgs);
console.log(`valid   -> accepted=${v.accepted}  op-cost~${v.opCost.toLocaleString()}`);
console.log(`invalid -> accepted=${x.accepted} (want false)  ${x.error ? 'rejected: ' + String(x.error).slice(0, 60) : ''}`);

const ok = v.accepted && !x.accepted;
console.log(`${ok ? 'PASS' : 'FAIL'}  verify(valid accepts, tampered rejects)`);
process.exit(ok ? 0 : 1);
