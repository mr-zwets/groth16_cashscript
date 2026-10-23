// Export bench vectors: valid (fixture 0), extraValidProofs (fixtures 1-3), worstCaseProof (fixture 4),
// as for densless-msm-spec, but one P2SH32 input. invalid: one tamper per push class (a middle
// byte of the push flipped; numbers + 1; W: its last limb), each must be rejected.
// Usage: VERIFIER_DIR=<zk-verifier-bench> node export.mjs vectors.json
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {producePushes, encodeUnlocking, program} from './transaction.mjs';
import {layout} from './build.mjs';

assert.equal(process.argv.length, 3, 'usage: node export.mjs output.json');
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const {locking} = program();
const step = (unlocking) => ({label: 'single', locking: locking.toString('hex'), unlocking: unlocking.toString('hex'), checkpoint: 'pairing-close'});
const run = ({proof, publicInputs}) => [step(encodeUnlocking(producePushes(fixtures.vk, proof, publicInputs)))];
const [primary, ...rest] = fixtures.fixtures;
const pushes = producePushes(fixtures.vk, primary.proof, primary.publicInputs);
const tampered = (label) => {
  const p = pushes.map((b) => Buffer.from(b)), k = layout.indexOf(label);
  // W: a byte of the last limb (the stage's final state evaluation). W's slope limbs are not
  // used by the accept decision in the inherited design (see README.md), so they are not tampered.
  if (label.endsWith('/W')) p[k][p[k].length - 16] ^= 0x01;
  else if (p[k].length > 33 || label === 'genesis/sel') { if (p[k].length === 0) p[k] = Buffer.from([2]); p[k][p[k].length >> 1] ^= 0x01; }
  else p[k] = Buffer.from(bigIntToVmNumber(vmNumberToBigInt(p[k]) + 1n));
  return [step(encodeUnlocking(p))];
};
const classes = ['genesis/sel', 'terminal/Q', 'terminal/v0', 'terminal/v14', 'exec0/FT', 'exec0/W', 'exec1/FT', 'exec1/W', 'exec2/FT', 'exec2/W',
  'genesis/p2', 'genesis/p6', 'genesis/p18', 'genesis/Grest', 'msm/zInv', 'msm/w', 'msm/n1', 'msm/n0'];
writeFileSync(process.argv[2], JSON.stringify({
  steps: run(primary),
  invalid: classes.map(tampered),
  extraValidProofs: rest.slice(0, 3).map(run),
  worstCaseProof: run(rest[3]),
}, null, 2) + '\n');
