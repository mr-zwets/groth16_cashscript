// Export bench vectors: valid (fixture 0), extraValidProofs (fixtures 1-3), worstCaseProof (fixture 4).
// invalid: one honest tamper per input, a middle byte of its largest non-redeem, non-zero-pad push
// (a pad tamper would be vacuous: the pad is unused).
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { decodeAuthenticationInstructions, encodeAuthenticationInstruction, hexToBin } from '@bitauth/libauth';
import { produceTransaction } from './transaction.mjs';

assert.equal(process.argv.length, 3, 'usage: node export.mjs output.json');
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const LABELS = ['exec0+vkx-msm', 'exec1+vkx-msm', 'exec2+vkx-msm', 'genesis+vkx-msm', 'terminal+vkx-msm-final'];
const CHECKPOINTS = ['executor-start', 'miller-interior', 'miller-interior', 'vkx-subgroup', 'pairing-close'];
const run = ({ proof, publicInputs }) => produceTransaction(fixtures.vk, proof, publicInputs)
  .map((s, i) => ({ label: LABELS[i], locking: s.locking, unlocking: s.unlocking, checkpoint: CHECKPOINTS[i] }));
const tamper = (unlockingHex) => {
  const ins = decodeAuthenticationInstructions(hexToBin(unlockingHex));
  const candidates = ins.slice(0, -1).map((i, k) => ({ k, d: i.data })).filter(({ d }) => d && d.length > 0 && d.some((b) => b !== 0));
  const { k } = candidates.reduce((a, b) => (b.d.length > a.d.length ? b : a));
  const data = Uint8Array.from(ins[k].data);
  data[data.length >> 1] ^= 0x01;
  ins[k] = { ...ins[k], data };
  return Buffer.concat(ins.map((i) => Buffer.from(encodeAuthenticationInstruction(i)))).toString('hex');
};
const [primary, ...rest] = fixtures.fixtures;
const steps = run(primary);
writeFileSync(process.argv[2], JSON.stringify({
  steps,
  invalid: steps.map((_, k) => steps.map((s, i) => (i === k ? { ...s, unlocking: tamper(s.unlocking) } : s))),
  extraValidProofs: rest.slice(0, 3).map(run),
  worstCaseProof: run(rest[3]),
}, null, 2) + '\n');
