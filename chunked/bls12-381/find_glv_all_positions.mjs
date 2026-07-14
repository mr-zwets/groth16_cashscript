// Deterministically reproduce the valid public inputs used to exercise every one of the
// 128 Straus positions in the GLV builders. This is a branch-coverage fixture, not a claim
// that these inputs globally maximize VM op-cost for every arithmetic operand.
import { createHash } from 'node:crypto';
import {
  glvDecompose, GLV_ALL_POSITIONS_INPUTS, GLV_R, VKXGLV_ITERS,
} from './gen_vkx_glv.mjs';

const SEED = 'zk-verifier-bench/bls12-381/glv-all-positions/v1';
const EXPECTED_COUNTER = 5069;
const FULL_COVERAGE = (1n << BigInt(VKXGLV_ITERS)) - 1n;
const scalar = (counter, lane) => BigInt(`0x${createHash('sha256').update(`${SEED}:${counter}:${lane}`).digest('hex')}`) % GLV_R;
const coversAllPositions = (inputs) => inputs
  .flatMap(glvDecompose)
  .reduce((coverage, part) => coverage | part, 0n) === FULL_COVERAGE;

let found;
for (let counter = 0; counter <= EXPECTED_COUNTER; counter++) {
  const inputs = [scalar(counter, 0), scalar(counter, 1)];
  if (coversAllPositions(inputs)) {
    found = { counter, inputs };
    break;
  }
}

if (found === undefined || found.counter !== EXPECTED_COUNTER) {
  throw new Error(`expected first all-positions pair at counter ${EXPECTED_COUNTER}`);
}
if (!found.inputs.every((input, index) => input === GLV_ALL_POSITIONS_INPUTS[index])) {
  throw new Error('derived all-positions inputs differ from the committed fixture');
}

console.log(`first all-positions pair: counter=${found.counter}`);
console.log(found.inputs.map((input) => input.toString()).join('\n'));
