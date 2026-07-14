// Deterministically reproduce the valid public inputs used to stress every one of the
// 128 Straus positions in the GLV builders. The selected pair had the highest total
// verifier op-cost among 32 full valid all-position proofs; a separate 256-pair audit
// measured the exact shared-table locking headroom. This script reproduces the inputs
// and branch coverage; the generator documents the empirical scope.
import { createHash } from 'node:crypto';
import {
  glvDecompose, GLV_HIGH_COST_INPUTS, GLV_R, VKXGLV_ITERS,
} from './gen_vkx_glv.mjs';

const SEED = 'zk-verifier-bench/bls12-381/glv-opcost-audit/v1';
const EXPECTED_COUNTER = 22012;
const EXPECTED_ALL_POSITION_ORDINAL = 8;
const FULL_COVERAGE = (1n << BigInt(VKXGLV_ITERS)) - 1n;
const scalar = (counter, lane) => BigInt(`0x${createHash('sha256').update(`${SEED}:${counter}:${lane}`).digest('hex')}`) % GLV_R;
const coversAllPositions = (inputs) => inputs
  .flatMap(glvDecompose)
  .reduce((coverage, part) => coverage | part, 0n) === FULL_COVERAGE;

let found;
let allPositionOrdinal = 0;
for (let counter = 0; counter <= EXPECTED_COUNTER; counter++) {
  const inputs = [scalar(counter, 0), scalar(counter, 1)];
  if (coversAllPositions(inputs)) {
    allPositionOrdinal += 1;
    if (counter === EXPECTED_COUNTER) found = { counter, inputs, allPositionOrdinal };
  }
}

if (found === undefined || found.counter !== EXPECTED_COUNTER || found.allPositionOrdinal !== EXPECTED_ALL_POSITION_ORDINAL) {
  throw new Error(`expected all-position pair ${EXPECTED_ALL_POSITION_ORDINAL} at counter ${EXPECTED_COUNTER}`);
}
if (!found.inputs.every((input, index) => input === GLV_HIGH_COST_INPUTS[index])) {
  throw new Error('derived all-positions inputs differ from the committed fixture');
}

console.log(`selected all-positions pair: ordinal=${found.allPositionOrdinal} counter=${found.counter}`);
console.log(found.inputs.map((input) => input.toString()).join('\n'));
