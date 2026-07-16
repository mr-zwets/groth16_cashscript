// Verify a proof-independent BCH relay encoding for the generated BN254
// one-transaction verifier.
//
// The intrinsic operation-cost ceilings below are tied to the exact generated
// locking graph by LOCKING_GRAPH_HASH. Inputs 0 and 1 combine the generic GLV
// trace ceilings with the key-agnostic fallback-event bound proved by
// ../pairing/prove_vkx_glv_resource_bound.mjs. Inputs 2 through 10 use the
// interval-shadow ceilings for the Miller trace: every proof-controlled limb is
// canonical in [0,p), each arithmetic interval is propagated through the exact
// compiler stack schedule, both canonicalization paths are charged, and the
// normalized/projective Miller hand-off uses branch-free cross products.
//
// This script independently measures the exact transaction-length/op-cost
// dependency matrix, checks the generated witness layout, solves the universal
// GLV fallback-event ceiling, constructs the exact padded transaction, asks the
// standard BCH2026 VM to verify it, and explicitly funds/asserts the default
// 1 sat/byte relay fee (which is outside VM policy evaluation). This proves
// every valid proof has an encoding at the reported lengths; it does not cap
// accepted serializations with additional OP_DROP padding.
//
// Run from the repository root with VERIFIER_DIR pointing to the matching
// zk-verifier-bench checkout.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  createVirtualMachineBch2026,
  decodeAuthenticationInstructions,
  encodeAuthenticationInstructions,
  encodeDataPush,
  encodeTransactionBch,
  hexToBin,
} from '@bitauth/libauth';
import {
  GLV_EQUAL_POINT_SURCHARGE,
  GLV_GENERIC_INTRINSIC,
} from './prove_glv_intrinsic_ceiling.mjs';
import { MILLER_INTRINSIC_CEILINGS } from './prove_miller_intrinsic_ceiling.mjs';
import { GLV_FALLBACK_EVENT_CEILINGS } from '../pairing/prove_vkx_glv_resource_bound.mjs';

const verifierDir = process.env.VERIFIER_DIR;
if (verifierDir === undefined) {
  throw new Error('VERIFIER_DIR must point to the matching zk-verifier-bench checkout');
}
const vectorPath = join(verifierDir, 'src/bch/groth16-intratx-residue-vectors.json');
const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'));
const vm = createVirtualMachineBch2026(true);

const INPUT_COUNT = 11;
const STANDARD_TRANSACTION_LIMIT = 100_000;
const SCRIPT_LIMIT = 10_000;
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;
const DENSITY_BASE = 41;
const DENSITY_MULTIPLIER = 800;
const LOCKING_GRAPH_HASH = 'cf6f11ca2d10eaf8fa5a7bbb401908908513a01e3270189aa8728965e28202ad';
const GLV_TABLE_HASH = '4dedc6a77ffe1f14a1faa12a533a2975e8d7304c8e740a82d8a5c9c41e490028';
const GLV_EVENT_CEILING_CASES = [GLV_FALLBACK_EVENT_CEILINGS];
const EXPECTED_EXTRA_COUNTS = [0, 1, 22, 18, 18, 22, 20, 18, 20, 22, 16];
const EXPECTED_FIXED_FLOORS = [2_424, 5_124, 9_105, 8_510, 7_398, 8_602, 8_796, 7_762, 8_282, 8_099, 9_056];

const extraValidProofs = vectors.extraValidProofs ?? [];
const resourceFixtureProof = vectors.resourceFixtureProof;
if (!Array.isArray(extraValidProofs) || !Array.isArray(resourceFixtureProof)) {
  throw new Error('missing named full-valid GLV resource fixture');
}
const runs = [
  ['committed', vectors.steps],
  ...extraValidProofs.map((steps, index) => [`proof${index + 1}`, steps]),
  ['resourceFixtureProof', resourceFixtureProof],
  ['worstCaseProof', vectors.worstCaseProof],
].filter(([, steps]) => Array.isArray(steps));

const toInputs = (steps) => {
  if (steps.length !== INPUT_COUNT) throw new Error(`expected ${INPUT_COUNT} verifier inputs`);
  return steps.map((step) => ({
    locking: hexToBin(step.locking),
    unlocking: hexToBin(step.unlocking),
  }));
};

const verificationData = (inputs) => {
  const transaction = {
    version: 2,
    inputs: inputs.map((input, index) => ({
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: index,
      sequenceNumber: 0,
      unlockingBytecode: input.unlocking,
    })),
    outputs: [{
      lockingBytecode: Uint8Array.of(0x6a),
      valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS,
    }],
    locktime: 0,
  };
  const requiredInputValue = TRANSACTION_OUTPUT_SATOSHIS +
    BigInt(encodeTransactionBch(transaction).length) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  const sourceOutputValue = (requiredInputValue + BigInt(inputs.length) - 1n) / BigInt(inputs.length);
  return {
    sourceOutputs: inputs.map((input) => ({
      lockingBytecode: input.locking,
      valueSatoshis: sourceOutputValue,
    })),
    transaction,
  };
};

const measure = (inputs) => {
  const data = verificationData(inputs);
  const states = inputs.map((_, inputIndex) => vm.evaluate({ inputIndex, ...data }));
  const failures = states.flatMap((state, inputIndex) => state.error === undefined
    ? []
    : [{ inputIndex, error: state.error }]);
  if (failures.length > 0) throw new Error(JSON.stringify(failures));
  const standard = vm.verify(data);
  if (standard !== true) throw new Error(`standard BCH2026 verification failed: ${JSON.stringify(standard)}`);
  const wireBytes = encodeTransactionBch(data.transaction).length;
  const feeSatoshis = data.sourceOutputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  ) - data.transaction.outputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  );
  const requiredRelayFee = BigInt(wireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  if (feeSatoshis < requiredRelayFee) {
    throw new Error(`transaction fee ${feeSatoshis} is below default relay fee ${requiredRelayFee}`);
  }
  return {
    lengths: inputs.map((input) => input.unlocking.length),
    operationCosts: states.map((state) => state.metrics.operationCost),
    wireBytes,
    feeSatoshis,
    standard: true,
  };
};

const lockingGraphHash = createHash('sha256')
  .update(vectors.steps.map((step) => step.locking).join(''))
  .digest('hex');
if (lockingGraphHash !== LOCKING_GRAPH_HASH) {
  throw new Error(`locking graph changed (${lockingGraphHash}); re-prove the intrinsic ceilings`);
}
runs.forEach(([name, steps]) => {
  const hash = createHash('sha256').update(steps.map((step) => step.locking).join('')).digest('hex');
  if (hash !== LOCKING_GRAPH_HASH) throw new Error(`${name} uses a different locking graph`);
});

// Padding is the penultimate push; changing it preserves every verifier
// argument while exposing each exact operation-cost dependency coefficient.
const addPaddingByte = (unlocking) => {
  const instructions = decodeAuthenticationInstructions(unlocking);
  const paddingIndex = instructions.length - 2;
  const padding = instructions[paddingIndex];
  if (padding?.data === undefined) throw new Error('penultimate instruction is not a padding push');
  const replacement = decodeAuthenticationInstructions(
    encodeDataPush(new Uint8Array(padding.data.length + 1)),
  );
  if (replacement.length !== 1) throw new Error('padding replacement is malformed');
  instructions[paddingIndex] = replacement[0];
  return encodeAuthenticationInstructions(instructions);
};

const baselineInputs = toInputs(vectors.worstCaseProof);
const baseline = measure(baselineInputs);
const dependencies = Array.from({ length: INPUT_COUNT }, () => Array(INPUT_COUNT).fill(0));
for (let changed = 0; changed < INPUT_COUNT; changed += 1) {
  const inputs = baselineInputs.map((input, index) => ({
    ...input,
    unlocking: index === changed ? addPaddingByte(input.unlocking) : input.unlocking,
  }));
  const perturbed = measure(inputs);
  perturbed.operationCosts.forEach((cost, inputIndex) => {
    dependencies[inputIndex][changed] = cost - baseline.operationCosts[inputIndex];
  });
}

const expectedDependencies = Array.from({ length: INPUT_COUNT }, (_, inputIndex) => {
  const row = Array(INPUT_COUNT).fill(0);
  if (inputIndex === 0) {
    row[0] = 1; row[1] = 4;
  } else if (inputIndex === 1) {
    row[1] = 1; row[2] = 2;
  } else if (inputIndex === 2) {
    row[2] = 1; row[3] = 2;
  } else if (inputIndex < INPUT_COUNT - 1) {
    // These generated schedules move the retained genesis-unlocking suffix
    // once more, adding one byte of cost per byte of input 2.
    row[2] = [3, 4, 5, 6, 8, 9].includes(inputIndex) ? 3 : 2;
    row[inputIndex] += 1; row[inputIndex + 1] += 2;
  } else {
    row[2] = 2; row[inputIndex] = 1;
  }
  return row;
});
if (JSON.stringify(dependencies) !== JSON.stringify(expectedDependencies)) {
  throw new Error(`unexpected operation-cost dependency matrix: ${JSON.stringify(dependencies)}`);
}

const intrinsic = (record) => record.operationCosts.map((cost, inputIndex) =>
  cost - dependencies[inputIndex].reduce(
    (sum, coefficient, dependencyIndex) => sum + coefficient * record.lengths[dependencyIndex],
    0,
  ));
const records = runs.map(([name, steps]) => {
  const record = measure(toInputs(steps));
  return { name, ...record, intrinsic: intrinsic(record) };
});

// Layout: fixed-width inBlob, fixed-count extras, density padding, redeem.
// Every minimally encoded field extra is at most 32 data bytes. Build the
// proof-independent maximum-size floor from that bound directly; no concrete
// proof fixture is required to realize every maximum simultaneously.
const layouts = records.map((record, recordIndex) =>
  toInputs(runs[recordIndex][1]).map((input, inputIndex) => {
    const instructions = decodeAuthenticationInstructions(input.unlocking);
    const pushed = instructions.map((instruction) => instruction.data ??
      (instruction.opcode === 0
        ? new Uint8Array(0)
        : instruction.opcode >= 81 && instruction.opcode <= 96
        ? Uint8Array.of(instruction.opcode - 80)
        : undefined));
    if (pushed.some((data) => data === undefined)) {
      throw new Error(`${record.name} input ${inputIndex} is not push-only`);
    }
    const expectedPushes = EXPECTED_EXTRA_COUNTS[inputIndex] + 3;
    if (instructions.length !== expectedPushes) {
      throw new Error(`${record.name} input ${inputIndex}: expected ${expectedPushes} pushes, got ${instructions.length}`);
    }
    return {
      inBlob: pushed[0],
      extras: pushed.slice(1, -2),
      padding: pushed.at(-2),
      redeem: pushed.at(-1),
    };
  }));
const hardLayout = layouts[runs.findIndex(([name]) => name === 'worstCaseProof')];
for (let inputIndex = 0; inputIndex < INPUT_COUNT; inputIndex += 1) {
  const hard = hardLayout[inputIndex];
  layouts.forEach((layout, recordIndex) => {
    if (layout[inputIndex].inBlob.length !== hard.inBlob.length) {
      throw new Error(`${records[recordIndex].name} input ${inputIndex} has a variable-width inBlob`);
    }
    if (layout[inputIndex].redeem.length !== hard.redeem.length) {
      throw new Error(`${records[recordIndex].name} input ${inputIndex} has a variable redeem`);
    }
  });
  if (inputIndex === 1) {
    if (hard.extras.length !== 1 || hard.extras[0].length !== 2880) {
      throw new Error('input 1 does not contain one fixed 2880-byte GLV table');
    }
    const tableHash = createHash('sha256').update(hard.extras[0]).digest('hex');
    if (tableHash !== GLV_TABLE_HASH) throw new Error(`unexpected GLV table hash ${tableHash}`);
  }
  layouts.forEach((layout, recordIndex) => {
    layout[inputIndex].extras.forEach((extra, extraIndex) => {
      if (inputIndex !== 1 && extra.length > 32) {
        throw new Error(`${records[recordIndex].name} input ${inputIndex} extra ${extraIndex} exceeds 32 bytes`);
      }
    });
  });
}

const fixedFloors = baselineInputs.map((input, inputIndex) => {
  const instructions = decodeAuthenticationInstructions(input.unlocking);
  const padding = instructions.at(-2);
  if (padding?.data === undefined) throw new Error('missing padding push');
  const maximumExtraGrowth = inputIndex === 1
    ? 0
    : hardLayout[inputIndex].extras.reduce((sum, extra) => sum + 32 - extra.length, 0);
  return input.unlocking.length - encodeAuthenticationInstructions([padding]).length +
    maximumExtraGrowth + 2;
});
if (JSON.stringify(fixedFloors) !== JSON.stringify(EXPECTED_FIXED_FLOORS)) {
  throw new Error(`fixed unlocking floors changed: ${JSON.stringify(fixedFloors)}`);
}

const resizePadding = (unlocking, targetLength) => {
  const instructions = decodeAuthenticationInstructions(unlocking);
  const paddingIndex = instructions.length - 2;
  const padding = instructions[paddingIndex];
  if (padding?.data === undefined) throw new Error('missing padding push');
  const fixedLength = unlocking.length - encodeAuthenticationInstructions([padding]).length;
  const encodedPaddingLength = targetLength - fixedLength;
  const replacement = [1, 2, 3]
    .map((overhead) => encodedPaddingLength - overhead)
    .filter((dataLength) => dataLength >= 0)
    .map((dataLength) => decodeAuthenticationInstructions(encodeDataPush(new Uint8Array(dataLength))))
    .find((candidate) => candidate.length === 1 &&
      encodeAuthenticationInstructions(candidate).length === encodedPaddingLength);
  if (replacement === undefined) throw new Error(`target length ${targetLength} is not exactly encodable`);
  instructions[paddingIndex] = replacement[0];
  const resized = encodeAuthenticationInstructions(instructions);
  if (resized.length !== targetLength) throw new Error('padding resize length mismatch');
  return resized;
};

const ceilDiv = (numerator, denominator) => numerator <= 0
  ? 0
  : Math.floor((numerator + denominator - 1) / denominator);
const solveLengths = (ceilings) => {
  let lengths = fixedFloors.slice();
  for (let round = 0; round < 10_000; round += 1) {
    const next = lengths.map((current, inputIndex) => {
      const selfCoefficient = dependencies[inputIndex][inputIndex];
      const otherCost = dependencies[inputIndex].reduce(
        (sum, coefficient, dependencyIndex) => dependencyIndex === inputIndex
          ? sum
          : sum + coefficient * lengths[dependencyIndex],
        ceilings[inputIndex],
      );
      const required = ceilDiv(
        otherCost - DENSITY_MULTIPLIER * DENSITY_BASE,
        DENSITY_MULTIPLIER - selfCoefficient,
      );
      return Math.max(current, required);
    });
    if (next.every((length, index) => length === lengths[index])) return lengths;
    lengths = next;
  }
  throw new Error('resource-length fixed point did not converge');
};

const compactSizeLength = (value) => value <= 252 ? 1 : value <= 0xffff ? 3 : 5;
const wireLength = (unlockingLengths) => {
  const inputs = unlockingLengths.reduce(
    (sum, length) => sum + 32 + 4 + compactSizeLength(length) + length + 4,
    0,
  );
  return 4 + compactSizeLength(unlockingLengths.length) + inputs + 1 + 8 + 1 + 1 + 4;
};

const results = GLV_EVENT_CEILING_CASES.map((allocation) => {
  const ceilings = [
    GLV_GENERIC_INTRINSIC[0] + allocation[0] * GLV_EQUAL_POINT_SURCHARGE,
    GLV_GENERIC_INTRINSIC[1] + allocation[1] * GLV_EQUAL_POINT_SURCHARGE,
    ...MILLER_INTRINSIC_CEILINGS,
  ];
  records.forEach((record) => {
    record.intrinsic.forEach((cost, inputIndex) => {
      if (cost > ceilings[inputIndex]) {
        throw new Error(`${record.name} input ${inputIndex} exceeds its intrinsic ceiling`);
      }
    });
  });
  const lengths = solveLengths(ceilings);
  const wireBytes = wireLength(lengths);
  const costs = ceilings.map((ceiling, inputIndex) => ceiling + dependencies[inputIndex].reduce(
    (sum, coefficient, dependencyIndex) => sum + coefficient * lengths[dependencyIndex],
    0,
  ));
  const limits = lengths.map((length) => DENSITY_MULTIPLIER * (DENSITY_BASE + length));
  const inputs = baselineInputs.map((input, inputIndex) => ({
    ...input,
    unlocking: resizePadding(input.unlocking, lengths[inputIndex]),
  }));
  const control = measure(inputs);
  if (control.wireBytes !== wireBytes) throw new Error('exact wire-length model mismatch');
  if (wireBytes > STANDARD_TRANSACTION_LIMIT) throw new Error('proof-independent relay encoding exceeds 100 kB');
  if (lengths.some((length) => length > SCRIPT_LIMIT)) throw new Error('unlocking script exceeds 10 kB');
  if (inputs.some((input) => input.locking.length > SCRIPT_LIMIT)) throw new Error('locking script exceeds 10 kB');
  if (costs.some((cost, inputIndex) => cost > limits[inputIndex])) {
    throw new Error('intrinsic ceiling exceeds a per-input density limit');
  }
  return {
    allocation,
    ceilings,
    lengths,
    wireBytes,
    feeSatoshis: control.feeSatoshis,
    costs,
    limits,
  };
});

results.forEach((result) => {
  console.log(`GLV fallback-event ceiling ${JSON.stringify(result.allocation)}:`);
  console.log(`  intrinsic ceilings: ${result.ceilings.join(',')}`);
  console.log(`  unlocking lengths: ${result.lengths.join(',')}`);
  console.log(`  wire bytes: ${result.wireBytes}; standard margin: ${STANDARD_TRANSACTION_LIMIT - result.wireBytes}`);
  console.log(`  funded fee: ${result.feeSatoshis} satoshis (default minimum ${result.wireBytes})`);
  console.log(`  ceiling costs: ${result.costs.join(',')}`);
  console.log(`  density limits: ${result.limits.join(',')}`);
  console.log(`  density slack: ${result.limits.map((limit, inputIndex) => limit - result.costs[inputIndex]).join(',')}`);
});

const universalWireBytes = Math.max(...results.map((result) => result.wireBytes));
const universalTotalOperationCost = Math.max(...results.map((result) =>
  result.costs.reduce((sum, cost) => sum + cost, 0)));
if (universalWireBytes !== 98_730 || universalTotalOperationCost !== 78_624_129) {
  throw new Error('certified proof-independent relay encoding changed');
}
console.log(`proved proof-independent relay encoding: ${universalWireBytes} wire bytes, ` +
  `${STANDARD_TRANSACTION_LIMIT - universalWireBytes} bytes standard-relay margin, ` +
  `${universalTotalOperationCost} summed ceiling op-cost`);
