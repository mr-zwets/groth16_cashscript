// Build the source-owned BN254 covenant-residue benchmark artifact.
//
// One fixed P2SH32 locking graph verifies every proof for the configured VK:
//   fast G2 validation (minting-baton genesis)
//     -> GLV vk_x while carrying the validated (-A,B,C) tuple
//     -> stage-bound c^-(6x+2)-fused Miller + residue verdict (immutable terminal).
//
// Each nonterminal redeem pins its successor locking. The token lifecycle is enforced
// in the contracts: minting baton -> mutable thread (plus recreated baton), mutable
// forward steps, then one immutable terminal output.
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Fp2, bn254, millerBatchOps, pairsFor, proof, proofFromLimbs, vec, ptLimbs, f12limbs, r6limbs,
  compileFileBytecode, compileFileBytecodeRaw, commitBin, CATEGORY, verifierPath,
  TARGET_UNLOCK, assertG2StageManifest,
} from './_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from './gen_g2check.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv } from './gen_vkx_glv.mjs';
import { fp12limbsOf, millerFusedOps, residueWitness } from './_residuemath.mjs';
import {
  bigIntToVmNumber, binToHex, createVirtualMachineBch2026, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, hexToBin, vmNumberToBigInt,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const STANDARD_VM = createVirtualMachineBch2026(true);
const CONSENSUS_VM = createVirtualMachineBch2026(false);
const FIELD_ORDER = bn254.fields.Fp.ORDER;
const SCALAR_ORDER = bn254.fields.Fr.ORDER;
const CATEGORY_HEX = binToHex(CATEGORY);
const CATEGORY_IMMUTABLE = `0x${CATEGORY_HEX}`;
const CATEGORY_MUTABLE = `0x${CATEGORY_HEX}01`;
const CATEGORY_MINTING = `0x${CATEGORY_HEX}02`;
const P2SH = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (value) => encodeDataPush(bigIntToVmNumber(BigInt(value)));

const padBytes = (total) => {
  const bytes = Math.max(2, total);
  const dataLength = bytes <= 76 ? bytes - 1 : bytes <= 257 ? bytes - 2 : bytes - 3;
  return encodeDataPush(new Uint8Array(dataLength));
};
const TUNE_SLACK = Number(process.env.TUNE_SLACK ?? 96);
const tunedLength = (fixedLength, operationCost) => Math.min(
  TARGET_UNLOCK,
  Math.max(fixedLength + 2, Math.ceil(operationCost / 800) - 41 + TUNE_SLACK),
);
const token = (category, capability, commitment) => ({
  amount: 0n,
  category,
  nft: { capability, commitment },
});

function evaluate(locking, unlocking, spec, outLocking, mutation = {}) {
  const kind = spec.kind;
  const inputCategory = mutation.inputCategory ?? CATEGORY;
  const outputCategory = mutation.outputCategory ?? CATEGORY;
  const inputCapability = mutation.inputCapability ?? (kind === 'genesis' ? 'minting' : 'mutable');
  const outputCapability = mutation.outputCapability ?? (kind === 'terminal' ? 'none' : 'mutable');
  const inCommitment = kind === 'genesis' ? new Uint8Array(0) : commitBin(spec.commitLimbs.map(BigInt));
  const outCommitment = kind === 'terminal' ? new Uint8Array(0) : commitBin(spec.outLimbs.map(BigInt));
  const actualOutLocking = mutation.outLocking ?? outLocking;
  const batonLocking = mutation.batonLocking ?? locking;
  const batonCommitment = mutation.batonCommitment ?? new Uint8Array(0);
  const sourceValue = kind === 'genesis' ? 3000n : 1000n;
  const outputs = kind === 'genesis'
    ? [
        { lockingBytecode: actualOutLocking, valueSatoshis: 1000n, token: token(outputCategory, outputCapability, outCommitment) },
        { lockingBytecode: batonLocking, valueSatoshis: 1000n, token: token(inputCategory, 'minting', batonCommitment) },
      ]
    : [{ lockingBytecode: actualOutLocking, valueSatoshis: 1000n, token: token(outputCategory, outputCapability, outCommitment) }];
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: sourceValue, token: token(inputCategory, inputCapability, inCommitment) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs,
      locktime: 0,
    },
  };
  const state = STANDARD_VM.evaluate(program);
  const consensusState = CONSENSUS_VM.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 && top?.length === 1 && top[0] === 1,
    operationCost: consensusState.metrics.operationCost,
    error: state.error ?? null,
  };
}

const lifecycleLines = (kind) => {
  if (kind === 'genesis') return [
    '        require(tx.inputs.length == 1); require(tx.outputs.length == 2);',
    `        require(tx.inputs[this.activeInputIndex].tokenCategory == ${CATEGORY_MINTING});`,
    '        require(tx.inputs[this.activeInputIndex].nftCommitment.length == 0);',
    `        require(tx.outputs[0].tokenCategory == ${CATEGORY_MUTABLE});`,
    `        require(tx.outputs[1].tokenCategory == ${CATEGORY_MINTING});`,
    '        require(tx.outputs[1].nftCommitment.length == 0);',
    '        require(tx.outputs[1].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode);',
  ];
  if (kind === 'terminal') return [
    '        require(tx.inputs.length == 1); require(tx.outputs.length == 1);',
    `        require(tx.inputs[this.activeInputIndex].tokenCategory == ${CATEGORY_MUTABLE});`,
    `        require(tx.outputs[0].tokenCategory == ${CATEGORY_IMMUTABLE});`,
    '        require(tx.outputs[0].nftCommitment.length == 0);',
    '        require(tx.outputs[0].lockingBytecode == tx.inputs[this.activeInputIndex].lockingBytecode);',
  ];
  return [
    '        require(tx.inputs.length == 1); require(tx.outputs.length == 1);',
    `        require(tx.inputs[this.activeInputIndex].tokenCategory == ${CATEGORY_MUTABLE});`,
    `        require(tx.outputs[0].tokenCategory == ${CATEGORY_MUTABLE});`,
  ];
};

function bindContract(spec, nextLocking) {
  let lines = readFileSync(spec.cashFile, 'utf8').split('\n');
  if (spec.kind === 'genesis') {
    const commitmentLine = lines.findIndex((line) => line.includes('tx.inputs[this.activeInputIndex].nftCommitment == hash256('));
    if (commitmentLine < 0) throw new Error(`genesis covenant input check not found in ${spec.cashFile}`);
    lines.splice(commitmentLine, 1);
    lines = lines.filter((line) => !line.includes('tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory'));
  }
  const functionClose = lines.lastIndexOf('    }');
  if (functionClose < 0 || lines[functionClose + 1] !== '}') throw new Error(`contract close not found in ${spec.cashFile}`);
  const additions = lifecycleLines(spec.kind);
  if (spec.kind !== 'terminal') {
    if (nextLocking === undefined) throw new Error(`missing successor locking for ${spec.label}`);
    additions.push(`        require(hash256(tx.outputs[0].lockingBytecode) == 0x${binToHex(hash256(nextLocking))});`);
  }
  lines.splice(functionClose, 0, ...additions);
  const suffix = nextLocking === undefined ? 'terminal' : binToHex(hash256(nextLocking)).slice(0, 16);
  const path = join(dirname(spec.cashFile), `._covenant_${basename(spec.cashFile, '.cash')}_${suffix}.cash`);
  writeFileSync(path, lines.join('\n'));
  return path;
}

const compiledCache = new Map();
function compiledVariants(spec, nextLocking) {
  const key = `${spec.cashFile}|${spec.kind}|${nextLocking === undefined ? 'terminal' : binToHex(nextLocking)}`;
  const cached = compiledCache.get(key);
  if (cached !== undefined) return { key, variants: cached };
  const path = bindContract(spec, nextLocking);
  try {
    const rescheduled = compileFileBytecode(path);
    const raw = compileFileBytecodeRaw(path);
    const variants = binToHex(rescheduled) === binToHex(raw) ? [rescheduled] : [rescheduled, raw];
    compiledCache.set(key, variants);
    return { key, variants };
  } finally {
    unlinkSync(path);
  }
}

function evaluateCompiled(contract, spec, nextLocking) {
  const redeem = Uint8Array.from(contract);
  const locking = P2SH(redeem);
  const redeemPush = encodeDataPush(redeem);
  const pushArgs = spec.allArgs ?? spec.commitLimbs;
  const argumentBytes = Uint8Array.from([...pushArgs].reverse().flatMap((value) => [...pushInt(value)]));
  const fixedLength = argumentBytes.length + redeemPush.length;
  const makeUnlocking = (target) => Uint8Array.from([
    ...padBytes(target - fixedLength),
    ...argumentBytes,
    ...redeemPush,
  ]);
  const makeUnlockingForArgs = (args, target) => {
    const bytes = Uint8Array.from([...args].reverse().flatMap((value) => [...pushInt(value)]));
    return Uint8Array.from([
      ...padBytes(target - bytes.length - redeemPush.length),
      ...bytes,
      ...redeemPush,
    ]);
  };
  const outLocking = spec.kind === 'terminal' ? locking : nextLocking;
  if (outLocking === undefined) throw new Error(`missing output locking for ${spec.label}`);
  const probe = evaluate(locking, makeUnlocking(TARGET_UNLOCK), spec, outLocking);
  let target = tunedLength(fixedLength, probe.operationCost);
  let unlocking = makeUnlocking(target);
  let result = evaluate(locking, unlocking, spec, outLocking);
  while (!result.accepted && target < TARGET_UNLOCK) {
    target = Math.min(TARGET_UNLOCK, target + 128);
    unlocking = makeUnlocking(target);
    result = evaluate(locking, unlocking, spec, outLocking);
  }

  const invalidArgs = [...pushArgs];
  invalidArgs[0] = BigInt(invalidArgs[0]) + 1n;
  const invalidUnlocking = makeUnlockingForArgs(invalidArgs, target);
  const stateMutationRejected = !evaluate(locking, invalidUnlocking, spec, outLocking).accepted;

  const wrongLocking = Uint8Array.from(outLocking);
  wrongLocking[wrongLocking.length - 1] ^= 1;
  const wrongLockRejected = !evaluate(locking, unlocking, spec, outLocking, { outLocking: wrongLocking }).accepted;
  const wrongCategory = Uint8Array.from(CATEGORY);
  wrongCategory[0] ^= 1;
  const categoryRejected = !evaluate(locking, unlocking, spec, outLocking, {
    inputCategory: wrongCategory,
    outputCategory: wrongCategory,
  }).accepted;
  const wrongCapability = spec.kind === 'terminal' ? 'mutable' : spec.kind === 'genesis' ? 'minting' : 'none';
  const capabilityRejected = !evaluate(locking, unlocking, spec, outLocking, { outputCapability: wrongCapability }).accepted;
  const inputCapabilityRejected = !evaluate(locking, unlocking, spec, outLocking, {
    inputCapability: spec.kind === 'genesis' ? 'mutable' : 'minting',
  }).accepted;
  let batonCommitmentRejected = true;
  let batonLockingRejected = true;
  if (spec.kind === 'genesis') {
    batonCommitmentRejected = !evaluate(locking, unlocking, spec, outLocking, {
      batonCommitment: new Uint8Array([1]),
    }).accepted;
    const wrongBatonLocking = Uint8Array.from(locking);
    wrongBatonLocking[wrongBatonLocking.length - 1] ^= 1;
    batonLockingRejected = !evaluate(locking, unlocking, spec, outLocking, {
      batonLocking: wrongBatonLocking,
    }).accepted;
  }
  let residueRangeRejected = true;
  if (spec.residueGenesis === true) {
    const cOffset = spec.commitLimbs.length;
    const rangeMutations = [
      [cOffset, -1n],
      [cOffset, FIELD_ORDER],
      [cOffset + 12, -1n],
      [cOffset + 12, FIELD_ORDER],
    ];
    residueRangeRejected = rangeMutations.every(([offset, value]) => {
      const args = [...pushArgs];
      args[offset] = value;
      return !evaluate(locking, makeUnlockingForArgs(args, target), spec, outLocking).accepted;
    });
  }
  const budget = (41 + unlocking.length) * 800;
  const fits = locking.length <= 201 && unlocking.length <= TARGET_UNLOCK && result.operationCost <= budget && result.accepted;
  return {
    step: {
      label: spec.label,
      locking: binToHex(locking),
      unlocking: binToHex(unlocking),
      invalidUnlocking: binToHex(invalidUnlocking),
      checkpoint: spec.checkpoint,
      kind: spec.kind,
      covenant: {
        category: CATEGORY_HEX,
        capability: spec.kind === 'terminal' ? 'none' : 'mutable',
        inCommitment: spec.kind === 'genesis' ? '' : binToHex(commitBin(spec.commitLimbs.map(BigInt))),
        outCommitment: spec.kind === 'terminal' ? '' : binToHex(commitBin(spec.outLimbs.map(BigInt))),
        outLockingBytecode: binToHex(outLocking),
      },
      lockingBytes: locking.length,
      unlockingBytes: unlocking.length,
      operationCost: result.operationCost,
    },
    accepted: result.accepted,
    rejectedChecks: stateMutationRejected && wrongLockRejected && categoryRejected && capabilityRejected &&
      inputCapabilityRejected && batonCommitmentRejected && batonLockingRejected && residueRangeRejected,
    fits,
    error: result.error,
  };
}

const chosenCache = new Map();
const stats = { maxLock: 0, maxUnlock: 0, maxOp: 0, allFit: true, allAccept: true, allRejected: true };
function buildStep(spec, nextLocking, countStats) {
  const { key, variants } = compiledVariants(spec, nextLocking);
  let chosen = chosenCache.get(key);
  if (chosen === undefined) {
    const measured = variants.map((contract) => ({ contract, result: evaluateCompiled(contract, spec, nextLocking) }));
    measured.sort((a, b) => {
      const scoreA = a.result.fits ? a.result.step.lockingBytes + a.result.step.unlockingBytes : Infinity;
      const scoreB = b.result.fits ? b.result.step.lockingBytes + b.result.step.unlockingBytes : Infinity;
      return scoreA - scoreB;
    });
    chosen = measured[0].contract;
    chosenCache.set(key, chosen);
  }
  const result = evaluateCompiled(chosen, spec, nextLocking);
  if (countStats) {
    stats.maxLock = Math.max(stats.maxLock, result.step.lockingBytes);
    stats.maxUnlock = Math.max(stats.maxUnlock, result.step.unlockingBytes);
    stats.maxOp = Math.max(stats.maxOp, result.step.operationCost);
    stats.allFit &&= result.fits;
    stats.allAccept &&= result.accepted;
    stats.allRejected &&= result.rejectedChecks;
  }
  return result;
}

function buildChain(specs, { countStats = false, tailLocking, expectRejected = false } = {}) {
  const steps = new Array(specs.length);
  const results = new Array(specs.length);
  let nextLocking = tailLocking;
  for (let index = specs.length - 1; index >= 0; index--) {
    const spec = specs[index];
    const result = buildStep(spec, nextLocking, countStats);
    steps[index] = result.step;
    results[index] = result;
    nextLocking = hexToBin(result.step.locking);
  }
  for (let index = 0; index + 1 < steps.length; index++) {
    if (steps[index].covenant.outCommitment !== steps[index + 1].covenant.inCommitment) {
      throw new Error(`commitment seam mismatch after ${steps[index].label}`);
    }
    if (steps[index].covenant.outLockingBytecode !== steps[index + 1].locking) {
      throw new Error(`locking seam mismatch after ${steps[index].label}`);
    }
  }
  const accepted = results.every((result) => result.accepted);
  if (expectRejected ? accepted : !accepted) {
    throw new Error(expectRejected ? 'invalid chain unexpectedly accepted' : 'valid chain rejected');
  }
  return steps;
}

function parseProofUnlocking(hex) {
  const bytes = hexToBin(hex);
  const values = [];
  let offset = 0;
  while (offset < bytes.length) {
    const opcode = bytes[offset++];
    if (opcode === 0) values.push(0n);
    else if (opcode === 0x4f) values.push(-1n);
    else if (opcode >= 0x51 && opcode <= 0x60) values.push(BigInt(opcode - 0x50));
    else {
      let length;
      if (opcode <= 75) length = opcode;
      else if (opcode === 0x4c) length = bytes[offset++];
      else if (opcode === 0x4d) { length = bytes[offset] | (bytes[offset + 1] << 8); offset += 2; }
      else throw new Error('unsupported proof unlocking push');
      values.push(vmNumberToBigInt(bytes.slice(offset, offset + length), { requireMinimalEncoding: false }));
      offset += length;
    }
  }
  const d = values.reverse();
  return {
    proof: proofFromLimbs(d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]),
    inputs: [d[8], d[9]],
  };
}

const multiproof = JSON.parse(readFileSync(verifierPath('src', 'bch', 'groth16-singleton-multiproof-vectors.json'), 'utf8'));
const second = parseProofUnlocking(multiproof.proofs[1].unlocking);
const dense = parseProofUnlocking(multiproof.worstCaseProof.unlocking);
const INSTANCES = [
  { tag: 'committed', proof, inputs: vec.publicInputs.map(BigInt) },
  { tag: 'second', ...second },
  { tag: 'dense', ...dense },
];

const proofTuple = (instance, override = {}) => {
  const A = instance.proof.a.negate().toAffine();
  const B = instance.proof.b.toAffine();
  const C = instance.proof.c.toAffine();
  return [
    override.Ax ?? A.x, override.Ay ?? A.y,
    override.Bx?.c0 ?? B.x.c0, override.Bx?.c1 ?? B.x.c1,
    override.By?.c0 ?? B.y.c0, override.By?.c1 ?? B.y.c1,
    override.Cx ?? C.x, override.Cy ?? C.y,
  ];
};
const g2State = (point, tuple) => [point[0][0], point[0][1], point[1][0], point[1][1], point[2][0], point[2][1], ...tuple];

function g2Specs(instance, override = {}) {
  const tuple = proofTuple(instance, override);
  const B = [[tuple[2], tuple[3]], [tuple[4], tuple[5]]];
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  assertG2StageManifest(manifest);
  if (manifest.numChunks !== 3) {
    throw new Error('G2 manifest is not the expected stage-bound fast-endo layout');
  }
  const inverse = g2checkFastZinv(B);
  return manifest.chunks.map((chunk, index) => {
    const commitLimbs = chunk.first ? tuple : g2State(g2checkAccAt(B, chunk.lo), tuple);
    return {
      cashFile: join(GEN, `g2check_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs: chunk.last ? tuple : g2State(g2checkAccAt(B, chunk.hi), tuple),
      allArgs: chunk.last ? [...commitLimbs, ...inverse] : commitLimbs,
      label: `g2check bits[${chunk.lo},${chunk.hi})${chunk.last ? ' subgroup verdict' : ''}`,
      checkpoint: index === 0 ? 'validate-inputs' : undefined,
      kind: index === 0 ? 'genesis' : 'forward',
    };
  });
}

function glvSpecs(instance) {
  const tuple = proofTuple(instance);
  const [in0, in1] = instance.inputs.map(BigInt);
  if (in0 < 0n || in0 >= SCALAR_ORDER || in1 < 0n || in1 >= SCALAR_ORDER) throw new Error(`${instance.tag} has noncanonical public inputs`);
  const [k10, k20] = glvDecompose(in0);
  const [k11, k21] = glvDecompose(in1);
  const genesis = [in0, in1, k10, k20, k11, k21];
  const stateAt = (position) => [...vkxGlvStateAt(k10, k20, k11, k21, position), ...genesis, ...tuple];
  const vkx = pairsFor(instance.inputs, instance.proof)[2].P.toAffine();
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (
    manifest.glv !== true || manifest.stageBound !== true || manifest.covenantResidue !== true ||
    manifest.exactProofHandoff !== true || manifest.numChunks !== 4 ||
    JSON.stringify(manifest.stageLayout) !== JSON.stringify(['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'vkxX', 'vkxY'])
  ) {
    throw new Error('GLV manifest is not the covenant-residue layout');
  }
  return manifest.chunks.map((chunk) => {
    const commitLimbs = chunk.first ? tuple : stateAt(chunk.lo);
    const outLimbs = chunk.final ? [...tuple, vkx.x, vkx.y] : stateAt(chunk.hi);
    return {
      cashFile: join(GEN, `vkxglv_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs,
      allArgs: chunk.first
        ? [...tuple, ...genesis]
        : chunk.final ? [...commitLimbs, vkxGlvZinv(k10, k20, k11, k21)] : commitLimbs,
      label: `vk_x GLV [${chunk.lo},${chunk.hi})${chunk.final ? ' bind (-A,B,C,vk_x)' : ''}`,
      checkpoint: chunk.final ? 'vk_x' : undefined,
      kind: 'forward',
    };
  });
}

const millerState = (state) => [...f12limbs(state.f), ...r6limbs(state.Rs[0]), ...f12limbs(state.c), ...f12limbs(state.cInv)];
function millerSpecs(instance) {
  const pairs = pairsFor(instance.inputs, instance.proof);
  const pointLimbs = pairs.flatMap((pair, index) => ptLimbs(index, pair.P.toAffine(), pair.Q.toAffine()));
  const stage = [...pointLimbs.slice(0, 6), ...pointLimbs.slice(8, 10), ...pointLimbs.slice(6, 8)];
  const rawBoundary = millerBatchOps(pairs).boundary;
  const { c, cInv, w } = residueWitness(rawBoundary);
  const trace = millerFusedOps(pairs, c, cInv);
  const withPoints = (limbs) => [...limbs.slice(0, 18), ...pointLimbs, ...limbs.slice(18)];
  const inputState = (position) => position === 0
    ? [...stage, ...fp12limbsOf(c), ...fp12limbsOf(cInv)]
    : withPoints(millerState(trace.states[position]));
  const outputState = (position) => position === trace.states.length - 1
    ? [...fp12limbsOf(trace.states[position].f), ...fp12limbsOf(c), ...fp12limbsOf(cInv)]
    : withPoints(millerState(trace.states[position]));
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (manifest.fused !== true || manifest.stageBound !== true || manifest.covenantResidue !== true || manifest.numOps !== trace.ops.length) {
    throw new Error('fused Miller manifest does not match the stage-bound trace');
  }
  return manifest.chunks.map((chunk) => {
    const allState = inputState(chunk.opLo);
    const commitLimbs = chunk.opLo === 0 ? stage : allState;
    const tailFused = chunk.tailFused === true;
    return {
      cashFile: join(GEN, `millerres_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs: tailFused ? [] : outputState(chunk.opHi),
      allArgs: tailFused
        ? [...allState, ...fp12limbsOf(w)]
        : chunk.opLo === 0 ? allState : commitLimbs,
      label: `fused Miller ops[${chunk.opLo},${chunk.opHi})${tailFused ? ' + residue verdict' : ''}`,
      checkpoint: tailFused ? 'verify' : undefined,
      kind: tailFused ? 'terminal' : 'forward',
      residueGenesis: chunk.opLo === 0,
    };
  });
}

function fullSpecs(instance) {
  const g2 = g2Specs(instance);
  const glv = glvSpecs(instance);
  const miller = millerSpecs(instance);
  if (miller[miller.length - 1].kind !== 'terminal') throw new Error('the residue verdict must be fused into the final Miller chunk');
  return { g2, glv, miller, all: [...g2, ...glv, ...miller] };
}

const committedSpecs = fullSpecs(INSTANCES[0]);
const committed = buildChain(committedSpecs.all, { countStats: true });
const secondRun = buildChain(fullSpecs(INSTANCES[1]).all);
const denseRun = buildChain(fullSpecs(INSTANCES[2]).all);

for (const run of [secondRun, denseRun]) {
  if (run.length !== committed.length || run.some((step, index) => step.locking !== committed[index].locking)) {
    throw new Error('valid proof runs do not share one locking graph');
  }
}

function invalidPointOverrides(instance) {
  const tuple = proofTuple(instance);
  const nonCanonicalA = { Ax: tuple[0] + FIELD_ORDER };
  const offCurveA = { Ay: (tuple[1] + 1n) % FIELD_ORDER };
  const offCurveC = { Cy: (tuple[7] + 1n) % FIELD_ORDER };
  const twistB = Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n]));
  let offSubgroup;
  for (let value = 1n; value < 400n && offSubgroup === undefined; value++) {
    const x = Fp2.fromBigTuple([value, 0n]);
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), twistB);
    let y;
    try { y = Fp2.sqrt(rhs); } catch { continue; }
    if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
    try { bn254.G2.Point.fromAffine({ x, y }).assertValidity(); }
    catch { offSubgroup = { Bx: x, By: y }; }
  }
  if (offSubgroup === undefined) throw new Error('failed to construct an off-subgroup G2 point');
  return { nonCanonicalA, offCurveA, offCurveC, offSubgroupB: offSubgroup };
}

const firstGlvLocking = hexToBin(committed[committedSpecs.g2.length].locking);
const invalidInputSteps = Object.fromEntries(
  Object.entries(invalidPointOverrides(INSTANCES[0])).map(([name, override]) => [
    name,
    buildChain(g2Specs(INSTANCES[0], override), { tailLocking: firstGlvLocking, expectRejected: true }),
  ]),
);

// A proof-stage splice must fail at the exact G2 -> GLV commitment seam.
const g2End = committedSpecs.g2[committedSpecs.g2.length - 1].outLimbs;
const secondGlvStart = glvSpecs(INSTANCES[1])[0];
const spliced = { ...secondGlvStart, commitLimbs: g2End };
const spliceResult = buildStep(spliced, hexToBin(secondRun[committedSpecs.g2.length + 1].locking), false);
if (spliceResult.accepted) throw new Error('cross-stage proof splice was accepted');

const glvEnd = committedSpecs.glv[committedSpecs.glv.length - 1].outLimbs;
const secondMillerStart = millerSpecs(INSTANCES[1])[0];
const splicedMiller = { ...secondMillerStart, commitLimbs: glvEnd };
const secondMillerOffset = committedSpecs.g2.length + committedSpecs.glv.length;
const millerSpliceResult = buildStep(splicedMiller, hexToBin(secondRun[secondMillerOffset + 1].locking), false);
if (millerSpliceResult.accepted) throw new Error('GLV-to-Miller proof splice was accepted');

const sum = (steps, key) => steps.reduce((total, step) => total + step[key], 0);
const totalBytes = sum(committed, 'lockingBytes') + sum(committed, 'unlockingBytes');
const totalOperationCost = sum(committed, 'operationCost');
if (!stats.allFit || !stats.allAccept || !stats.allRejected) {
  throw new Error('validity, standardness, or negative-case gates failed; refusing to write vectors');
}

const output = verifierPath('src', 'bch', 'groth16-chunked-covenant-residue-vectors.json');
writeFileSync(output, JSON.stringify({
  description: 'Source-reproducible BN254 Groth16 covenant-residue verifier: minting-baton fast-G2 genesis -> GLV vk_x with the validated proof tuple carried in the mutable NFT state -> stage-bound prepared-VK Miller with c^-(6x+2) folded into the loop -> witnessed residue verdict fused into the terminal chunk. Canonical 32-byte BN254 state limbs, exact commitment seams, P2SH32 successor pins, and an immutable verdict output. Every step and every negative fixture is evaluated on the standard BCH 2026 VM.',
  proofBinding: 'runtime',
  stateBytes: 32,
  numSteps: committed.length,
  budgetPerInput: (41 + TARGET_UNLOCK) * 800,
  totalOperationCost,
  maxStepOperationCost: stats.maxOp,
  totalBytes,
  totalLockingBytes: sum(committed, 'lockingBytes'),
  totalUnlockingBytes: sum(committed, 'unlockingBytes'),
  allAccept: stats.allAccept,
  allInvalidRejected: stats.allRejected,
  verification: {
    vm: 'BCH_2026 standard',
    validProofRuns: 3,
    oneLockingGraph: true,
    stateArgumentMutationsRejected: committed.length,
    wrongSuccessorLockingsRejected: committed.length - 1,
    terminalSelfLockMutationsRejected: 1,
    categoryAndCapabilityMutationsRejected: committed.length * 3,
    genesisBatonMutationsRejected: 2,
    residueRangeMutationsRejected: 4,
    stageSplicesRejected: 2,
    nonCanonicalCoordinatesRejected: 1,
    isolatedInvalidPointsRejected: Object.keys(invalidInputSteps).length,
  },
  steps: committed,
  extraProofSteps: secondRun,
  worstCaseSteps: denseRun,
  invalidInputSteps,
}, null, 2));

console.error(`covenant residue: ${committed.length} steps, ${totalBytes.toLocaleString()} bytes, ${totalOperationCost.toLocaleString()} op`);
console.error(`max locking ${stats.maxLock} B, max unlocking ${stats.maxUnlock} B, max op ${stats.maxOp.toLocaleString()}`);
console.error(`wrote ${output}`);
