// Build the source-owned BLS12-381 covenant-residue benchmark artifact.
//
// One fixed P2SH32 locking graph verifies every proof for the configured VK:
//   five-window full-stage GLV vk_x (minting-baton genesis)
//     -> input-validation-fused prepared Miller with c^-|x| folded into the loop
//     -> the one-input Fp6 membership and immutable terminal verdict.
//
// Each nonterminal redeem pins its successor locking. The contracts enforce the token
// lifecycle: minting baton -> mutable thread (plus recreated baton), mutable forward
// steps, then one immutable terminal output.
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Fp12, f12limbs, r6limbs, pairsFor, ptLimbs, millerBatchOps,
  commitBinExact, CATEGORY, P, TARGET_UNLOCK, verifierPath,
} from './_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { compileFileBytecode, compileFileBytecodeRaw, computeVkx } from './_vkxmath.mjs';
import { fp12limbsOf, frob, millerFusedOps, mk12, residueWitness } from './_residuemath.mjs';
import {
  GLV_HIGH_COST_INPUTS, GLV_SHARED_AUDITED_BOUNDS, GLV_TABLE_HEX,
  glvDecompose, regenGlvSharedAudited, vkxGlvStateAt, vkxGlvZinv,
} from './gen_vkx_glv.mjs';
import {
  bigIntToVmNumber, binToHex, createVirtualMachineBch2026, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, hexToBin,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const STANDARD_VM = createVirtualMachineBch2026(true);
const CONSENSUS_VM = createVirtualMachineBch2026(false);
const SCALAR_ORDER = bls12_381.fields.Fr.ORDER;
const CATEGORY_HEX = binToHex(CATEGORY);
const CATEGORY_IMMUTABLE = `0x${CATEGORY_HEX}`;
const CATEGORY_MUTABLE = `0x${CATEGORY_HEX}01`;
const CATEGORY_MINTING = `0x${CATEGORY_HEX}02`;
const P2SH = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (value) => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const token = (category, capability, commitment) => ({
  amount: 0n,
  category,
  nft: { capability, commitment },
});

// The generated contracts absorb a leading, minimally encoded zero push in their final bytes
// argument. Return the shortest such push whose encoded length buys at least `minimum` bytes.
const paddingForMinimum = (minimum) => {
  const target = Math.max(2, minimum);
  let dataLength = Math.max(1, target - 5);
  let encoded = encodeDataPush(new Uint8Array(dataLength));
  while (encoded.length < target) {
    dataLength++;
    encoded = encodeDataPush(new Uint8Array(dataLength));
  }
  return encoded;
};

function evaluate(locking, unlocking, spec, outLocking, mutation = {}) {
  const inputCategory = mutation.inputCategory ?? CATEGORY;
  const outputCategory = mutation.outputCategory ?? CATEGORY;
  const inputCapability = mutation.inputCapability ?? (spec.kind === 'genesis' ? 'minting' : 'mutable');
  const outputCapability = mutation.outputCapability ?? (spec.kind === 'terminal' ? 'none' : 'mutable');
  const inCommitment = spec.kind === 'genesis'
    ? new Uint8Array(0)
    : commitBinExact(spec.commitLimbs.map(BigInt));
  const outCommitment = spec.kind === 'terminal'
    ? new Uint8Array(0)
    : commitBinExact(spec.outLimbs.map(BigInt));
  const actualOutLocking = mutation.outLocking ?? outLocking;
  const batonLocking = mutation.batonLocking ?? locking;
  const batonCommitment = mutation.batonCommitment ?? new Uint8Array(0);
  const sourceValue = spec.kind === 'genesis' ? 3000n : 1000n;
  const outputs = spec.kind === 'genesis'
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
  const standardState = STANDARD_VM.evaluate(program);
  const consensusState = CONSENSUS_VM.evaluate(program);
  const top = standardState.stack[standardState.stack.length - 1];
  return {
    accepted: standardState.error === undefined && standardState.stack.length === 1 && top?.length === 1 && top[0] === 1,
    operationCost: consensusState.metrics.operationCost,
    error: standardState.error ?? null,
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

function evaluateCompiled(contract, spec, nextLocking, { verifyMutations, forcedLength } = {}) {
  const redeem = Uint8Array.from(contract);
  const locking = P2SH(redeem);
  const redeemPush = encodeDataPush(redeem);
  const pushArgs = spec.allArgs ?? spec.commitLimbs;
  const argumentBytes = (args) => Uint8Array.from([...args].reverse().flatMap((value) => [...pushInt(value)]));
  const makeUnlocking = (args, minimumLength) => {
    const bytes = argumentBytes(args);
    return Uint8Array.from([
      ...paddingForMinimum(minimumLength - bytes.length - redeemPush.length),
      ...bytes,
      ...redeemPush,
    ]);
  };
  const outLocking = spec.kind === 'terminal' ? locking : nextLocking;
  if (outLocking === undefined) throw new Error(`missing output locking for ${spec.label}`);

  let unlocking;
  let result;
  if (forcedLength !== undefined) {
    unlocking = makeUnlocking(pushArgs, forcedLength);
    result = evaluate(locking, unlocking, spec, outLocking);
  } else {
    const probeUnlocking = makeUnlocking(pushArgs, TARGET_UNLOCK);
    const probe = evaluate(locking, probeUnlocking, spec, outLocking);
    let minimumLength = Math.max(
      argumentBytes(pushArgs).length + redeemPush.length + 2,
      Math.ceil(probe.operationCost / 800) - 41,
    );
    unlocking = makeUnlocking(pushArgs, minimumLength);
    result = evaluate(locking, unlocking, spec, outLocking);
    while (!result.accepted && unlocking.length < TARGET_UNLOCK) {
      minimumLength++;
      unlocking = makeUnlocking(pushArgs, minimumLength);
      result = evaluate(locking, unlocking, spec, outLocking);
    }
  }

  let mutationsRejected = true;
  let invalidUnlocking = unlocking;
  if (verifyMutations) {
    const invalidArgs = [...pushArgs];
    invalidArgs[0] = BigInt(invalidArgs[0]) + 1n;
    invalidUnlocking = makeUnlocking(invalidArgs, unlocking.length);
    const stateMutationRejected = !evaluate(locking, invalidUnlocking, spec, outLocking).accepted;

    const wrongLocking = Uint8Array.from(outLocking);
    wrongLocking[wrongLocking.length - 1] ^= 1;
    const wrongLockRejected = !evaluate(locking, unlocking, spec, outLocking, { outLocking: wrongLocking }).accepted;

    const wrongInputCategory = Uint8Array.from(CATEGORY);
    wrongInputCategory[0] ^= 1;
    const inputCategoryRejected = !evaluate(locking, unlocking, spec, outLocking, { inputCategory: wrongInputCategory }).accepted;
    const wrongOutputCategory = Uint8Array.from(CATEGORY);
    wrongOutputCategory[0] ^= 1;
    const outputCategoryRejected = !evaluate(locking, unlocking, spec, outLocking, { outputCategory: wrongOutputCategory }).accepted;
    const inputCapabilityRejected = !evaluate(locking, unlocking, spec, outLocking, {
      inputCapability: spec.kind === 'genesis' ? 'mutable' : 'minting',
    }).accepted;
    const outputCapabilityRejected = !evaluate(locking, unlocking, spec, outLocking, {
      outputCapability: spec.kind === 'terminal' ? 'mutable' : 'none',
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

    let millerRangesRejected = true;
    if (spec.millerGenesis === true) {
      millerRangesRejected = [[0, -1n], [0, P], [12, -1n], [12, P]].every(([offset, value]) => {
        const args = [...pushArgs];
        args[offset] = value;
        return !evaluate(locking, makeUnlocking(args, unlocking.length), spec, outLocking).accepted;
      });
    }
    let witnessRangesRejected = true;
    if (spec.tailGenesis === true) {
      witnessRangesRejected = [[36, -1n], [36, P]].every(([offset, value]) => {
        const args = [...pushArgs];
        args[offset] = value;
        return !evaluate(locking, makeUnlocking(args, unlocking.length), spec, outLocking).accepted;
      });
    }
    mutationsRejected = stateMutationRejected && wrongLockRejected && inputCategoryRejected &&
      outputCategoryRejected && inputCapabilityRejected && outputCapabilityRejected &&
      batonCommitmentRejected && batonLockingRejected && millerRangesRejected && witnessRangesRejected;
  }

  const budget = (41 + unlocking.length) * 800;
  const fits = locking.length <= 201 && unlocking.length <= TARGET_UNLOCK &&
    result.operationCost <= budget && result.accepted;
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
        inCommitment: spec.kind === 'genesis' ? '' : binToHex(commitBinExact(spec.commitLimbs.map(BigInt))),
        outCommitment: spec.kind === 'terminal' ? '' : binToHex(commitBinExact(spec.outLimbs.map(BigInt))),
        outLockingBytecode: binToHex(outLocking),
      },
      lockingBytes: locking.length,
      unlockingBytes: unlocking.length,
      operationCost: result.operationCost,
    },
    accepted: result.accepted,
    fits,
    mutationsRejected,
    error: result.error,
  };
}

const chosenCache = new Map();
const stats = { maxLock: 0, maxUnlock: 0, maxOp: 0, allFit: true, allAccept: true, allRejected: true };
function buildStep(spec, nextLocking, { recordStats = false, expectValid = true, tuneInvalid = false } = {}) {
  const { key, variants } = compiledVariants(spec, nextLocking);
  let chosen = chosenCache.get(key);
  if (chosen === undefined) {
    if (!expectValid && !tuneInvalid) throw new Error(`invalid fixture reached an unmeasured locking: ${spec.label}`);
    const measured = variants.map((contract) => ({
      contract,
      result: evaluateCompiled(contract, spec, nextLocking, { verifyMutations: false }),
    }));
    measured.sort((a, b) => {
      const scoreA = a.result.fits ? a.result.step.lockingBytes + a.result.step.unlockingBytes : Infinity;
      const scoreB = b.result.fits ? b.result.step.lockingBytes + b.result.step.unlockingBytes : Infinity;
      return scoreA - scoreB;
    });
    chosen = measured[0].contract;
    chosenCache.set(key, chosen);
  }
  const result = evaluateCompiled(chosen, spec, nextLocking, {
    verifyMutations: expectValid,
    forcedLength: expectValid || tuneInvalid ? undefined : TARGET_UNLOCK,
  });
  if (recordStats) {
    stats.maxLock = Math.max(stats.maxLock, result.step.lockingBytes);
    stats.maxUnlock = Math.max(stats.maxUnlock, result.step.unlockingBytes);
    stats.maxOp = Math.max(stats.maxOp, result.step.operationCost);
    stats.allFit &&= result.fits;
    stats.allAccept &&= result.accepted;
    stats.allRejected &&= result.mutationsRejected;
  }
  return result;
}

function buildChain(specs, { recordStats = false, tailLocking, rejectAt } = {}) {
  const steps = new Array(specs.length);
  const results = new Array(specs.length);
  let nextLocking = tailLocking;
  for (let index = specs.length - 1; index >= 0; index--) {
    const expectValid = rejectAt === undefined;
    const tuneInvalid = rejectAt !== undefined && index < rejectAt;
    const result = buildStep(specs[index], nextLocking, { recordStats, expectValid, tuneInvalid });
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
  if (rejectAt === undefined) {
    if (results.some((result) => !result.accepted || !result.fits || !result.mutationsRejected)) {
      throw new Error('valid chain failed its standardness or mutation gates');
    }
  } else {
    const earlyReject = results.slice(0, rejectAt).findIndex((result) => !result.accepted);
    if (earlyReject >= 0) {
      throw new Error(`fixture rejected at ${steps[earlyReject].label} before ${steps[rejectAt].label}: ${results[earlyReject].error ?? 'false result'}`);
    }
    if (results[rejectAt].accepted) throw new Error(`fixture accepted at ${steps[rejectAt].label}`);
  }
  return { steps, results };
}

const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;
const Fr = bls12_381.fields.Fr;
const modR = (value) => ((value % SCALAR_ORDER) + SCALAR_ORDER) % SCALAR_ORDER;
const mkInstance = (inputs, bScalar = 1n, cScalar = 13n) => {
  const [in0, in1] = inputs.map(BigInt);
  const vkxScalar = modR(2n + in0 * 4n + in1 * 6n);
  const rhs = modR(3n * 5n + vkxScalar * 7n + cScalar * 11n);
  const aScalar = Fr.mul(rhs, Fr.inv(bScalar));
  return {
    inputs,
    proof: {
      a: G1.BASE.multiply(aScalar),
      b: G2.BASE.multiply(bScalar),
      c: G1.BASE.multiply(cScalar),
    },
  };
};
const INSTANCES = [
  { tag: 'committed', inputs: PUBLIC_INPUTS, proof },
  { tag: 'distinct', ...mkInstance([135208n, 67633n], 17n, 19n) },
  { tag: 'dense', ...mkInstance(GLV_HIGH_COST_INPUTS, 23n, 29n) },
];

const stageLimbs = (instance, override = {}) => {
  const A = instance.proof.a.negate().toAffine();
  const B = instance.proof.b.toAffine();
  const C = instance.proof.c.toAffine();
  const vkx = computeVkx(instance.inputs.map(BigInt)).toAffine();
  return [
    override.Ax ?? A.x, override.Ay ?? A.y,
    override.Bx?.c0 ?? B.x.c0, override.Bx?.c1 ?? B.x.c1,
    override.By?.c0 ?? B.y.c0, override.By?.c1 ?? B.y.c1,
    override.Cx ?? C.x, override.Cy ?? C.y,
    override.vkxX ?? vkx.x, override.vkxY ?? vkx.y,
  ];
};

regenGlvSharedAudited(GEN, null, true, true);
function glvSpecs(instance, override = {}) {
  const [in0, in1] = instance.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0);
  const [k11, k21] = glvDecompose(in1);
  const scalars = [in0, in1, k10, k20, k11, k21];
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglvfull.json'), 'utf8'));
  const expectedChunks = GLV_SHARED_AUDITED_BOUNDS.slice(0, -1).map((lo, index) => ({
    idx: index,
    lo,
    hi: GLV_SHARED_AUDITED_BOUNDS[index + 1],
    first: index === 0,
    final: index === GLV_SHARED_AUDITED_BOUNDS.length - 2,
  }));
  if (manifest.curve !== 'BLS12-381' || manifest.glv !== true || manifest.iters !== 128 ||
    manifest.stageBound !== true || manifest.fullStageBound !== true || manifest.sharedTable !== false ||
    manifest.numChunks !== expectedChunks.length || JSON.stringify(manifest.chunks) !== JSON.stringify(expectedChunks)) {
    throw new Error('full GLV manifest is not the canonical five-window stage-bound layout');
  }
  const stage = stageLimbs(instance, override);
  const proofTuple = stage.slice(0, 8);
  return manifest.chunks.map((chunk) => {
    const fullInput = [...vkxGlvStateAt(k10, k20, k11, k21, chunk.lo), ...scalars];
    const commitLimbs = chunk.first ? fullInput.slice(3) : fullInput;
    const outLimbs = chunk.final
      ? stage
      : [...vkxGlvStateAt(k10, k20, k11, k21, chunk.hi), ...scalars];
    const allArgs = chunk.final
      ? [...commitLimbs, vkxGlvZinv(k10, k20, k11, k21), ...proofTuple]
      : commitLimbs;
    const cashFile = join(GEN, `vkxglvfull_${String(chunk.idx).padStart(2, '0')}.cash`);
    if (!readFileSync(cashFile, 'utf8').includes(GLV_TABLE_HEX)) {
      throw new Error('covenant GLV chunk does not embed the exact VK table');
    }
    return {
      cashFile,
      commitLimbs,
      outLimbs,
      allArgs,
      label: `GLV vk_x [${chunk.lo},${chunk.hi})${chunk.final ? ' bind (-A,B,C,vk_x)' : ''}`,
      checkpoint: chunk.first ? 'public-inputs' : chunk.final ? 'vk_x' : undefined,
      kind: chunk.first ? 'genesis' : 'forward',
    };
  });
}

const millerState = (state) => [
  ...f12limbs(state.f),
  ...r6limbs(state.Rs[0]),
  ...f12limbs(state.c),
  ...f12limbs(state.cInv),
];
function millerSpecs(instance, c, cInv, override = {}) {
  const pairs = pairsFor(instance.inputs, instance.proof);
  const trace = millerFusedOps(pairs, c, cInv);
  const pointLimbs = pairs.flatMap((pair, index) => ptLimbs(index, pair.P.toAffine(), pair.Q.toAffine()));
  const stage = stageLimbs(instance, override);
  const hotPoints = [...stage.slice(2, 6), ...stage.slice(0, 2), ...stage.slice(8, 10), ...stage.slice(6, 8)];
  const withPoints = (limbs) => [...limbs.slice(0, 18), ...pointLimbs, ...limbs.slice(18)];
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  const chunksValid = Array.isArray(manifest.chunks) && manifest.chunks.length === manifest.numChunks &&
    manifest.chunks.every((chunk, index) => chunk.idx === index &&
      chunk.opLo === (index === 0 ? 0 : manifest.chunks[index - 1].opHi) &&
      chunk.opHi > chunk.opLo && chunk.opHi <= trace.ops.length &&
      chunk.final === (index === manifest.chunks.length - 1)) &&
    manifest.chunks.at(-1)?.opHi === trace.ops.length;
  if (manifest.fused !== true || manifest.deployment !== 'covenant' || manifest.stageBound !== true ||
    manifest.covenantResidue !== true || manifest.inputValidationFused !== true ||
    manifest.numPairs !== 4 || manifest.numOps !== trace.ops.length || !chunksValid) {
    throw new Error('fused Miller manifest is not the covenant-residue stage-bound layout');
  }
  return manifest.chunks.map((chunk) => {
    const allState = chunk.opLo === 0
      ? [...fp12limbsOf(cInv), ...fp12limbsOf(c), ...hotPoints]
      : withPoints(millerState(trace.states[chunk.opLo]));
    const commitLimbs = chunk.opLo === 0 ? stage : allState;
    const outLimbs = chunk.final
      ? [...fp12limbsOf(trace.states[chunk.opHi].f), ...fp12limbsOf(c), ...fp12limbsOf(cInv)]
      : withPoints(millerState(trace.states[chunk.opHi]));
    return {
      cashFile: join(GEN, `millerres_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs,
      allArgs: chunk.opLo === 0 ? allState : commitLimbs,
      label: `fused Miller ops[${chunk.opLo},${chunk.opHi})${chunk.final ? ' hand off residue state' : ''}`,
      checkpoint: chunk.opLo === 0 ? 'validate-inputs' : chunk.final ? 'miller-boundary' : undefined,
      kind: 'forward',
      millerGenesis: chunk.opLo === 0,
    };
  });
}

function tailSpecs(fF, c, cInv, w) {
  const fLimbs = fp12limbsOf(fF);
  const cLimbs = fp12limbsOf(c);
  const cInvLimbs = fp12limbsOf(cInv);
  const wLimbs = fp12limbsOf(w);
  const handoff = [...fLimbs, ...cLimbs, ...cInvLimbs];
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_finalexpres.json'), 'utf8'));
  const chunk = manifest.chunks?.[0];
  if (manifest.residueTail !== true || manifest.fp6Membership !== true || manifest.deployment !== 'covenant' ||
    manifest.covenantResidue !== true || manifest.numChunks !== 1 || manifest.nwalk !== 0 ||
    chunk?.idx !== 0 || chunk.role !== 'finalize' || chunk.final !== true) {
    throw new Error('covenant BLS residue requires the one-chunk Fp6 tail');
  }
  return [{
    cashFile: join(GEN, 'finalexpres_00.cash'),
    commitLimbs: handoff,
    outLimbs: [],
    allArgs: [...handoff, ...wLimbs],
    label: 'residue Fp6 membership + verdict',
    checkpoint: 'verify',
    kind: 'terminal',
    tailGenesis: true,
  }];
}

function fullSpecs(instance) {
  const pairs = pairsFor(instance.inputs, instance.proof);
  const rawBoundary = millerBatchOps(pairs).boundary;
  const { c, cInv, w } = residueWitness(rawBoundary);
  const glv = glvSpecs(instance);
  const miller = millerSpecs(instance, c, cInv);
  const tail = tailSpecs(millerFusedOps(pairs, c, cInv).boundary, c, cInv, w);
  return { glv, miller, tail, all: [...glv, ...miller, ...tail], witness: { c, cInv, w } };
}

const committedSpecs = fullSpecs(INSTANCES[0]);
const committedRun = buildChain(committedSpecs.all, { recordStats: true });
const secondSpecs = fullSpecs(INSTANCES[1]);
const secondRun = buildChain(secondSpecs.all, { recordStats: true });
const denseSpecs = fullSpecs(INSTANCES[2]);
const denseRun = buildChain(denseSpecs.all, { recordStats: true });

for (const run of [secondRun.steps, denseRun.steps]) {
  if (run.length !== committedRun.steps.length || run.some((step, index) => step.locking !== committedRun.steps[index].locking)) {
    throw new Error('valid proof runs do not share one locking graph');
  }
}

const invalidInputSteps = {};
const firstMillerIndex = committedSpecs.glv.length;
const firstTailIndex = firstMillerIndex + committedSpecs.miller.length;
const secondMillerLocking = hexToBin(committedRun.steps[firstMillerIndex + 1].locking);
const firstTailLocking = hexToBin(committedRun.steps[firstTailIndex].locking);

const invalidStageCases = {
  nonCanonicalA: { Ax: stageLimbs(INSTANCES[0])[0] + P },
  offCurveA: { Ay: (stageLimbs(INSTANCES[0])[1] + 1n) % P },
  offCurveC: { Cy: (stageLimbs(INSTANCES[0])[7] + 1n) % P },
};
for (const [name, override] of Object.entries(invalidStageCases)) {
  const glvFinal = glvSpecs(INSTANCES[0], override).at(-1);
  const millerFirst = millerSpecs(
    INSTANCES[0],
    committedSpecs.witness.c,
    committedSpecs.witness.cInv,
    override,
  )[0];
  invalidInputSteps[name] = buildChain(
    [glvFinal, millerFirst],
    { tailLocking: secondMillerLocking, rejectAt: 1 },
  ).steps;
}

// Construct one ordinary on-curve point outside G2 and the exact order-13 point that exercises
// the fused Miller walk's point-at-infinity guard. Both reuse the committed c/cInv: their Miller
// final chunk must reject before any residue witness is needed.
const Fp2 = bls12_381.fields.Fp2;
const twistB = Fp2.create({ c0: 4n, c1: 4n });
let offSubgroup = null;
for (let value = 1n; value < 800n && offSubgroup === null; value++) {
  const x = Fp2.create({ c0: value, c1: 0n });
  const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), twistB);
  let y;
  try { y = Fp2.sqrt(rhs); } catch { continue; }
  if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); }
  catch { offSubgroup = G2.fromAffine({ x, y }); }
}
if (offSubgroup === null) throw new Error('failed to construct the off-subgroup B fixture');

const subgroupOrder = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const twistCofactor = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n;
let valuation = 0n;
let reducedCofactor = twistCofactor;
while (reducedCofactor % 13n === 0n) {
  valuation++;
  reducedCofactor /= 13n;
}
const cofactorToSylow = (twistCofactor * subgroupOrder) / (13n ** valuation);
const multiplyAny = (point, scalar) => {
  let result = G2.ZERO;
  let base = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if (remaining & 1n) result = result.add(base);
    base = base.double();
    remaining >>= 1n;
  }
  return result;
};
let order13 = null;
for (let value = 1n; value < 300n && order13 === null; value++) {
  const x = Fp2.create({ c0: value, c1: 1n });
  const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), twistB);
  let y;
  try { y = Fp2.sqrt(rhs); } catch { continue; }
  let candidate = multiplyAny(G2.fromAffine({ x, y }), cofactorToSylow);
  if (candidate.is0()) continue;
  while (!multiplyAny(candidate, 13n).is0()) candidate = multiplyAny(candidate, 13n);
  if (!candidate.is0() && multiplyAny(candidate, 13n).is0()) order13 = candidate;
}
if (order13 === null) throw new Error('failed to construct the order-13 B fixture');

for (const [name, point] of [['offSubgroupB', offSubgroup], ['order13B', order13]]) {
  const instance = { ...INSTANCES[0], proof: { ...proof, b: point } };
  const glvFinal = glvSpecs(instance).at(-1);
  const miller = millerSpecs(instance, committedSpecs.witness.c, committedSpecs.witness.cInv);
  invalidInputSteps[name] = buildChain(
    [glvFinal, ...miller],
    { tailLocking: firstTailLocking, rejectAt: miller.length },
  ).steps;
}

const firstGlvSuccessor = hexToBin(committedRun.steps[1].locking);
const glvRangeCases = {
  negativePublicInput: [0, -1n],
  outOfRangePublicInput: [0, SCALAR_ORDER],
  oversizedGlvWitness: [2, 1n << 128n],
  incongruentGlvWitness: [2, committedSpecs.glv[0].commitLimbs[2] + 1n],
};
for (const [name, [offset, value]] of Object.entries(glvRangeCases)) {
  const genesis = { ...committedSpecs.glv[0] };
  genesis.commitLimbs = [...genesis.commitLimbs];
  genesis.commitLimbs[offset] = value;
  genesis.allArgs = genesis.commitLimbs;
  invalidInputSteps[name] = buildChain(
    [genesis],
    { tailLocking: firstGlvSuccessor, rejectAt: 0 },
  ).steps;
}

const firstMiller = committedSpecs.miller[0];
for (const [name, offset, value] of [
  ['negativeCInv', 0, -1n],
  ['largeCInv', 0, P],
  ['negativeC', 12, -1n],
  ['largeC', 12, P],
]) {
  const mutated = { ...firstMiller, allArgs: [...firstMiller.allArgs] };
  mutated.allArgs[offset] = value;
  invalidInputSteps[name] = buildChain(
    [mutated],
    { tailLocking: secondMillerLocking, rejectAt: 0 },
  ).steps;
}

const firstTail = committedSpecs.tail[0];
for (const [name, value] of [['negativeW', -1n], ['largeW', P]]) {
  const mutated = { ...firstTail, allArgs: [...firstTail.allArgs] };
  mutated.allArgs[36] = value;
  invalidInputSteps[name] = buildChain(
    [mutated],
    { rejectAt: 0 },
  ).steps;
}

const cInvLimbs = fp12limbsOf(committedSpecs.witness.cInv);
const wrongCInvLimbs = [...cInvLimbs];
wrongCInvLimbs[0] = (wrongCInvLimbs[0] + 1n) % P;
const wrongCInv = mk12(wrongCInvLimbs.slice(0, 6), wrongCInvLimbs.slice(6));
const wrongCInvMiller = millerSpecs(INSTANCES[0], committedSpecs.witness.c, wrongCInv);
const wrongCInvBoundary = millerFusedOps(
  pairsFor(INSTANCES[0].inputs, INSTANCES[0].proof),
  committedSpecs.witness.c,
  wrongCInv,
).boundary;
const wrongCInvTail = tailSpecs(
  wrongCInvBoundary,
  committedSpecs.witness.c,
  wrongCInv,
  committedSpecs.witness.w,
);
invalidInputSteps.wrongCanonicalCInv = buildChain(
  [...wrongCInvMiller, ...wrongCInvTail],
  { rejectAt: wrongCInvMiller.length + wrongCInvTail.length - 1 },
).steps;

const wLimbs = fp12limbsOf(committedSpecs.witness.w);
const wrongWLimbs = [...wLimbs];
wrongWLimbs[0] = (wrongWLimbs[0] + 1n) % P;
const wrongW = mk12(wrongWLimbs.slice(0, 6), wrongWLimbs.slice(6));
const wrongWTail = tailSpecs(
  millerFusedOps(
    pairsFor(INSTANCES[0].inputs, INSTANCES[0].proof),
    committedSpecs.witness.c,
    committedSpecs.witness.cInv,
  ).boundary,
  committedSpecs.witness.c,
  committedSpecs.witness.cInv,
  wrongW,
);
invalidInputSteps.wrongCanonicalW = buildChain(
  wrongWTail,
  { rejectAt: wrongWTail.length - 1 },
).steps;

for (let upper = 0; upper < 6; upper++) {
  const hi = Array(6).fill(0n);
  hi[upper] = 1n;
  const wBad = mk12([1n, 0n, 0n, 0n, 0n, 0n], hi);
  const rhs = frob(committedSpecs.witness.c, 1);
  const fFBad = Fp12.mul(rhs, Fp12.inv(wBad));
  if (!Fp12.eql(Fp12.mul(fFBad, wBad), rhs)) throw new Error('failed to isolate the Fp6 witness gate');
  invalidInputSteps[`nonFp6W${upper + 6}`] = buildChain(
    tailSpecs(fFBad, committedSpecs.witness.c, committedSpecs.witness.cInv, wBad),
    { rejectAt: 0 },
  ).steps;
}

// Cross-proof seam mutations must reject at the consumer, after its predecessor state is known
// to be valid in the complete runs above.
const secondMillerFirst = { ...secondSpecs.miller[0], commitLimbs: committedSpecs.glv.at(-1).outLimbs };
const glvMillerSplice = buildStep(secondMillerFirst, secondMillerLocking, { expectValid: false });
if (glvMillerSplice.accepted) throw new Error('GLV-to-Miller cross-proof seam accepted');
const secondTailFirst = { ...secondSpecs.tail[0], commitLimbs: committedSpecs.miller.at(-1).outLimbs };
const millerTailSplice = buildStep(secondTailFirst, undefined, { expectValid: false });
if (millerTailSplice.accepted) throw new Error('Miller-to-tail cross-proof seam accepted');

const sum = (steps, key) => steps.reduce((total, step) => total + step[key], 0);
const totalBytes = sum(committedRun.steps, 'lockingBytes') + sum(committedRun.steps, 'unlockingBytes');
const totalOperationCost = sum(committedRun.steps, 'operationCost');
if (!stats.allFit || !stats.allAccept || !stats.allRejected) {
  throw new Error('validity, standardness, or mutation gates failed; refusing to write vectors');
}

const output = verifierPath('src', 'bch', 'groth16-bls12381-chunked-covenant-residue-vectors.json');
writeFileSync(output, JSON.stringify({
  description: 'Source-reproducible BLS12-381 Groth16 covenant-residue verifier: five-window full-stage GLV vk_x, input-validation-fused prepared Miller, and a one-input Fp6 residue verdict. The terminal checks c*cInv==1, fF*w==frob(c,1), and six zero upper limbs of w. This is sound because p^6-1 divides (p^12-1)/r; the equations exclude zero. The genesis spends and recreates a minting baton, every nonterminal P2SH32 contract pins its successor, and the terminal creates an immutable empty-commitment verdict locked to itself. Exact 48-byte stage seams carry (-A,B,C,vk_x), c, and cInv without modular aliasing. Every valid and invalid fixture is evaluated on the standard BCH 2026 VM.',
  generator: 'chunked/bls12-381/generate_covenant_residue.mjs',
  proofBinding: 'runtime',
  curve: 'BLS12-381',
  stateBytes: 48,
  numSteps: committedRun.steps.length,
  budgetPerInput: (41 + TARGET_UNLOCK) * 800,
  totalOperationCost,
  maxStepOperationCost: stats.maxOp,
  totalBytes,
  totalLockingBytes: sum(committedRun.steps, 'lockingBytes'),
  totalUnlockingBytes: sum(committedRun.steps, 'unlockingBytes'),
  allAccept: stats.allAccept,
  allInvalidRejected: stats.allRejected,
  verification: {
    vm: 'BCH_2026 standard',
    validProofRuns: 3,
    oneLockingGraph: true,
    stateArgumentMutationsRejected: committedRun.steps.length * 3,
    successorAndTerminalLockingMutationsRejected: committedRun.steps.length * 3,
    categoryAndCapabilityMutationsRejected: committedRun.steps.length * 12,
    genesisBatonMutationsRejected: 6,
    millerResidueRangeMutationsRejected: 12,
    residueWitnessRangeMutationsRejected: 6,
    stageSplicesRejected: 2,
    isolatedInvalidRunsRejected: Object.keys(invalidInputSteps).length,
  },
  steps: committedRun.steps,
  extraProofSteps: secondRun.steps,
  worstCaseSteps: denseRun.steps,
  invalidInputSteps,
}, null, 2));

console.error(`BLS covenant residue: ${committedRun.steps.length} steps, ${totalBytes.toLocaleString()} bytes, ${totalOperationCost.toLocaleString()} op`);
console.error(`max locking ${stats.maxLock} B, max unlocking ${stats.maxUnlock} B, max op ${stats.maxOp.toLocaleString()}`);
console.error(`wrote ${output}`);
