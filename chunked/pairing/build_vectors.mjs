// Assemble the generic BN254 covenant chunks into continuously bound benchmark
// vectors. Runtime state lives in one mutable NFT commitment; every nonterminal
// contract also pins the actual P2SH32 locking bytecode of its successor.
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join } from 'node:path';
import {
  Fp12, bn254, preparedMillerOps, assertPreparedMillerManifest, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileFileBytecode, compileFileBytecodeRaw, commitBin, CATEGORY, ptLimbs,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace,
  TARGET_UNLOCK, OP_BUDGET, verifierPath, invalidG2Overrides, assertG2StageManifest,
} from './_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from './gen_g2check.mjs';
import {
  hexToBin, binToHex, bigIntToVmNumber, vmNumberToBigInt, hash256,
  encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const realVm = createVirtualMachineBch2026(false);
const P = bn254.fields.Fp.ORDER;
const Rord = bn254.fields.Fr.ORDER;

const P2SH = process.env.CHUNKED_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => {
  const b = Math.max(2, total);
  const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3;
  return encodeDataPush(new Uint8Array(n));
};
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const TUNE_SLACK = Number(process.env.TUNE_SLACK ?? 96);
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + TUNE_SLACK));
const tok = (commitment, category = CATEGORY, capability = 'mutable') => ({ amount: 0n, category, nft: { capability, commitment } });

function evalCov(locking, unlocking, inCommit, outCommit, outLocking = locking, outputCategory = CATEGORY, outputCapability = 'mutable') {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLocking, valueSatoshis: 1000n, token: tok(outCommit, outputCategory, outputCapability) }],
      locktime: 0,
    },
  };
  const state = realVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1,
    operationCost: state.metrics.operationCost,
    error: state.error ?? null,
  };
}

const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map();

const bindSuccessor = (cashFile, nextLocking) => {
  const src = readFileSync(cashFile, 'utf8');
  if (nextLocking === undefined) return { path: cashFile, cleanup: false };
  const expected = binToHex(hash256(nextLocking));
  const marker = '\n    }\n}\n';
  if (!src.endsWith(marker)) throw new Error(`cannot bind successor locking in ${cashFile}`);
  const bound = src.slice(0, -marker.length) + `\n        require(hash256(tx.outputs[0].lockingBytecode) == 0x${expected});${marker}`;
  const temp = join(dirname(cashFile), `._bound_${basename(cashFile, '.cash')}_${expected.slice(0, 16)}.cash`);
  writeFileSync(temp, bound);
  return { path: temp, cleanup: true };
};

function compiledVariants(cashFile, nextLocking) {
  const key = `${cashFile}|${nextLocking === undefined ? 'unbound' : binToHex(nextLocking)}`;
  let variants = compileCache.get(key);
  if (variants) return { key, variants };
  const bound = bindSuccessor(cashFile, nextLocking);
  try {
    const rescheduled = compileFileBytecode(bound.path);
    const raw = RESCHED ? compileFileBytecodeRaw(bound.path) : rescheduled;
    variants = { rescheduled };
    if (RESCHED && binToHex(raw) !== binToHex(rescheduled)) variants.raw = raw;
    compileCache.set(key, variants);
    return { key, variants };
  } finally {
    if (bound.cleanup) unlinkSync(bound.path);
  }
}

function evalStepWith(contract, spec, nextLocking, label = '', checkpoint = undefined) {
  const { commitLimbs, outLimbs, allArgs, terminal = false, selfLoop = false } = spec;
  const pushArgs = allArgs ?? commitLimbs;
  const redeem = Uint8Array.from(contract);
  const redeemPush = encodeDataPush(redeem);
  const locking = P2SH ? p2shSpk(redeem) : redeem;
  const tail = P2SH ? redeemPush.length : 0;
  const inCommit = commitBin(commitLimbs.map(BigInt));
  const outCommit = terminal ? new Uint8Array(32) : commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...pushArgs].reverse().flatMap((value) => [...pushInt(BigInt(value))]));
  const mkUnlock = (target) => {
    const pad = padBytes(target - argBytes.length - tail);
    return P2SH ? Uint8Array.from([...pad, ...argBytes, ...redeemPush]) : Uint8Array.from([...pad, ...argBytes]);
  };
  const outLocking = terminal || selfLoop ? locking : nextLocking;
  if (outLocking === undefined) throw new Error(`missing successor locking for ${label}`);
  const probe = evalCov(locking, mkUnlock(TARGET_UNLOCK), inCommit, outCommit, outLocking);
  let target = tunedLen(argBytes.length + tail, probe.operationCost);
  let unlocking = mkUnlock(target);
  let real = evalCov(locking, unlocking, inCommit, outCommit, outLocking);
  while (!real.accepted && target < TARGET_UNLOCK) {
    target = Math.min(TARGET_UNLOCK, target + 256);
    unlocking = mkUnlock(target);
    real = evalCov(locking, unlocking, inCommit, outCommit, outLocking);
  }

  const invalid = Uint8Array.from(unlocking);
  const padLen = unlocking.length - argBytes.length - tail;
  invalid[padLen + 1] ^= 0x01;
  const stateMutation = evalCov(locking, invalid, inCommit, outCommit, outLocking);
  let wrongLockAccepted = false;
  if (!terminal && !selfLoop) {
    const wrongLocking = Uint8Array.from(outLocking);
    wrongLocking[wrongLocking.length - 1] ^= 0x01;
    wrongLockAccepted = evalCov(locking, unlocking, inCommit, outCommit, wrongLocking).accepted;
  }
  let wrongCategoryAccepted = false;
  if (!terminal) {
    const wrongCategory = Uint8Array.from(CATEGORY);
    wrongCategory[0] ^= 0x01;
    wrongCategoryAccepted = evalCov(locking, unlocking, inCommit, outCommit, outLocking, wrongCategory).accepted;
  }
  const strippedCapabilityAccepted = terminal
    ? false
    : evalCov(locking, unlocking, inCommit, outCommit, outLocking, CATEGORY, 'none').accepted;

  return {
    step: {
      label,
      locking: binToHex(locking),
      unlocking: binToHex(unlocking),
      invalidUnlocking: binToHex(invalid),
      checkpoint,
      covenant: {
        category: binToHex(CATEGORY), capability: 'mutable',
        inCommitment: binToHex(inCommit), outCommitment: binToHex(outCommit),
        outLockingBytecode: binToHex(outLocking),
      },
      lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost,
    },
    accepted: real.accepted,
    invalidRejected: !stateMutation.accepted && !wrongLockAccepted && !wrongCategoryAccepted && !strippedCapabilityAccepted,
    error: real.error,
    fits: locking.length <= 10_000 && unlocking.length <= 10_000 && real.operationCost <= OP_BUDGET && real.accepted,
  };
}

function buildCovStep(spec, nextLocking, noStats) {
  const binding = spec.terminal || spec.selfLoop ? undefined : nextLocking;
  const { key, variants } = compiledVariants(spec.cashFile, binding);
  let contract = chosenCache.get(key);
  if (contract === undefined) {
    if (!variants.raw) contract = variants.rescheduled;
    else {
      const a = evalStepWith(variants.rescheduled, spec, nextLocking);
      const b = evalStepWith(variants.raw, spec, nextLocking);
      const score = (result) => result.fits ? result.step.lockingBytes + result.step.unlockingBytes : Infinity;
      contract = score(b) < score(a) ? variants.raw : variants.rescheduled;
    }
    chosenCache.set(key, contract);
  }
  const result = evalStepWith(contract, spec, nextLocking, spec.label, spec.checkpoint);
  if (!noStats) {
    stats.maxLock = Math.max(stats.maxLock, result.step.lockingBytes);
    stats.maxUnlock = Math.max(stats.maxUnlock, result.step.unlockingBytes);
    stats.allFit &&= result.fits;
    stats.allAccept &&= result.accepted;
    stats.allInvalid &&= result.invalidRejected;
    if (!result.fits || !result.accepted || !result.invalidRejected) {
      console.error(`  !! ${spec.label}: lock=${result.step.lockingBytes} unlock=${result.step.unlockingBytes} op=${result.step.operationCost.toLocaleString()} accepted=${result.accepted} invalidRejected=${result.invalidRejected} err=${result.error ?? '(none)'}`);
    }
  }
  return result;
}

function buildChain(specs, { noStats = false, tailLocking, expectRejected = false } = {}) {
  const built = new Array(specs.length);
  const results = new Array(specs.length);
  let nextLocking = tailLocking;
  for (let i = specs.length - 1; i >= 0; i--) {
    const spec = specs[i];
    if (!spec.terminal && !spec.selfLoop && nextLocking === undefined) throw new Error(`nonterminal tail has no successor: ${spec.label}`);
    const result = buildCovStep(spec, nextLocking, noStats);
    results[i] = result;
    built[i] = result.step;
    nextLocking = hexToBin(result.step.locking);
  }
  for (let i = 0; i + 1 < built.length; i++) {
    if (built[i].covenant.outCommitment !== built[i + 1].covenant.inCommitment) throw new Error(`commitment seam mismatch at ${built[i].label}`);
    if (built[i].covenant.outLockingBytecode !== built[i + 1].locking) throw new Error(`locking seam mismatch at ${built[i].label}`);
  }
  const accepted = results.every((result) => result.accepted);
  if (expectRejected ? accepted : !accepted) throw new Error(expectRejected ? 'invalid chain unexpectedly accepted' : 'valid chain rejected');
  return built;
}

function parseProofUnlocking(hex) {
  const bytes = hexToBin(hex);
  const values = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i++];
    if (op === 0x00) values.push(0n);
    else if (op === 0x4f) values.push(-1n);
    else if (op >= 0x51 && op <= 0x60) values.push(BigInt(op - 0x50));
    else {
      let length;
      if (op <= 75) length = op;
      else if (op === 0x4c) length = bytes[i++];
      else if (op === 0x4d) { length = bytes[i] | (bytes[i + 1] << 8); i += 2; }
      else throw new Error('unsupported proof unlocking push');
      values.push(vmNumberToBigInt(bytes.slice(i, i + length), { requireMinimalEncoding: false }));
      i += length;
    }
  }
  const d = values.reverse();
  return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] };
}

const multiproof = JSON.parse(readFileSync(verifierPath('src', 'bch', 'groth16-singleton-multiproof-vectors.json'), 'utf8'));
const p1 = parseProofUnlocking(multiproof.proofs[1].unlocking);
const INSTANCES = [
  { tag: 'committed', proof, inputs: vec.publicInputs.map(BigInt) },
  { tag: 'proof#1', proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
];
const worst = parseProofUnlocking(multiproof.worstCaseProof.unlocking);
const WC_INSTANCE = {
  tag: 'worst-case',
  proof: proofFromLimbs(worst.Ax, worst.Ay, worst.Bxa, worst.Bxb, worst.Bya, worst.Byb, worst.Cx, worst.Cy),
  inputs: [worst.in0, worst.in1],
};

const sameLimbs = (a, b) => a.length === b.length && a.every((value, i) => BigInt(value) === BigInt(b[i]));
const stageLimbs = (inst, bad = {}) => {
  const A = inst.proof.a.negate().toAffine();
  const B = inst.proof.b.toAffine();
  const C = inst.proof.c.toAffine();
  const vkx = vkxPoint(inst.inputs).toAffine();
  return [
    bad.Ax ?? A.x, bad.Ay ?? A.y,
    bad.Bx?.c0 ?? B.x.c0, bad.Bx?.c1 ?? B.x.c1,
    bad.By?.c0 ?? B.y.c0, bad.By?.c1 ?? B.y.c1,
    bad.Cx ?? C.x, bad.Cy ?? C.y,
    bad.vkxX ?? vkx.x, bad.vkxY ?? vkx.y,
  ];
};

const millerStateLimbs = (state) => [...f12limbs(state.f), ...r6limbs(state.Rs[0])];
function specsPairing(inst) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const trace = preparedMillerOps(pairs);
  const pointLimbs = pairs.flatMap((pair, i) => ptLimbs(i, pair.P.toAffine(), pair.Q.toAffine()));
  const stage = [...pointLimbs.slice(0, 6), ...pointLimbs.slice(8, 10), ...pointLimbs.slice(6, 8)];
  if (!sameLimbs(stage, stageLimbs(inst))) throw new Error(`Miller genesis layout mismatch for ${inst.tag}`);
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  assertPreparedMillerManifest(manifest, trace);
  if (manifest.stageBound !== true || manifest.genesisDerived !== true || manifest.emitsBoundaryOnly !== true) throw new Error('Miller manifest is not stage-bound');
  const specs = manifest.chunks.map((chunk) => ({
    cashFile: join(GEN, `miller_${String(chunk.idx).padStart(2, '0')}.cash`),
    commitLimbs: chunk.opLo === 0 ? stage : [...millerStateLimbs(trace.states[chunk.opLo]), ...pointLimbs],
    outLimbs: chunk.final ? f12limbs(trace.boundary) : [...millerStateLimbs(trace.states[chunk.opHi]), ...pointLimbs],
    label: `miller ops[${chunk.opLo},${chunk.opHi})${chunk.final ? ' =boundary' : ''}`,
    checkpoint: chunk.final ? 'miller-boundary' : undefined,
  }));
  return { specs, boundaryVal: trace.boundary };
}

function specsFinalexp(inst, boundaryVal, expectOne = true) {
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  const trace = finalexpTrace(boundaryVal);
  if (expectOne && !Fp12.eql(trace.result, Fp12.ONE)) throw new Error(`final exponentiation did not produce one for ${inst.tag}`);
  const liveLimbs = (cut) => trace.liveAt(cut).flatMap((id) => trace.limbs12(id));
  return manifest.chunks.map((chunk) => ({
    cashFile: join(GEN, `finalexp_${String(chunk.idx).padStart(2, '0')}.cash`),
    commitLimbs: liveLimbs(chunk.opLo),
    outLimbs: chunk.final ? [] : liveLimbs(chunk.opHi),
    label: `finalexp ops[${chunk.opLo},${chunk.opHi})${chunk.final ? ' verdict==1' : ''}`,
    checkpoint: chunk.final ? 'verify' : undefined,
    terminal: chunk.final,
  }));
}

function specsVkx(inst, fullStage) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const prefix = fullStage ? 'vkxfull' : 'vkx';
  const manifest = JSON.parse(readFileSync(join(GEN, `manifest_${prefix}.json`), 'utf8'));
  if (
    manifest.genesisDerived !== true ||
    manifest.stageBound !== true ||
    manifest.fullStageBound !== fullStage ||
    manifest.exactProofHandoff !== fullStage
  ) throw new Error(`${prefix} manifest has the wrong layout`);
  const stage = stageLimbs(inst);
  const proofTuple = stage.slice(0, 8);
  return manifest.chunks.map((chunk) => {
    const commitLimbs = chunk.lo === 0 ? [in0, in1] : [...vkxStateAt(in0, in1, chunk.lo), in0, in1];
    const final = chunk.final;
    return {
      cashFile: join(GEN, `${prefix}_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs: final ? (fullStage ? stage : stage.slice(8)) : [...vkxStateAt(in0, in1, chunk.hi), in0, in1],
      allArgs: final ? [...commitLimbs, vkxFinalZinv(in0, in1), ...(fullStage ? proofTuple : [])] : commitLimbs,
      label: `vk_x [${chunk.lo},${chunk.hi})${final ? (fullStage ? ' bind (-A,B,C,vk_x)' : ' output vk_x') : ''}`,
      checkpoint: final ? 'vk_x' : undefined,
      selfLoop: final && !fullStage,
    };
  });
}

const g2StateLimbs = (R, stage) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1], ...stage];
function specsG2check(inst, bad) {
  const stage = stageLimbs(inst, bad);
  const B = [[stage[2], stage[3]], [stage[4], stage[5]]];
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_g2checkfull.json'), 'utf8'));
  assertG2StageManifest(manifest, { carriesVkx: true });
  const zinv = g2checkFastZinv(B);
  return manifest.chunks.map((chunk) => {
    const commitLimbs = chunk.first ? stage : g2StateLimbs(g2checkAccAt(B, chunk.lo), stage);
    return {
      cashFile: join(GEN, `g2checkfull_${String(chunk.idx).padStart(2, '0')}.cash`),
      commitLimbs,
      outLimbs: chunk.last ? stage : g2StateLimbs(g2checkAccAt(B, chunk.hi), stage),
      allArgs: chunk.last ? [...commitLimbs, ...zinv] : commitLimbs,
      label: `g2check bits[${chunk.lo},${chunk.hi})${chunk.last ? ' subgroup verdict' : ''}`,
      checkpoint: chunk.first ? 'validate-inputs' : undefined,
    };
  });
}

function buildGroth16(inst) {
  const vkx = specsVkx(inst, true);
  const g2 = specsG2check(inst);
  const { specs: miller, boundaryVal } = specsPairing(inst);
  const finalexp = specsFinalexp(inst, boundaryVal);
  const all = buildChain([...vkx, ...g2, ...miller, ...finalexp]);
  return { all, pairing: all.slice(vkx.length + g2.length, vkx.length + g2.length + miller.length) };
}

const run0 = buildGroth16(INSTANCES[0]);
const run1 = buildGroth16(INSTANCES[1]);
const runWc = buildGroth16(WC_INSTANCE);
const standaloneVkx0 = buildChain(specsVkx(INSTANCES[0], false));
const standaloneVkx1 = buildChain(specsVkx(INSTANCES[1], false));
const standaloneVkxWc = buildChain(specsVkx(WC_INSTANCE, false));

const millerTail = hexToBin(run0.pairing[0].locking);
const buildInvalidG2 = (bad) => buildChain(specsG2check(INSTANCES[0], bad), { noStats: true, tailLocking: millerTail, expectRejected: true });
const invalidInputs = invalidG2Overrides(INSTANCES[0].proof).map(buildInvalidG2);

// The full vk_x terminal must preserve supplied proof coordinates byte-for-byte so the
// first G2 stage, rather than an implicit modulo reduction, rejects alternate field encodings.
const rawStage = stageLimbs(INSTANCES[0]);
rawStage[2] += P;
const rawVkxSpecs = specsVkx(INSTANCES[0], true);
const rawVkxFinal = rawVkxSpecs[rawVkxSpecs.length - 1];
rawVkxSpecs[rawVkxSpecs.length - 1] = {
  ...rawVkxFinal,
  outLimbs: rawStage,
  allArgs: [...rawVkxFinal.allArgs.slice(0, -8), ...rawStage.slice(0, 8)],
};
const rawVkxPrefix = buildChain(rawVkxSpecs, {
  noStats: true,
  tailLocking: hexToBin(run0.all[rawVkxSpecs.length].locking),
});
const rawG2Specs = specsG2check(INSTANCES[0]);
rawG2Specs[0] = { ...rawG2Specs[0], commitLimbs: rawStage, allArgs: rawStage };
const nonCanonicalG2 = buildChain(rawG2Specs, { noStats: true, tailLocking: millerTail, expectRejected: true });
invalidInputs.push(nonCanonicalG2);

const forgedG2 = specsG2check(INSTANCES[0]);
forgedG2[0] = { ...forgedG2[0], allArgs: [9n, 8n, 7n, 6n, 5n, 4n, ...forgedG2[0].commitLimbs] };
const forgedR = buildChain(forgedG2, { noStats: true, tailLocking: millerTail, expectRejected: true });

const badRange = specsVkx(INSTANCES[0], true);
badRange[0] = { ...badRange[0], commitLimbs: [Rord, INSTANCES[0].inputs[1]], allArgs: [Rord, INSTANCES[0].inputs[1]] };
const outOfRange = buildChain([badRange[0]], { noStats: true, tailLocking: hexToBin(run0.all[1].locking), expectRejected: true });

const spliced = { tag: 'proof-splice', inputs: INSTANCES[0].inputs, proof: INSTANCES[1].proof };
const splicedVkx = specsVkx(spliced, true);
const splicedG2 = specsG2check(spliced);
const { specs: splicedMiller, boundaryVal: splicedBoundary } = specsPairing(spliced);
const proofSplice = buildChain([...splicedVkx, ...splicedG2, ...splicedMiller, ...specsFinalexp(spliced, splicedBoundary, false)], { noStats: true, expectRejected: true });

let seamSpliceRejected = false;
try {
  const { specs: wrongMiller, boundaryVal: wrongBoundary } = specsPairing(INSTANCES[1]);
  buildChain([...specsVkx(INSTANCES[0], true), ...specsG2check(INSTANCES[0]), ...wrongMiller, ...specsFinalexp(INSTANCES[1], wrongBoundary)], { noStats: true });
} catch (error) {
  seamSpliceRejected = String(error?.message ?? error).includes('commitment seam mismatch');
}
if (!seamSpliceRejected) throw new Error('cross-proof stage seam was not rejected');

// `invalidInputs` is reserved for isolated curve/subgroup validation runs in the
// benchmark harness. The other cases are generation-time assertions above.
if ([rawVkxPrefix, forgedR, outOfRange, proofSplice].some((run) => run.length === 0)) throw new Error('a validation run was not built');
const sumOp = (steps) => steps.reduce((sum, step) => sum + step.operationCost, 0);
const maxOp = (steps) => Math.max(...steps.map((step) => step.operationCost));
if (!stats.allFit || !stats.allAccept || !stats.allInvalid) throw new Error('valid or negative-case fixture failed; refusing to write vectors');

writeFileSync(verifierPath('src', 'bch', 'pairing-chunked-vectors.json'), JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BN254 Groth16 pairing to the Miller boundary. Pairing-only intentionally omits G1/G2 input validation. Miller genesis consumes only (-A,B,C,vk_x), derives f=1 and R_B=B, and every covenant pins the actual successor P2SH32 locking used by the full verifier. Fixed gamma/delta trajectories use baked line coefficients; fixed e(alpha,beta) is folded with one precomputed raw-Miller multiplication.',
  proofBinding: 'runtime', numSteps: run0.pairing.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(run0.pairing), maxStepOperationCost: maxOp(run0.pairing),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: run0.pairing, extraValidProofs: [run1.pairing], worstCaseProof: runWc.pairing,
}, null, 2));

writeFileSync(verifierPath('src', 'bch', 'groth16-chunked-vectors.json'), JSON.stringify({
  description: 'PROOF-AGNOSTIC full BN254 Groth16 verifier: canonical public inputs -> vk_x -> exact (-A,B,C,vk_x) handoff -> canonical-coordinate/on-curve/subgroup validation -> prepared-VK Miller product -> final exponentiation -> verdict. vk_x, G2, and Miller derive their genesis accumulators in-contract. Every stage emits the exact next-stage tuple, and every nonterminal covenant pins the actual successor P2SH32 locking, forming one continuous mutable-NFT state chain. Distinct valid proofs share the same locking graph; negative fixtures cover non-canonical and off-curve points, an off-subgroup B, legacy extra accumulator state, out-of-range scalars, state/script mutations, and a cross-proof splice.',
  proofBinding: 'runtime', numSteps: run0.all.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(run0.all), maxStepOperationCost: maxOp(run0.all),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: run0.all, extraValidProofs: [run1.all], worstCaseProof: runWc.all, invalidInputs,
}, null, 2));

writeFileSync(verifierPath('src', 'bch', 'vkx-chunked-covenant-vectors.json'), JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BN254 vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus), multi-tx. The first chunk accepts only canonical Fr public inputs and derives the Jacobian infinity accumulator. The standalone terminal emits only vk_x; one locking graph aggregates distinct inputs.',
  proofBinding: 'runtime', numSteps: standaloneVkx0.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(standaloneVkx0), maxStepOperationCost: maxOp(standaloneVkx0),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: standaloneVkx0, extraValidProofs: [standaloneVkx1], worstCaseProof: standaloneVkxWc,
}, null, 2));

console.error(`pairing: ${run0.pairing.length} steps, ${sumOp(run0.pairing).toLocaleString()} op`);
console.error(`full groth16: ${run0.all.length} steps, ${sumOp(run0.all).toLocaleString()} op`);
console.error(`vk_x standalone: ${standaloneVkx0.length} steps, ${sumOp(standaloneVkx0).toLocaleString()} op`);
console.error(`max lock ${stats.maxLock}B max unlock ${stats.maxUnlock}B; all negative cases rejected`);
