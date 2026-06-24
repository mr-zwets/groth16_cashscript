// Assemble the GENERIC (proof-agnostic) BLS12-381 vk_x covenant chunks into the
// benchmark vectors. Each chunk carries NO baked state: the running Jacobian
// accumulator + the public inputs live in the token NFT commitment, checked by
// introspection. The SAME chunk lockings aggregate ANY public inputs (runtime-
// general) -- we replay TWO distinct public-input instances through identical
// lockings: instance #0 = the committed singleton instance, extraValidProofs[0] =
// a distinct pair from the BLS multiproof vectors.
//
// Windows are WORST-CASE sized (gen_vkx planned against an all-bits-set input), so
// every step here -- with small real inputs -- has op-cost headroom and fits.
//
// Writes verifier/src/bch/vkx-bls12381-chunked-covenant-vectors.json for the
// bch-vkx-bls12381-chunked-covenant milestone entry.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, PUBLIC_INPUTS, computeVkx, compileBytecode, commitBin, CATEGORY, tok,
  vkxStateAt, vkxFinalZinv, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2, OP_BUDGET,
} from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
import { binToHex, bigIntToVmNumber, encodeDataPush, numberToBinUint16LE, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

function evalCov(locking, unlocking, inCommit, outCommit) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// Build one covenant step: pad the unlocking to afford op-cost, attach the token
// covenant context, verify it accepts, and that a tampered limb is rejected.
// `commitLimbs` = committed carried state (hashed into the NFT commitment, decl
// order). `allArgs` = everything the unlocking pushes (== commitLimbs, except the
// final chunk also pushes an uncommitted zInv).
const compileCache = new Map();
function buildCovStep(cashFile, commitLimbs, outLimbs, label, checkpoint, allArgs) {
  const pushArgs = allArgs ?? commitLimbs;
  let redeem = compileCache.get(cashFile);
  if (!redeem) { redeem = compileBytecode(readFileSync(cashFile, 'utf8')); compileCache.set(cashFile, redeem); }
  const locking = Uint8Array.from([...redeem]); // no OP_DROP: trailing `bytes unused zeroPadding` param
  const inCommit = commitBin(commitLimbs.map(BigInt)), outCommit = commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...pushArgs].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  // `zeroPadding` is the LAST spend param -> pushed FIRST -> the pad leads the unlocking ([pad][args]).
  const probe = evalCov(locking, Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]), inCommit, outCommit);
  let target = tunedLen(argBytes.length, probe.operationCost);
  let unlocking = Uint8Array.from([...padPush(argBytes.length, target), ...argBytes]);
  let real = evalCov(locking, unlocking, inCommit, outCommit);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = Uint8Array.from([...padPush(argBytes.length, target), ...argBytes]); real = evalCov(locking, unlocking, inCommit, outCommit); }
  // tamper a state limb: args follow the leading pad, so the first arg push payload is at padLen + 1.
  const invalid = Uint8Array.from(unlocking); const padLen = unlocking.length - argBytes.length; invalid[padLen + 1] ^= 0x01;
  const invReal = evalCov(locking, invalid, inCommit, outCommit);
  return {
    step: {
      label, locking: binToHex(locking), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalid), checkpoint,
      covenant: { category: binToHex(CATEGORY), capability: 'mutable', inCommitment: binToHex(inCommit), outCommitment: binToHex(outCommit), outLockingBytecode: binToHex(locking) },
      lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost,
    },
    accepted: real.accepted, invalidRejected: !invReal.accepted, operationCost: real.operationCost,
    fits: locking.length <= 10000 && unlocking.length <= 10000 && real.operationCost <= OP_BUDGET && real.accepted,
  };
}

// ---- the two public-input instances: #0 committed, #1 from the BLS multiproof ----
function secondInputs() {
  try {
    const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-bls12381-singleton-multiproof-vectors.json', 'utf8'));
    for (const pr of mp.proofs ?? []) if (Array.isArray(pr.publicInputs) && pr.publicInputs.length >= 2) {
      const pi = pr.publicInputs.map(BigInt);
      if (pi[0] !== PUBLIC_INPUTS[0] || pi[1] !== PUBLIC_INPUTS[1]) return [pi[0], pi[1]];
    }
  } catch { /* fall through */ }
  return [135208n, 67633n];
}
const INSTANCES = [
  { tag: 'committed', inputs: PUBLIC_INPUTS },
  { tag: 'proof#1', inputs: secondInputs() },
];

const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
function buildVkx(inst) {
  const [in0, in1] = inst.inputs;
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const steps = [];
  for (const ch of man.chunks) {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const commitLimbs = [...inAcc, in0, in1];
    let outLimbs, allArgs;
    if (ch.final) { outLimbs = [vkxAff.x, vkxAff.y]; allArgs = [...commitLimbs, vkxFinalZinv(in0, in1)]; }
    else { outLimbs = [...vkxStateAt(in0, in1, ch.hi), in0, in1]; allArgs = commitLimbs; }
    const r = buildCovStep(join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), commitLimbs, outLimbs, `vk_x [${ch.lo},${ch.hi})${ch.final ? ' assemble vk_x' : ''}`, ch.final ? 'vk_x' : undefined, allArgs);
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
    steps.push(r.step);
  }
  return steps;
}

const v0 = buildVkx(INSTANCES[0]);
const v1 = buildVkx(INSTANCES[1]);
const sumOp = (a) => a.reduce((x, s) => x + s.operationCost, 0);
const maxOpOf = (a) => Math.max(...a.map((s) => s.operationCost));
console.error(`vk_x(BLS12-381 covenant): ${v0.length} steps/instance, op ${sumOp(v0).toLocaleString()}; instance#1 also built (${v1.length} steps)`);
console.error(`max lock ${stats.maxLock}B max unlock ${stats.maxUnlock}B | allFit=${stats.allFit} allAccept=${stats.allAccept} allInvalidRejected=${stats.allInvalid}`);
if (!stats.allFit || !stats.allAccept || !stats.allInvalid) { console.error('!! a step did not fit/accept/reject -- NOT writing vectors'); process.exit(1); }

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/vkx-bls12381-chunked-covenant-vectors.json', JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BLS12-381 vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus, G1), multi-tx. Generic covenant: the Jacobian accumulator + public inputs live in the token NFT commitment, NO baked instance. The MSM tiles all 255 scalar-field bit positions and the chunk windows are WORST-CASE sized (every input bit set), so one fixed set of lockings aggregates ANY public inputs < r (magnitude-independent, EVM ecMul-equivalent). Runtime-general: instance #0 = committed singleton instance, extraValidProofs = distinct public inputs under the same VK.',
  proofBinding: 'runtime', curve: 'BLS12-381', scalarBits: 255, worstCaseSized: true,
  numSteps: v0.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(v0), maxStepOperationCost: maxOpOf(v0),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: v0, extraValidProofs: [v1],
}, null, 2));
console.error('wrote src/bch/vkx-bls12381-chunked-covenant-vectors.json (proof-agnostic, 2 instances)');
