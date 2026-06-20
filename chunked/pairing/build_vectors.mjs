// Assemble the GENERIC (proof-agnostic) covenant chunks into benchmark vectors.
// Each chunk carries NO baked state: the running-state HASH lives in the token's
// NFT commitment. Per step we emit a `covenant` context (category, in/out NFT
// commitments) so the harness drives it through a synthetic token tx; the unlocking
// pushes the raw state limbs + a zero pad that buys the op-cost budget. The SAME
// chunk lockings verify multiple proofs (runtime-general) — we replay proof #0 (the
// committed instance) and proof #1 (minted under the same VK, from the singleton
// multiproof vectors) through identical lockings -> extraValidProofs.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, Fp12, ATE_NAF, millerStep, postPrecompute, pairsFor, proofFromLimbs, vec,
  f12limbs, r6limbs, compileBytecode, commitBin, CATEGORY, ptLimbs,
  TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2, OP_BUDGET,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, binToHex, bigIntToVmNumber, vmNumberToBigInt } = await import(LIBAUTH);
const { createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]); };
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
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
// covenant context, and verify it accepts (and that a tampered limb is rejected).
const compileCache = new Map();
function buildCovStep(cashFile, inLimbs, outLimbs, label, checkpoint) {
  let redeem = compileCache.get(cashFile);
  if (!redeem) { redeem = compileBytecode(readFileSync(cashFile, 'utf8')); compileCache.set(cashFile, redeem); }
  const locking = Uint8Array.from([OP_DROP, ...redeem]);
  const inCommit = commitBin(inLimbs.map(BigInt)), outCommit = commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  const probe = evalCov(locking, Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]), inCommit, outCommit);
  let target = tunedLen(argBytes.length, probe.operationCost);
  let unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]);
  let real = evalCov(locking, unlocking, inCommit, outCommit);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]); real = evalCov(locking, unlocking, inCommit, outCommit); }
  const invalid = Uint8Array.from(unlocking); invalid[1] ^= 0x01; // perturb a state limb -> commitment mismatch
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

// ---- per-pair Miller state replay (states[k] BEFORE step k) ----
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.R)];
function pairStates(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  const states = [{ f: Fp12.ONE, R: { x: Qa.x, y: Qa.y, z: Fp2.ONE } }];
  let cur = states[0];
  for (let k = 0; k < ATE_NAF.length; k++) { cur = millerStep(cur.f, cur.R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y); states.push(cur); }
  const final = postPrecompute(states[ATE_NAF.length].f, states[ATE_NAF.length].R, Qa.x, Qa.y, Pa.x, Pa.y);
  return { states, final };
}

// ---- parse a singleton-proof unlocking (pushes, reverse decl order) -> limbs ----
// decl order: Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1 (pushed reversed, in1 first).
function parseProofUnlocking(hex) {
  const b = hexToBin(hex); const vals = []; let i = 0;
  while (i < b.length) {
    const op = b[i++];
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; }
  }
  const d = vals.reverse(); // -> decl order
  return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] };
}

// ---- the two proof instances: #0 committed, #1 from the multiproof vectors ----
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
const INSTANCES = [
  { tag: 'committed', proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  { tag: 'proof#1', proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
];

// ---- build the Miller-boundary (pairing) steps for one instance ----
const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
function buildPairing(inst) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const steps = [];
  for (let pi = 0; pi < 4; pi++) {
    const man = JSON.parse(readFileSync(join(GEN, `manifest_p${pi}.json`), 'utf8'));
    const { states, final } = pairStates(pairs[pi]);
    const ptL = ptLimbs(pi, pairs[pi].P.toAffine(), pairs[pi].Q.toAffine());
    for (const ch of man.chunks) {
      const inLimbs = [...stateLimbs(states[ch.lo]), ...ptL];
      const outLimbs = [...stateLimbs(ch.final ? final : states[ch.hi]), ...ptL];
      const r = buildCovStep(join(GEN, `miller_p${pi}_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs, `miller p${pi} [${ch.lo},${ch.hi})${ch.final ? ' +postPre' : ''}`);
      stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
      stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
      steps.push(r.step);
    }
  }
  // combine
  const finals = pairs.map((p) => pairStates(p).final);
  const inLimbs = finals.flatMap(stateLimbs); // 72
  const boundary = finals.reduce((a, s) => Fp12.mul(a, s.f), Fp12.ONE);
  const r = buildCovStep(join(GEN, 'combine.cash'), inLimbs, f12limbs(boundary), 'combine: boundary = f0*f1*f2*f3', 'miller-boundary');
  stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
  stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
  steps.push(r.step);
  return steps;
}

const pairing0 = buildPairing(INSTANCES[0]);
const pairing1 = buildPairing(INSTANCES[1]);
const sumOp = (a) => a.reduce((x, s) => x + s.operationCost, 0);
const maxOpOf = (a) => Math.max(...a.map((s) => s.operationCost));
console.error(`pairing(boundary): ${pairing0.length} steps/proof, op ${sumOp(pairing0).toLocaleString()}; proof#1 also built (${pairing1.length} steps)`);
console.error(`max lock ${stats.maxLock}B max unlock ${stats.maxUnlock}B | allFit=${stats.allFit} allAccept=${stats.allAccept} allInvalidRejected=${stats.allInvalid}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-chunked-vectors.json', JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BN254 Groth16 pairing to the Miller boundary (4 Miller chains + combine), multi-tx. Generic covenant: running state in the token NFT commitment, NO baked proof. One fixed set of lockings verifies multiple proofs (runtime-general): proof #0 = committed instance, extraValidProofs = a distinct proof under the same VK.',
  proofBinding: 'runtime', numSteps: pairing0.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(pairing0), maxStepOperationCost: maxOpOf(pairing0),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: pairing0, extraValidProofs: [pairing1],
}, null, 2));
console.error('wrote src/bch/pairing-chunked-vectors.json (proof-agnostic, 2 proofs)');
