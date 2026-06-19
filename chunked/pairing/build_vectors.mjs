// Assemble the chunked-pairing steps (4 Miller chains + combine) into padded
// (locking, unlocking) vectors measured on the real BCH 2026 VM, and write
// src/bch/pairing-chunked-vectors.json for the bch-pairing-chunked benchmark
// entry. Each chunk: OP_DROP-prefixed locking (consumes the pad) + unlocking =
// incoming-state pushes (reverse decl order, minimal) + a TUNED zero pad sized to
// the minimum that affords the chunk's op-cost. Recomputes per-chunk incoming
// state via the shared miller math (the manifests store only hashes + windows).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, Fp12, ATE_NAF, millerStep, postPrecompute, pairsFor, vec,
  f12limbs, r6limbs, CASHC, TARGET_UNLOCK, OP_DROP, OP_PUSHDATA2, OP_BUDGET,
} from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated'); // generators' git-ignored output dir
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, binToHex, bigIntToVmNumber, createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = await import(LIBAUTH);
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
const evalReal = (locking, unlocking) => {
  const st = realVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

// build padded vectors for one chunk file given its incoming-state ints (decl order)
function buildChunk(cashFile, stateInts) {
  const lockHex = execFileSync('node', [CASHC, cashFile, '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
  const locking = Uint8Array.from([OP_DROP, ...hexToBin(lockHex)]);
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const probe = evalReal(locking, Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]));
  let target = tunedLen(argBytes.length, probe.operationCost);
  let unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]);
  let real = evalReal(locking, unlocking);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]); real = evalReal(locking, unlocking); }
  const invalid = Uint8Array.from(unlocking); invalid[1] ^= 0x01; // perturb first coord -> hash mismatch -> reject
  const invReal = evalReal(locking, invalid);
  return { locking, unlocking, invalidUnlocking: invalid, operationCost: real.operationCost, accepted: real.accepted, invalidRejected: !invReal.accepted };
}

// ---- recompute per-pair step states (states[k] BEFORE step k; states[65]=after loop) ----
function pairStates(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine(), negQy = Fp2.neg(Qa.y);
  const states = [{ f: Fp12.ONE, R: { x: Qa.x, y: Qa.y, z: Fp2.ONE } }];
  let cur = states[0];
  for (let k = 0; k < ATE_NAF.length; k++) { cur = millerStep(cur.f, cur.R, k, Qa.x, Qa.y, negQy, Pa.x, Pa.y); states.push(cur); }
  const final = postPrecompute(states[ATE_NAF.length].f, states[ATE_NAF.length].R, Qa.x, Qa.y, Pa.x, Pa.y);
  return { states, final };
}
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.R)];

const pairs = pairsFor(vec.publicInputs);
const steps = [];
let totalOp = 0, maxOp = 0, maxLock = 0, maxUnlock = 0, allFit = true, allAccept = true, allInvalid = true;

for (let pi = 0; pi < 4; pi++) {
  const man = JSON.parse(readFileSync(join(GEN, `manifest_p${pi}.json`), 'utf8'));
  const { states } = pairStates(pairs[pi]);
  for (const ch of man.chunks) {
    const inInts = stateLimbs(states[ch.lo]); // 18 incoming-state ints
    const b = buildChunk(join(GEN, `miller_p${pi}_${String(ch.idx).padStart(2, '0')}.cash`), inInts);
    const fits = b.locking.length <= 10000 && b.unlocking.length <= 10000 && b.operationCost <= OP_BUDGET && b.accepted;
    totalOp += b.operationCost; maxOp = Math.max(maxOp, b.operationCost); maxLock = Math.max(maxLock, b.locking.length); maxUnlock = Math.max(maxUnlock, b.unlocking.length);
    allFit &&= fits; allAccept &&= b.accepted; allInvalid &&= b.invalidRejected;
    steps.push({ label: `miller p${pi} [${ch.lo},${ch.hi})${ch.final ? ' +postPre' : ''}`, locking: binToHex(b.locking), unlocking: binToHex(b.unlocking), invalidUnlocking: binToHex(b.invalidUnlocking), checkpoint: (pi === 3 && ch.final) ? undefined : undefined, lockingBytes: b.locking.length, unlockingBytes: b.unlocking.length, operationCost: b.operationCost });
  }
  console.error(`pair ${pi}: ${man.chunks.length} chunks built`);
}
// combine chunk
{
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_combine.json'), 'utf8'));
  const inInts = man.incomingLimbs.map((s) => BigInt(s));
  const b = buildChunk(join(GEN, 'combine.cash'), inInts);
  const fits = b.locking.length <= 10000 && b.unlocking.length <= 10000 && b.operationCost <= OP_BUDGET && b.accepted;
  totalOp += b.operationCost; maxOp = Math.max(maxOp, b.operationCost); maxLock = Math.max(maxLock, b.locking.length); maxUnlock = Math.max(maxUnlock, b.unlocking.length);
  allFit &&= fits; allAccept &&= b.accepted; allInvalid &&= b.invalidRejected;
  steps.push({ label: 'combine: boundary = f0*f1*f2*f3', locking: binToHex(b.locking), unlocking: binToHex(b.unlocking), invalidUnlocking: binToHex(b.invalidUnlocking), checkpoint: 'miller-boundary', lockingBytes: b.locking.length, unlockingBytes: b.unlocking.length, operationCost: b.operationCost });
  console.error(`combine built`);
}

console.error(`--- ${steps.length} steps | total op ${totalOp.toLocaleString()} max/step ${maxOp.toLocaleString()} (budget ${OP_BUDGET.toLocaleString()})`);
console.error(`max lock ${maxLock}B max unlock ${maxUnlock}B | allFit=${allFit} allAccept=${allAccept} allInvalidRejected=${allInvalid}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-chunked-vectors.json', JSON.stringify({
  description: 'chunked BN254 Groth16 pairing to the Miller boundary (4 single-pair Miller chains + combine), multi-tx, every step fits one BCH input',
  numSteps: steps.length, budgetPerInput: OP_BUDGET, totalOperationCost: totalOp, maxStepOperationCost: maxOp,
  allFit, allAccept, allInvalidRejected: allInvalid, steps,
}, null, 2));
console.error('wrote src/bch/pairing-chunked-vectors.json');
