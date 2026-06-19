// Compile every chunkNN.cash, build per-chunk PADDED (locking, unlocking)
// vectors, and measure op-cost + size on the real & loosened BCH 2026 VMs.
// Writes src/bch/vkx-chunked-shamir-vectors.json into the verifier repo for the
// bch-vkx-chunked benchmark entry.
//
// PADDING MECHANISM (the key to fitting one BCH input):
//   A P2SH unlocking must be PUSH-ONLY, so OP_DROP cannot live in the unlocking.
//   Instead we (a) PREPEND one OP_DROP (0x75) to the locking/redeem bytecode and
//   (b) APPEND one big zero-PUSH as the LAST item of the unlocking. The pad push
//   lands on top of the stack and is dropped first, before the contract runs.
//   Padding the unlocking to ~10,000 bytes buys the real-VM op-cost budget
//   (41 + 10000) * 800 = 8,032,800 for that input.
//
// Unlocking layout:
//   <arg pushes, REVERSE declaration order> <OP_PUSHDATA2 N 0x00*N>
//   Non-final spend() declares (rX,rY,rZ,input0,input1) so the spender pushes
//   input1,input0,rZ,rY,rX; the final chunk also appends zInv (pushed first).
//   cashc reverses ctor/function args. Arg ints are pushed with MINIMAL encoding
//   (OP_0 for 0, OP_1..OP_16 for 1..16, else a data push) -- libauth's real VM
//   rejects non-minimal pushes.
//
// Locking layout:  OP_DROP (0x75) || compiled chunk redeem bytecode.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
// Resolve libauth from the verifier repo's node_modules (this generator lives in
// the groth16_contract repo, which has no node_modules of its own).
import { pathToFileURL } from 'node:url';
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
const manifest = JSON.parse(readFileSync(join(here, 'manifest.json'), 'utf8'));

const TARGET_UNLOCK = 10_000;      // pad each unlocking up to this many bytes
const OP_DROP = 0x75;
const OP_PUSHDATA2 = 0x4d;         // 0x4d = PUSHDATA2 (2-byte LE length)
const STANDARD_BUDGET = (41 + 10_000) * 800; // 8,032,800

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: loosened, ripemd160, secp256k1, sha1, sha256,
}));
const realVm = createVirtualMachineBch2026(false);

const evalPair = (vm, locking, unlocking) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: state.error, operationCost: state.metrics.operationCost };
};

// MINIMAL VM-number push: OP_0 / OP_1NEGATE / OP_1..OP_16 / data push.
const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);                  // OP_0
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]); // OP_1..OP_16
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]); // OP_1NEGATE
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]); // OP_PUSHDATA1
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]); // OP_PUSHDATA2
};

// One big zero-push that brings argLen up to `target` total unlocking bytes.
// `target` is TUNED per chunk to the minimum that affords the chunk's op-cost
// (not blindly TARGET_UNLOCK) so we don't waste bytes buying budget we don't use.
const padPush = (argLen, target) => {
  const overhead = 3; // OP_PUSHDATA2 + 2-byte length
  const N = target - argLen - overhead;
  if (N < 0) throw new Error(`arg pushes (${argLen}B) already exceed target ${target}`);
  return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]);
};

// Minimal unlocking length that affords `opCost` op-cost: budget=(41+len)*800 >= opCost.
// + MARGIN bytes of slack (the pad push's own op-cost is ~1/byte, well covered), and
// never below the arg pushes (+3 for the empty pad push OP_DROP consumes), nor above
// the 10,000-byte cap.
const tunedUnlockLen = (argLen, opCost) => {
  const MARGIN = 64;
  const need = Math.ceil(opCost / 800) - 41 + MARGIN;
  return Math.min(TARGET_UNLOCK, Math.max(argLen + 3, need));
};

const out = {
  K: manifest.K, byteBudget: manifest.byteBudget, algorithm: manifest.algorithm,
  numChunks: manifest.numChunks, input0: manifest.input0,
  input1: manifest.input1, T: manifest.T, expected: manifest.expected,
  padding: { mode: 'tuned-per-chunk (min unlock to afford op-cost)', maxUnlockBytes: TARGET_UNLOCK, opDropPrefix: true, padOpcode: 'OP_PUSHDATA2(0x4d)' },
  budgetPerInput: STANDARD_BUDGET,
  chunks: [],
};
let totalOp = 0, maxOp = 0, maxLock = 0, maxUnlock = 0;
let allFit = true, allAccept = true, allReal = true;

// Build the unlocking arg list for a chunk in REVERSE declaration order.
// Public inputs are now carried at RUNTIME, so incoming_state is the 5-tuple
// (rX,rY,rZ,input0,input1).
// Non-final chunks declare spend(rX,rY,rZ,input0,input1)       -> push reversed.
// The final chunk declares  spend(rX,rY,rZ,input0,input1,zInv) -> push reversed.
const argListFor = (ch) => {
  const coords = ch.incoming_state.map((s) => BigInt(s)); // [rX,rY,rZ,input0,input1]
  const args = ch.final ? [...coords, BigInt(ch.zInv)] : coords; // declaration order
  return [...args].reverse();
};

for (const ch of manifest.chunks) {
  const lockHex = execFileSync('node', [CASHC, join(here, ch.file), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
  const rawLock = hexToBin(lockHex);
  // PREPEND OP_DROP to consume the padding push that lands on top of the stack.
  const locking = Uint8Array.from([OP_DROP, ...rawLock]);

  // unlocking: args reverse declaration order, MINIMAL pushes, then a TUNED zero pad.
  const reversed = argListFor(ch);
  const argBytes = Uint8Array.from(reversed.flatMap((c) => [...pushInt(c)]));
  // Probe op-cost at full pad (its padding cost only over-estimates, so the tuned
  // pad is conservatively safe), then size the pad to the minimum that affords it.
  const probeOp = evalPair(looseVm, locking, Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)])).operationCost;
  let target = tunedUnlockLen(argBytes.length, probeOp);
  let unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]);
  let real = evalPair(realVm, locking, unlocking);
  // safety net: if the real VM still rejects (op-cost > tuned budget), bump and retry.
  while (!real.accepted && target < TARGET_UNLOCK) {
    target = Math.min(TARGET_UNLOCK, target + 256);
    unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, target)]);
    real = evalPair(realVm, locking, unlocking);
  }
  const loose = evalPair(looseVm, locking, unlocking);
  const fits = locking.length <= 10_000 && unlocking.length <= 10_000 && real.operationCost <= STANDARD_BUDGET && real.accepted;
  totalOp += real.operationCost; maxOp = Math.max(maxOp, real.operationCost);
  maxLock = Math.max(maxLock, locking.length); maxUnlock = Math.max(maxUnlock, unlocking.length);
  if (!fits) allFit = false;
  if (!loose.accepted) allAccept = false;
  if (!real.accepted) allReal = false;

  // Build an INVALID unlocking for this chunk so the benchmark can show a
  // rejected case. For the final chunk we tamper zInv (Z*zInv != 1 -> reject);
  // for others we flip a bit inside the first incoming-coord push (wrong state).
  let invalidUnlocking;
  if (ch.final) {
    const args = ch.incoming_state.map((s) => BigInt(s));
    const badZInv = BigInt(ch.zInv) ^ 1n; // forge the supplied inverse
    const rev = [...args, badZInv].reverse();
    const ab = Uint8Array.from(rev.flatMap((c) => [...pushInt(c)]));
    invalidUnlocking = Uint8Array.from([...ab, ...padPush(ab.length, target)]);
  } else {
    invalidUnlocking = Uint8Array.from(unlocking);
    invalidUnlocking[1] = invalidUnlocking[1] ^ 0x01; // perturb first coord push payload
  }
  const invalidReal = evalPair(realVm, locking, invalidUnlocking);

  console.log(
    `chunk ${String(ch.idx).padStart(2)} [${String(ch.lo).padStart(3)},${String(ch.hi).padStart(3)}) ` +
    `fin=${ch.final ? 1 : 0} | lock ${String(locking.length).padStart(5)}B unlock ${unlocking.length}B | ` +
    `loose=${loose.accepted ? 'OK' : 'X'} real=${real.accepted ? 'OK' : 'X'} ` +
    `op-cost ${real.operationCost.toLocaleString().padStart(11)} fits=${fits ? 'Y' : 'N'} ` +
    `invalid-rejected=${!invalidReal.accepted ? 'Y' : 'N'} ` +
    `${loose.error ?? ''}${real.error ? ' realerr:' + real.error : ''}`,
  );

  out.chunks.push({
    idx: ch.idx, file: ch.file, lo: ch.lo, hi: ch.hi,
    final: ch.final, incoming: ch.incoming, outgoing: ch.outgoing,
    locking: binToHex(locking), unlocking: binToHex(unlocking),
    invalidUnlocking: binToHex(invalidUnlocking),
    invalidRejected: !invalidReal.accepted,
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    operationCost: real.operationCost, accepted: real.accepted,
  });
}

console.log('---');
console.log(`chunks=${manifest.numChunks} K=${manifest.K} | total op-cost ${totalOp.toLocaleString()} | max/step ${maxOp.toLocaleString()} (budget ${STANDARD_BUDGET.toLocaleString()})`);
console.log(`max lock ${maxLock}B max unlock ${maxUnlock}B | allLooseAccept=${allAccept} allRealAccept=${allReal} allFit=${allFit}`);

const outPath = process.env.OUT || 'C:/Users/mathi/Desktop/verifier/src/bch/vkx-chunked-shamir-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote', outPath);
