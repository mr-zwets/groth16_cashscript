// Compile every chunkNN.cash, build per-chunk PADDED (locking, unlocking)
// vectors, and measure op-cost + size on the real & loosened BCH 2026 VMs.
// Writes src/bch/vkx-chunked-vectors.json into the verifier repo for the
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
//   spend() declares (accX,accY,accZ,bX,bY,bZ,rX,rY,rZ) so the spender pushes
//   rZ,rY,rX,bZ,bY,bX,accZ,accY,accX (cashc reverses ctor/function args).
//   Arg ints are pushed with MINIMAL encoding (OP_0 for 0, OP_1..OP_16 for
//   1..16, else a data push) -- libauth's real VM rejects non-minimal pushes.
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

// One big zero-push that brings argLen up to TARGET_UNLOCK total bytes.
const padPush = (argLen) => {
  const overhead = 3; // OP_PUSHDATA2 + 2-byte length
  const N = TARGET_UNLOCK - argLen - overhead;
  if (N < 0) throw new Error(`arg pushes (${argLen}B) already exceed target ${TARGET_UNLOCK}`);
  return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]);
};

const out = {
  K: manifest.K, numChunks: manifest.numChunks, input0: manifest.input0,
  input1: manifest.input1, expected: manifest.expected,
  padding: { targetUnlockBytes: TARGET_UNLOCK, opDropPrefix: true, padOpcode: 'OP_PUSHDATA2(0x4d)' },
  budgetPerInput: STANDARD_BUDGET,
  chunks: [],
};
let totalOp = 0, maxOp = 0, maxLock = 0, maxUnlock = 0;
let allFit = true, allAccept = true, allReal = true;

for (const ch of manifest.chunks) {
  const lockHex = execFileSync('node', [CASHC, join(here, ch.file), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
  const rawLock = hexToBin(lockHex);
  // PREPEND OP_DROP to consume the padding push that lands on top of the stack.
  const locking = Uint8Array.from([OP_DROP, ...rawLock]);

  // unlocking: 9 coords reverse declaration order, MINIMAL pushes, then big zero pad.
  const coords = ch.incoming_state.map((s) => BigInt(s)); // [accX..rZ]
  const reversed = [...coords].reverse();                 // rZ..accX
  const argBytes = Uint8Array.from(reversed.flatMap((c) => [...pushInt(c)]));
  const pad = padPush(argBytes.length);
  const unlocking = Uint8Array.from([...argBytes, ...pad]);

  const loose = evalPair(looseVm, locking, unlocking);
  const real = evalPair(realVm, locking, unlocking);
  const fits = locking.length <= 10_000 && unlocking.length <= 10_000 && real.operationCost <= STANDARD_BUDGET && real.accepted;
  totalOp += real.operationCost; maxOp = Math.max(maxOp, real.operationCost);
  maxLock = Math.max(maxLock, locking.length); maxUnlock = Math.max(maxUnlock, unlocking.length);
  if (!fits) allFit = false;
  if (!loose.accepted) allAccept = false;
  if (!real.accepted) allReal = false;

  console.log(
    `chunk ${String(ch.idx).padStart(2)} term${ch.term} [${String(ch.lo).padStart(3)},${String(ch.hi).padStart(3)}) ` +
    `fold=${ch.fold ? 1 : 0} fin=${ch.final ? 1 : 0} | lock ${String(locking.length).padStart(5)}B unlock ${unlocking.length}B | ` +
    `loose=${loose.accepted ? 'OK' : 'X'} real=${real.accepted ? 'OK' : 'X'} ` +
    `op-cost ${real.operationCost.toLocaleString().padStart(11)} fits=${fits ? 'Y' : 'N'} ` +
    `${loose.error ?? ''}${real.error ? ' realerr:' + real.error : ''}`,
  );

  out.chunks.push({
    idx: ch.idx, file: ch.file, term: ch.term, lo: ch.lo, hi: ch.hi,
    fold: ch.fold, final: ch.final, incoming: ch.incoming, outgoing: ch.outgoing,
    locking: binToHex(locking), unlocking: binToHex(unlocking),
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    operationCost: real.operationCost, accepted: real.accepted,
  });
}

console.log('---');
console.log(`chunks=${manifest.numChunks} K=${manifest.K} | total op-cost ${totalOp.toLocaleString()} | max/step ${maxOp.toLocaleString()} (budget ${STANDARD_BUDGET.toLocaleString()})`);
console.log(`max lock ${maxLock}B max unlock ${maxUnlock}B | allLooseAccept=${allAccept} allRealAccept=${allReal} allFit=${allFit}`);

const outPath = process.env.OUT || 'C:/Users/mathi/Desktop/verifier/src/bch/vkx-chunked-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote', outPath);
