// Compile every chunkNN.cash, build per-chunk PADDED (locking, unlocking)
// vectors, and measure op-cost + size on the real & loosened BCH 2026 VMs.
// Writes src/bch/vkx-chunked-vectors.json into the verifier repo for the
// bch-vkx-chunked benchmark entry.
//
// PADDING MECHANISM (`unused` modifier): each chunk's spend() ends with a trailing
//   `bytes unused zeroPadding` arg the unlocker fills with zero bytes to buy the real-VM
//   op-cost budget ((41 + 10000) * 800 = 8,032,800). `unused` exempts it from the
//   unused-variable check and the compiler drops it during stack cleanup, so no OP_DROP
//   prefix is needed. As the LAST param it is pushed FIRST -> it sits at the bottom of
//   the stack (the coords keep their positions, so the bytecode is unchanged but for one
//   cleanup OP_NIP -- cost-neutral, unlike a leading pad which deepens every coord access).
//
// Unlocking layout:
//   <OP_PUSHDATA2 N 0x00*N> <arg pushes, REVERSE declaration order>
//   spend() declares (accX,accY,accZ,bX,bY,bZ,rX,rY,rZ,zeroPadding) so the spender pushes
//   the zeroPadding pad first, then rZ..accX (cashc reverses args). Arg ints use MINIMAL
//   encoding (OP_0 for 0, OP_1..OP_16 for 1..16, else a data push) -- libauth's real VM
//   rejects non-minimal pushes.
//
// Locking layout:  compiled chunk redeem bytecode (no OP_DROP prefix).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
// Resolve libauth from the verifier repo's node_modules (this generator lives in
// the groth16_contract repo, which has no node_modules of its own).
import { pathToFileURL } from 'node:url';
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush, numberToBinUint16LE,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
// Chunk contracts + manifest are generated (gitignored); run `python gen_chunks.py` first.
const GEN = join(here, 'generated');
const manifest = JSON.parse(readFileSync(join(GEN, 'manifest.json'), 'utf8'));

const TARGET_UNLOCK = 10_000;      // pad each unlocking up to this many bytes
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
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));

// One big zero-push that brings argLen up to TARGET_UNLOCK total bytes.
const padPush = (argLen) => {
  const overhead = 3; // OP_PUSHDATA2 + 2-byte length
  const N = TARGET_UNLOCK - argLen - overhead;
  if (N < 0) throw new Error(`arg pushes (${argLen}B) already exceed target ${TARGET_UNLOCK}`);
  return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]);
};

const out = {
  K: manifest.K, numChunks: manifest.numChunks, input0: manifest.input0,
  input1: manifest.input1, expected: manifest.expected,
  padding: { targetUnlockBytes: TARGET_UNLOCK, mechanism: 'unused-modifier', padParam: 'zeroPadding', padOpcode: 'OP_PUSHDATA2(0x4d)' },
  budgetPerInput: STANDARD_BUDGET,
  chunks: [],
};
let totalOp = 0, maxOp = 0, maxLock = 0, maxUnlock = 0;
let allFit = true, allAccept = true, allReal = true;

for (const ch of manifest.chunks) {
  const lockHex = execFileSync('node', [CASHC, join(GEN, ch.file), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
  const rawLock = hexToBin(lockHex);
  // No OP_DROP: the pad is the chunk's leading `bytes unused zeroPadding` param now.
  const locking = Uint8Array.from([...rawLock]);

  // unlocking: big zero pad first (trailing `zeroPadding` param -> pushed first), then
  // the 9 coords in reverse declaration order with MINIMAL pushes.
  const coords = ch.incoming_state.map((s) => BigInt(s)); // [accX..rZ]
  const reversed = [...coords].reverse();                 // rZ..accX
  const argBytes = Uint8Array.from(reversed.flatMap((c) => [...pushInt(c)]));
  const pad = padPush(argBytes.length);
  const unlocking = Uint8Array.from([...pad, ...argBytes]);

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
