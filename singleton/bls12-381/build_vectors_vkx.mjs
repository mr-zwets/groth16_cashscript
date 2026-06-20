// Build PADDED (locking, unlocking) vectors for the FULL single-tx BLS12-381 vk_x
// contract (VkX, singleton/bls12-381/vkx.cash) -- the monolithic baseline -- and
// measure op-cost + size on the real & loosened BCH 2026 VMs. Writes
// verifier/src/bch/vkx-bls12381-singleton-vectors.json for the
// bch-vkx-bls12381-singleton milestone entry.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BLS12-381, b=4)
//
// Honesty model + constructor binding + padding mechanism are identical to the
// BN254 builder (../bn254/build_vectors_vkx.mjs): public inputs at RUNTIME, only
// the expected vk_x affine baked (constructor args expectedX/expectedY); locking =
// OP_DROP || push(expY) || push(expX) || template, unlocking = push(in1) ||
// push(in0) || zero-pad to the 10,000-byte cap (the pad lands on top and the
// OP_DROP removes it before the contract runs).
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { vkx as vkxPoint, PUBLIC_INPUTS } from './bls_instance.mjs';

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';

const INPUT0 = PUBLIC_INPUTS[0];
const INPUT1 = PUBLIC_INPUTS[1];
const va = vkxPoint.toAffine();
const EXPECTED_X = va.x;
const EXPECTED_Y = va.y;

const TARGET_UNLOCK = 10_000;
const OP_DROP = 0x75;
const OP_PUSHDATA2 = 0x4d;
const STANDARD_BUDGET = (41 + 10_000) * 800; // 8,032,800

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const realVm = createVirtualMachineBch2026(false);

const evalPair = (vm, locking, unlocking) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: state.error, operationCost: state.metrics.operationCost };
};
const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const padPush = (argLen, target) => {
  const N = target - argLen - 3;
  if (N < 0) throw new Error(`arg pushes (${argLen}B) already exceed target ${target}`);
  return Uint8Array.from([OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]);
};

const template = hexToBin(execFileSync('node', [CASHC, join(here, 'vkx.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
const buildLocking = (expX, expY) => Uint8Array.from([OP_DROP, ...pushInt(expY), ...pushInt(expX), ...template]);

const lockingOK = buildLocking(EXPECTED_X, EXPECTED_Y);
const lockingBAD = buildLocking(EXPECTED_X, EXPECTED_Y + 1n);
const argBytes = Uint8Array.from([...pushInt(INPUT1), ...pushInt(INPUT0)]);
const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);
const invalidInput = Uint8Array.from(unlocking);
invalidInput[1] = invalidInput[1] ^ 0x01;

const looseAccept = evalPair(looseVm, lockingOK, unlocking);
const looseRejectBadExpected = evalPair(looseVm, lockingBAD, unlocking);
const looseRejectBadInput = evalPair(looseVm, lockingOK, invalidInput);
const realAccept = evalPair(realVm, lockingOK, unlocking);

const opCost = looseAccept.operationCost;
const fitsOneInput = opCost <= STANDARD_BUDGET && realAccept.accepted && lockingOK.length <= 10_000 && unlocking.length <= 10_000;
const inputsNeeded = Math.ceil(opCost / STANDARD_BUDGET);

console.log('=== VkX BLS12-381 singleton (full vk_x, single-tx, monolithic baseline) ===');
console.log(`input0=${INPUT0} input1=${INPUT1} (RUNTIME spend args; only expected vk_x baked)`);
console.log(`locking ${lockingOK.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT correct = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})`);
console.log(`loosened: REJECT bad-expected = ${!looseRejectBadExpected.accepted}`);
console.log(`loosened: REJECT bad-input    = ${!looseRejectBadInput.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`budget/input = ${STANDARD_BUDGET.toLocaleString()}  fitsOneInput = ${fitsOneInput}  inputsNeeded = ${inputsNeeded}`);

const out = {
  contract: 'VkX (singleton/bls12-381/vkx.cash)',
  description: 'full BLS12-381 vk_x = IC0 + input0*IC1 + input1*IC2 in ONE contract (monolithic baseline)',
  input0: Number(INPUT0), input1: Number(INPUT1),
  expected: [EXPECTED_X.toString(), EXPECTED_Y.toString()],
  padding: { maxUnlockBytes: TARGET_UNLOCK, opDropPrefix: true, padOpcode: 'OP_PUSHDATA2(0x4d)' },
  budgetPerInput: STANDARD_BUDGET,
  lockingOK: binToHex(lockingOK),
  lockingBAD: binToHex(lockingBAD),
  unlocking: binToHex(unlocking),
  invalidUnlocking: binToHex(invalidInput),
  lockingBytes: lockingOK.length,
  unlockingBytes: unlocking.length,
  operationCost: opCost,
  realAccepted: realAccept.accepted,
  realError: realAccept.error ?? null,
  fitsOneInput,
  inputsNeeded,
  looseAccept: looseAccept.accepted,
  rejectBadExpected: !looseRejectBadExpected.accepted,
  rejectBadInput: !looseRejectBadInput.accepted,
};
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/vkx-bls12381-singleton-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/vkx-bls12381-singleton-vectors.json');
