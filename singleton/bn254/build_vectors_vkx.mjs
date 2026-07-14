// Build PADDED (locking, unlocking) vectors for the FULL single-tx vk_x contract
// (VkX, singleton/vkx.cash) -- the monolithic baseline -- and measure op-cost +
// size on the real & loosened BCH 2026 VMs. Writes
// src/bch/vkx-singleton-vectors.json into the verifier repo for the
// bch-vkx-singleton benchmark entry.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// HONESTY MODEL (identical to the chunked entries): the PUBLIC INPUTS
// (input0,input1) are supplied at RUNTIME as spend() args and bit-tested in
// script; only the EXPECTED vk_x affine point is baked (the constructor args
// expectedX/expectedY) as the checkpoint comparison. We do NOT bake the input
// bits.
//
// CONSTRUCTOR BINDING: cashc's `-h` emits the redeem TEMPLATE (no constructor
// args bound). A P2SH redeem script binds constructor args by PREPENDING their
// pushes in REVERSE declaration order. VkX(expectedX, expectedY) => prepend
// push(expectedY) then push(expectedX) ahead of the template.
//
// PADDING MECHANISM (`unused` modifier): vkx.cash declares spend(bytes unused
// zeroPadding, ...). The never-referenced `zeroPadding` arg is the pad -- `unused` lets
// the compiler drop it during stack cleanup (no hand-built OP_DROP). We pad the unlocking
// to the 10,000-byte cap to buy the max per-input op-cost budget ((41+10000)*800 =
// 8,032,800); for this vector the singleton still needs ~11.95M op-cost, so even max
// padding cannot fit one input -- the CORRECT, honest multi-input baseline.
//
// Unlocking:  push(input1) || push(input0) || <pad>  (cashc reverses; pad = zeroPadding, on top)
// Locking:    push(expectedY) || push(expectedX) || template
import { compileFile } from 'cashc';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush, numberToBinUint16LE,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));

// --- vk_x parameters (consistent with bn254-vkx/vkx_vectors.json) ---
const INPUT0 = 123456789n;
const INPUT1 = 987654321n;
// expected vk_x = IC0 + input0*IC1 + input1*IC2 (py_ecc.bn128; see bn254-vkx/vkx_vectors.json)
const EXPECTED_X = 9749522656125667161218610527789566824082547561737311503154242585977001677528n;
const EXPECTED_Y = 11261491184979604396731387498248109768593573743752840655503305098314920652045n;

const TARGET_UNLOCK = 10_000;      // pad the unlocking to the standard cap
const OP_PUSHDATA2 = 0x4d;
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

// One big zero-push bringing argLen up to `target` total unlocking bytes.
const padPush = (argLen, target) => {
  const overhead = 3; // OP_PUSHDATA2 + 2-byte length
  const N = target - argLen - overhead;
  if (N < 0) throw new Error(`arg pushes (${argLen}B) already exceed target ${target}`);
  return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]);
};

// --- compile the redeem template, bind constructor args (reverse order) ---
const templateHex = compileFile(join(here, 'vkx.cash'), { optimizeFor: 'size', rescheduleStacks: true }).debug.bytecode;
const template = hexToBin(templateHex);

// No OP_DROP prefix: the pad is vkx.cash's leading `bytes unused zeroPadding` param now.
const buildLocking = (expX, expY) => Uint8Array.from([
  ...pushInt(expY), // reverse declaration order: expectedY first
  ...pushInt(expX),
  ...template,
]);

const lockingOK = buildLocking(EXPECTED_X, EXPECTED_Y);
const lockingBAD = buildLocking(EXPECTED_X, EXPECTED_Y + 1n); // tampered expected -> must reject

// --- unlocking: spend(zeroPadding,input0,input1) -> push reversed (input1, input0) + zero pad ---
const argBytes = Uint8Array.from([...pushInt(INPUT1), ...pushInt(INPUT0)]);
const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);

// Tampered INPUT: flip a bit inside the first arg push payload (corrupts input1 ->
// recomputed vk_x != expected -> must reject). The pad push is untouched.
const invalidInput = Uint8Array.from(unlocking);
invalidInput[1] = invalidInput[1] ^ 0x01;

// --- evaluate ---
const looseAccept = evalPair(looseVm, lockingOK, unlocking);
const looseRejectBadExpected = evalPair(looseVm, lockingBAD, unlocking);
const looseRejectBadInput = evalPair(looseVm, lockingOK, invalidInput);
const realAccept = evalPair(realVm, lockingOK, unlocking);

const opCost = looseAccept.operationCost;
const fitsOneInput = opCost <= STANDARD_BUDGET && realAccept.accepted
  && lockingOK.length <= 10_000 && unlocking.length <= 10_000;
const inputsNeeded = Math.ceil(opCost / STANDARD_BUDGET);

console.log('=== VkX singleton (full vk_x, single-tx, monolithic baseline) ===');
console.log(`input0=${INPUT0} input1=${INPUT1} (RUNTIME spend args; only expected vk_x baked)`);
console.log(`locking ${lockingOK.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT correct = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})`);
console.log(`loosened: REJECT bad-expected = ${!looseRejectBadExpected.accepted}`);
console.log(`loosened: REJECT bad-input    = ${!looseRejectBadInput.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`budget/input = ${STANDARD_BUDGET.toLocaleString()}  fitsOneInput = ${fitsOneInput}  inputsNeeded = ${inputsNeeded}`);

const out = {
  contract: 'VkX (singleton/vkx.cash)',
  description: 'full vk_x = IC0 + input0*IC1 + input1*IC2 in ONE contract (monolithic baseline)',
  input0: Number(INPUT0), input1: Number(INPUT1),
  expected: [EXPECTED_X.toString(), EXPECTED_Y.toString()],
  padding: { maxUnlockBytes: TARGET_UNLOCK, mechanism: 'unused-modifier', padParam: 'zeroPadding', padOpcode: 'OP_PUSHDATA2(0x4d)' },
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

const outPath = process.env.OUT || 'C:/Users/mathi/Desktop/verifier/src/bch/vkx-singleton-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote', outPath);
