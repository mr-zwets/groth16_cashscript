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
// PADDING MECHANISM (mirrors chunked/shamir/build_vectors.mjs): a P2SH unlocking
// must be PUSH-ONLY, so OP_DROP cannot live in the unlocking. We (a) PREPEND one
// OP_DROP (0x75) to the locking/redeem bytecode and (b) APPEND one big zero-PUSH
// as the LAST item of the unlocking. The pad lands on top of the stack and is
// dropped first, before the contract runs. We pad to the 10,000-byte cap to buy
// the maximum per-input op-cost budget ((41+10000)*800 = 8,032,800) -- but the
// singleton needs ~76M op-cost, so even max padding cannot fit one input. That
// is the CORRECT, honest result (this is the multi-input monolithic baseline).
//
// Unlocking layout:  <push(input1)> <push(input0)> <OP_PUSHDATA2 N 0x00*N>
//   spend(input0, input1) -> cashc reverses -> push input1 then input0.
// Locking layout:    OP_DROP (0x75) || push(expectedY) || push(expectedX) || template.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush, numberToBinUint16LE,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';

// --- vk_x parameters (consistent with groth16_contract/vkx_vectors.json) ---
const INPUT0 = 123456789n;
const INPUT1 = 987654321n;
// expected vk_x = IC0 + input0*IC1 + input1*IC2 (py_ecc.bn128; see vkx_vectors.json)
const EXPECTED_X = 9749522656125667161218610527789566824082547561737311503154242585977001677528n;
const EXPECTED_Y = 11261491184979604396731387498248109768593573743752840655503305098314920652045n;

const TARGET_UNLOCK = 10_000;      // pad the unlocking to the standard cap
const OP_DROP = 0x75;
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
const templateHex = execFileSync('node', [CASHC, join(here, 'vkx.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
const template = hexToBin(templateHex);

const buildLocking = (expX, expY) => Uint8Array.from([
  OP_DROP,
  ...pushInt(expY), // reverse declaration order: expectedY first
  ...pushInt(expX),
  ...template,
]);

const lockingOK = buildLocking(EXPECTED_X, EXPECTED_Y);
const lockingBAD = buildLocking(EXPECTED_X, EXPECTED_Y + 1n); // tampered expected -> must reject

// --- unlocking: spend(input0,input1) -> push reversed (input1, input0) + zero pad ---
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

const outPath = process.env.OUT || 'C:/Users/mathi/Desktop/verifier/src/bch/vkx-singleton-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote', outPath);
