// Build (locking, unlocking) vectors for the BLS12-381 pairing-only verdict
// (GrothVerify, singleton/bls12-381/verify.cash) -- four Miller loops + product +
// final exp, require == 1 -- and measure op-cost + size. Writes
// verifier/src/bch/pairing-bls12381-singleton-vectors.json for the
// bch-pairing-bls12381-singleton entry.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { vkx, grothPairs, pairRow, computeVkx, PUBLIC_INPUTS } from './bls_instance.mjs';

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
const STANDARD_BUDGET = (41 + 10_000) * 800;

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
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

const validArgs = grothPairs(vkx).flatMap(pairRow);
const invalidArgs = grothPairs(computeVkx([PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]])).flatMap(pairRow);

const template = hexToBin(execFileSync('node', [CASHC, join(here, 'verify.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
const unlocking = unlockingFor(validArgs);
const invalidUnlocking = unlockingFor(invalidArgs);

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log('=== GrothVerify BLS12-381 pairing verdict (single-tx) ===');
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

const out = {
  contract: 'GrothVerify (singleton/bls12-381/verify.cash)',
  description: 'BLS12-381 pairing verdict: e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)==1 (vk_x supplied as pair-3 G1 input)',
  lockingOK: binToHex(template),
  unlocking: binToHex(unlocking),
  invalidUnlocking: binToHex(invalidUnlocking),
  lockingBytes: template.length,
  unlockingBytes: unlocking.length,
  operationCost: opCost,
  realAccepted: realAccept.accepted,
  realError: realAccept.error ?? null,
  inputsNeeded: Math.ceil(opCost / STANDARD_BUDGET),
  looseAccept: looseAccept.accepted,
  rejectInvalid: !looseRejectInvalid.accepted,
};
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-bls12381-singleton-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/pairing-bls12381-singleton-vectors.json');
