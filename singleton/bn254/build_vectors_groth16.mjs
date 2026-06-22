// Build (locking, unlocking) vectors for the FULL single-tx Groth16 VERIFIER
// (Groth16Verify, singleton/pairing/groth16.cash) -- vk_x computed on-chain +
// the pairing -- and measure op-cost + size on the real & loosened BCH 2026 VMs.
// Writes src/bch/groth16-singleton-vectors.json for the bch-groth16-singleton
// benchmark entry (head-to-head with nchain / scrypt full verifiers).
//
// Runtime: proof (A,B,C) + public inputs (in0,in1). VK hardcoded. The contract
// computes vk_x = IC0 + in0*IC1 + in1*IC2 on-chain and require()s the pairing
// product == 1. ~1.26B op-cost, ~21.7 KB -> does NOT fit one BCH input.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
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
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
// spend(Ax,Ay, Bxa,Bxb,Bya,Byb, Cx,Cy, in0,in1)
const proofArgs = (inputs) => {
  const A = vec.proof.a, B = vec.proof.b, C = vec.proof.c;
  return [
    BigInt(A.x), BigInt(A.y),
    BigInt(B.x.c0), BigInt(B.x.c1), BigInt(B.y.c0), BigInt(B.y.c1),
    BigInt(C.x), BigInt(C.y),
    ...inputs.map(BigInt),
  ];
};

const template = hexToBin(execFileSync('node', [CASHC, join(here, 'groth16.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
const unlocking = unlockingFor(proofArgs(vec.publicInputs));
const invalidUnlocking = unlockingFor(proofArgs(vec.invalid.publicInputs));

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log('=== Groth16Verify singleton (full verifier: vk_x on-chain + pairing, single-tx) ===');
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

const out = {
  contract: 'Groth16Verify (singleton/pairing/groth16.cash)',
  description: 'full Groth16 verifier: vk_x = IC0+in0*IC1+in1*IC2 computed on-chain, then e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)==1',
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
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/groth16-singleton-vectors.json');
