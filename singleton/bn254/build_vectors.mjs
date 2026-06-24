// Build (locking, unlocking) vectors for the FULL single-tx Groth16 pairing
// verifier (GrothPairing, singleton/pairing/verify.cash) and measure op-cost +
// size on the real & loosened BCH 2026 VMs. Writes
// src/bch/pairing-singleton-vectors.json into the verifier repo for the
// bch-pairing-singleton benchmark entry.
//
//   verify: e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1
//
// The four (P in G1, Q in G2) pairs are supplied at RUNTIME (spend args); the
// contract computes the four Miller loops, their product, the final
// exponentiation, and require()s the result == Fp12 ONE (the verification
// verdict is intrinsic -- nothing is baked). The invalid instance feeds the same
// vk/proof but a tampered public input (different vk_x) -> result != 1 -> reject.
//
// At ~1.21B op-cost (and a ~20 KB contract) it does NOT fit one BCH input -- the
// honest result that motivates the chunked multi-tx pairing (task #8).
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';
const { Fp2 } = bn254.fields;

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = fileURLToPath(import.meta.resolve('cashc/dist/cashc-cli.js'));
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

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
// unlocking = spend args pushed in REVERSE declaration order (cashc convention)
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// --- reconstruct the 4 Groth16 pairs (valid + invalid) from the committed instance ---
const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
const pairArgs = (inputs) => {
  let vkx = vk.ic[0];
  inputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
  const pairs = [
    { P: proof.a.negate(), Q: proof.b }, { P: vk.alpha, Q: vk.beta },
    { P: vkx, Q: vk.gamma }, { P: proof.c, Q: vk.delta },
  ];
  const a = [];
  for (const { P, Q } of pairs) { const Pa = P.toAffine(), Qa = Q.toAffine(); a.push(Qa.x.c0, Qa.x.c1, Qa.y.c0, Qa.y.c1, Pa.x, Pa.y); }
  return a;
};

// --- compile contract, build vectors ---
const template = hexToBin(execFileSync('node', [CASHC, join(here, 'verify.cash'), '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
const unlocking = unlockingFor(pairArgs(vec.publicInputs));
const invalidUnlocking = unlockingFor(pairArgs(vec.invalid.publicInputs));

// --- evaluate ---
const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log('=== GrothPairing singleton (full pairing verdict, single-tx) ===');
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`budget/input = ${STANDARD_BUDGET.toLocaleString()}  inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

const out = {
  contract: 'GrothPairing (singleton/pairing/verify.cash)',
  description: 'full Groth16 pairing verdict e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)==1 in ONE contract',
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
const outPath = process.env.OUT || 'C:/Users/mathi/Desktop/verifier/src/bch/pairing-singleton-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote', outPath);
