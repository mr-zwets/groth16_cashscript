// Shared dev harness for the singleton pairing layers. Compiles a .cash with the
// local cashc `feat/multi-returns` build, then evaluates spend() on the
// LOOSENED BCH 2026 VM (all resource ceilings lifted) so we measure correctness
// and op-cost without the consensus wall. Contracts here have NO constructor
// args, so locking = redeem template; unlocking = spend args pushed in REVERSE
// declaration order (cashc reverses so the first param ends on top of stack).
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  hexToBin, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

export const CASHC = fileURLToPath(import.meta.resolve('cashc/dist/cashc-cli.js'));
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

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

// minimal VM-number push (OP_0 / OP_1NEGATE / OP_1..16 / data push)
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));

export const compileTemplate = (file) =>
  hexToBin(execFileSync('node', [CASHC, file, '-h', '--optimize-for', 'size'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());

// args: bigint[] in DECLARATION order. Pushed reversed so first param ends on top.
export const evalArgs = (template, args) => {
  const unlocking = Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: template, unlockingBytecode: unlocking, valueSatoshis: 1000n,
  });
  const state = looseVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1
    && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: state.error, opCost: state.metrics.operationCost, unlockLen: unlocking.length };
};

// deterministic SplitMix64 PRNG -> random Fp elements (reproducible vectors)
export const splitmix64 = (seed) => {
  let s = BigInt.asUintN(64, seed);
  return () => {
    s = BigInt.asUintN(64, s + 0x9e3779b97f4a7c15n);
    let z = s;
    z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
    z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
    return z ^ (z >> 31n);
  };
};
// a full ~254-bit field element from 4 64-bit draws
export const randFp = (rng) => {
  let x = 0n;
  for (let i = 0; i < 4; i++) x = (x << 64n) | rng();
  return x % P;
};

// run a list of vectors (each = bigint[] decl-order args) and report pass/fail.
export const runVectors = (label, template, vectors, { tamperIndex } = {}) => {
  let pass = 0, opCost = 0;
  for (const v of vectors) {
    const r = evalArgs(template, v);
    if (r.accepted) { pass++; opCost = r.opCost; }
    else { console.log(`  [FAIL] ${label}: ${r.error ?? 'rejected'}  args=${v.slice(0, 4).join(',')}...`); }
  }
  // negative control: tamper one expected limb -> must reject
  let rejectOK = true;
  if (tamperIndex !== undefined && vectors.length) {
    const bad = vectors[0].slice();
    bad[tamperIndex] = (bad[tamperIndex] + 1n) % P;
    rejectOK = !evalArgs(template, bad).accepted;
  }
  const ok = pass === vectors.length && rejectOK;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}: ${pass}/${vectors.length} accept, tamper-reject=${rejectOK}, op-cost~${opCost.toLocaleString()}`);
  return ok;
};
