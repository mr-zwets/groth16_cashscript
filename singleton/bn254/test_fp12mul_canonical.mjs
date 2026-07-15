import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { compileFile, utils } from 'cashc';
import {
  bigIntToVmNumber,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const M = 64n * P;
const here = fileURLToPath(new URL('.', import.meta.url));
const redeem = utils.asmToBytecode(compileFile(join(here, 'fp12mul_canonical_probe.cash'), { rescheduleStacks: true }).bytecode);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const redeemPush = encodeDataPush(redeem);
const vms = [
  ['consensus', createVirtualMachineBch2026(false)],
  ['standard', createVirtualMachineBch2026(true)],
];

const mod = (x) => ((x % P) + P) % P;
const limbs = (x) => [
  x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
  x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1,
];
const expectedMul = (a, b) => limbs(bn254.fields.Fp12.mul(
  bn254.fields.Fp12.fromBigTwelve(a.map(mod)),
  bn254.fields.Fp12.fromBigTwelve(b.map(mod)),
));
const pushInt = (value) => encodeDataPush(bigIntToVmNumber(value));
const padPush = (fixedLength) => {
  const budget = 10_000 - fixedLength;
  const dataLength = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  if (dataLength < 0) throw new Error('probe exceeds the unlocking-bytecode limit');
  return encodeDataPush(new Uint8Array(dataLength));
};
const evaluate = (a, b, expected, vm) => {
  const args = [...a, ...b, ...expected];
  const argBytes = Uint8Array.from(args.slice().reverse().flatMap((value) => [...pushInt(value)]));
  const padding = padPush(argBytes.length + redeemPush.length);
  const unlocking = Uint8Array.from([...padding, ...argBytes, ...redeemPush]);
  const state = vm.evaluate(createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  }));
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 && top?.length === 1 && top[0] === 1,
    error: state.error ?? null,
  };
};

const splitmix64 = (seed) => {
  let state = BigInt.asUintN(64, seed);
  return () => {
    state = BigInt.asUintN(64, state + 0x9e3779b97f4a7c15n);
    let z = state;
    z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
    z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
    return z ^ (z >> 31n);
  };
};
const rng = splitmix64(0x63616e6f6e696361n);
const randomBelow = (limit) => {
  let value = 0n;
  for (let i = 0; i < 5; i++) value = (value << 64n) | rng();
  return value % limit;
};
const vectors = [
  ...Array.from({ length: 24 }, (_, index) => ({
    name: `random-${index}`,
    a: Array.from({ length: 12 }, () => randomBelow(P)),
    b: Array.from({ length: 12 }, () => randomBelow(P)),
  })),
  ...Array.from({ length: 24 }, (_, index) => ({
    name: `lazy-${index}`,
    a: Array.from({ length: 12 }, () => randomBelow(M)),
    b: Array.from({ length: 12 }, () => randomBelow(M)),
  })),
  ...Array.from({ length: 8 }, (_, index) => ({
    name: `dense-${index}`,
    a: Array.from({ length: 12 }, (_, limb) => P - 1n - BigInt((index * 24 + limb) % 251)),
    b: Array.from({ length: 12 }, (_, limb) => P - 1n - BigInt((index * 24 + 12 + limb) % 251)),
  })),
  { name: 'zero', a: Array(12).fill(0n), b: Array(12).fill(0n) },
  { name: 'one', a: [1n, ...Array(11).fill(0n)], b: [1n, ...Array(11).fill(0n)] },
  { name: 'p-1', a: Array(12).fill(P - 1n), b: Array(12).fill(P - 1n) },
  { name: 'lazy-max', a: Array(12).fill(M - 1n), b: Array(12).fill(M - 1n) },
  {
    name: 'lazy-alternating',
    a: Array.from({ length: 12 }, (_, i) => i % 2 === 0 ? M - 1n : 0n),
    b: Array.from({ length: 12 }, (_, i) => i % 2 === 1 ? M - 1n : 0n),
  },
];

let accepted = 0;
for (const vector of vectors) {
  const expected = expectedMul(vector.a, vector.b);
  for (const [name, vm] of vms) {
    const result = evaluate(vector.a, vector.b, expected, vm);
    if (!result.accepted) throw new Error(`${vector.name} failed on ${name}: ${result.error}`);
  }
  accepted++;
}

const mutationVector = vectors[0];
const expected = expectedMul(mutationVector.a, mutationVector.b);
const plusOne = expected.slice(); plusOne[0] += 1n;
const plusP = expected.slice(); plusP[0] += P;
for (const [name, vm] of vms) {
  if (evaluate(mutationVector.a, mutationVector.b, plusOne, vm).accepted) {
    throw new Error(`ordinary expected-limb mutation accepted on ${name}`);
  }
  if (evaluate(mutationVector.a, mutationVector.b, plusP, vm).accepted) {
    throw new Error(`modulo-equivalent noncanonical expected limb accepted on ${name}`);
  }
}

console.log(`fp12Mul canonical outputs: ${accepted}/${vectors.length} accepted on consensus+standard BCH VMs`);
console.log('expected-limb +1 and +P mutations: rejected on both BCH VMs');
