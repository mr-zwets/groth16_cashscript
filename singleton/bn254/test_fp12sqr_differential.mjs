import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { compileFile, utils } from 'cashc';
import {
  bigIntToVmNumber,
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const M = 64n * P;
const here = fileURLToPath(new URL('.', import.meta.url));
const redeem = utils.asmToBytecode(compileFile(
  join(here, 'fp12sqr_differential_probe.cash'),
  { rescheduleStacks: true },
).bytecode);
const redeemPush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const vms = [
  ['consensus', createVirtualMachineBch2026(false)],
  ['standard', createVirtualMachineBch2026(true)],
];

const pushInt = (value) => encodeDataPush(bigIntToVmNumber(value));
const padPush = (fixedLength) => {
  const budget = 10_000 - fixedLength;
  const dataLength = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  if (dataLength < 0) throw new Error('differential probe exceeds the unlocking-bytecode limit');
  return encodeDataPush(new Uint8Array(dataLength));
};
const evaluate = (limbs, vm) => {
  const argBytes = Uint8Array.from(limbs.slice().reverse().flatMap((value) => [...pushInt(value)]));
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
const rng = splitmix64(0x73717264696666n);
const randomBelow = (limit) => {
  let value = 0n;
  for (let i = 0; i < 5; i++) value = (value << 64n) | rng();
  return value % limit;
};

const vectors = [
  { name: 'zero', limbs: Array(12).fill(0n) },
  { name: 'one', limbs: [1n, ...Array(11).fill(0n)] },
  { name: 'p-minus-one', limbs: Array(12).fill(P - 1n) },
  { name: 'negative-p-plus-one', limbs: Array(12).fill(1n - P) },
  { name: 'lazy-max', limbs: Array(12).fill(M - 1n) },
  {
    name: 'signed-alternating',
    limbs: Array.from({ length: 12 }, (_, index) => index % 2 === 0 ? P - 1n : 1n - P),
  },
  {
    name: 'lazy-alternating',
    limbs: Array.from({ length: 12 }, (_, index) => index % 2 === 0 ? M - 1n : 0n),
  },
  ...Array.from({ length: 24 }, (_, index) => ({
    name: 'lazy-random-' + index,
    limbs: Array.from({ length: 12 }, () => randomBelow(M)),
  })),
  ...Array.from({ length: 24 }, (_, index) => ({
    name: 'signed-random-' + index,
    limbs: Array.from({ length: 12 }, () => randomBelow(2n * P - 1n) - (P - 1n)),
  })),
];

for (const vector of vectors) {
  for (const [vmName, vm] of vms) {
    const result = evaluate(vector.limbs, vm);
    if (!result.accepted) {
      throw new Error(vector.name + ' failed on ' + vmName + ': ' + result.error);
    }
  }
}

console.log(
  'fp12Sqr canonical/signed differential: ' + vectors.length + '/' + vectors.length +
  ' vectors accepted on consensus+standard BCH VMs; redeem=' + redeem.length + 'B',
);
