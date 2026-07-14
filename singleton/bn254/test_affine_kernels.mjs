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
const root = process.env.PROBE_ROOT ?? fileURLToPath(new URL('.', import.meta.url));
const compileOptions = process.env.RAW === '1' ? {} : { rescheduleStacks: true };
const probes = Object.fromEntries(['fp2sqr', 'affine_double', 'affine_add'].map((name) => {
  const redeem = utils.asmToBytecode(compileFile(join(root, `${name}_kernel_probe.cash`), compileOptions).bytecode);
  return [name, { redeem, locking: encodeLockingBytecodeP2sh32(hash256(redeem)), redeemPush: encodeDataPush(redeem) }];
}));
const vms = [
  ['consensus', createVirtualMachineBch2026(false)],
  ['standard', createVirtualMachineBch2026(true)],
];
const Fp2 = bn254.fields.Fp2;
const mod = (x) => ((x % P) + P) % P;
const asFp2 = (x) => Fp2.fromBigTuple(x.map(mod));
const limbs = (x) => [x.c0, x.c1];

const pushInt = (value) => encodeDataPush(bigIntToVmNumber(value));
const evaluate = (probe, args, vm) => {
  const argBytes = Uint8Array.from(args.slice().reverse().flatMap((value) => [...pushInt(value)]));
  const budget = 10_000 - argBytes.length - probe.redeemPush.length;
  const paddingLength = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  if (paddingLength < 0) throw new Error('probe exceeds the unlocking-bytecode limit');
  const padding = encodeDataPush(new Uint8Array(paddingLength));
  const unlocking = Uint8Array.from([...padding, ...argBytes, ...probe.redeemPush]);
  const state = vm.evaluate(createTestAuthenticationProgramBch({
    lockingBytecode: probe.locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  }));
  const top = state.stack[state.stack.length - 1];
  return {
    accepted: state.error === undefined && state.stack.length === 1 && top?.length === 1 && top[0] === 1,
    error: state.error ?? null,
    operationCost: state.metrics.operationCost,
    evaluatedInstructions: state.metrics.evaluatedInstructionCount,
    stackPushedBytes: state.metrics.stackPushedBytes,
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
const rng = splitmix64(0x616666696e656b65n);
const randomBelow = (limit) => {
  let value = 0n;
  for (let i = 0; i < 5; i++) value = (value << 64n) | rng();
  return value % limit;
};

const sqrExpected = (a) => limbs(Fp2.sqr(asFp2(a)));
const doubleVector = (name, x, y, slope) => {
  const X = asFp2(x), Y = asFp2(y);
  const m = slope === undefined
    ? Fp2.div(Fp2.mul(Fp2.sqr(X), 3n), Fp2.mul(Y, 2n))
    : asFp2(slope);
  const nX = Fp2.sub(Fp2.sqr(m), Fp2.mul(X, 2n));
  const nY = Fp2.sub(Fp2.mul(m, Fp2.sub(X, nX)), Y);
  const mx = limbs(Fp2.mul(m, X));
  const exactC0 = [mod(y[0]) - mx[0] + P, mod(y[1]) - mx[1] + P];
  return { name, args: [...x.map(mod), ...y.map(mod), ...limbs(m), ...exactC0, ...limbs(m), P - 1n, 0n, ...limbs(nX), ...limbs(nY)] };
};
const addVector = (name, x, y, qx, qy, slope) => {
  const X = asFp2(x), Y = asFp2(y), Qx = asFp2(qx), Qy = asFp2(qy);
  const m = slope === undefined ? Fp2.div(Fp2.sub(Qy, Y), Fp2.sub(Qx, X)) : asFp2(slope);
  const nX = Fp2.sub(Fp2.sub(Fp2.sqr(m), X), Qx);
  const nY = Fp2.sub(Fp2.mul(m, Fp2.sub(X, nX)), Y);
  const mx = limbs(Fp2.mul(m, X));
  const exactC0 = [mod(y[0]) - mx[0] + P, mod(y[1]) - mx[1] + P];
  return { name, args: [...x.map(mod), ...y.map(mod), ...qx.map(mod), ...qy.map(mod), ...limbs(m), ...exactC0, ...limbs(m), P - 1n, 0n, ...limbs(nX), ...limbs(nY)] };
};

const sqrVectors = [
  ...Array.from({ length: 24 }, (_, i) => ({ name: `random-${i}`, a: [randomBelow(36n * P), randomBelow(36n * P)] })),
  { name: 'dense', a: [P - 1n, P - 2n] },
  { name: 'lazy-max', a: [36n * P - 1n, 36n * P - 2n] },
  { name: 'corner-zero', a: [0n, 0n] },
  { name: 'corner-one', a: [1n, 0n] },
];
const doubleVectors = [
  ...Array.from({ length: 24 }, (_, i) => doubleVector(`random-${i}`,
    [randomBelow(P), randomBelow(P)], [randomBelow(P), randomBelow(P)])),
  doubleVector('dense', [P - 2n, P - 3n], [P - 5n, P - 7n]),
  doubleVector('corner', [0n, 0n], [1n, 0n], [0n, 0n]),
];
const addVectors = [
  ...Array.from({ length: 24 }, (_, i) => addVector(`random-${i}`,
    [randomBelow(P), randomBelow(P)], [randomBelow(P), randomBelow(P)],
    [randomBelow(P), randomBelow(P)], [randomBelow(P), randomBelow(P)])),
  addVector('dense', [P - 2n, P - 3n], [P - 5n, P - 7n], [P - 11n, P - 13n], [P - 17n, P - 19n]),
  addVector('corner', [0n, 0n], [0n, 0n], [1n, 0n], [0n, 0n], [0n, 0n]),
];

const run = (label, probe, vectors, argsFor) => {
  const samples = {};
  for (const vector of vectors) {
    const args = argsFor(vector);
    for (const [vmName, vm] of vms) {
      const result = evaluate(probe, args, vm);
      if (!result.accepted) throw new Error(`${label} ${vector.name} failed on ${vmName}: ${result.error}`);
      if (vector.name === 'dense' || vector.name.startsWith('corner')) (samples[vector.name] ??= {})[vmName] = result;
    }
  }
  console.log(`${label}: ${vectors.length}/${vectors.length} accepted on consensus+standard BCH VMs`);
  console.log(JSON.stringify({ redeemBytes: probe.redeem.length, samples }));
};

run('fp2Sqr', probes.fp2sqr, sqrVectors, (vector) => [...vector.a, ...sqrExpected(vector.a)]);
run('pointDoubleAffine', probes.affine_double, doubleVectors, (vector) => vector.args);
run('pointAddAffine', probes.affine_add, addVectors, (vector) => vector.args);

const badSqr = [...sqrVectors[0].a, ...sqrExpected(sqrVectors[0].a)]; badSqr[2] += P;
const badDoubleSlope = doubleVectors[0].args.slice(); badDoubleSlope[4] = (badDoubleSlope[4] + 1n) % P;
const zeroDoubleDenominator = doubleVectors[0].args.slice(); zeroDoubleDenominator[2] = 0n; zeroDoubleDenominator[3] = 0n;
const badAddSlope = addVectors[0].args.slice(); badAddSlope[8] = (badAddSlope[8] + 1n) % P;
const zeroAddDenominator = addVectors[0].args.slice(); zeroAddDenominator[4] = zeroAddDenominator[0]; zeroAddDenominator[5] = zeroAddDenominator[1];
for (const [vmName, vm] of vms) {
  for (const [label, probe, args] of [
    ['noncanonical square result', probes.fp2sqr, badSqr],
    ['double slope mutation', probes.affine_double, badDoubleSlope],
    ['zero double denominator', probes.affine_double, zeroDoubleDenominator],
    ['add slope mutation', probes.affine_add, badAddSlope],
    ['zero add denominator', probes.affine_add, zeroAddDenominator],
  ]) {
    if (evaluate(probe, args, vm).accepted) throw new Error(`${label} accepted on ${vmName}`);
  }
}
console.log('negative fixtures: noncanonical result, slope mutations, and zero denominators rejected on both BCH VMs');
