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

import { millerBatchOps, pairsFor, vec } from '../../chunked/pairing/_millermath.mjs';
import { fp12limbsOf, millerFusedOps, residueWitness } from '../../chunked/pairing/_residuemath.mjs';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const here = fileURLToPath(new URL('.', import.meta.url));
const probe = process.env.PROBE ?? join(here, 'residue_verdict_probe.cash');
const redeem = utils.asmToBytecode(compileFile(probe, { rescheduleStacks: true }).bytecode);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const redeemPush = encodeDataPush(redeem);
const vms = [
  ['consensus', createVirtualMachineBch2026(false)],
  ['standard', createVirtualMachineBch2026(true)],
];

const pushInt = (value) => encodeDataPush(bigIntToVmNumber(value));
const evaluate = (args, vm) => {
  const argBytes = Uint8Array.from(args.slice().reverse().flatMap((value) => [...pushInt(value)]));
  const paddingLength = 10_000 - argBytes.length - redeemPush.length - 3;
  if (paddingLength < 0) throw new Error('probe exceeds the unlocking-bytecode limit');
  const padding = encodeDataPush(new Uint8Array(paddingLength));
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
    operationCost: state.metrics.operationCost,
  };
};

const pairs = pairsFor(vec.publicInputs.map(BigInt));
const { boundary: fRaw } = millerBatchOps(pairs);
const { c, cInv, w } = residueWitness(fRaw);
const { boundary: fF } = millerFusedOps(pairs, c, cInv);
const valid = [...fp12limbsOf(fF), ...fp12limbsOf(c), ...fp12limbsOf(cInv), ...fp12limbsOf(w)];
const tampered = valid.slice(); tampered[0] = (tampered[0] + 1n) % P;
const equivalentCinv = valid.slice(); equivalentCinv[24] += P;

for (const [name, vm] of vms) {
  const good = evaluate(valid, vm);
  const bad = evaluate(tampered, vm);
  const equivalent = evaluate(equivalentCinv, vm);
  if (!good.accepted) throw new Error(`valid residue witness failed on ${name}: ${good.error}`);
  if (bad.accepted) throw new Error(`tampered residue witness accepted on ${name}`);
  if (!equivalent.accepted) throw new Error(`modulo-equivalent cInv witness failed on ${name}: ${equivalent.error}`);
  console.log(`${name}: valid=true tampered=false equivalent-cInv=true op-cost=${good.operationCost.toLocaleString()}`);
}
console.log(`redeem bytes: ${redeem.length.toLocaleString()}`);
