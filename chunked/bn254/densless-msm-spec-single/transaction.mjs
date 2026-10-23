// One input: the pushes of layout (build.mjs) followed by the redeem.
import assert from 'node:assert/strict';
import {bigIntToVmNumber, encodeDataPush} from '@bitauth/libauth';
import {build, layout, PINS} from './build.mjs';
import {witness as msmWitness} from '../pairfold5-msm/vkx-msm-asm.mjs';
import {produceWitness} from '../densless-recovered/witness.mjs';

let cached;
export const program = () => (cached ??= build());

// With pins, the terminal's ten boundary-line evaluations (values 0..9) go in ascending order.
const terminalValues = (hexes, pins) => {
  const values = hexes.slice(0, 26).map((x) => Buffer.from(x, 'hex'));
  if (!pins) return values;
  const asNumber = (b) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));
  return [...values.slice(0, 10).sort((a, b) => (asNumber(a) < asNumber(b) ? -1 : asNumber(a) > asNumber(b) ? 1 : 0)), ...values.slice(10)];
};

// msm (optional): {zInv, w} replacing the canonical GLV witness (any w with the right sums is
// accepted on-chain; the sweep uses this to force all 128 Straus additions).
export function producePushes(vk, proof, publicInputs, pins = PINS, msm = undefined) {
  const w = produceWitness(vk, proof, publicInputs);
  const hex = (x) => Buffer.from(x, 'hex'), num = (x) => Buffer.from(bigIntToVmNumber(BigInt(x)));
  const quotient = Buffer.concat(w.quotient.map((x) => Buffer.from(BigInt(x).toString(16).padStart(64, '0'), 'hex')));
  const m = msm ?? msmWitness(BigInt(publicInputs[0]), BigInt(publicInputs[1]), 0);
  if (m.vkx) assert.equal(m.vkx.toString('hex'), hex(w.genesisKnownPushes[0]).subarray(128, 192).toString('hex'));
  assert.equal(w.terminalWitnessHex.length, 50);
  // the last 24 terminal values are decoded on-chain from genesis push 18 (c || c^-1, big-endian)
  const p18 = hex(w.genesisKnownPushes[18]);
  assert.deepEqual(w.terminalWitnessHex.slice(26), Array.from({length: 24}, (_, i) =>
    Buffer.from(bigIntToVmNumber(BigInt('0x' + p18.subarray(768 - 32 * (i + 1), 768 - 32 * i).toString('hex')))).toString('hex')));
  const values = {
    'genesis/sel': num(w.selector), 'terminal/Q': quotient,
    // genesis push 0 without vk_x (bytes 128..192), which the MSM returns on-chain
    'genesis/Grest': Buffer.concat([hex(w.genesisKnownPushes[0]).subarray(0, 128), hex(w.genesisKnownPushes[0]).subarray(192)]),
    ...Object.fromEntries(terminalValues(w.terminalWitnessHex, pins).map((x, i) => [`terminal/v${i}`, x])),
    ...Object.fromEntries([0, 1, 2].flatMap((i) => [[`exec${i}/FT`, hex(w.fixedTableHex[i])], [`exec${i}/W`, hex(w.executorWitnessHex[i])]])),
    ...Object.fromEntries(Array.from({length: 17}, (_, i) => [`genesis/p${i + 2}`, hex(w.genesisKnownPushes[i + 2])])),
    'msm/zInv': num(m.zInv), 'msm/w': m.w ?? Buffer.concat([m.wa, m.wb]), 'msm/n1': num(publicInputs[1]), 'msm/n0': num(publicInputs[0]),
  };
  return layout.map((label) => { assert(Buffer.isBuffer(values[label]), label); return values[label]; });
}

export const encodeUnlocking = (pushes, redeem = program().redeem) =>
  Buffer.concat([...pushes, redeem].map((p) => Buffer.from(encodeDataPush(p))));

export function produceTransaction(vk, proof, publicInputs) {
  const {locking} = program();
  return [{locking: locking.toString('hex'), unlocking: encodeUnlocking(producePushes(vk, proof, publicInputs)).toString('hex')}];
}
