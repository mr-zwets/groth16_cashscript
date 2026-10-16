// Maintainer red-team runs for bch-groth16-intratx-pairfold5-densless-msm (zk-verifier-bench
// src/bch/redteam/<id>.json). Every run must be rejected.
// Layout: genesis (input 3) carries MSM part A; its unlocking ends with
// pad, wa, n1, n0, redeem (the claimed public inputs). MSM part B is input 5.
//   forged-public-inputs: claimed n changed in genesis, everything else honest
//   forged-public-inputs-adaptive: genesis tail and input 5 rebuilt with a valid MSM witness for
//     the forged inputs (true vk_x kept in genesis push 0), optionally also swapping genesis vk_x;
//     and the pad-shift forgery found in review (forged witness bytes hidden in the pad)
//   proof-point-validation: non-canonical or off-curve B in genesis push 0
// Usage: node redteam.mjs vectors.json out.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, decodeAuthenticationInstructions, encodeAuthenticationInstruction, encodeDataPush} from '@bitauth/libauth';
import {build, MSM_SPLIT, MSM_PAD, GENESIS_PAD} from './build.mjs';
import {witness as msmWitness, P} from '../pairfold5-msm/vkx-msm-asm.mjs';

const [vectorsPath, outPath] = process.argv.slice(2);
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const steps = vectors.steps;
const program = build();
const enc = (b) => Buffer.from(encodeDataPush(b));
const num = (x) => Buffer.from(bigIntToVmNumber(x));
const hex = (pushes) => Buffer.concat(pushes.map(enc)).toString('hex');
const [n0, n1] = fixtures.fixtures[0].publicInputs.map(BigInt);
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// honest genesis pushes: 19 genesis witness pushes, then pad, wa, n1, n0, redeem
const genesisPushes = decodeAuthenticationInstructions(Buffer.from(steps[3].unlocking, 'hex')).map((x) => Buffer.from(x.data ?? []));
assert.equal(genesisPushes.length, 24, 'unexpected genesis layout');
const genesisWith = ({push0 = genesisPushes[0], pad = Buffer.alloc(GENESIS_PAD), wa, c1, c0}) =>
  hex([push0, ...genesisPushes.slice(1, 19), pad, wa, num(c1), num(c0), program.redeems[3]]);
const inputB = (m, st = m.st) => hex([m.vkx, st, m.wb, Buffer.alloc(MSM_PAD.b), num(m.zInv), program.redeems[5]]);
const honest = msmWitness(n0, n1, MSM_SPLIT);
assert.equal(genesisWith({wa: honest.wa, c1: n1, c0: n0}), steps[3].unlocking, 'honest genesis does not reproduce');
assert.equal(inputB(honest), steps[5].unlocking, 'honest MSM input 5 does not reproduce');

// genesis push 0 holds 14 LE32 fields after a 3-byte PUSHDATA2 header:
// [0, 0, Ax, -Ay, vkx.x, vkx.y, Cx, Cy, Bx0, Bx1, By0, By1, 0, 0]
const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();
const push0With = (field, value) => { const p = Buffer.from(genesisPushes[0]); le32(value).copy(p, 32 * field); return p; };
const fieldOf = (field) => BigInt('0x' + Buffer.from(genesisPushes[0].subarray(32 * field, 32 * field + 32)).reverse().toString('hex'));

const runs = [];
for (const [label, c0, c1] of [['n0 + 1', n0 + 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0 = r - 1', R - 1n, n1]]) {
  runs.push({label: `forged ${label} (honest MSM witness)`, kind: 'forged-public-inputs', patches: [{input: 3, unlocking: genesisWith({wa: honest.wa, c1, c0})}]});
  const m = msmWitness(c0, c1, MSM_SPLIT);
  runs.push({label: `forged ${label} with a valid MSM witness for it`, kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({wa: m.wa, c1, c0})}, {input: 5, unlocking: inputB(m)}]});
}
{
  const m = msmWitness(n0 + 1n, n1, MSM_SPLIT);
  const push0 = Buffer.from(genesisPushes[0]); m.vkx.copy(push0, 32 * 4);
  runs.push({label: 'forged n0 + 1, valid MSM witness, genesis vk_x swapped to match', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({push0, wa: m.wa, c1: n1, c0: n0 + 1n})}, {input: 5, unlocking: inputB(m)}]});
}
{
  // Pad-shift forgery: forged witness bytes w' (one bit flipped at Straus position 1, k10 + 2^62,
  // so n0' = n0 + 2^62) hidden in a longer genesis pad, the MSM run on the honest wa, n0' claimed.
  // Input 5 takes wa from the state genesis pins, so neither choice of wa there satisfies both.
  const wForged = Buffer.from(honest.wa); wForged[1] ^= 0x01;
  const n0f = (n0 + (1n << 62n)) % R;
  const g = genesisWith({pad: Buffer.concat([Buffer.alloc(GENESIS_PAD + 1), wForged]), wa: honest.wa, c1: n1, c0: n0f});
  for (const [variant, wa] of [['honest wa in the pinned state', honest.wa], ["w' in the pinned state", wForged]]) {
    const st = Buffer.from(honest.st); le32(n0f).copy(st, 96); Buffer.from(wa).copy(st, 160);
    runs.push({label: `pad-shift forgery n0 + 2^62, ${variant}`, kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: g}, {input: 5, unlocking: inputB(honest, st)}]});
  }
}
runs.push({label: 'B.x0 non-canonical (+p)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(8, fieldOf(8) + P), wa: honest.wa, c1: n1, c0: n0})}]});
runs.push({label: 'B.y0 + 1 (off curve)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(10, (fieldOf(10) + 1n) % P), wa: honest.wa, c1: n1, c0: n0})}]});

writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-intratx-pairfold5-densless-msm',
  description: 'Forged public inputs (with honest and with adaptively rebuilt MSM witnesses, optionally with the genesis vk_x swapped to match, and the pad-shift forgery) and invalid proof point B. A verifier that binds vk_x to its claimed public inputs and validates B must reject every run.',
  generator: 'groth16_cashscript chunked/bn254/densless-msm/redteam.mjs',
  lockingSha256: steps.map((s) => createHash('sha256').update(Buffer.from(s.locking, 'hex')).digest('hex')),
  runs,
}, null, 2) + '\n');
console.log(`wrote ${runs.length} runs -> ${outPath}`);
