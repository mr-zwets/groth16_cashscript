// Maintainer red-team runs for bch-groth16-intratx-pairfold5-densless-msm (zk-verifier-bench
// src/bch/redteam/<id>.json). Every run must be rejected.
// Layout: genesis (input 3) carries MSM part A; its unlocking ends with pad, wa, n1, n0, redeem
// (the claimed public inputs). The executors (inputs 0, 1, 2) and the terminal (input 4) carry
// the remaining MSM stages; each ends with a state push before its redeem (executors: 160 bytes X, Y, Z, w;
// terminal: 224 bytes n0, n1, X, Y, Z, w; genesis pins n0, n1 into the terminal's push directly), the terminal with zInv below it (see vkx-stages.mjs).
//   forged-public-inputs: claimed n changed in genesis, everything else honest
//   forged-public-inputs-adaptive: the whole MSM chain rebuilt for the forged inputs (true vk_x
//     kept in genesis push 0), optionally also swapping genesis vk_x; a witness swapped mid-chain;
//     a lengthened state push whose pinned suffix carries the forged claim; forged witness bytes
//     hidden in the genesis pad
//   msm-state-tamper: one byte of one stage's state push flipped
//   proof-point-validation: non-canonical or off-curve B in genesis push 0
// Usage: node redteam.mjs vectors.json out.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, decodeAuthenticationInstructions, encodeDataPush} from '@bitauth/libauth';
import {build, MSM_SPLIT, CUTS, GENESIS_PAD} from './build.mjs';
import {witness as msmWitness, P} from '../pairfold5-msm/vkx-msm-asm.mjs';

const [vectorsPath, outPath] = process.argv.slice(2);
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const steps = vectors.steps;
const program = build();
const enc = (b) => Buffer.from(encodeDataPush(b));
const num = (x) => Buffer.from(bigIntToVmNumber(x));
const hex = (pushes) => Buffer.concat(pushes.map(enc)).toString('hex');
const pushesOf = (i) => decodeAuthenticationInstructions(Buffer.from(steps[i].unlocking, 'hex')).map((x) => Buffer.from(x.data ?? []));
const [n0, n1] = fixtures.fixtures[0].publicInputs.map(BigInt);
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();

// a full MSM witness for claimed (c0, c1): genesis wa and the four stage state pushes
const chain = (c0, c1, w = null) => {
  const m = msmWitness(c0, c1, MSM_SPLIT, CUTS);
  const bytes = w ?? m.w;
  return {...m, wa: bytes.subarray(0, 64 - MSM_SPLIT),
    state: (k) => Buffer.concat([...[...(k === 3 ? [c0, c1] : []), ...m.states[CUTS[k]]].map(le32), bytes])};
};

// honest genesis pushes: 19 genesis witness pushes, then pad, wa, n1, n0, redeem
const genesisPushes = pushesOf(3);
assert.equal(genesisPushes.length, 24, 'unexpected genesis layout');
const genesisWith = ({push0 = genesisPushes[0], pad = Buffer.alloc(GENESIS_PAD), wa, c1, c0}) =>
  hex([push0, ...genesisPushes.slice(1, 19), pad, wa, num(c1), num(c0), program.redeems[3]]);
// executor k / terminal with its MSM pushes replaced
const stageWith = (k, st, zInv) => {
  const pushes = pushesOf(k);
  return k < 3 ? hex([...pushes.slice(0, -2), st, pushes.at(-1)]) : hex([...pushes.slice(0, -3), num(zInv), st, pushes.at(-1)]);
};
const stagesFor = (c) => [0, 1, 2, 4].map((input, k) => ({input, unlocking: stageWith(input, c.state(k), c.zInv)}));
const honest = chain(n0, n1);
assert.equal(genesisWith({wa: honest.wa, c1: n1, c0: n0}), steps[3].unlocking, 'honest genesis does not reproduce');
[0, 1, 2, 4].forEach((input, k) => assert.equal(stageWith(input, honest.state(k), honest.zInv), steps[input].unlocking, `honest stage ${input} does not reproduce`));

// genesis push 0 holds 14 LE32 fields after a 3-byte PUSHDATA2 header:
// [0, 0, Ax, -Ay, vkx.x, vkx.y, Cx, Cy, Bx0, Bx1, By0, By1, 0, 0]
const push0With = (field, value) => { const p = Buffer.from(genesisPushes[0]); le32(value).copy(p, 32 * field); return p; };
const fieldOf = (field) => BigInt('0x' + Buffer.from(genesisPushes[0].subarray(32 * field, 32 * field + 32)).reverse().toString('hex'));

const runs = [];
for (const [label, c0, c1] of [['n0 + 1', n0 + 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0 = r - 1', R - 1n, n1]]) {
  runs.push({label: `forged ${label} (honest MSM witness)`, kind: 'forged-public-inputs', patches: [{input: 3, unlocking: genesisWith({wa: honest.wa, c1, c0})}]});
  const f = chain(c0, c1);
  runs.push({label: `forged ${label} with the whole MSM chain rebuilt for it`, kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({wa: f.wa, c1, c0})}, ...stagesFor(f)]});
}
const f = chain(n0 + 1n, n1);
{
  const push0 = Buffer.from(genesisPushes[0]); f.vkx.copy(push0, 32 * 4);
  runs.push({label: 'forged n0 + 1, MSM chain rebuilt, genesis vk_x swapped to match', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({push0, wa: f.wa, c1: n1, c0: n0 + 1n})}, ...stagesFor(f)]});
}
{
  // Mid-chain swap: genesis and exec0 honest, exec1 onward on the forged chain (state and w).
  runs.push({label: 'forged n0 + 1, chain switched to the forged witness from exec1 on', kind: 'forged-public-inputs-adaptive', patches: stagesFor(f).slice(1)});
}
{
  // Lengthened state push: the terminal's push is 0x00 || st with the forged claim, so the n0, n1
  // window genesis pins (the first 64 of the last 224 bytes) holds n0 + 1; the terminal must
  // reject the length.
  const st = honest.state(3); le32(n0 + 1n).copy(st, 0);
  runs.push({label: 'terminal state push lengthened by one byte (forged n0 + 1 in the pinned window)', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({wa: honest.wa, c1: n1, c0: n0 + 1n})}, {input: 4, unlocking: stageWith(4, Buffer.concat([Buffer.alloc(1), st]), honest.zInv)}]});
}
{
  // Pad-shift: forged witness bytes w' (k10 + 2^62, so n0' = n0 + 2^62) hidden in a longer genesis
  // pad, the MSM run on the honest wa, n0' claimed and the chain's state and w set to w'.
  const wForged = Buffer.from(honest.w); wForged[1] ^= 0x01;
  const n0f = (n0 + (1n << 62n)) % R;
  const g = genesisWith({pad: Buffer.concat([Buffer.alloc(GENESIS_PAD + 1), wForged.subarray(0, 64 - MSM_SPLIT)]), wa: honest.wa, c1: n1, c0: n0f});
  const c = chain(n0, n1, wForged), st = (k) => { const s = c.state(k); if (k === 3) le32(n0f).copy(s, 0); return s; };
  runs.push({label: 'pad-shift forgery n0 + 2^62, forged w in the chain', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: g}, ...[0, 1, 2, 4].map((input, k) => ({input, unlocking: stageWith(input, st(k), c.zInv)}))]});
}
[0, 1, 2, 4].forEach((input, k) => {
  for (const [what, at] of (k < 3 ? [['X', 5], ['Z', 70], ['w', 150]] : [['n0', 5], ['X', 70], ['w', 200]])) {
    const st = Buffer.from(honest.state(k)); st[at] ^= 0x01;
    runs.push({label: `input ${input} state push: one byte of ${what} flipped`, kind: 'msm-state-tamper', patches: [{input, unlocking: stageWith(input, st, honest.zInv)}]});
  }
});
runs.push({label: 'B.x0 non-canonical (+p)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(8, fieldOf(8) + P), wa: honest.wa, c1: n1, c0: n0})}]});
runs.push({label: 'B.y0 + 1 (off curve)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(10, (fieldOf(10) + 1n) % P), wa: honest.wa, c1: n1, c0: n0})}]});

writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-intratx-pairfold5-densless-msm',
  description: 'Forged public inputs (with the honest MSM witness, with the whole MSM chain rebuilt for them, optionally with the genesis vk_x swapped to match, a witness swapped mid-chain, a lengthened state push and the pad-shift forgery), tampered MSM state pushes and invalid proof point B. A verifier that binds vk_x to its claimed public inputs and validates B must reject every run.',
  generator: 'groth16_cashscript chunked/bn254/densless-msm/redteam.mjs',
  lockingSha256: steps.map((s) => createHash('sha256').update(Buffer.from(s.locking, 'hex')).digest('hex')),
  runs,
}, null, 2) + '\n');
console.log(`wrote ${runs.length} runs -> ${outPath}`);
