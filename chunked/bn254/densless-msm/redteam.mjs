// Maintainer red-team runs for bch-groth16-intratx-pairfold5-densless-msm (zk-verifier-bench
// src/bch/redteam/<id>.json). Every run must be rejected.
//   forged-public-inputs: claimed n changed in input 5, everything else honest
//   forged-public-inputs-adaptive: inputs 5 and 6 rebuilt with a valid MSM witness for the
//     forged inputs (true vk_x kept in genesis), optionally also swapping genesis vk_x
//   proof-point-validation: non-canonical or off-curve B in genesis push 0 (the slice keeps
//     these genesis checks)
// Usage: node redteam.mjs vectors.json out.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, encodeDataPush, hexToBin} from '@bitauth/libauth';
import {build, MSM_SPLIT, MSM_PAD} from './build.mjs';
import {witness as msmWitness, P} from '../pairfold5-msm/vkx-msm-asm.mjs';

const [vectorsPath, outPath] = process.argv.slice(2);
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const steps = vectors.steps;
const program = build();
const enc = (b) => Buffer.from(encodeDataPush(b));
const num = (x) => Buffer.from(bigIntToVmNumber(x));
const [n0, n1] = fixtures.fixtures[0].publicInputs.map(BigInt);
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const msmInputs = (c0, c1) => {
  const m = msmWitness(c0, c1, MSM_SPLIT);
  return {
    a: Buffer.concat([enc(Buffer.alloc(MSM_PAD.a)), enc(m.wa), enc(num(c1)), enc(num(c0)), enc(program.redeems[5])]).toString('hex'),
    b: Buffer.concat([enc(m.vkx), enc(m.st), enc(m.wb), enc(Buffer.alloc(MSM_PAD.b)), enc(num(m.zInv)), enc(program.redeems[6])]).toString('hex'),
    vkx: m.vkx,
  };
};
const honestA = steps[5].unlocking;
assert.equal(honestA, msmInputs(n0, n1).a, 'honest MSM input 5 does not reproduce');

// input 5 with only the claimed public inputs changed (honest wa and pad)
const swapInputs = (c0, c1) => {
  const m = msmWitness(n0, n1, MSM_SPLIT);
  return Buffer.concat([enc(Buffer.alloc(MSM_PAD.a)), enc(m.wa), enc(num(c1)), enc(num(c0)), enc(program.redeems[5])]).toString('hex');
};
// genesis push 0 holds 14 LE32 fields after a 3-byte PUSHDATA2 header:
// [0, 0, Ax, -Ay, vkx.x, vkx.y, Cx, Cy, Bx0, Bx1, By0, By1, 0, 0]
const genesisWithField = (field, value) => {
  const g = Buffer.from(steps[3].unlocking, 'hex');
  Buffer.from(value.toString(16).padStart(64, '0'), 'hex').reverse().copy(g, 3 + 32 * field);
  return g.toString('hex');
};
const fieldOf = (field) => BigInt('0x' + Buffer.from(hexToBin(steps[3].unlocking).slice(3 + 32 * field, 35 + 32 * field)).reverse().toString('hex'));

const runs = [];
for (const [label, c0, c1] of [['n0 + 1', n0 + 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0 = r - 1', R - 1n, n1]]) {
  runs.push({label: `forged ${label} (honest MSM witness)`, kind: 'forged-public-inputs', patches: [{input: 5, unlocking: swapInputs(c0, c1)}]});
  const m = msmInputs(c0, c1);
  runs.push({label: `forged ${label} with a valid MSM witness for it`, kind: 'forged-public-inputs-adaptive', patches: [{input: 5, unlocking: m.a}, {input: 6, unlocking: m.b}]});
}
{
  const m = msmInputs(n0 + 1n, n1);
  const g = Buffer.from(steps[3].unlocking, 'hex');
  m.vkx.copy(g, 3 + 32 * 4);
  runs.push({label: 'forged n0 + 1, valid MSM witness, genesis vk_x swapped to match', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: g.toString('hex')}, {input: 5, unlocking: m.a}, {input: 6, unlocking: m.b}]});
}
{
  // Pad-shift forgery (found by the slice review): grow input 5's unconstrained pad so its tail
  // holds w' (wa with one bit flipped at Straus position 1, i.e. k10 + 2^62, so n0' = n0 + 2^62),
  // run the MSM on the honest wa, and claim n0'. Input 6 now takes wa from the state input 5
  // pins, so neither choice of wa in that state can satisfy both inputs.
  const m = msmWitness(n0, n1, MSM_SPLIT);
  const wForged = Buffer.from(m.wa); wForged[1] ^= 0x01;
  const n0f = (n0 + (1n << 62n)) % R;
  const a = Buffer.concat([enc(Buffer.concat([Buffer.alloc(MSM_PAD.a + 1), wForged])), enc(m.wa), enc(num(n1)), enc(num(n0f)), enc(program.redeems[5])]).toString('hex');
  const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();
  for (const [variant, wa] of [['honest wa in the pinned state', m.wa], ["w' in the pinned state", wForged]]) {
    const st = Buffer.from(m.st); le32(n0f).copy(st, 96); Buffer.from(wa).copy(st, 160);
    const b = Buffer.concat([enc(m.vkx), enc(st), enc(m.wb), enc(Buffer.alloc(MSM_PAD.b)), enc(num(m.zInv)), enc(program.redeems[6])]).toString('hex');
    runs.push({label: `pad-shift forgery n0 + 2^62, ${variant}`, kind: 'forged-public-inputs-adaptive', patches: [{input: 5, unlocking: a}, {input: 6, unlocking: b}]});
  }
}
runs.push({label: 'B.x0 non-canonical (+p)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWithField(8, fieldOf(8) + P)}]});
runs.push({label: 'B.y0 + 1 (off curve)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWithField(10, (fieldOf(10) + 1n) % P)}]});

writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-intratx-pairfold5-densless-msm',
  description: 'Forged public inputs (with honest and with adaptively rebuilt MSM witnesses, optionally with the genesis vk_x swapped to match) and invalid proof point B. A verifier that binds vk_x to its claimed public inputs and validates B must reject every run.',
  generator: 'groth16_cashscript chunked/bn254/densless-msm/redteam.mjs',
  lockingSha256: steps.map((s) => createHash('sha256').update(Buffer.from(s.locking, 'hex')).digest('hex')),
  runs,
}, null, 2) + '\n');
console.log(`wrote ${runs.length} runs -> ${outPath}`);
