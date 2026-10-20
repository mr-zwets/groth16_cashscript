// Maintainer red-team runs for bch-groth16-intratx-pairfold5-densless-msm-spec (zk-verifier-bench
// src/bch/redteam/<id>.json). Every run must be rejected.
// Layout: genesis (input 3) carries the whole vk_x MSM; its unlocking ends with
// pad, zInv, w (64 witness bytes), n1, n0, redeem. The MSM checks its result against genesis push 0.
// Usage: node redteam.mjs vectors.json out.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, decodeAuthenticationInstructions, encodeDataPush, OpcodesBCH} from '@bitauth/libauth';
import {build} from './build.mjs';
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

// decodeAuthenticationInstructions attaches no data to the number opcodes (OP_1NEGATE,
// OP_1..OP_16); recover the pushed byte from the opcode so re-encoding round-trips.
const numberPushData = (opcode) => opcode === OpcodesBCH.OP_1NEGATE ? Buffer.from([0x81])
  : opcode >= OpcodesBCH.OP_1 && opcode <= OpcodesBCH.OP_16 ? Buffer.from([opcode - OpcodesBCH.OP_1 + 1])
  : undefined;
const pushes = decodeAuthenticationInstructions(Buffer.from(steps[3].unlocking, 'hex')).map((x) => Buffer.from(x.data ?? numberPushData(x.opcode) ?? []));
assert.equal(pushes.length, 25, 'unexpected genesis layout');
const genesisWith = ({push0 = pushes[0], pad = Buffer.alloc(0), zInv, w, c1, c0}) =>
  Buffer.concat([push0, ...pushes.slice(1, 19), pad, num(zInv), w, num(c1), num(c0), program.redeems[3]].map(enc)).toString('hex');
const wit = (c0, c1) => { const m = msmWitness(c0, c1, 0); return {zInv: m.zInv, w: Buffer.concat([m.wa, m.wb]), vkx: m.vkx}; };
const honest = wit(n0, n1);
assert.equal(genesisWith({...honest, c1: n1, c0: n0}), steps[3].unlocking, 'honest genesis does not reproduce');
const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();
const push0With = (field, value) => { const p = Buffer.from(pushes[0]); le32(value).copy(p, 32 * field); return p; };
const fieldOf = (field) => BigInt('0x' + Buffer.from(pushes[0].subarray(32 * field, 32 * field + 32)).reverse().toString('hex'));

const runs = [];
for (const [label, c0, c1] of [['n0 + 1', n0 + 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0 = r - 1', R - 1n, n1]]) {
  runs.push({label: `forged ${label} (honest MSM witness)`, kind: 'forged-public-inputs', patches: [{input: 3, unlocking: genesisWith({...honest, c1, c0})}]});
  runs.push({label: `forged ${label} with a valid MSM witness for it`, kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({...wit(c0, c1), c1, c0})}]});
}
{
  const f = wit(n0 + 1n, n1);
  const push0 = Buffer.from(pushes[0]); f.vkx.copy(push0, 32 * 4);
  runs.push({label: 'forged n0 + 1, valid MSM witness, genesis vk_x swapped to match', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({push0, ...f, c1: n1, c0: n0 + 1n})}]});
}
{
  const wForged = Buffer.from(honest.w); wForged[1] ^= 0x01; // k10 + 2^62
  runs.push({label: 'forged n0 + 2^62 with a pad-hidden alternative witness', kind: 'forged-public-inputs-adaptive', patches: [{input: 3, unlocking: genesisWith({pad: Buffer.concat([Buffer.alloc(1), wForged]), ...honest, c1: n1, c0: (n0 + (1n << 62n)) % R})}]});
}
runs.push({label: 'B.x0 non-canonical (+p)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(8, fieldOf(8) + P), ...honest, c1: n1, c0: n0})}]});
runs.push({label: 'B.y0 + 1 (off curve)', kind: 'proof-point-validation', patches: [{input: 3, unlocking: genesisWith({push0: push0With(10, (fieldOf(10) + 1n) % P), ...honest, c1: n1, c0: n0})}]});

writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-intratx-pairfold5-densless-msm-spec',
  description: 'Forged public inputs (honest and adaptively rebuilt MSM witnesses, the genesis vk_x swapped to match, a pad-hidden alternative witness) and invalid proof point B. Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bn254/densless-msm-spec/redteam.mjs',
  lockingSha256: steps.map((s) => createHash('sha256').update(Buffer.from(s.locking, 'hex')).digest('hex')),
  runs,
}, null, 2) + '\n');
console.log(`wrote ${runs.length} runs -> ${outPath}`);
