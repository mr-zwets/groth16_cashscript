// Red-team runs for bch-groth16-pairfold5-densless-msm-spec-single (zk-verifier-bench
// src/bch/redteam/<id>.json). Adapted from ../densless-msm-spec/redteam.mjs and
// ../densless-msm-slim (issue-39 cases): forged public inputs (honest and adaptively rebuilt MSM
// witnesses), invalid proof point B, public-input encodings, the issue-39 malleability classes
// that survive the merge (terminal limb order, fixed-table sign/+p, trailers), a tamper of every
// push class, and layout mutations (extra/missing/reordered pushes, a lengthened genesis block,
// non-standard selector encodings). Every run is evaluated on the bch-spec VM (consensus) here
// and must be rejected; the script aborts otherwise.
// Usage: VERIFIER_DIR=<zk-verifier-bench> node redteam.mjs vectors.json out.json
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bigIntToVmNumber, createVirtualMachineBchSpec, encodeDataPush, vmNumberToBigInt} from '@bitauth/libauth';
import {producePushes, encodeUnlocking, program} from './transaction.mjs';
import {layout} from './build.mjs';
import {witness as msmWitness, P} from '../pairfold5-msm/vkx-msm-asm.mjs';

const [vectorsPath, outPath] = process.argv.slice(2);
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const fixtures = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const {locking, redeem} = program();
const f = fixtures.fixtures[0];
const honest = producePushes(fixtures.vk, f.proof, f.publicInputs);
assert.equal(encodeUnlocking(honest).toString('hex'), vectors.steps[0].unlocking, 'honest unlocking does not reproduce the vectors');
const L = (l) => { const k = layout.indexOf(l); assert(k >= 0, l); return k; };
const num = (x) => Buffer.from(bigIntToVmNumber(BigInt(x)));
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const [n0, n1] = f.publicInputs.map(BigInt);
const vm = createVirtualMachineBchSpec(false);
const accepts = (unlocking) => {
  const transaction = {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]};
  return vm.verify({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}], transaction}) === true;
};
assert(accepts(encodeUnlocking(honest)), 'honest run must accept');

const runs = [];
const add = (label, kind, pushes, raw) => {
  const unlocking = raw ?? encodeUnlocking(pushes);
  assert(!accepts(unlocking), `red-team run accepted: ${label}`);
  runs.push({label, kind, patches: [{input: 0, unlocking: unlocking.toString('hex')}]});
};
const mut = (fn) => { const p = honest.map((b) => Buffer.from(b)); fn(p); return p; };
const withMsm = (p, a, b, m) => { p[L('msm/n0')] = num(a); p[L('msm/n1')] = num(b); p[L('msm/zInv')] = num(m.zInv); p[L('msm/w')] = Buffer.concat([m.wa, m.wb]); };

// forged public inputs
for (const [label, c0, c1] of [['n0 + 1', n0 + 1n, n1], ['n1 + 1', n0, n1 + 1n], ['n0 = 0', 0n, n1], ['n0 = r - 1', R - 1n, n1], ['n0, n1 swapped', n1, n0]]) {
  add(`forged ${label} (honest MSM witness)`, 'forged-public-inputs', mut((p) => { p[L('msm/n0')] = num(c0); p[L('msm/n1')] = num(c1); }));
  add(`forged ${label} with a valid MSM witness for it`, 'forged-public-inputs-adaptive', mut((p) => withMsm(p, c0, c1, msmWitness(c0, c1, 0))));
}
add('forged n0 + 2^62 via an alternative GLV witness (k10 + 2^62)', 'forged-public-inputs-adaptive', mut((p) => { const w = p[L('msm/w')]; w[1] ^= 0x01; p[L('msm/n0')] = num((n0 + (1n << 62n)) % R); }));
// public-input encodings
add('n0 + r', 'public-input-encoding', mut((p) => { p[L('msm/n0')] = num(n0 + R); }));
add('n1 + r', 'public-input-encoding', mut((p) => { p[L('msm/n1')] = num(n1 + R); }));
add('n0 - r (negative)', 'public-input-encoding', mut((p) => { p[L('msm/n0')] = num(n0 - R); }));
add('n0 non-minimally encoded', 'public-input-encoding', mut((p) => { p[L('msm/n0')] = Buffer.concat([num(n0), Buffer.from([0x00])]); }));
// proof point B (genesis block without vk_x: field k at 32k for k < 4, 32k - 64 for k >= 6)
const fieldAt = (k) => (k < 4 ? 32 * k : 32 * k - 64);
const le = (b, o) => BigInt('0x' + Buffer.from(b.subarray(o, o + 32)).reverse().toString('hex'));
const setLe = (b, o, v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse().copy(b, o);
add('B.x0 non-canonical (+p)', 'proof-point-validation', mut((p) => { const g = p[L('genesis/Grest')]; setLe(g, fieldAt(8), le(g, fieldAt(8)) + P); }));
add('B.y0 + 1 (off curve)', 'proof-point-validation', mut((p) => { const g = p[L('genesis/Grest')]; setLe(g, fieldAt(10), (le(g, fieldAt(10)) + 1n) % P); }));
add('A.x + 1', 'proof-point-validation', mut((p) => { const g = p[L('genesis/Grest')]; setLe(g, fieldAt(2), (le(g, fieldAt(2)) + 1n) % P); }));
add('C.y + 1', 'proof-point-validation', mut((p) => { const g = p[L('genesis/Grest')]; setLe(g, fieldAt(7), (le(g, fieldAt(7)) + 1n) % P); }));
// issue-39 classes (malleability) that survive the merge
const vs = Array.from({length: 10}, (_, i) => L(`terminal/v${i}`));
for (const [i, j] of [[2, 3], [5, 6], [8, 9], [0, 9]]) add(`terminal values ${i}/${j} swapped`, 'witness-malleability', mut((p) => { [p[vs[i]], p[vs[j]]] = [p[vs[j]], p[vs[i]]]; }));
for (const e of [0, 1, 2]) {
  add(`exec${e} fixed-table limb 13 sign bit`, 'witness-malleability', mut((p) => { p[L(`exec${e}/FT`)][32 * 13 + 31] ^= 0x80; }));
  add(`exec${e} fixed-table limb 0 + p`, 'witness-malleability', mut((p) => { const t = p[L(`exec${e}/FT`)]; setLe(t, 0, le(t, 0) + P); }));
  add(`exec${e} fixed table + 32 trailing zero bytes`, 'witness-malleability', mut((p) => { p[L(`exec${e}/FT`)] = Buffer.concat([p[L(`exec${e}/FT`)], Buffer.alloc(32)]); }));
}
add('quotient + 32 trailing zero bytes', 'witness-malleability', mut((p) => { p[L('terminal/Q')] = Buffer.concat([p[L('terminal/Q')], Buffer.alloc(32)]); }));
add('quotient - last 32 bytes', 'witness-malleability', mut((p) => { p[L('terminal/Q')] = p[L('terminal/Q')].subarray(0, -32); }));
add('genesis push 18 + 32 trailing bytes', 'witness-malleability', mut((p) => { p[L('genesis/p18')] = Buffer.concat([p[L('genesis/p18')], Buffer.alloc(32)]); }));
// every push class tampered (a middle byte; numbers + 1; W: its final state evaluation). Not
// tampered: genesis pushes 4 and 5 and the W slope limbs, the running-point slopes of B, which
// the inherited design never feeds into the accept decision (README.md, open risks).
for (const label of layout.filter((l) => l !== 'genesis/p4' && l !== 'genesis/p5')) {
  add(`${label} tampered`, 'witness-tamper', mut((p) => {
    const k = L(label);
    if (label.endsWith('/W')) p[k][p[k].length - 16] ^= 0x01;
    else if (label === 'genesis/sel') p[k] = num(vmNumberToBigInt(p[k]) + 1n);
    else if (p[k].length > 33) p[k][p[k].length >> 1] ^= 0x01;
    else p[k] = num(vmNumberToBigInt(p[k]) + 1n);
  }));
}
// layout
add('extra empty push at the bottom', 'layout', [Buffer.alloc(0), ...honest]);
add('extra push of the genesis block at the bottom', 'layout', [Buffer.concat([honest[L('genesis/Grest')].subarray(0, 128), Buffer.alloc(64), honest[L('genesis/Grest')].subarray(128)]), ...honest]);
add('last value push missing', 'layout', honest.slice(0, -1));
add('first push (selector) missing', 'layout', honest.slice(1));
add('genesis block + 1 byte (would extend function G)', 'layout', mut((p) => { p[L('genesis/Grest')] = Buffer.concat([p[L('genesis/Grest')], Buffer.from([0x75])]); }));
add('genesis block - 1 byte', 'layout', mut((p) => { p[L('genesis/Grest')] = p[L('genesis/Grest')].subarray(0, -1); }));
add('exec0 and exec1 witnesses swapped', 'layout', mut((p) => { [p[L('exec0/W')], p[L('exec1/W')]] = [p[L('exec1/W')], p[L('exec0/W')]]; }));
const sel = honest[L('genesis/sel')];
add('selector pushed non-minimally (PUSHBYTES_1)', 'layout', null,
  Buffer.concat([Buffer.from([0x01, sel.length ? sel[0] : 0x00]), encodeUnlocking(honest.slice(1))]));
add('selector = 3', 'layout', mut((p) => { p[L('genesis/sel')] = num(3); }));

writeFileSync(outPath, JSON.stringify({
  id: 'bch-groth16-pairfold5-densless-msm-spec-single',
  description: 'Forged public inputs (honest and adaptively rebuilt MSM witnesses, alternative GLV witness), public-input encodings, invalid proof points, the issue-39 malleability classes that survive the single-input merge, a tamper of every push class, and layout mutations. Every run must be rejected.',
  generator: 'groth16_cashscript chunked/bn254/densless-msm-spec-single/redteam.mjs',
  lockingSha256: [createHash('sha256').update(locking).digest('hex')],
  runs,
}, null, 2) + '\n');
console.log(`wrote ${runs.length} runs (all rejected) -> ${outPath}; redeem ${redeem.length} B`);
