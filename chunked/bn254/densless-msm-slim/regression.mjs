// Whole-transaction regression checks and exact-byte attack re-encoding.
// Original 26 submitter + 10 maintainer cases retained; 8 issue-39 cases added.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import * as lib from '@bitauth/libauth';
import {produceTransaction} from './transaction.mjs';
import {compileTerminalPinsOrderOnly} from './malleability-pins.mjs';

const out = resolve(process.argv[2]);
mkdirSync(out, {recursive: true});
const write = (name, value) => writeFileSync(resolve(out, name), JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
for (const mode of ['default', 'full']) {
  const env = {...process.env};
  if (mode === 'default') delete env.SLIM_PINS; else env.SLIM_PINS = mode;
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('export.mjs', import.meta.url)), resolve(out, mode + '.json')], {env, encoding: 'utf8'});
  assert.equal(child.status, 0, child.stderr);
}
assert(readFileSync(resolve(out, 'default.json')).equals(readFileSync(resolve(out, 'full.json'))), 'default and explicit full must export identical bytes');
const vectors = JSON.parse(readFileSync(resolve(out, 'default.json')));
const suggested = spawnSync(process.execPath, [fileURLToPath(new URL('redteam.mjs', import.meta.url)), resolve(out, 'default.json'), resolve(out, 'suggested.json')], {encoding: 'utf8', env: {...process.env, SLIM_PINS: 'full'}});
assert.equal(suggested.status, 0, suggested.stderr);
const attack = JSON.parse(readFileSync(resolve(out, 'suggested.json')));
assert.equal(attack.runs.length, 26);
const old = JSON.parse(readFileSync(resolve(process.env.VERIFIER_DIR, 'src/bch/redteam/bch-groth16-intratx-pairfold5-densless-msm-slim.json')));
const hex = bytes => Buffer.from(bytes).toString('hex');
const push = bytes => lib.decodeAuthenticationInstructions(lib.encodeDataPush(bytes))[0];
const number = n => push(lib.bigIntToVmNumber(n));
const n0 = lib.vmNumberToBigInt(lib.decodeAuthenticationInstructions(lib.hexToBin(vectors.steps[4].unlocking))[53].data);
const n1 = lib.vmNumberToBigInt(lib.decodeAuthenticationInstructions(lib.hexToBin(vectors.steps[4].unlocking))[52].data);
const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mutate = (input, edit) => {
  const xs = lib.decodeAuthenticationInstructions(lib.hexToBin(vectors.steps[input].unlocking));
  edit(xs);
  return [{input, unlocking: hex(lib.encodeAuthenticationInstructions(xs))}];
};
const extra = [
  ['terminal n0 + r', 'public-input-encoding', 4, xs => {xs[53] = number(n0 + r);}],
  ['terminal n1 + r', 'public-input-encoding', 4, xs => {xs[52] = number(n1 + r);}],
  ['terminal n0 non-minimally encoded', 'public-input-encoding', 4, xs => {xs[53] = push(Uint8Array.from([...xs[53].data, 0]));}],
  ['terminal n0, n1 swapped', 'public-input-encoding', 4, xs => {[xs[52], xs[53]] = [xs[53], xs[52]];}],
  ['terminal n0 - r (negative)', 'public-input-encoding', 4, xs => {xs[53] = number(n0 - r);}],
  ['terminal state split into w and X,Y,Z pushes', 'msm-state-layout', 4, xs => {const st = xs.at(-2).data; xs.splice(-2, 1, push(st.slice(0, 64)), push(st.slice(64)));}],
  ['terminal state push lengthened by one byte (honest state)', 'msm-state-layout', 4, xs => {xs[xs.length - 2] = push(Uint8Array.from([0, ...xs.at(-2).data]));}],
  ['exec0 state push lengthened by one byte', 'msm-state-layout', 0, xs => {xs[xs.length - 2] = push(Uint8Array.from([0, ...xs.at(-2).data]));}],
  ['extra push before the genesis redeem', 'msm-state-layout', 3, xs => {xs.splice(-1, 0, number(1n));}],
  ['extra empty push below the terminal n1', 'msm-state-layout', 4, xs => {xs.splice(52, 0, number(0n));}],
];
assert.deepEqual(extra.map(x => x[0]), old.runs.slice(26, 36).map(x => x.label), 'retain all ten maintainer cases');
for (const [label, kind, input, edit] of extra) attack.runs.push({label, kind, patches: mutate(input, edit)});
assert.deepEqual(attack.runs.map(x => x.label), old.runs.slice(0, 36).map(x => x.label), 'retain the original 36 case labels');
for (const input of [0, 1, 2]) attack.runs.push({label: `issue39: exec${input} quotient trailer`, kind: 'witness-malleability', patches: mutate(input, xs => {xs[4] = push(Uint8Array.from([...xs[4].data, 0x5a]));})});
attack.runs.push({label: 'issue39: terminal header trailer', kind: 'witness-malleability', patches: mutate(4, xs => {xs[0] = push(Uint8Array.from([...xs[0].data, 0x5a]));})});
for (const [a, b] of [[2, 3], [5, 6], [8, 9]]) attack.runs.push({label: `issue39: terminal pushes ${a}/${b} swapped`, kind: 'witness-malleability', patches: mutate(4, xs => {[xs[a], xs[b]] = [xs[b], xs[a]];})});
attack.runs.push({label: 'issue39: exec2 fixed-table limb13 sign', kind: 'witness-malleability', patches: mutate(2, xs => {xs[3].data = Uint8Array.from(xs[3].data); xs[3].data[13 * 32 + 31] ^= 0x80;})});
attack.generator = 'groth16_cashscript chunked/bn254/densless-msm-slim/regression.mjs; GPT-6.1 Sol re-encoding of the original 36 cases plus 8 issue39 cases; upstream maintainer review pending';
attack.description = 'Original 26 submitter-suggested and 10 maintainer cases retained against new code, plus eight issue39 mutations. Refreshed by GPT-6.1 Sol at Kallisti\'s request; not a claim of fresh independent upstream-maintainer authorship.';
write('attacks.json', attack);
const fx = JSON.parse(readFileSync(new URL('../densless-recovered/public-fixtures.json', import.meta.url)));
const short = JSON.parse(readFileSync(new URL('short-number-fixture.json', import.meta.url)));
const runs = [vectors.steps, ...vectors.extraValidProofs, vectors.worstCaseProof].map((steps, k) => ({name: 'fixture-' + k, steps, accepted: true}));
runs.push({name: 'short-number', steps: produceTransaction(fx.vk, short.proof, short.publicInputs), accepted: true});
for (const [k, run] of attack.runs.entries()) runs.push({name: 'attack-' + k, accepted: false, steps: vectors.steps.map((s, i) => ({...s, unlocking: run.patches.find(p => p.input === i)?.unlocking ?? s.unlocking}))});
const context = steps => ({inputIndex: 0, transaction: {version: 2, locktime: 0,
  inputs: steps.map((s, i) => ({outpointIndex: i, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: lib.hexToBin(s.unlocking)})),
  outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]},
sourceOutputs: steps.map(s => ({lockingBytecode: lib.hexToBin(s.locking), valueSatoshis: 1000n}))});
const rows = [], wires = [];
for (const standard of [false, true]) {
  const vm = lib.createVirtualMachineBch2026(standard);
  for (const run of runs) {
    const program = context(run.steps), verified = vm.verify(program);
    const outcomes = run.steps.map((_, inputIndex) => {const state = vm.evaluate({...program, inputIndex}); return {accepted: vm.stateSuccess(state) === true, error: state.error, operationCost: state.metrics.operationCost};});
    const name = (standard ? 'standard-' : 'consensus-') + run.name;
    rows.push({name, expectedAccepted: run.accepted, accepted: outcomes.every(x => x.accepted), wholeAccepted: verified === true,
      wholeError: verified === true ? null : String(verified), transactionBytes: lib.encodeTransaction(program.transaction).length,
      challengeBytes: lib.encodeTransaction(program.transaction).length + program.sourceOutputs.reduce((s, o) => s + o.lockingBytecode.length, 0),
      vmCost: outcomes.reduce((s, x) => s + x.operationCost, 0), outcomes});
    wires.push({name, transaction: hex(lib.encodeTransaction(program.transaction)), utxos: hex(lib.encodeTransactionOutputs(program.sourceOutputs)), mode: standard ? 'standard' : 'consensus', iterations: 1});
  }
  // Exercise the public order-pin program with OP_0, small integer opcodes and 31/32-byte numbers.
  const values = [0n, 1n, 2n, 16n, 17n, 255n, 1n << 119n, 1n << 239n, (1n << 247n) - 1n, (1n << 253n) - 1n];
  for (const ordered of [true, false]) {
    const ns = [...values]; if (!ordered) [ns[2], ns[3]] = [ns[3], ns[2]];
    const redeem = Uint8Array.from([...Array(6).fill(lib.OpcodesBCH.OP_2DROP), ...compileTerminalPinsOrderOnly(), lib.OpcodesBCH.OP_1]);
    const hash = lib.sha256.hash(lib.sha256.hash(redeem));
    const locking = Uint8Array.from([lib.OpcodesBCH.OP_HASH256, ...lib.encodeDataPush(hash), lib.OpcodesBCH.OP_EQUAL]);
    const data = [new Uint8Array(296), new Uint8Array(2336), ...ns.map(n => lib.bigIntToVmNumber(n)), redeem];
    const unlocking = Uint8Array.from(data.flatMap(x => [...lib.encodeDataPush(x)]));
    assert.equal(vm.verify(context([{locking: hex(locking), unlocking: hex(unlocking)}])) === true, ordered, 'variable-width order contract');
  }
}
const mismatches = rows.filter(x => x.accepted !== x.expectedAccepted || x.wholeAccepted !== x.expectedAccepted);
write('results.json', {status: mismatches.length ? 'FAIL' : 'PASS', fixtureCases: 6, attackCases: attack.runs.length, contexts: rows.length, rows, mismatches,
  vectorSha256: createHash('sha256').update(readFileSync(resolve(out, 'default.json'))).digest('hex')});
writeFileSync(resolve(out, 'replay.jsonl'), wires.map(x => JSON.stringify(x)).join('\n') + '\n', {flag: 'wx'});
assert.equal(mismatches.length, 0, JSON.stringify(mismatches.map(x => ({name: x.name, error: x.wholeError}))));
console.log(JSON.stringify({status: 'PASS', fixtures: 6, attacks: attack.runs.length, contexts: rows.length}));
