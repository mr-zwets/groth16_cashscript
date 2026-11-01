// Track 9 S0 acceptance: the CashVM Poseidon2-Gl-8 permutation (p2gl8.mjs) against p3-goldilocks.
//   - Plonky3's test vector (goldilocks/src/poseidon2.rs test_default_goldilocks_poseidon2_width_8);
//   - 1,000 random inputs (deterministic: SHA-256 counter stream, rejection-sampled < p) plus 4 edge inputs
//     (all 0, all p - 1, alternating 0 / p - 1, all 2^63), each checked three ways: the script in libauth (consensus
//     and standard flags, full 8-lane output and the 4-lane compress output), the JS reference permRef
//     (= air8_ref.py perm) and p3-goldilocks itself (p3ref/, default_goldilocks_poseidon2_8()).
//   - op-cost per permutation: libauth op-cost between two OP_NOP markers (marker cost subtracted). The permutation is
//     straight-line code with no OP_DEFINE, so the BCHN-adjusted figure equals the libauth figure; the DEFINE cost of the
//     packaged function (body bytes, charged once per input by BCHN) is reported separately.
//   - plain rejections: the script's output compared with (expected + 1) and (expected + p) on one lane must fail.
// Usage: node test-p2.mjs [--p3ref BIN] [--cache DIR]   (BIN default: $P2_CACHE/target-p3ref/release/p2gl8-ref)
import fs from 'fs';
import {execFileSync} from 'child_process';
import {createHash} from 'crypto';
import {permRef, permCode, setOptions, K, P} from './p2gl8.mjs';
import {asm} from './lib/asm.mjs';
import {evaluate} from './vm.mjs';

const HERE = new URL('.', import.meta.url).pathname;
const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const CACHE = arg('--cache', process.env.P2_CACHE ?? '/home/mrzwets/BCH-projects/verifier.cash/work/pool/cache');
const BIN = arg('--p3ref', `${CACHE}/target-p3ref/release/p2gl8-ref`);
const N = Number(arg('--n', 1000));

// ---- inputs
const sha = (s) => createHash('sha256').update(s).digest();
let ctr = 0;
const randLane = () => { for (;;) { const b = sha(`t9-s0-p2gl8/${ctr++}`); const v = b.readBigUInt64LE(0); if (v < P) return v; } };
const inputs = [K.test_vector.input.map(BigInt), Array(8).fill(0n), Array(8).fill(P - 1n), [...Array(8)].map((_, i) => (i % 2 ? P - 1n : 0n)), Array(8).fill(2n ** 63n)];
const labels = ['test_vector', 'zero', 'p-1', 'alt', '2^63'];
for (let i = 0; i < N; i++) { inputs.push([...Array(8)].map(randLane)); labels.push(`rand${i}`); }

// ---- p3-goldilocks outputs
fs.mkdirSync(`${CACHE}/s0`, {recursive: true});
const inText = inputs.map((x) => x.join(' ')).join('\n') + '\n';
fs.writeFileSync(`${CACHE}/s0/inputs.txt`, inText);
const p3Text = execFileSync(BIN, {input: inText, maxBuffer: 1 << 26}).toString();
fs.writeFileSync(`${CACHE}/s0/p3-outputs.txt`, p3Text);
const p3 = p3Text.trim().split('\n').map((l) => l.split(' ').map(BigInt));
if (p3.length !== inputs.length) throw new Error('p3ref returned ' + p3.length + ' lines');

// ---- script
setOptions({sbox: 'mid', m4: 'chain', psum: '3dup'});
const code8 = permCode({out: 8}), code4 = permCode({out: 4});
const NOP = {raw: [0x61]};
const check = (ys) => ys.slice().reverse().map((y, i) => (i < ys.length - 1 ? [y, 'NUMEQUALVERIFY'] : [y, 'NUMEQUAL']));
const run = (vm, code, x, ys) => {
  const r = evaluate(vm, asm(NOP, {raw: code}, NOP, check(ys)), asm(x));
  const d = (k) => r.snaps[1][k] - r.snaps[0][k];
  return {accepted: r.accepted, error: r.error, op: d('op') - 100, instr: d('instr') - 1, arith: d('arith'), pushed: d('pushed')};
};

const tvOk = JSON.stringify(permRef(inputs[0]).map(String)) === JSON.stringify(K.test_vector.output.map(String))
  && JSON.stringify(p3[0].map(String)) === JSON.stringify(K.test_vector.output.map(String));
const stats = {};
const acc = (k, v) => { const s = stats[k] ??= {min: Infinity, max: -Infinity, sum: 0, n: 0}; s.min = Math.min(s.min, v); s.max = Math.max(s.max, v); s.sum += v; s.n++; };
const bad = [];
let agreeRef = 0, agreeScript = 0, rejOk = 0, rejN = 0;
for (let t = 0; t < inputs.length; t++) {
  const x = inputs[t], want = p3[t];
  const ref = permRef(x);
  if (ref.every((v, i) => v === want[i])) agreeRef++; else bad.push({t: labels[t], what: 'permRef != p3'});
  const rc = run('looseCons', code8, x, want), rs = run('looseStd', code8, x, want), r4 = run('looseStd', code4, x, want.slice(0, 4));
  if (rc.accepted && rs.accepted && r4.accepted) agreeScript++;
  else bad.push({t: labels[t], what: 'script', cons: rc.error ?? rc.accepted, std: rs.error ?? rs.accepted, c4: r4.error ?? r4.accepted});
  if (rc.op !== rs.op) bad.push({t: labels[t], what: 'cons/std op-cost differ'});
  for (const [k, v] of Object.entries(rs)) if (typeof v === 'number') acc('perm8.' + k, v);
  for (const [k, v] of Object.entries(r4)) if (typeof v === 'number') acc('compress4.' + k, v);
  if (t < 50) {   // plain rejections: a wrong expected output on one lane
    for (const [lane, delta] of [[t % 8, 1n], [(t + 3) % 8, P]]) {
      const w = [...want]; w[lane] += delta;
      const r = run('looseStd', code8, x, w); rejN++; if (!r.accepted) rejOk++; else bad.push({t: labels[t], what: `accepted wrong output lane ${lane} + ${delta}`});
    }
  }
}
const fin = (s) => ({min: s.min, max: s.max, mean: Math.round(s.sum / s.n)});
const out = {
  stage: 'Track 9 S0', what: 'Poseidon2-Gl-8 in CashVM (libauth 3.1.0-next.8, BCH 2026 VM)',
  constants: 'poseidon2-gl8-constants.json (copied from bench research/pq-stark/design-t8, Plonky3 0d803737)',
  options: {sbox: 'mid', m4: 'chain', psum: '3dup'},
  test_vector: tvOk,
  inputs: inputs.length, random: N, edge: inputs.length - N,
  inputs_sha256: createHash('sha256').update(inText).digest('hex'), p3_outputs_sha256: createHash('sha256').update(p3Text).digest('hex'),
  agree_permRef_vs_p3: agreeRef, agree_script_vs_p3: agreeScript,
  rejections: {cases: rejN, rejected: rejOk},
  code_bytes: {perm8: code8.length, compress4: code4.length},
  opcost: Object.fromEntries(Object.entries(stats).map(([k, s]) => [k, fin(s)])),
  bchn_adjusted_note: 'straight-line code, no OP_DEFINE inside: BCHN op-cost = libauth op-cost per permutation. Packaged as one OP_DEFINE body, BCHN adds the body bytes once per input (perm8: ' + code8.length + ', compress4: ' + code4.length + ').',
  bad,
};
fs.writeFileSync(HERE + 'results/s0-p2.json', JSON.stringify(out, null, 1) + '\n');
console.log(JSON.stringify({...out, bad: bad.slice(0, 5)}, null, 1));
process.exit(bad.length || !tvOk ? 1 : 0);
