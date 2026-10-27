// Bench vectors (one bch-2026 transaction, 3 P2SH32 inputs): valid = fixture 0, extraValidProofs = fixtures 1-3,
// worstCaseProof = the forced op-cost worst case (every GT-GLS nibble 15, n_q 132: a proof minted under the fixture VK
// for denseStatement(), the same case as sweep.mjs's first forced case, seed bn-native-sound-v1); invalid = one tamper per push class (each run is the full
// 3-input transaction, and must be rejected). Fillers are prover-sized (6% standard margin per input).
//   node export.mjs vectors.json
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {mint, rng, denseStatement} from '../sound-si-gls/mint.mjs';
import {NQ_MAX} from './protocol.mjs';
import {STMT_LAYOUT} from './protocol.mjs';
import {buildProgram} from './script.mjs';
import {transactionFor} from './transaction.mjs';
import {encodeUnlocking, spendAll} from './vm.mjs';

assert.equal(process.argv.length, 3, 'usage: node export.mjs vectors.json');
const prog = buildProgram();
const built = JSON.parse(readFileSync(new URL('./build.json', import.meta.url), 'utf8'));
assert.equal(createHash('sha256').update(prog.code).digest('hex'), built.codeSha256, 'build.json is stale: run build.mjs');
export const LABELS = ['input 0: events 0-24', 'input 1: events 24-48', 'input 2: events 48-65, terminal, binding, quotient'];
export const CHECKPOINTS = ['miller-events-24', 'miller-events-48', 'pairing-close'];
const stepsOf = (unlockings, locking) => unlockings.map((u, i) => ({label: LABELS[i], locking: locking.toString('hex'), unlocking: Buffer.from(u).toString('hex'), checkpoint: CHECKPOINTS[i]}));
const run = (fx, opts = {}, check = () => {}) => { const t = transactionFor(fx, prog, opts); check(t); const r = spendAll(t.unlockings.map(() => t.locking), t.unlockings, 'standard'); assert.ok(r.every((x) => x.accepted), 'valid run rejected'); return stepsOf(t.unlockings, t.locking); };
const [primary, ...rest] = FIXTURES.fixtures;
const worst = (() => { const d = denseStatement(); return run(mint(...d.n, rng('bn-native-sound-v1')), {es: d.es}, (t) => assert.equal(t.core.nq, NQ_MAX, 'worst case: n_q')); })();
const T = transactionFor(primary, prog); const lock = T.locking;
// one tamper per push class: [label, input, push index, byte offset within the push]
const P = T.pushes;
const classes = [
  ['S_0: first inverse-norm witness t', 0, 0, 5], ['S_0: state S_1 (end of the first record)', 0, 0, 32 * 2 + 100], ['S_0: last state', 0, 0, P[0][0].length - 10],
  ['DS_0: a delta slope (K_DS)', 0, 1, 700], ['C_0: code piece byte (K_code)', 0, 2, 1000], ['FILL_0: nonzero byte', 0, 3, 0],
  ['S_1: a witness t', 1, 0, 40], ['HAND_1: x_T.c0', 1, 1, 3], ['HAND_1: R', 1, 1, 6 * 32 + 3], ['DS_1: a delta slope', 1, 2, 1500], ['C_1: code piece byte', 1, 3, 77],
  ['DG: d1 byte', 2, 0, 40], ['STMT: A.x', 2, 1, 5], ['STMT: B.y.c1', 2, 1, 5 * 32 + 5], ['STMT: n0', 2, 1, STMT_LAYOUT.n0], ['STMT: n1', 2, 1, STMT_LAYOUT.n1],
  ['STMT: nibble N0', 2, 1, STMT_LAYOUT.N0 + 30], ['STMT: residue root s^c', 2, 1, STMT_LAYOUT.sc + 70], ['S_2: a state', 2, 2, 600], ['S_2: terminal witness t_psi', 2, 2, P[2][2].length - 40],
  ['HAND_2: F-', 2, 3, 5 * 32 + 3], ['WQ: leading word', 2, 6, 3], ['WQ: middle word', 2, 6, P[2][6].length >> 1], ['R (input 1): redeem byte', 1, 5, 10],
].filter(([, i, k]) => P[i][k] !== undefined && P[i][k].length > 0);
const invalid = classes.map(([label, i, k, off]) => {
  const pushes = P.map((ps) => ps.map((b) => Buffer.from(b))); if (label.startsWith('FILL')) assert.ok(pushes[i][k].length > 0, 'filler empty');
  pushes[i][k][off] ^= 0x01; const unl = pushes.map((ps) => Buffer.from(encodeUnlocking(ps)));
  const r = spendAll(unl.map(() => lock), unl, 'consensus'); assert.ok(!r.every((x) => x.accepted), label + ' accepted');
  return stepsOf(unl, lock).map((s, j) => ({...s, label: (j === i ? 'TAMPERED ' : '') + s.label + ': ' + label}));
});
writeFileSync(process.argv[2], JSON.stringify({steps: run(primary), invalid, extraValidProofs: rest.slice(0, 3).map((f) => run(f)), worstCaseProof: worst}, null, 1) + '\n');
console.log('wrote', process.argv[2], 'invalid classes', invalid.length);
