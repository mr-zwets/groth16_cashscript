// Ordinary rejection tests on the VM skeleton (bcast layout): each mutation of the honest 5-input transaction must make
// the input whose check owns it fail (standard and consensus). The positive control must be accepted.
//   node rejections.mjs [layout=layout-rec.json] [seed=3]
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {encodeDataPush} from '@bitauth/libauth';
import {p} from './blsmath.mjs';
import {le, rdle} from './protocol.mjs';
import {prepare, layoutFromModel} from './proto_skeleton.mjs';
import {W, BC_NAMES} from './split.mjs';
const L = JSON.parse(readFileSync(process.argv[2] ?? 'layout-rec.json')); const seed = Number(process.argv[3] ?? 3);
const layout = layoutFromModel(L);
const N = layout.N, T = N - 1; const preps = new Map(); const P = (role) => { if (!preps.has(role)) preps.set(role, prepare(layout, seed, role, {terminal: role === T})); return preps.get(role); };
const results = []; let failures = 0;
const run = (name, role, mutate, {expect = 'reject'} = {}) => {
  const pr = P(role); let Wj = pr.Wj.map((x) => Buffer.from(x)); let red = pr.R; let extraInputs = 0; let lockOf = null; let order = null;
  const ctx = {Wj, s: pr.s, setRedeem: (r) => (red = r), addInput: () => extraInputs++, foreignLock: (i) => (lockOf = i), swap: (i, j) => (order = [i, j])};
  mutate?.(ctx); Wj = ctx.Wj;
  let unl = pr.unlOf(Wj, red); if (order) { const [i, j] = order; [unl[i], unl[j]] = [unl[j], unl[i]]; }
  if (ctx.extraPush) unl[role] = Uint8Array.from([0x51, ...unl[role]]);
  for (let k = 0; k < extraInputs; k++) unl.push(unl[1]);
  const src = pr.srcOf(unl.length); if (lockOf !== null) src[lockOf] = {lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n};
  const tx = pr.txOf(unl);
  const r = {name, role, std: pr.evalInput(role, tx, src, 'std'), cons: pr.evalInput(role, tx, src, 'cons')};
  const ok = expect === 'accept' ? r.std === 'accepted' && r.cons === 'accepted' : r.std !== 'accepted' && r.cons !== 'accepted';
  if (!ok) failures++; results.push({...r, ok});
  console.log(ok ? 'ok  ' : 'FAIL', `[input ${role}]`, name.padEnd(58), '->', r.std.slice(0, 90));
};
const word = (buf, off) => rdle(buf, off, W);
const setWord = (buf, off, v) => le(v, W).copy(buf, off);
const at = (j) => P(j).s.offsets[j];
// positive controls
for (let j = 0; j < N; j++) run('honest transaction', j, null, {expect: 'accept'});
// pinning and layout (owned by every input; tested at input 1 and the hub)
run('extra (6th) input', 1, (c) => c.addInput());
run('a sibling with a foreign locking', 0, (c) => c.foreignLock(2));
run('inputs 1 and 2 swapped', 1, (c) => c.swap(1, 2));
run('witness one byte longer', 2, (c) => { c.Wj[2] = Buffer.concat([c.Wj[2], Buffer.of(0)]); });
run('an extra push before the witness', 3, (c) => { c.extraPush = true; });
for (const {host} of layout.cbSlots) run(`code blob part in input ${host} tampered (one byte)`, 0, (c) => { c.Wj[host][P(0).s.offsets[host].CB + 10] ^= 1; });
// constants
run('delta constant tampered (input 2)', 2, (c) => { c.Wj[2][at(2).K + 5] ^= 1; });
// transcript (the hub derives z from every input's phase-1 slice and the quotient; the broadcast then mismatches)
run('state word tampered (input 3 phase-1 slice)', 0, (c) => { c.Wj[3][at(3).P1 + 7] ^= 1; });
run('statement word tampered (x_A)', 0, (c) => { c.Wj[0][at(0).P1 + 3] ^= 1; });
run('quotient word tampered', 0, (c) => { const j = layout.q.findIndex((x) => x > 0); c.Wj[j][P(0).s.offsets[j].Q + 20] ^= 1; });
run('GLS nibble tampered', 0, (c) => { c.Wj[0][at(0).P1 + 448 + 30] ^= 1; });
// broadcast (owned by the hub's equality check)
for (const n of ['z', 'rho', 'cp', 'TP0_7', 'TM1_0']) run(`broadcast word ${n} changed (+1)`, 0, (c) => { const o = at(0).BC + W * BC_NAMES.indexOf(n); setWord(c.Wj[0], o, (word(c.Wj[0], o) + 1n) % p); });
run('broadcast word z aliased (+p, non-canonical)', 0, (c) => { const o = at(0).BC; const v = word(c.Wj[0], o) + p; if (v < 1n << 384n) setWord(c.Wj[0], o, v); });
// handoff (owned by the producer's OUT comparison; non-canonical IN also fails the consumer's decode)
run('handoff T word changed in input 2 (producer 1 checks)', 1, (c) => { const o = at(2).IN; setWord(c.Wj[2], o, (word(c.Wj[2], o) + 1n) % p); });
run('handoff R changed in input 3 (producer 2 checks)', 2, (c) => { const o = at(3).IN + 6 * W; setWord(c.Wj[3], o, (word(c.Wj[3], o) + 1n) % p); });
run('handoff word aliased +p (consumer 2 decodes)', 2, (c) => { const o = at(2).IN; setWord(c.Wj[2], o, word(c.Wj[2], o) + p); });
// terminal (final identity / endpoint / binding / curve, with the honest post-loop values)
run('s^c tampered: transcript changes (hub)', 0, (c) => { c.Wj[0][at(0).P1 + 448 + 128 + 9] ^= 1; });
run('public input n0 + 1 (terminal: binding)', T, (c) => { const o = at(0).P1 + 384; const v = rdle(c.Wj[0], o, 32) + 1n; le(v, 32).copy(c.Wj[0], o); });
run('quotient word changed (terminal: final identity)', T, (c) => { const j = layout.q.findIndex((x) => x > 0); c.Wj[j][P(T).s.offsets[j].Q + 47] ^= 1; });
console.log(`${results.length - failures}/${results.length} as expected`);
writeFileSync('rejections.json', JSON.stringify(results, null, 1));
assert.equal(failures, 0);
void encodeDataPush;
