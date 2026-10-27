// Per-event op-cost profile of the reviewed SI-GLS single-input program (identical op-cost model on bch-2026).
//   node prof-events.mjs [fixtureIndex|dense|zero|thin] > out.json
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildRedeem} from '../../chunked/bn254/sound-si-gls/script.mjs';
import {FIXTURES, DIGITS} from '../../chunked/bn254/sound-si-gls/math.mjs';
import {redeem, locking, unlocking} from '../../chunked/bn254/sound-si-gls/transaction.mjs';
import {programOf, VMS} from '../../chunked/bn254/sound-si-gls/vm.mjs';
import {mint, rng, denseStatement, zeroStatement, thinDenseStatement} from '../../chunked/bn254/sound-si-gls/mint.mjs';
const {info} = buildRedeem(); if (!Buffer.from(buildRedeem().redeem).equals(redeem)) throw new Error('stale');
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const marks = info.marks.slice().sort((a, b) => a.off - b.off);
const arg = process.argv[2] ?? '0'; let fx, opts;
if (/^\d+$/.test(arg)) fx = FIXTURES.fixtures[Number(arg)];
else { const rnd = rng('prof'); const d = {dense: denseStatement, zero: zeroStatement, thin: thinDenseStatement}[arg](); fx = mint(...d.n, rnd); opts = {es: d.es}; }
const {w, unlocking: u} = unlocking(fx, opts);
const mode = process.env.MODE ?? 'standard';
const tr = VMS[mode].debug(programOf(locking, u));
let prev = 0, cur = 'p2sh', ev = -1; const pre = {}, post = {}; const evs = Array.from({length: 65}, () => ({}));
for (const s of tr) {
  const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c;
  if (s.instructions?.length === ins.length) { let n = 'prologue'; for (const m of marks) if (m.off <= offs[Math.max(0, s.ip - 1)]) n = m.name; if (n === 'bdbl' && cur !== 'bdbl') ev++; cur = n; }
  const bucket = ev < 0 ? pre : (cur.startsWith('end:') && cur !== 'end:loop-setup' ? post : evs[ev]);
  bucket[cur] = (bucket[cur] ?? 0) + d;
}
const tot = (o) => Object.values(o).reduce((a, b) => a + b, 0);
console.log(JSON.stringify({arg, nq: w.nq, unlocking: u.length, total: prev, pre, preTotal: tot(pre), post, postTotal: tot(post),
  events: evs.map((e, i) => ({e: i, d: DIGITS[i], total: tot(e), ...e}))}, null, 0));
