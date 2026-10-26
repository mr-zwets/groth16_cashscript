// Forced liveness witnesses (honest statements whose canonical base-|x| digits are chosen on purpose).
// Op cost model (measured; review-repro mval/m15 families): the Miller inputs cost ~24k op more per NONZERO GLS
// nibble (48-byte table entries instead of 1) and ~0.2k op more per extra SET BIT of a nonzero nibble (value-length
// effects); B and C move the total by ~2k op (sd). Input 0 (the head) also pays for the GT-GLS binding loop, whose
// TB[N_k[g]] lookups are 1..25 B long (TB[m] = sum_{i in m} |x|^i: TB[1] = 1 is 1 B, TB[8] = |x|^3 is 24 B), so at a
// fixed slot pattern the head costs more when the bits sit in the high digits (review r1: digit 3 first is ~0.05%
// of input 0's budget dearer than the `j mod 4` placement). The structural degree (hence n_q) grows by 6 per set bit
// (`eventDeg`), and only input 0's budget grows with n_q (48 B per WQ word); inputs 1-3 have fixed-size unlockings.
// So the liveness extremes are
//  * inputs 1-3: the statement with the most set bits on bytes 8..63 (events 7..62): every nibble = 15 there, i.e.
//    n0 = n1 = (2^56 - 1) * sum_{i<4} |x|^i (`ALL15`); it reaches n_q = NQ_MAX = 116 (input 0 at its cap size);
//  * input 0: the smallest n_q with the most op: for each target n_q, `maxSlots` picks, chunk by chunk, the number of
//    set bits per byte (0..8 over the two nibbles) that maximizes 24k * nonzero nibbles + 0.2k * set bits within the
//    degree bound (so one bit per nibble first, then extra bits where the degree has slack).
//   node worst.mjs [nq,...]     prints n_q, set bits, op and margin (consensus / standard) per target
import assert from 'node:assert/strict';
import {r, AX, AXPOW, mint, glsDigits} from './math.mjs';
import {CHUNK_END, K_IDS, degDBound, NQ_MAX, N_MIN, prove} from './protocol.mjs';

const NZ_OP = 24000, BIT_OP = 180;                       // the op model above (only the ordering matters)
const slotScore = (t) => NZ_OP * Math.min(t, 2) + BIT_OP * t;
// slots: s[j] in 0..8 set bits at byte j over both nibbles (j = 0: the initial value; j = e + 1: event e)
// a chunk's structural degree only depends on its own bytes (chunk 0 also owns byte 0)
const chunkBytes = (k) => { const a = k ? CHUNK_END[k - 1] + 1 : 0; const b = CHUNK_END[k]; const out = []; if (k === 0) out.push(0); for (let e = a; e <= b; e++) out.push(e + 1); return out; };
export function maxSlots(nq) {
  const s = Array(64).fill(0); const lim = 2 * nq + 12; // odd part of D <= 2 nq + 11
  for (let k = 0; k < K_IDS; k++) {
    const bytes = chunkBytes(k); let best = null;
    const rec = (i, cur) => {
      if (i === bytes.length) { const bitsOf = (e) => cur[bytes.indexOf(e + 1)] ?? 0; if (degDBound(k, bitsOf) <= lim) { const sc = cur.reduce((x, t) => x + slotScore(t), 0); if (!best || sc > best.sc) best = {sc, cur: cur.slice()}; } return; }
      for (let v = 8; v >= 0; v--) { cur.push(v); rec(i + 1, cur); cur.pop(); }
    };
    rec(0, []); assert.ok(best, 'target n_q below the zero-statement minimum'); bytes.forEach((j, i) => { s[j] = best.cur[i]; });
  }
  return s;
}
// canonical digits from slot bit counts: n0 gets ceil(t/2) bits and n1 floor(t/2) bits at byte j (bit 63 - j of
// that many of its 4 digits, starting at digit j mod 4); a bit is only placed where the digit stays below its
// canonical bound (|x| - 1 for digits 0..2, D3MAX for digit 3, which keeps n < r for any lower digits), else the
// next digit is tried, else the bit is dropped (fewer bits only lower the degree). With `order` (a digit preference
// list, e.g. D3FIRST = [3, 2, 1, 0]) the digits are tried in that order instead. So every digit is the canonical
// base-|x| expansion of n_k (the honest prover's own choice; asserted against glsDigits) and n_k < r.
const D3MAX = (r - 1n - (AX - 1n) * (AXPOW[0] + AXPOW[1] + AXPOW[2])) / AXPOW[3];
const DMAX = [AX - 1n, AX - 1n, AX - 1n, D3MAX];
export const D3FIRST = [3, 2, 1, 0];
export function statementFor(slots, order) {
  const dg = [0, 1].map(() => [0n, 0n, 0n, 0n]);
  slots.forEach((t, j) => { const per = [Math.ceil(t / 2), Math.floor(t / 2)];
    for (let k = 0; k < 2; k++) { let need = per[k];
      for (let o = 0; o < 4 && need > 0; o++) { const d = order ? order[o] : (j + o) % 4; const v = dg[k][d] | (1n << BigInt(63 - j)); if (v <= DMAX[d]) { dg[k][d] = v; need--; } } } });
  dg.forEach((a) => a.forEach((v, d) => assert.ok(v <= DMAX[d])));
  const ns = dg.map((a) => a.reduce((s, v, i) => s + v * AXPOW[i], 0n)); ns.forEach((n) => assert.ok(n < r));
  ns.forEach((n, k) => assert.deepEqual(glsDigits(n), dg[k]));
  return {ns, digits: dg};
}
const LOW56 = (1n << 56n) - 1n;
export const ALL15 = LOW56 * (AXPOW[0] + AXPOW[1] + AXPOW[2] + AXPOW[3]);    // every nibble on bytes 8..63 = 15
assert.ok(ALL15 < r);
export function forcedCases(targets = [46, 47, 48, 49, 50, 51, 52, 53, 54, 56, 58, 60]) {
  const out = [];
  for (const nq of targets) { const slots = maxSlots(nq); const {ns} = statementFor(slots); out.push({label: `forced n_q<=${nq}: ${slots.reduce((a, b) => a + b, 0)} set bits`, ns, slots}); }
  // input 0's extreme: the floor witness with its bits in the high digits first (longest binding-loop TB lookups)
  { const nq = Math.min(...targets); const slots = maxSlots(nq); out.push({label: `forced n_q<=${nq}, digit 3 first`, ns: statementFor(slots, D3FIRST).ns, slots}); }
  // every nibble nonzero (one bit each): the densest lookups at the smallest n_q that allows them
  { const slots = Array(64).fill(2); out.push({label: 'forced: all 128 nibbles nonzero (1 bit each)', ns: statementFor(slots).ns, slots}); }
  out.push({label: 'forced: every nibble 15 on bytes 8..63 (n_q = NQ_MAX)', ns: [ALL15, ALL15]});
  out.push({label: 'zero statement (every nibble 0)', ns: [0n, 0n]});
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const {pushesFor, unlockingsOf, ctxOf} = await import('./transaction.mjs');
  const {evalTx} = await import('./vm.mjs');
  const targets = process.argv[2] ? process.argv[2].split(',').map(Number) : undefined;
  for (const c of forcedCases(targets)) {
    const {w, pushes} = pushesFor(mint(c.ns)); const ctx = ctxOf(unlockingsOf(pushes));
    const line = ['consensus', 'standard'].map((m) => evalTx(ctx, m).map((x) => (100 * (1 - x.op / x.budget)).toFixed(2)).join('/') + '%').join(' | ');
    console.log(c.label.padEnd(56), 'n_q', String(w.nq).padStart(3), 'margins cons | std', line);
  }
  console.log('NQ_MAX', NQ_MAX, 'N_MIN', N_MIN);
}
