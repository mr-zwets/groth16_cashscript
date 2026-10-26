// Forced liveness witnesses (honest statements whose canonical base-|x| digits are chosen on purpose).
// The op cost is almost statement-independent except for the GT-GLS lookups: a nonzero nibble costs ~25k op more
// than a zero one (48-byte table entries instead of 1). The budget grows with the quotient length n_q (48 B per
// word). So the liveness extreme is a statement that keeps n_q small while making as many of the 128 nibbles
// nonzero as the degree bound allows: for each target n_q this module finds, chunk by chunk, the largest number of
// nonzero nibbles (one set bit each, the cheapest in degree) whose structural degree stays within the target.
//   node worst.mjs [nq,...]     prints n_q, nonzero nibbles, op and margin (consensus / standard) per target
import assert from 'node:assert/strict';
import {r, AX, AXPOW, mint} from './math.mjs';
import {CHUNK_END, K_IDS, degDBound, NQ_MAX, N_MIN, prove} from './protocol.mjs';

// slots: s[j] in {0, 1, 2} nonzero nibbles at byte j (j = 0: the initial value; j = e + 1: event e)
// a chunk's structural degree only depends on its own bytes (chunk 0 also owns byte 0)
const chunkBytes = (k) => { const a = k ? CHUNK_END[k - 1] + 1 : 0; const b = CHUNK_END[k]; const out = []; if (k === 0) out.push(0); for (let e = a; e <= b; e++) out.push(e + 1); return out; };
export function maxSlots(nq) {
  const s = Array(64).fill(0); const lim = 2 * nq + 12; // odd part of D <= 2 nq + 11
  for (let k = 0; k < K_IDS; k++) {
    const bytes = chunkBytes(k); let best = null;
    const rec = (i, cur) => {
      if (i === bytes.length) { const bitsOf = (e) => cur[bytes.indexOf(e + 1)] ?? 0; if (degDBound(k, bitsOf) <= lim) { const tot = cur.reduce((x, y) => x + y, 0); if (!best || tot > best.tot) best = {tot, cur: cur.slice()}; } return; }
      for (const v of [2, 1, 0]) { cur.push(v); rec(i + 1, cur); cur.pop(); }
    };
    rec(0, []); assert.ok(best, 'target n_q below the zero-statement minimum'); bytes.forEach((j, i) => { s[j] = best.cur[i]; });
  }
  return s;
}
// digits with bit (63 - j) set in digit (j mod 4) of group k for each nonzero slot: every digit < |x|, so the
// digits are the canonical base-|x| expansion of n_k (the honest prover's own choice), and n_k < r.
export function statementFor(slots) {
  const dg = [0, 1].map(() => [0n, 0n, 0n, 0n]);
  slots.forEach((c, j) => { for (let k = 0; k < c; k++) dg[k][j % 4] |= 1n << BigInt(63 - j); });
  dg.forEach((a) => a.forEach((v) => assert.ok(v < AX)));
  const ns = dg.map((a) => a.reduce((s, v, i) => s + v * AXPOW[i], 0n)); ns.forEach((n) => assert.ok(n < r));
  return {ns, digits: dg};
}
export function forcedCases(targets = [46, 47, 48, 49, 50, 51, 52, 53, 54, 56, 58, 60]) {
  const out = [];
  for (const nq of targets) { const slots = maxSlots(nq); const {ns} = statementFor(slots); out.push({label: `forced n_q<=${nq}: ${slots.reduce((a, b) => a + b, 0)} nonzero nibbles`, ns, slots}); }
  // every nibble nonzero (one bit each): the densest lookups at the smallest n_q that allows them
  { const slots = Array(64).fill(2); out.push({label: 'forced: all 128 nibbles nonzero (1 bit each)', ns: statementFor(slots).ns, slots}); }
  out.push({label: 'zero statement (every nibble 0)', ns: [0n, 0n]});
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const {redeem, locking} = await import('./transaction.mjs');
  const {spend, unlockingFor} = await import('./vm.mjs');
  const targets = process.argv[2] ? process.argv[2].split(',').map(Number) : undefined;
  let worst = null;
  for (const c of forcedCases(targets)) {
    const fx = mint(c.ns); const w = prove(fx); const u = unlockingFor(w.WS, w.WQ, redeem);
    const rs = ['consensus', 'standard'].map((m) => spend(locking, u, m));
    const line = rs.map((x) => `${x.accepted ? 'ACCEPT' : 'REJECT ' + x.error} ${x.opCost} / ${x.budget} (${(100 * x.opCost / x.budget).toFixed(2)}%, margin ${x.budget - x.opCost})`).join(' | ');
    console.log(c.label.padEnd(48), 'n_q', String(w.nq).padStart(3), line);
    const m = rs[1].budget - rs[1].opCost; if (!worst || m < worst.m) worst = {m, label: c.label, pct: 100 * m / rs[1].budget};
  }
  console.log('min standard margin', worst.m, `(${worst.pct.toFixed(2)}%)`, worst.label, 'NQ_MAX', NQ_MAX);
}
