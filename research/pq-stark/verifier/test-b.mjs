// Layout (b) accept/reject sweep.
//   - every valid proof: accepted (TXv5 standard + consensus when it fits one 100 KB input, else the loose VM);
//   - every tampered proof of the vectors (prover/gen-tampered.mjs): rejected on the loose VM (no budget limits, so a
//     rejection is a failed check, not a resource limit), and by the model;
//   - witness manipulations of a valid spend (most of them count- and size-preserving): rejected on the loose VM.
// usage: node test-b.mjs [--wit] vectors...   (exit 1 on any unexpected verdict)
import {readFileSync} from 'node:fs';
import {spendB, casesOf} from './layout-b.mjs';
import {vkxFromVector, verifyModel, P, le8} from './model.mjs';
import {evaluate} from './vm.mjs';

const args = process.argv.slice(2), WIT = args.includes('--wit');
let total = 0, bad = 0;
const report = (ok, label) => { total++; if (!ok) bad++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`); };

function witnessCases(vk, items) {
  const Q = vk.Q, nRec = Math.ceil(Q / 2), nT = vk.trees.length;
  const iG = (t, g) => Q + t * nRec + g;                       // record group index
  const pt0 = Q + nT * nRec;                                   // ROOTS
  const iOOD = pt0 + 1, iFIN = pt0 + 2 + (vk.bpow ? 1 : 0) + 1 + (vk.cpow ? 1 : 0);
  const flip = (b, at) => { const c = Buffer.from(b); c[at] ^= 1; return c; };
  const C = [];
  const mut = (name, f) => C.push({name, f});
  mut('swap L blobs of two queries', (it) => { [it[0], it[1]] = [it[1], it[0]]; return it; });
  mut('flip a row byte (input batch 0)', (it) => { it[0] = flip(it[0], 0); return it; });
  mut('flip a row byte (last input batch)', (it) => { const o = vk.batchBytes.slice(0, -1).reduce((a, x) => a + x, 0); it[1] = flip(it[1], o + 3); return it; });
  if (vk.salt) mut('flip a salt byte', (it) => { it[0] = flip(it[0], 8 * vk.claims[0][0].width); return it; });
  mut('flip a FRI sibling byte (round 0)', (it) => { const o = vk.batchBytes.reduce((a, x) => a + x, 0); it[2] = flip(it[2], o + 5); return it; });
  mut('flip a FRI sibling byte (last round)', (it) => { const o = vk.batchBytes.reduce((a, x) => a + x, 0) + vk.friBytes.slice(0, -1).reduce((a, x) => a + x, 0); it[3] = flip(it[3], o + 9); return it; });
  if (vk.friBytes.length > 1 && vk.friBytes[0] === vk.friBytes[1]) mut('swap the FRI blocks of rounds 0 and 1 in one query blob', (it) => {
    const o = vk.batchBytes.reduce((a, x) => a + x, 0), n = vk.friBytes[0], b = Buffer.from(it[0]);
    it[0] = Buffer.concat([b.subarray(0, o), b.subarray(o + n, o + 2 * n), b.subarray(o, o + n), b.subarray(o + 2 * n)]); return it;
  });
  mut('hint T + p (or T flipped when T + p does not fit 8 bytes)', (it) => {
    const b = Buffer.from(it[0]); const T = b.readBigUInt64LE(b.length - 8);
    if (T + P < 1n << 64n) b.writeBigUInt64LE(T + P, b.length - 8); else b[b.length - 8] ^= 1;
    it[0] = b; return it;
  });
  mut('hint T = 0', (it) => { const b = Buffer.from(it[0]); b.writeBigUInt64LE(0n, b.length - 8); it[0] = b; return it; });
  mut('query blob one byte short', (it) => { it[0] = it[0].subarray(0, it[0].length - 1); return it; });
  mut('query blob one byte long', (it) => { it[0] = Buffer.concat([it[0], Buffer.alloc(1)]); return it; });
  mut('records: move a record between the first two pushes of tree 0 (repack, same bytes)', (it) => {
    // group 0 = r0 ‖ r1, group 1 = r2 ‖ r3 -> group 0 = r0, group 1 = r1 ‖ r2 ‖ r3 (needs the record boundary: from the encoder)
    const g0 = it[iG(0, 0)], g1 = it[iG(0, 1)]; const cut = recCut(vk, g0);
    it[iG(0, 0)] = g0.subarray(0, cut); it[iG(0, 1)] = Buffer.concat([g0.subarray(cut), g1]); return it;
  });
  mut('records: swap the first two pushes of tree 0', (it) => { [it[iG(0, 0)], it[iG(0, 1)]] = [it[iG(0, 1)], it[iG(0, 0)]]; return it; });
  mut('records: swap push 0 of tree 0 and tree 1', (it) => { [it[iG(0, 0)], it[iG(1, 0)]] = [it[iG(1, 0)], it[iG(0, 0)]]; return it; });
  mut('records: swap push 0 of the first and the last FRI tree', (it) => { const a = vk.claims.length, b = nT - 1; [it[iG(a, 0)], it[iG(b, 0)]] = [it[iG(b, 0)], it[iG(a, 0)]]; return it; });
  mut('records: change sigma of the first record', (it) => { const g = Buffer.from(it[iG(0, 0)]); g[0] = (g[0] + 1) % Q; it[iG(0, 0)] = g; return it; });
  mut('records: sigma >= Q', (it) => { const g = Buffer.from(it[iG(0, 0)]); g[0] = Q; it[iG(0, 0)] = g; return it; });
  mut('records: flip a sibling byte', (it) => { it[iG(1, 0)] = flip(it[iG(1, 0)], 6); return it; });
  mut('records: replace push 1 of tree 0 by a copy of push 0', (it) => { it[iG(0, 1)] = Buffer.from(it[iG(0, 0)]); return it; });
  mut('records: one trailing byte on the last push', (it) => { const i = iG(nT - 1, nRec - 1); it[i] = Buffer.concat([it[i], Uint8Array.of(9)]); return it; });
  mut('records: last push of tree 0 empty, its bytes appended to the one before', (it) => { const i = iG(0, nRec - 1); it[i - 1] = Buffer.concat([it[i - 1], it[i]]); it[i] = Buffer.alloc(0); return it; });
  mut('extra empty item at the bottom', (it) => [Buffer.alloc(0), ...it]);
  mut('one item missing (first query blob)', (it) => it.slice(1));
  mut('swap OOD and FIN', (it) => { [it[iOOD], it[iFIN]] = [it[iFIN], it[iOOD]]; return it; });
  // a value v < 2^64 - p has the non-canonical twin v + p (same residue); random values almost never qualify
  const twin = (b) => { for (let o = 0; o + 8 <= b.length; o += 8) if (b.readBigUInt64LE(o) + P < 1n << 64n) return o; return -1; };
  for (const [nm, i] of [['OOD', iOOD], ['FIN', iFIN]]) {
    const o = twin(items[i]);
    if (o < 0) { console.log(`n/a  ${nm} value + p: no value below 2^64 - p in this proof (no non-canonical twin exists)`); continue; }
    mut(`${nm} value + p (non-canonical, same residue)`, (it) => { const b = Buffer.from(it[i]); b.writeBigUInt64LE(b.readBigUInt64LE(o) + P, o); it[i] = b; return it; });
  }
  mut('flip a ROOTS byte', (it) => { it[pt0] = flip(it[pt0], 1); return it; });
  if (vk.qpow) mut('query PoW witness + 1', (it) => { const i = it.length - 1; const b = Buffer.from(it[i]); b.writeBigUInt64LE((b.readBigUInt64LE(0) + 1n) % (1n << 64n)); it[i] = b; return it; });
  return C;
}
// byte length of the first record of a group (walk the record program)
function recCut(vk, g) {
  let o = 1;
  for (;;) {
    const op = g[o++]; const fresh = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}[op];
    if (fresh) o += fresh * vk.h; else if (op === 8 || op === 9) return o;
  }
}

for (const path of args.filter((a) => !a.startsWith('--'))) {
  const v = JSON.parse(readFileSync(path, 'utf8'));
  const vk = vkxFromVector(v), file = path.split('/').pop();
  for (const c of casesOf(v)) {
    const sp = spendB(vk, c.pis, c.proof, c.pis);
    const fits = sp.unlocking.length <= 100_000;
    if (c.expect) {
      const r1 = evaluate(fits ? 'txv5Std' : 'looseStd', sp.locking, sp.unlocking), r2 = evaluate(fits ? 'txv5Cons' : 'looseCons', sp.locking, sp.unlocking);
      report(r1.accepted && r2.accepted, `${file} valid: ${fits ? 'txv5' : 'loose'} ${r1.accepted}/${r2.accepted} ${r1.error ?? ''}`);
      if (WIT) for (const w of witnessCases(vk, sp.items)) {
        const items = w.f(sp.items.map((x) => Buffer.from(x)));
        const sp2 = spendB(vk, c.pis, c.proof, c.pis, {}, () => items);
        const r = evaluate('looseStd', sp2.locking, sp2.unlocking);
        report(!r.accepted, `${file} witness: ${w.name}: ${r.accepted ? 'ACCEPTED' : 'rejected (' + String(r.error).slice(0, 60) + ')'}`);
      }
    } else {
      const r = evaluate('looseStd', sp.locking, sp.unlocking);
      const m = verifyModel(vk, c.proof, c.pis);
      report(!r.accepted && !m.ok, `${file} ${c.name}: ${r.accepted ? 'ACCEPTED' : 'rejected'} (model: ${m.reason}) ${String(r.error ?? '').slice(0, 50)}`);
    }
  }
}
console.log(`test-b: ${total} cases, ${bad} unexpected`);
process.exit(bad ? 1 : 0);
