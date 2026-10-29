// Markdown tables for README.md from results/layout-b.json, results/layout-a.json, results/profile-b.json and
// results/security.json.  usage: node tables.mjs > results/tables.md
import {readFileSync} from 'node:fs';

const rd = (f) => JSON.parse(readFileSync(new URL('./results/' + f, import.meta.url), 'utf8'));
const B = rd('layout-b.json'), A = rd('layout-a.json'), PR = rd('profile-b.json'), SEC = rd('security.json');
const n = (x) => (x == null ? '-' : Number(x).toLocaleString('en-US'));
const M = (x) => (x == null ? '-' : (x / 1e6).toFixed(2) + 'M');
const key = (v) => v.replace(/\.json$/, '');
const sec = (v) => SEC[v.replace(/-\d\.json$/, '-0.json')] ?? {};

console.log('### Layout (b): one input, "100 KB inputs" (TXv5: 100,000 B items and scripts, density base 41)\n');
console.log('| vector | security (bits, regime) | proof B | unlocking B | redeem B | op-cost std | BCHN-adj. | % of base-41 budget | TXv5 std/cons | bch-spec % |');
console.log('|---|---|--:|--:|--:|--:|--:|--:|---|--:|');
for (const r of B) {
  const s = sec(r.vector);
  const fits = r.fitsOneInput100k;
  console.log(`| ${key(r.vector)} | ${s.label ?? '-'} | ${n(r.proofBytes)} | ${n(r.unlockingBytes)} | ${n(r.redeemBytes)} | ${M(r.opStd)} | ${M(r.opBchnAdjusted)} | ${fits ? r.txv5Pct + '%' : '(' + r.txv5Pct + '%)'} | ${fits ? (r.accepted.txv5Std && r.accepted.txv5Cons ? 'accepted' : 'REJECTED') : 'does not fit 100 KB'} | ${fits ? r.specPct + '%' : '-'} |`);
}
console.log('\n### Layout (a): today\'s standard rules (10,000 B unlocking per input, 100,000 B per transaction, base 41)\n');
console.log('| vector | security (bits, regime) | txs | inputs | total B | per QRY input | code blobs B | pad B | op-cost std | BCHN-adj. | max input % | real BCH 2026 std+cons, tx verify |');
console.log('|---|---|--:|--:|--:|--:|---|--:|--:|--:|--:|---|');
for (const r of A) {
  const s = sec(r.vector);
  const mx = Math.max(...r.perInputDetail.flat().map((x) => x.pct));
  console.log(`| ${key(r.vector)} | ${s.label ?? '-'} | ${r.transactions} | ${r.inputs} | ${n(r.totalBytes)} | ${r.perInput} | ${r.codeBytes.join(' + ')} | ${n(r.padBytes)} | ${M(r.opStdTotal)} | ${M(r.opBchnTotal)} | ${mx}% | ${r.accepted && r.fitsStandard ? 'accepted' : 'NO'} |`);
}
console.log('\n### Profile, layout (b): per-query op-cost and the AIR-specific part\n');
console.log('| vector | queries | total | per query: x / DEEP / folds / final | Merkle (share) | per-proof: transcript / AIR block / consts+tables / unpack | AIR-specific op-cost (share) | AIR-specific code B (share of redeem) |');
console.log('|---|--:|--:|---|--:|---|--:|--:|');
for (const r of PR) {
  const p = r.phases, q = r.perQuery;
  const airBlock = (p['air-start'] ?? 0) + (p['air-generic-a'] ?? 0) + (p['air-specific'] ?? 0) + (p['air-generic-b'] ?? 0);
  console.log(`| ${key(r.vector)} | ${r.Q} | ${M(r.opStd)} | ${n(q['q-x'])} / ${n(q['q-deep'])} / ${n(q['q-folds'])} / ${n(q['q-final'])} | ${M(r.merkle)} (${r.merklePct}%) | ${n(p.transcript)} / ${n(airBlock)} / ${n((p['deep-consts'] ?? 0) + (p.tables ?? 0))} / ${n(p.unpack)} | ${n(r.airSpecific.opCost)} (${r.airSpecific.pctOfTotal}%) | ${n(r.airSpecific.codeBytes)} (${r.airSpecific.pctOfRedeem}%) |`);
}
