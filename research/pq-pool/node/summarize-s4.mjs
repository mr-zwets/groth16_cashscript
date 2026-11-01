// Track 9 S4: summary of s4.ts output.  usage: node summarize-s4.mjs results/NAME.jsonl > results/NAME-summary.json
import {readFileSync} from 'node:fs';
const ev = readFileSync(process.argv[2], 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const by = (k) => ev.filter((e) => e.ev === k);
const mm = (xs) => (xs.length ? [Math.min(...xs), Math.max(...xs)] : null);
const tmaRows = []; const walk = (o) => { if (o && typeof o === 'object') { if ('allowed' in o && 'label' in o) tmaRows.push(o); for (const v of Object.values(o)) walk(v); } }; walk(ev);
const fl = by('flush'), dp = by('deposits'), wd = by('withdraw'), pr = by('prove');
const out = {
  setup: by('setup')[0], genesis: by('genesis').map((g) => ({ok: g.ok, txid: g.txid, bytes: g.bytes, tmaAllowed: g.bchn.allowed, noMintingNft: g.noMintingNft, tokenOutputs: g.tokenOutputsOfCategory}))[0],
  deposits: {rounds: dp.length, ok: dp.filter((e) => e.ok).length, txs: dp.reduce((a, e) => a + e.n, 0), bytes: mm(dp.flatMap((e) => e.bytes)), allTmaAllowed: dp.every((e) => e.allAllowed)},
  flushes: {n: fl.length, ok: fl.filter((e) => e.ok).length, rootEqualsOffline: fl.filter((e) => e.rootEqualsOffline).length, bytes: mm(fl.map((e) => e.bchn.bytes)),
    maxInputPct: mm(fl.map((e) => e.lib.maxPct)), rate: mm(fl.map((e) => +e.rate.toFixed(3))), tmaAllowed: fl.filter((e) => e.bchn.allowed).length, per: fl[0]?.lib.per},
  proofs: pr.map((p) => ({note: p.note, root: p.root, ms: p.ms, bytes: p.proofBytes, publicValuesMatch: p.publicValuesMatch})),
  withdrawals: wd.map((w) => ({label: w.label, expect: w.expect, ok: w.ok, bytes: w.bytes, maxPct: w.lib1 ? Math.max(w.lib0.maxPct, w.lib1.maxPct) : undefined, W: w.lib1?.W,
    tma: [w.bchn0?.allowed, w.bchn1?.allowed], reject: w.expect === 'reject' ? {libauth: `${w.lib1.firstRejectRole}: ${w.lib1.firstRejectErr}`, tma: w.bchn1.rejectReason, block: w.blockVerdict?.result} : undefined})),
  e2e: by('e2e-summary')[0], wrap: by('wrap-summary')[0],
  testmempoolaccept: {rows: tmaRows.length, allowed: tmaRows.filter((t) => t.allowed).length, rejected: tmaRows.filter((t) => !t.allowed).map((t) => `${t.label}: ${t.rejectReason}`)},
  end: by('end')[0], errors: by('error'),
};
console.log(JSON.stringify(out, null, 1));
