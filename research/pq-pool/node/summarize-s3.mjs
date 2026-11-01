// Track 9 S3: summary of s3.ts output.  usage: node summarize-s3.mjs results/s3.jsonl > results/s3-summary.json
import {readFileSync} from 'node:fs';
const ev = readFileSync(process.argv[2], 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const by = (k) => ev.filter((e) => e.ev === k);
const mm = (xs) => [Math.min(...xs), Math.max(...xs)];
const seq = by('seq');
const tmaRows = []; const walk = (o) => { if (o && typeof o === 'object') { if ('allowed' in o && 'label' in o) tmaRows.push(o); for (const v of Object.values(o)) walk(v); } }; walk(ev);
const valid = [...seq.flatMap((e) => [e.lib0, e.lib1])];
const ch = by('chain10')[0], race = by('race')[0], conf = by('conflict')[0], rep = by('replay')[0];
const out = {
  setup: by('setup')[0], geneses: by('w-genesis').map((g) => ({pool: g.pool, txid: g.txid, category: g.category, noMintingNft: g.noMintingNft, value: g.value})),
  seq: {accepted: seq.filter((e) => e.ok).length, of: 24, tx0Bytes: mm(seq.map((e) => e.bchn0.bytes)), tx1Bytes: mm(seq.map((e) => e.bchn1.bytes)),
    totalBytes: mm(seq.map((e) => e.bchn0.bytes + e.bchn1.bytes)), rate0: mm(seq.map((e) => +e.rate0.toFixed(3))), rate1: mm(seq.map((e) => +e.rate1.toFixed(3))),
    maxInputPct: Math.max(...valid.map((l) => l.maxPct)), W: {pct: mm(seq.map((e) => e.lib1.W.pct)), unlocking: mm(seq.map((e) => e.lib1.W.unlocking)), op: mm(seq.map((e) => e.lib1.W.opBchnAdj))},
    tmaAllowed: seq.filter((e) => e.bchn0.allowed && e.bchn1.allowed).length, sameBlock: seq.filter((e) => e.block.inBlock).length},
  replay: {tx0Accepted: rep.tx0.lib.ok && rep.tx0.bchn.allowed && rep.tx0.mined,
    variants: rep.variants.map((v) => ({name: v.name, rejected: v.rejected, libauth: `${v.lib1.firstRejectRole}: ${v.lib1.firstRejectErr}`, tma: v.bchn1.rejectReason, block: v.block.result})), Wunchanged: rep.Wunchanged.ok},
  chain10: {ok: ch.ok, tmaAllowed: ch.steps.filter((s) => s.r0.allowed && s.r1.allowed).length, block: ch.block, bytes: ch.bytes, W: mm(ch.libs.map((l) => l.W.pct)), maxPct: Math.max(...ch.libs.map((l) => l.maxPct))},
  race: {ok: race.ok, loser: race.bchn.Y1loser.rejectReason, rebuilt: race.rebuilt, rebuiltAllowed: race.bchn.Y1rebuilt.allowed, block: race.block},
  conflict: {ok: conf.ok, second: conf.bchn.B1conflict.rejectReason, rebuiltLibauth: `${conf.libBrebuilt.firstRejectRole}: ${conf.libBrebuilt.firstRejectErr}`, rebuiltTma: conf.bchn.B1rebuilt.rejectReason, rebuiltBlock: conf.blockVerdictRebuilt.result},
  testmempoolaccept: {rows: tmaRows.length, allowed: tmaRows.filter((t) => t.allowed).length, rejected: tmaRows.filter((t) => !t.allowed).map((t) => `${t.label}: ${t.rejectReason}`)},
  end: by('end')[0], errors: by('error'),
};
console.log(JSON.stringify(out, null, 1));
