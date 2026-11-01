// Track 9 S4 results summary: reads the committed S4 result files and the S1-S3 re-runs, writes summary-s4.json.
// (summary-t9.json stays the S0-S3 snapshot.)  usage: node summary-s4.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const J = (p) => JSON.parse(readFileSync(join(HERE, p), 'utf8'));
const d = J('d/results/s4-d.json');
const n4 = J('node/results/t9s4a-summary.json');
const g = J('r/results/s4rerun/grade-a.json');
const sw = J('r/results/s4rerun/test-a-2tx-pool.json');
const hs = J('r/results/s4rerun/test-a-harness.json');
const w = J('w/results/s4rerun/s1-w.json');
const s3 = J('node/results/t9s3b-summary.json');
const sum = (fams, k) => Object.values(fams).reduce((a, f) => a + (f[k] || 0), 0);

const out = {
  track: 9, stage: 'S4', date: '2026-11-01',
  title: 'Deposits (D state, SHA-256 queue), permissionless flush (Poseidon2-Gl-8 subtree and path in 4 worker inputs), 16-slot ring; R pins the pool W (A3)',
  vm: 'libauth 3.1.0-next.8 BCH 2026 (op-cost BCHN-adjusted: libauth + OP_DEFINE body bytes); BCHN 29.1.0 regtest, POLICY=1',
  sizes: d.sizes,
  libauth: { pass: d.fail.length === 0, cases: d.cases.length, unexpected: d.fail.length, families: d.families, seq: d.seq.map((x) => ({ flush: x.flush, rootEqualsOffline: x.rootEqualsOffline, histRootEqualsRing: x.histRootEqualsRing })),
    wrap: d.wrap, deposit: d.summary.deposit, flush: d.summary.flush },
  bchn_e2e: { genesis: n4.genesis, deposits: n4.deposits, flushes: { ...n4.flushes, per: undefined }, proofs: n4.proofs, withdrawals: n4.withdrawals, wrap: n4.wrap,
    testmempoolaccept: { tx_rows: n4.testmempoolaccept.rows, allowed: n4.testmempoolaccept.allowed, deposits_allowed: n4.deposits.allTmaAllowed ? n4.deposits.txs : 'not all', expected_refusals: n4.testmempoolaccept.rejected },
    errors: n4.errors },
  reruns: {
    s1_test_w: { pass: w.pass, w_redeem_bytes: w.redeemBytes, library_disagreements: w.library.disagreements.length, w_disagreements: w.w.disagreements.length, rejections: w.rejections.summary },
    s2_grade: g.summary,
    s2_production_sweep: { cases: sum(sw.families, 'cases'), unexpected: sw.unexpected, chain_reject: sum(sw.families, 'chainReject'), accept: sum(sw.families, 'accept'), encoder_only: sw.encoderOnly, wpin: sw.families.wpin },
    s2_harness: { cases: sum(hs.families, 'cases'), unexpected: hs.unexpected },
    s3_bchn: { seq: s3.seq, replay: s3.replay.variants.map((v) => v.rejected), chain10: s3.chain10.ok, race: s3.race.ok, conflict: s3.conflict.ok, geneses: s3.geneses, testmempoolaccept: { rows: s3.testmempoolaccept.rows, allowed: s3.testmempoolaccept.allowed, expected_refusals: s3.testmempoolaccept.rejected.length }, errors: s3.errors },
  },
  review_items: {
    A3: 'closed: the final HEAD pins input 5 to category CAT||01 and commitment prefix 0x57 (R is pool specific: +46 B in a code blob)',
    A1: 'resolved by G (initial ring all Z); no script change: per-pool ring roots built from the pool\'s own deposits bound withdrawals per pool; the pin alone does not stop a proof from being used in another pool whose ring holds the same root',
  },
};
writeFileSync(join(HERE, 'summary-s4.json'), JSON.stringify(out, null, 1) + '\n');
console.log('wrote summary-s4.json');
