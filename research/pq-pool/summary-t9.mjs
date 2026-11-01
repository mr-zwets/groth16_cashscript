// Track 9 (S0-S3) results summary: reads the committed stage result files, writes summary-t9.json.
//   node summary-t9.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const J = (p) => JSON.parse(readFileSync(join(HERE, p), 'utf8'));

const p2 = J('p2/results/s0-p2.json');
const fl = J('p2/results/s0-flush.json');
const w = J('w/results/s1-w.json');
const g = J('r/results/grade-a.json');
const sw = J('r/results/test-a-2tx-pool.json');
const hs = J('r/results/test-a-harness.json');
const s3 = J('node/results/s3-summary.json');

const sum = (fams, k) => Object.values(fams).reduce((a, f) => a + (f[k] || 0), 0);
const worst = w.costs.reduce((a, c) => (c.pct > a.pct ? c : a));

const out = {
  track: 9,
  date: '2026-11-01',
  title: 'Post-quantum shielded pool on the Track 8 STARK verifier (S0-S3: static genesis tree, nullifier SMT, 2-tx withdrawal)',
  scope: 'S0-S3 only (maintainer decision 6). No deposits/flush (S4), relayer (S5), M1-N (S6) or SOUNDNESS-T9 (S7).',
  vm: 'libauth 3.1.0-next.8 BCH 2026 (op-cost BCHN-adjusted: libauth + OP_DEFINE body bytes); BCHN 29.1.0 regtest',
  s0_poseidon2: {
    agree_with_p3_goldilocks: `${p2.agree_script_vs_p3}/${p2.inputs}`,
    rejections: p2.rejections,
    perm8_opcost: p2.opcost['perm8.op'],
    compress4_opcost: p2.opcost['compress4.op'],
    instructions_perm8: p2.opcost['perm8.instr'].max,
    code_bytes: p2.code_bytes,
    gate_1_2M_triggered: p2.opcost['perm8.op'].max > 1.2e6,
    flush_worker_input_10k: {
      compressions_max: fl.today.nMax,
      bchn_adjusted: fl.today.atMax.bchnAdjusted,
      budget: fl.today.atMax.budget,
      pct: fl.today.atMax.pctBchn,
    },
    flush_worker_input_100k_compressions_max: fl.raised100k.nMax,
    per_compression_in_loop: fl.perCompressionInLoop,
    flush_table: fl.table.map((r) => ({
      flush: r.flush, k: r.k, compressions: r.perms, bchn_adjusted: r.opCostWithFixed,
      inputs_10k: r.inputs10k, inputs_100k: r.inputs100k,
    })),
    not_counted: 'non-Poseidon2 parts of a flush (S4): queue SHA-256, frontier check, ring update, lane < p checks, covenant checks',
  },
  s1_smt_w: {
    w_redeem_bytes: w.redeemBytes,
    library_agreement: { cases: w.library.cases, disagreements: w.library.disagreements.length, opcost: w.library.opCost },
    w_agreement: { cases: w.w.cases, withdrawals: w.w.withdrawals, present_rejected: w.w.presentAttempts, disagreements: w.w.disagreements.length },
    w_opcost_10k_run: w.w.opCost,
    w_worst_pct_10k_run: w.w.worstPct,
    w_constructed_worst: { name: worst.name, opCost: worst.opCost, budget: worst.budget, pct: worst.pct },
    rejections: w.rejections.summary,
    sequence_double_spend: w.sequenceDoubleSpend,
    pass: w.pass,
  },
  s2_r_grading: {
    R_bytes: 118,
    W_redeem_bytes: 499,
    plans: g.summary,
    vs_track8_2tx_bytes: { track8: 131556, track9: g.summary['2tx+W'].totalBytes[1], delta: g.summary['2tx+W'].totalBytes[1] - 131556 },
    define_bytes_per_R_input: 37790,
    note_1tx: '1-tx + W measured only (maintainer decision 3); fits at the empty nullifier set, exceeds 100,000 B after roughly a few thousand spends',
  },
  s2_sweeps: {
    production_2tx_pool: {
      cases: sum(sw.families, 'cases'), unexpected: sw.unexpected,
      chain_reject: sum(sw.families, 'chainReject'), accept: sum(sw.families, 'accept'),
      encoder_only: sw.encoderOnly, na: sw.na, noop_skipped: sw.noop,
      documented_R_does_not_pin_W: Array.isArray(sw.documented) ? sw.documented.length : sw.documented,
      families: sw.families,
    },
    harness_1tx: { cases: sum(hs.families, 'cases'), unexpected: hs.unexpected, encoder_only: hs.encoderOnly, not_run_on_chain: hs.notRunOnChain },
  },
  s3_bchn: {
    node: s3.setup.subversion,
    acceptnonstdtxn: s3.setup.acceptnonstdtxn,
    geneses: s3.geneses.map((x) => ({ pool: x.pool, noMintingNft: x.noMintingNft, value: x.value })),
    sequence: s3.seq,
    nf_replay: s3.replay,
    chain10: s3.chain10,
    race: s3.race,
    same_nf_conflict: s3.conflict,
    testmempoolaccept: { rows: s3.testmempoolaccept.rows, allowed: s3.testmempoolaccept.allowed, expected_refusals: s3.testmempoolaccept.rejected },
    scope_note: 'testmempoolaccept covers withdrawal transactions (tx0, tx1); W geneses and funding spend bare-OP_1 coinbases via submitblock',
    errors: s3.errors,
  },
  review: { verdict: 'pass', blocker: 0, major: 0, minor: 6, fixed_in: '86415d2' },
  open: [
    'R does not pin W (griefing only; pinning CAT||01 at wIdx makes R pool-specific)',
    'ring roots must be unique to one pool (no pool category in the leaf/NF domain)',
    'no-minting-NFT genesis property is an off-chain check',
  ],
  caveats: [
    'static genesis tree: no deposits or flush',
    'simulation extractability assumed',
    'Track 5 powers-batching adaptation unreviewed',
    '128-bit classical; about 85-bit generic quantum collision level',
    'fixed denomination D = 1,000,000 sat (regtest)',
    'anonymity set: the 32 genesis notes of one pool',
  ],
};

writeFileSync(join(HERE, 'summary-t9.json'), JSON.stringify(out, null, 1) + '\n');
console.log('wrote summary-t9.json');
