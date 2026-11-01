// Track 8 results summary: reads the post-fix results/ files and writes results/summary-t8.json.
// Usage (from onchain/): node summary-t8.mjs
// Pure JSON reading; no VM, no node_modules needed. The soundness block is copied from SOUNDNESS-T8 §1 and
// params8.py --asbuilt (design branch wip/stark-usable-design 6050eaf); it is not recomputed here.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const R = (f) => JSON.parse(readFileSync(join(here, 'results', f), 'utf8'));
const range = (s) => [s.min, s.max];

const gb = R('grade-b.json').summary;
const gb2 = R('grade-b2.json').summary;
const ga = R('grade-a.json').summary;

function sweep(file) {
  const d = R(file);
  return {
    file: `results/${file}`,
    files: d.files,
    cases: d.cases,
    unexpected: d.unexpected,
    notRunOnChain: d.notRunOnChain ?? 0,
    encoderOnly: d.encoderOnlyRelabel ?? 0,
    notApplicable: d.na ?? 0,
    skippedFiles: (d.skippedFiles || []).length,
  };
}

const lbl = 'JB, powers-batching adaptation, unpublished';
const out = {
  track: 8,
  date: '2026-11-01',
  build: 'groth16_cashscript wip/stark-usable: scripts at 12d47d4 (S8b residue fix), results at c47d104/726ea25',
  protocol: 'p3-batch-stark at Plonky3 0d80373, SHA-256 / Goldilocks / cubic trinomial, hiding two-adic FRI, wire format p3b-v1',
  vm: 'libauth 3.1.0-next.8 (BCH 2026); BCHN-adjusted op-cost = libauth op-cost + OP_DEFINE body bytes (Track 8a)',
  statements: {
    M1: 'depth-30 Merkle membership + nullifier + CTX; one table 2^10 x 17, 53 constraints, degree 4, 8 ZK chunks',
    M2: 'M1 split into T_hash (2^10) + T_ctl (2^7) joined by one LogUp bus (width 13), preprocessed columns',
  },
  parameters: {
    Z128: { logBlowup: 9, D: 3, fold: [3], finalPolyLen: 256, queries: 24, powQuery: 24, powCommit: 2, powBatch: 20, zk: true, cap: '0 (b, b2) or 5 (a\')' },
    'Z128-g (M2)': { logBlowup: 9, D: 3, fold: [3, 3], finalPolyLen: 32, queries: 24, powQuery: 24, powCommit: 3, powBatch: 20, powLookup: 8, zk: true, cap: 0 },
  },
  soundness: {
    label: lbl,
    source: 'SOUNDNESS-T8.md §1, params8.py --asbuilt (design 6050eaf)',
    M1: { lambdaIOP: 128.06, binding: 'fold1', lambda: 128, strictDigest: 127.21 },
    M2: { lambdaIOP: 128.70, binding: 'query', lambda: 128, strictDigest: 127.21 },
    quantumCollisionBits: 85,
    adaptationMargins: { M1batch: 8.33, M2batch: 7.15, M2rollInFold1: 0.87 },
  },
  layouts: {
    'b (M1, cap 0, one input)': {
      regimeNeeded: 'per-input unlocking, bytecode and stack-item limits raised to 100,000 B; tx size unchanged',
      statements: gb.vectors, inputs: 1, transactions: 1,
      proofBytes: range(gb.proofBytes), unlockingBytes: range(gb.unlockingBytes), txBytes: range(gb.txBytes),
      redeemBytes: gb.redeemBytes.max,
      opCostBchnAdjusted: range(gb.opBchnAdjusted), opCostBchnAdjustedMean: gb.opBchnAdjusted.mean,
      opCostConsensus: range(gb.opCons),
      budgetPctOneInput: range(gb.pctR100), budgetPctBchSpec: range(gb.pctSpec),
      accepted: { oneInput: `${gb.vectors}/${gb.vectors}`, bchSpec: `${gb.vectors}/${gb.vectors}`, today: `${gb.todayAccepted}/${gb.vectors}` },
      vsModel: { params8: gb.model.params8, deviationPct: +(100 * (gb.opBchnAdjusted.mean / gb.model.params8 - 1)).toFixed(1) },
    },
  },
  sweeps: {
    'S4 b production': sweep('test-b.json'),
    'S4 b harness': sweep('test-b-harness.json'),
    'S5/S6 b2 M2 + Plonky3': sweep('test-b2-m2p3.json'),
    'S5/S6 b2 M1 harness': sweep('test-b2-m1.json'),
    'S5/S6 b2 production': sweep('test-b2-prod.json'),
    "S7 a' 1 tx": sweep('test-a-1tx.json'),
    "S7 a' 2 tx": sweep('test-a-2tx.json'),
    "S7 a' harness": sweep('test-a-harness.json'),
  },
  agreement: {
    rustVsJs: { cases: 14027, disagreements: 0, transcriptsIdentical: '128/128' },
    modelVsReference: { S4: 3762, S5S6: 17911, disagreements: 0 },
  },
};

for (const [k, name, need] of [
  ['m1', 'b2 (M1, cap 0, two inputs)', 'per-input unlocking, bytecode and stack-item limits raised to 100,000 B; tx size 100,000 B unchanged'],
  ['m2', 'b2 (M2, cap 0, two inputs)', 'per-input limits raised to 100,000 B and tx size raised (passes at 200,000 B)'],
]) {
  const s = gb2[k];
  out.layouts[name] = {
    regimeNeeded: need,
    statements: s.statements, inputs: 2, transactions: 1, queriesInput0: s.QA,
    proofBytes: range(s.proofBytes), libBytes: s.libBytes.max,
    unlockingBytes: [range(s.unlocking0), range(s.unlocking1)], txBytes: range(s.txBytes),
    opCostBchnAdjusted: [range(s.op0), range(s.op1)],
    budgetPctOneInput: [range(s.pct0), range(s.pct1)], budgetPctBchSpec: [range(s.pctSpec0), range(s.pctSpec1)],
    accepted: {
      perInputRaised: s.bothInputsR100 ? `${s.statements}/${s.statements}` : 'no',
      bchSpec: s.bothInputsSpec ? `${s.statements}/${s.statements}` : 'no',
      wholeTxAt100000: `${s.txVerifyR100}/${s.statements}`,
      wholeTxAt200000: `${s.txVerifyR100t}/${s.statements}`,
      today: `${s.todayAccepted}/${s.statements}`,
    },
  };
}

for (const plan of ['1tx', '2tx']) {
  const s = ga[plan];
  out.layouts[`a' (M1, cap 5, today's rules, ${plan})`] = {
    regimeNeeded: "none: today's standard rules",
    statements: s.statements, inputs: s.inputs, transactions: s.txs,
    txBytes: s.txBytes, totalBytes: s.totalBytes,
    opCostBchnAdjustedTotal: s.opTotalBchnAdjusted, maxInputBudgetPct: s.maxPct,
    perRole: s.perRole,
    accepted: `${s.accepted}/${s.statements}`,
  };
}

writeFileSync(join(here, 'results', 'summary-t8.json'), JSON.stringify(out, null, 1) + '\n');
console.log('wrote results/summary-t8.json');
