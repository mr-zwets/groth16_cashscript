// Aggregate the measurements into results/summary.json (and print a table):
//   node summary.mjs        (reads results/test-*.json and results/chain-*.json; runs the phase profile, light)
// Score convention (bench): unlocking + 35 B P2SH32 locking per input + tx overhead (63 B for the first input,
// 43 B per further input: outpoint, sequence, 3-byte length). BCHN-adjusted op-cost adds the body bytes of every
// OP_DEFINE an input executes (libauth charges OP_DEFINE a flat 100; BCHN also charges the body bytes).
import {readFileSync, writeFileSync, existsSync} from 'node:fs';
import {loadVectors, parseVK, proofLen, fixedNames} from './plonk.mjs';
import {buildRedeem} from './script.mjs';
import {witnessFor} from './witness.mjs';
import {profile} from './profile.mjs';
import {makePlan, buildMulti, planOpts} from './multi.mjs';
import {chains} from './si.mjs';

// Track 7 integrated build (Ignition SRS, BSB22, GT fold): J from sweep.mjs. BSB22 circuits (10 folded bases) take
// J = 21 at bch-spec for a >= 3% BCHN-adjusted margin (J = 23 leaves 0.9-1.4%).
const JOF = (c) => ({spec: ['range64', 'merkle16rc'].includes(c) ? 21 : 23, txv5: 14});
// Track 6 (origin/main results/summary.json, test SRS, no fold, no BSB22): score and op-cost (libauth standard) ranges
const TRACK6 = {'mul2/bch-spec': {score: [66290, 66549], op: [58043950, 58338567], J: 13}, 'mul2/100 KB input (TXv5)': {score: [69757, 69919], op: [55401807, 55700719], J: 8},
  'mul2/today (multi-input)': {inputs: 10, score: [92845, 93095], op: [70645374, 71004868]}, 'merkle16/bch-spec': {score: [68494, 68655], op: [60415634, 60723845], J: 13},
  'merkle16/100 KB input (TXv5)': {score: [72188, 72438], op: [57602422, 57853036], J: 8}, 'merkle16/today (multi-input)': {inputs: 10, score: [95637, 95985], op: [73166730, 73485376]},
  'merkle16rc/bch-spec': {score: [72404, 72760], op: [64977911, 65205320], J: 13, note: 'wip/plonk-usable-bsb22 (test SRS, no fold)'},
  'merkle16rc/100 KB input (TXv5)': {score: [77402, 77720], op: [61824816, 62079333], J: 8, note: 'wip/plonk-usable-bsb22'},
  'merkle16rc/today (multi-input)': {inputs: 11, score: [103706, 104085], note: 'wip/plonk-usable-bsb22: does not fit 100,000 B (relaxed VM probe only)'}};
const R = (f) => JSON.parse(readFileSync(new URL('./results/' + f, import.meta.url)));
const score = (unl, n) => unl + 35 * n + 63 + 43 * (n - 1);
const out = {date: '2026-10-30', build: 'Track 7 integrated (wip/plonk-usable-verifier): Aztec Ignition SRS, BSB22 commitments, GT fold of the fixed bases, TV/TV2 split', track6: TRACK6, gnark: 'v0.16.4', gnarkCrypto: 'v0.21.1-0.20260913224755-1409fe592052', regimes: {}, profile: {}, bytes: {}, groth16: {
  'sound-native (today, 3 inputs)': 27624, 'sound-si-gls (bch-spec)': 21915, 'sound-si-gls TXv5 padded (100 KB input)': 29300}};
for (const c of ['mul2', 'merkle16', 'range64', 'merkle16rc']) {
  const d = loadVectors(c); const vk = parseVK(d.vk.hex); const J = JOF(c);
  out.srs ??= {ceremony: d.srs.ceremony, srsFileSha: d.srs.srsFileSha, tau2Raw: d.srs.tau2Raw};
  out.circuits = {...out.circuits, [c]: {...d.circuit, foldedBases: vk.fold ? fixedNames(vk).length : 0, foldedBaseNames: vk.fold ? fixedNames(vk) : []}};
  for (const reg of ['spec', 'txv5']) {
    const f = `test-${c}-${reg}.json`; if (!existsSync(new URL('./results/' + f, import.meta.url))) continue;
    const t = R(f); const {redeem, info} = buildRedeem(vk, {J: J[reg], pad: reg === 'txv5'});
    const defBytes = Object.values(info.funcs).reduce((a, b) => a + b, 0);
    const v = t.valid.map((x) => ({unlocking: x.standard.unlocking, opStd: x.standard.opCost, opCons: x.consensus.opCost, budget: x.standard.budget, pad: x.pad}));
    const worst = v.reduce((a, b) => (b.opStd / b.budget > a.opStd / a.budget ? b : a));
    out.regimes[`${c}/${reg === 'spec' ? 'bch-spec' : '100 KB input (TXv5)'}`] = {inputs: 1, transactions: 1, J: J[reg], proofBytes: proofLen(vk), publicInputBytes: 32 * vk.nbPublic, redeemBytes: redeem.length,
      unlocking: v.map((x) => x.unlocking), score: v.map((x) => score(x.unlocking, 1)), opCostStandard: v.map((x) => x.opStd), opCostConsensus: v.map((x) => x.opCons),
      opCostBchnAdjusted: v.map((x) => x.opStd + defBytes), defineBodyBytes: defBytes, budget: v.map((x) => x.budget), pad: v.map((x) => x.pad),
      worstMarginPct: +(100 * (1 - (worst.opStd + defBytes) / worst.budget)).toFixed(2),
      tests: {valid: `${t.valid.filter((x) => x.consensus.accepted && x.standard.accepted).length}/${t.valid.length}`, tampered: `${t.tampered.filter((x) => x.rejected).length}/${t.tampered.length}`, manipulations: `${t.manipulations.filter((x) => x.rejected).length}/${t.manipulations.length}`}};
    if (reg === 'spec') {
      const wt = witnessFor(vk, d.valid[0].proof, d.valid[0].publicInputs, {J: J.spec});
      out.profile[c] = profile(vk, wt, {J: J.spec}).phases.map((x) => ({phase: x.phase, what: x.what, opCost: x.op}));
      // bytes: universal ([1]_2 chain, code), SRS-specific ([x]_2 chain), circuit-specific (VK)
      const CH = chains(vk);
      out.bytes[c] = {redeem: redeem.length, chainSlopes1_2_universal: 88 * 64, chainSlopesX2_srsSpecific: 88 * 64, vkRawPoints_circuitSpecific: 512 + 5 + 64 * vk.m,
        frConstants_circuitSpecific: 'omega^i, n^-1, coset shift k, omega, log2(n) squarings (a few hundred bytes of pushes)',
        codeAndRest: redeem.length - 2 * 88 * 64 - 517 - 64 * vk.m, witness: {slopes: wt.w.slopes.length * 32, WS: wt.WS.length, WQ: wt.WQ.length, X: wt.X.length, proof: proofLen(vk), PI: wt.PI.length}};
    }
  }
  const cf = `chain-${c}.json`;
  if (existsSync(new URL('./results/' + cf, import.meta.url))) {
    const t = R(cf); const plan = makePlan(vk, planOpts(vk, c)); const built = buildMulti(vk, plan);
    // every input defines C1 and C0 (functions 0, 1) and then every function inside them
    const defBytes = built.defBytes;
    const v = t.valid;
    out.regimes[`${c}/today (multi-input)`] = {inputs: v[0].inputs, transactions: 1, roles: v[0].perInput.map((x) => x.role).join(','), proofBytes: proofLen(vk), publicInputBytes: 32 * vk.nbPublic,
      codeBlobs: t.codeBytes, redeemBytes: t.redeemBytes, unlocking: v.map((x) => x.unlocking), txBytes: v.map((x) => x.txBytes), score: v.map((x) => score(x.unlocking, x.inputs)),
      opCostStandard: v.map((x) => x.perInput.reduce((s, y) => s + y.opCost, 0)), opCostBchnAdjusted: v.map((x) => x.perInput.reduce((s, y) => s + y.opCost, 0) + x.inputs * defBytes),
      defineBodyBytesPerInput: defBytes, perInput0: v[0].perInput,
      worstInputMarginPct: +(100 * Math.min(...v.flatMap((x) => x.perInput.map((y) => 1 - (y.opCost + defBytes) / y.budget)))).toFixed(2),
      tests: {valid: `${v.filter((x) => x.accepted).length}/${v.length}`, tampered: `${t.tampered.filter((x) => x.rejected).length}/${t.tampered.length}`, manipulations: `${t.manipulations.filter((x) => x.rejected).length}/${t.manipulations.length}`}};
  }
}
writeFileSync(new URL('./results/summary.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
const fmt = (a) => (Array.isArray(a) ? `${Math.min(...a)}-${Math.max(...a)}` : a);
for (const [k, x] of Object.entries(out.regimes)) console.log(k.padEnd(34), 'inputs', x.inputs, 'score', fmt(x.score), 'op', fmt(x.opCostStandard), 'bchn', fmt(x.opCostBchnAdjusted), 'margin%', x.worstMarginPct ?? x.worstInputMarginPct, JSON.stringify(x.tests));
for (const [c, ph] of Object.entries(out.profile)) console.log(c, ph.map((x) => `${x.phase} ${(x.opCost / 1e6).toFixed(2)}M`).join(', '));
