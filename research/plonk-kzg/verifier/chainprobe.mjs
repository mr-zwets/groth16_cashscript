// Track 7 (BSB22): probe of today's-rules chain for a circuit with commitments. The chain (multi.mjs) handles m >= 1,
// but no layout fits today's standard limits, so it is run on the relaxed 'free' VM in consensus mode (no item,
// bytecode or density limit; op-cost is still counted) to check the logic, and the bytes are reported.
//   node chainprobe.mjs [circuit=merkle16rc]   -> results/chain-<circuit>-probe.json
import {writeFileSync} from 'node:fs';
import {loadVectors, parseVK} from './plonk.mjs';
import {makePlan, buildMulti, multiWitness} from './multi.mjs';
import {spendTx} from './vm.mjs';
import {chainTx, sizeFills, txBytes} from './chain.mjs';

const c = process.argv[2] ?? 'merkle16rc';
const d = loadVectors(c); const vk = parseVK(d.vk.hex);
const PLANS = {'10 inputs (Track 6 default)': {}, '11 inputs (5 MA roles)': {mj: [[50, 47], [46, 46], [45, 42]], ma: [[41, 34], [33, 26], [25, 18], [17, 9], [8, 0]]}};
const out = {circuit: c, m: vk.m, vm: 'free (libauth BCH 2026 rules, no limits on items, bytecode or density), consensus mode', plans: {}};
for (const [label, P] of Object.entries(PLANS)) {
  const plan = makePlan(vk, P); const built = buildMulti(vk, plan);
  const rec = {roles: plan.roles.map((r) => r.kind).join(','), TV: plan.TV_SIZE, TF: plan.TF_SIZE, G0: plan.G0_SIZE, C0: built.code.length, C1: built.c1.length, cases: []};
  const cases = d.valid.map((v, i) => ({name: 'valid ' + i, proof: v.proof, pub: v.publicInputs, expect: true}));
  if (label.startsWith('10')) cases.push(...d.tampered.filter((t) => /bsb22\.|Bsb22_0\.(plusG|negated)|qcp0_zeta\.plus1/.test(t.name)).map((t) => ({name: t.name, proof: t.proof, pub: t.publicInputs, expect: false})));
  for (const cs of cases) {
    const w = multiWitness(vk, plan, built, cs.proof, cs.pub); // adaptive: the tampered statement is re-witnessed
    const fills = sizeFills(vk, plan, built, w.pushes, {strict: false}); const tx = chainTx(vk, plan, built, w.pushes, fills);
    const res = spendTx('free', 'consensus', tx); const ok = res.every((x) => x.accepted);
    const r = {name: cs.name, accepted: ok, asExpected: ok === cs.expect, txBytes: txBytes(tx), opCost: res.reduce((a, x) => a + x.opCost, 0), unlocking: tx.map((x) => x.unlocking.length)};
    rec.cases.push(r); console.log(label, '|', r.name.padEnd(38), ok ? 'ACCEPT' : 'reject', r.asExpected ? '' : 'UNEXPECTED', 'tx', r.txBytes, 'op', r.opCost, 'max unlocking', Math.max(...r.unlocking));
  }
  out.plans[label] = rec;
}
writeFileSync(new URL(`./results/chain-${c}-probe.json`, import.meta.url), JSON.stringify(out, null, 1) + '\n');
