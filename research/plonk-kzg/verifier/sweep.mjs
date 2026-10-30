// Single-input J sweep: per J, unlocking and the worst BCHN-adjusted margin over the valid proofs.
//   node sweep.mjs <circuit> <spec|txv5> J1 J2 ...
import {loadVectors, parseVK} from './plonk.mjs';
import {buildRedeem} from './script.mjs';
import {witnessFor} from './witness.mjs';
import {runSingle} from './single.mjs';
const [c, regime, ...Js] = process.argv.slice(2);
const d = loadVectors(c); const vk = parseVK(d.vk.hex);
for (const J of Js.map(Number)) {
  const {redeem, info} = buildRedeem(vk, {J, pad: regime === 'txv5'}); const def = Object.values(info.funcs).reduce((a, b) => a + b, 0);
  const rows = d.valid.map((pr) => { const wt = witnessFor(vk, pr.proof, pr.publicInputs, {J}); const {res, unlocking} = runSingle(vk, wt, {regime, J, JR: 0, redeem});
    const s = res.standard; return {ok: res.consensus.accepted && s.accepted, u: unlocking.length, m: 1 - (s.opCost + def) / s.budget}; });
  console.log(JSON.stringify({c, regime, J, ok: rows.every((x) => x.ok), umin: Math.min(...rows.map((x) => x.u)), umax: Math.max(...rows.map((x) => x.u)), worstMarginPct: +(100 * Math.min(...rows.map((x) => x.m))).toFixed(2), redeem: redeem.length, defBytes: def}));
}
