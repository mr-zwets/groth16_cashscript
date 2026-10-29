// Op-cost profile of the single-input program by phase: the program is cut at its STOP labels and each prefix is
// run (bare, after the honest pushes) on an unbudgeted TXv5 VM; the phase cost is the difference of consecutive prefixes.
//   node profile.mjs <circuit> [J] [JR] [mode=standard]
import {loadVectors, parseVK} from './plonk.mjs';
import {buildRedeem} from './script.mjs';
import {witnessFor, pushesOf} from './witness.mjs';
import {bare} from './vm.mjs';

export const PHASES = [['decode', 'statement decode + curve checks'], ['transcript', 'gnark transcript (gamma..zeta)'], ['fr1', 'Fr block 1 (PI, lin, inverse check)'],
  ['fr2', 'v, u, t\' and the MSM scalars'], ['recode', 'signed-digit recoding'], ['tables', 'MSM tables (affine, witnessed slopes)'], ['msmR0', 'P_right MSM'], ['msm', 'P* MSM (+ Wz add)'],
  ['preloop', 'SI transcript, z powers, setup'], ['postloop', 'Miller events (65, two fixed chains) + boundaries'], [null, 'terminal, quotient, final identity']];
export function profile(vk, wt, {J = 0, JR = 0, mode = 'standard'} = {}) {
  const pushes = pushesOf(wt); const base = bare('free', [0x61], pushes, mode).opCost - 100; let prev = 0; const out = [];
  for (const [label, what] of PHASES) {
    let code; if (label) { try { buildRedeem(vk, {J, JR, stop: label}); } catch (e) { if (!e.stopAt) throw e; code = Uint8Array.from([...e.asm.prologue(), ...e.asm.code]); } } else code = buildRedeem(vk, {J, JR}).redeem;
    const r = bare('free', code, pushes, mode); if (r.error && !/unexpected number of items/.test(r.error)) throw new Error(label + ': ' + r.error);
    const op = r.opCost - base; out.push({phase: label ?? 'final', what, op: op - prev}); prev = op;
  }
  return {total: prev, phases: out};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [c, J = 0, JR = 0, mode = 'standard'] = process.argv.slice(2);
  const d = loadVectors(c); const vk = parseVK(d.vk.hex);
  const wt = witnessFor(vk, d.valid[0].proof, d.valid[0].publicInputs, {J: Number(J), JR: Number(JR)});
  const pr = profile(vk, wt, {J: Number(J), JR: Number(JR), mode});
  console.log('total (script, excl. pushes)', pr.total);
  for (const x of pr.phases) console.log(' ', x.phase.padEnd(9), (x.op / 1e6).toFixed(3).padStart(7) + 'M', x.what);
}
