// Single-input regimes: build the redeem for a circuit, spend the honest witnesses (P2SH32) on the libauth VMs.
//   node single.mjs <circuit> <regime: spec|txv5> [J] [JR]
import {loadVectors, parseVK} from './plonk.mjs';
import {buildRedeem} from './script.mjs';
import {witnessFor, pushesOf} from './witness.mjs';
import {p2sh32, encodeUnlocking, spend} from './vm.mjs';

// minimal pad (TXv5 / 100 KB regime) so that (41 + unlocking) * 800 covers the measured op-cost
export function padFor(opCost, unlockingLen, regime) {
  if (regime !== 'txv5') return undefined;
  const need = Math.ceil(opCost / 800) - 41 - unlockingLen + 64; // + slack for the pad's own push/DROP cost
  return need > 0 ? Buffer.alloc(need) : Buffer.alloc(1);
}
export function runSingle(vk, wt, {regime, J, JR, redeem}) {
  const locking = p2sh32(redeem);
  const mk = (pad) => encodeUnlocking([...pushesOf(wt, {pad}), redeem]);
  let pad = regime === 'txv5' ? Buffer.alloc(1) : undefined;
  if (regime === 'txv5') { // size the pad from an unbudgeted measurement (consensus op-cost = standard op-cost except hashing)
    const probe = spend('spec', 'standard', locking, mk(pad)); pad = padFor(probe.opCost, mk(pad).length, regime); }
  const unlocking = mk(pad);
  const res = Object.fromEntries(['consensus', 'standard'].map((m) => [m, spend(regime, m, locking, unlocking)]));
  return {res, unlocking, locking, pad: pad?.length ?? 0};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [c, regime = 'spec', J = 0, JR = 0] = process.argv.slice(2);
  const d = loadVectors(c); const vk = parseVK(d.vk.hex);
  const opts = {J: Number(J), JR: Number(JR), pad: regime === 'txv5'};
  const {redeem, info} = buildRedeem(vk, opts);
  const wt = witnessFor(vk, d.valid[0].proof, d.valid[0].publicInputs, opts);
  const {res, unlocking, pad} = runSingle(vk, wt, {regime, ...opts, redeem});
  console.log(c, regime, 'J', J, 'JR', JR, 'redeem', redeem.length, 'unlocking', unlocking.length, 'pad', pad, 'slopes', wt.w.slopes.length, 'nq', wt.S.nq);
  for (const [m, r] of Object.entries(res)) console.log(' ', m, r.accepted, r.error ?? '', 'op', r.opCost, 'budget', r.budget);
}
