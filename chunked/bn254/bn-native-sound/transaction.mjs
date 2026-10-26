// Unlocking construction for the 3-input transaction, with prover-sized zero fillers.
//   input 0: [DG] [STMT] [S_0] [DS_0] [C_0] [FILL_0] [R]
//   input 1: [S_1] [HAND_1] [DS_1] [C_1] [FILL_1] [R]
//   input 2: [S_2] [HAND_2] [DS_2] [FILL_2] [WQ] [R]
// The fillers only buy op budget: each is all zero, read by nothing except (FILL_2) the z-tail hash. The honest
// prover sizes each filler so that the input's STANDARD op cost is at most (1 - MARGIN) of its budget, capped at the
// 10,000-byte unlocking limit.
import {readFileSync, existsSync} from 'node:fs';
import {DS, proveCore, handovers, zOf, zTail} from './protocol.mjs';
import {encodeUnlocking, p2sh32, spendAll} from './vm.mjs';

export const MARGIN = Number(process.env.MARGIN ?? 0.06);
export const UNLOCK_CAP = 10000;
export function loadBuild() {
  const f = new URL('./build.json', import.meta.url); if (!existsSync(f)) return null;
  const b = JSON.parse(readFileSync(f, 'utf8'));
  return {R: Buffer.from(b.redeemHex, 'hex'), pieces: b.codePiecesHex.map((h) => Buffer.from(h, 'hex')), lay: b.layout};
}
export const lockingOf = (prog) => Buffer.from(p2sh32(prog.R));
export function unlockingsFor(core, prog, fills) {
  const z = zOf(core, zTail(fills[2], core.WQ)); const {H} = handovers(core, z);
  const F = fills.map((n) => Buffer.alloc(n));
  const pushes = [
    [core.D, core.STMT, core.S[0], DS[0], prog.pieces[0], F[0], prog.R],
    [core.S[1], H[1], DS[1], prog.pieces[1], F[1], prog.R],
    [core.S[2], H[2], DS[2], F[2], core.WQ, prog.R],
  ];
  return {pushes, unlockings: pushes.map((ps) => Buffer.from(encodeUnlocking(ps))), z, H};
}
// prover-sized fillers: iterate until every input meets the margin (standard mode) or hits the cap
export function sizeFills(core, prog, {margin = MARGIN, fills0 = [0, 0, 0], maxIter = 8} = {}) {
  const lock = lockingOf(prog); let fills = fills0.slice();
  for (let it = 0; it < maxIter; it++) {
    const {unlockings} = unlockingsFor(core, prog, fills);
    const runs = spendAll(unlockings.map(() => lock), unlockings, 'standard');
    const next = runs.map((x, i) => { const base = unlockings[i].length - fills[i] - (fills[i] >= 256 ? 3 : fills[i] >= 76 ? 2 : 1) + 1;
      const need = Math.ceil(x.opCost / ((1 - margin) * 800)) - 41; let f = Math.max(0, need - base); // filler bytes so that U >= need
      // the push header grows with the filler: re-add it
      f = Math.max(0, need - (base - 1) - (f >= 256 ? 3 : f >= 76 ? 2 : 1));
      return Math.min(f, Math.max(0, UNLOCK_CAP - base - 2)); });
    if (next.every((f, i) => f <= fills[i]) && runs.every((x) => x.opCost <= (1 - margin) * x.budget || x.length >= UNLOCK_CAP - 3)) return {fills, runs};
    fills = next.map((f, i) => Math.max(f, fills[i]));
  }
  throw new Error('filler sizing did not converge');
}
export function transactionFor(fx, prog, opts = {}) {
  const core = proveCore(fx, opts); const {fills} = opts.fills ? {fills: opts.fills} : sizeFills(core, prog, opts);
  const {unlockings, pushes, z, H} = unlockingsFor(core, prog, fills);
  return {core, fills, unlockings, pushes, z, H, locking: lockingOf(prog)};
}
