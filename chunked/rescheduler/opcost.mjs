// Op-cost-objective rescheduler for compiled CHUNK redeem bytecode.
//
// Reuses the byte-objective singleton recompiler's machinery (dissect the OP_DEFINE
// table + main routine, lift each body to a dataflow DAG, re-derive the evaluation
// schedule) but selects by the BCH2026 op-cost meter instead of serialized bytes:
//   - subroutine bodies: candidates {cashc, topo, greedy, opcost} MEASURED on the
//     loosened VM with fixed pseudo-random inputs; the cheapest diff-test-equivalent
//     variant wins (recompileAllOpcost).
//   - main routine: candidates ranked by the static op-cost estimate (chunk mains are
//     straight-line and executed once, so the static rank tracks the meter up to the
//     nominal item-length approximation). Correctness is validated downstream: the
//     vector builder evaluates every chunk in its real group tx (accept valid /
//     reject tampered) and recomputes P2SH/link/padding from the final redeems.
//
// Opt-in via the builder hook in chunked/pairing/_millermath.mjs (env RESCHEDULE=opcost);
// default off, so every consumer stays A/B-able.
import { createHash } from 'node:crypto';
import { binToHex } from '@bitauth/libauth';
import { dissect, probeArity, recompileAllOpcost, recompileMain, rebuild } from '../../singleton/bn254/recompiler/recompiler.mjs';
import { opCostEstimate } from '../../singleton/bn254/recompiler/schedule.mjs';
import { parse, serialize } from '../../singleton/bn254/recompiler/asm.mjs';

// Chunks of one family share their DEFINE table verbatim (same imported library, same
// reachable set), so arity probing + body rescheduling is cached per table.
const tableCache = new Map();
const tableKey = (d) => {
  const h = createHash('sha256');
  for (const id of d.order) { h.update(String(id)); h.update(d.bodies.get(id)); }
  return h.digest('hex');
};

export function rescheduleRedeemOpcost(redeem, { mainInArity, label = '' } = {}) {
  const d = dissect(redeem);
  const key = tableKey(d);
  let entry = tableCache.get(key);
  if (!entry) {
    const arity = probeArity(d);
    const { override, rows } = recompileAllOpcost(d, arity);
    entry = { arity, override, rows };
    tableCache.set(key, entry);
  }
  const { arity, override } = entry;

  // main routine: static op-cost rank (+1/byte: redeem bytes are pushed in the scriptSig)
  const mainOrig = serialize(d.mainOps);
  const est = (bytes) => opCostEstimate(parse(bytes)) + bytes.length;
  let bestMain = null, bestCost = est(mainOrig), mainTag = 'cashc';
  for (const strat of ['topo', 'greedy', 'opcost']) {
    let m; try { m = recompileMain(d, arity, mainInArity, strat, 'opcost'); } catch { continue; }
    const c = est(m);
    if (c < bestCost) { bestMain = m; bestCost = c; mainTag = strat; }
  }
  const bytes = rebuild(d, override, bestMain ?? undefined);
  return { bytes, mainTag, mainEstimate: bestCost, origEstimate: est(mainOrig), bodyRows: entry.rows };
}

// Debug aid: hex of a redeem's main routine (for eyeballing schedules).
export const mainHex = (redeem) => binToHex(serialize(dissect(redeem).mainOps));
