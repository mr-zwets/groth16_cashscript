// Op-cost profile of one spend by section of the redeem (and by function), from a libauth debug trace.
//   [FIX=committed] [MODE=standard] node profile.mjs     (UNLIMITED=1: run on the diagnostics VM, see vm.mjs)
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildRedeem} from './script.mjs';
import {FIXTURES} from './math.mjs';
import {prove} from './protocol.mjs';
import {programOf, VMS, VM_UNLIMITED, p2sh32, unlockingFor, budgetOf} from './vm.mjs';
const {redeem: rd, info} = buildRedeem(); const redeem = Buffer.from(rd), locking = Buffer.from(p2sh32(redeem));
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const NEXT = {'end:init': 'transcript', 'end:transcript': 'parse+checks', 'end:parse+checks': 'powers', 'end:powers': 'gls-tables', 'end:gls-tables': 'loop-setup', 'end:loop-setup': 'loop', 'end:loop': 'terminal', 'end:terminal': 'quotient', 'end:final': 'cleanup'};
const marks = info.marks.slice().sort((a, b) => a.off - b.off).map((m) => ({...m, name: NEXT[m.name] ?? 'loop:' + m.name}));
const w = prove(FIXTURES[process.env.FIX ?? 'committed']); const u = unlockingFor(w.WS, w.WQ, redeem);
const vm = process.env.UNLIMITED ? VM_UNLIMITED : VMS[process.env.MODE ?? 'standard'];
const tr = vm.debug(programOf(locking, u));
const by = new Map(); let prev = 0, cur = 'p2sh';
for (const s of tr) {
  const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c; let key;
  if (s.instructions?.length === ins.length) { let n = 'prologue'; for (const m of marks) if (m.off <= offs[Math.max(0, s.ip - 1)]) n = m.name; cur = n; key = n; } else key = `${cur} > fn(${s.instructions?.length ?? 0} instr)`;
  by.set(key, (by.get(key) ?? 0) + d);
}
const last = tr.at(-1);
console.log('total', prev, 'budget', budgetOf(u), (100 * prev / budgetOf(u)).toFixed(2) + '%', 'error', last.error ?? 'none', 'stack', last.stack?.length);
for (const [k, v] of [...by].sort((a, b) => b[1] - a[1])) if (v > 20000) console.log(k.padEnd(36), (v / 1e6).toFixed(3) + 'M');
