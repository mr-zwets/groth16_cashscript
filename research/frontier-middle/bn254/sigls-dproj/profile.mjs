// Op-cost profile of one spend by section of the redeem (and by function), from a libauth debug trace.
//   [FIX=0] [MODE=standard] node profile.mjs
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildRedeem} from './script.mjs';
import {FIXTURES} from './math.mjs';
import {redeem, locking, unlocking} from './transaction.mjs';
import {programOf, VMS} from './vm.mjs';
const {info} = buildRedeem(); if (!Buffer.from(buildRedeem().redeem).equals(redeem)) throw new Error('redeem.hex is stale: run build.mjs');
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const NEXT = {'end:init': 'transcript', 'end:transcript': 'parse+checks', 'end:parse+checks': 'powers', 'end:powers': 'gls-tables', 'end:gls-tables': 'loop-setup', 'end:loop-setup': 'loop', 'end:loop': 'terminal', 'end:terminal': 'quotient', 'end:final': 'cleanup'};
const marks = info.marks.slice().sort((a, b) => a.off - b.off).map((m) => ({...m, name: NEXT[m.name] ?? 'loop:' + m.name}));
const {unlocking: u} = unlocking(FIXTURES.fixtures[Number(process.env.FIX ?? 0)]);
const tr = VMS[process.env.MODE ?? 'standard'].debug(programOf(locking, u));
const by = new Map(); let prev = 0, cur = 'p2sh';
for (const s of tr) {
  const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c; let key;
  if (s.instructions?.length === ins.length) { let n = 'prologue'; for (const m of marks) if (m.off <= offs[Math.max(0, s.ip - 1)]) n = m.name; cur = n; key = n; } else key = `${cur} > fn(${s.instructions?.length ?? 0} instr)`;
  by.set(key, (by.get(key) ?? 0) + d);
}
console.log('total', prev); for (const [k, v] of [...by].sort((a, b) => b[1] - a[1])) if (v > 20000) console.log(k.padEnd(36), (v / 1e6).toFixed(3) + 'M');
