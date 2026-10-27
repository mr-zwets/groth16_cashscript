// Op-cost profile of each input by function body (libauth debug trace on the diagnostics VM).
//   [FIX=committed] [MODE=standard] [IN=0,1,2,3] node profile.mjs
import {encodeAuthenticationInstructions, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildAll} from './script.mjs';
import {FIXTURES, mint} from './math.mjs';
import {prove, txPushes} from './protocol.mjs';
import {p2sh32, txOf, unlockingsFor, VM_UNLIMITED, budgetOf} from './vm.mjs';
const b = buildAll();
const names = new Map(); for (const [n, f] of b.info.ctx.funcs) if (f.code) names.set(Buffer.from(f.code).toString('hex'), n);
b.info.roleCode.forEach((c, i) => names.set(Buffer.from(c).toString('hex'), 'ROLE' + i)); names.set(Buffer.from(b.blob).toString('hex'), 'BLOB'); names.set(Buffer.from(b.R).toString('hex'), 'R');
let fx = FIXTURES[process.env.FIX ?? 'committed']; if (process.env.DENSE) { const {statementFor} = await import('./worst.mjs'); fx = mint(statementFor(Array(64).fill(2)).ns); }
const w = prove(fx);
const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
const vm = VM_UNLIMITED[process.env.MODE ?? 'standard'];
for (const i of (process.env.IN ?? '0,1,2,3').split(',').map(Number)) {
  const tr = vm.debug({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
  const cache = new WeakMap(); const nameOf = (ins) => { if (!ins) return '?'; if (!cache.has(ins)) cache.set(ins, names.get(Buffer.from(encodeAuthenticationInstructions(ins)).toString('hex')) ?? `anon(${ins.length})`); return cache.get(ins); };
  // role body sections by marks (byte offsets -> instruction indices)
  const rc = b.info.roleCode[i]; const offs = []; { let o = 0; for (const x of decodeAuthenticationInstructions(rc)) { offs.push(o); o += encodeAuthenticationInstruction(x).length; } }
  const mk = b.info.marks.filter((m) => m.role === i).sort((x, y) => x.off - y.off);
  const sectOf = (ip) => { const off = offs[Math.max(0, ip - 1)] ?? 0; let n = 'start'; for (const m of mk) if (m.off <= off) n = m.name.replace(/^r\d:end:/, 'after-'); return n; };
  const by = new Map(); let prev = 0;
  for (const s of tr) { const c = s.metrics?.operationCost ?? 0; let k = nameOf(s.instructions); if (k === 'ROLE' + i) k = 'ROLE' + i + ':' + sectOf(s.ip); by.set(k, (by.get(k) ?? 0) + c - prev); prev = c; }
  const last = tr.at(-1);
  console.log(`input ${i}: total ${prev} budget ${budgetOf(un[i])} (${(100 * prev / budgetOf(un[i])).toFixed(1)}%) U ${un[i].length} error ${last.error ?? 'none'}`);
  for (const [k, v] of [...by].sort((a, b2) => b2[1] - a[1])) if (v > 5000) console.log('   ', k.padEnd(12), (v / 1e6).toFixed(3) + 'M');
}
