// Diagnostics (read-only measurement, task native-bls-breakdown): per-input op by function body and call counts,
// for given witnesses. WIT=committed,all15,forced:44d3 node breakdown/opcat.mjs out.json
import {writeFileSync} from 'node:fs';
import {encodeAuthenticationInstructions, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildAll} from '../script.mjs';
import {txPushes, pushesOf, hdrLen} from '../protocol.mjs';
import {witnessFor} from '../measure.mjs';
import {p2sh32, txOf, unlockingsFor, VM_UNLIMITED, budgetOf} from '../vm.mjs';
const b = buildAll();
const names = new Map(); for (const [n, f] of b.info.ctx.funcs) if (f.code) names.set(Buffer.from(f.code).toString('hex'), n);
b.info.roleCode.forEach((c, i) => names.set(Buffer.from(c).toString('hex'), 'ROLE' + i)); names.set(Buffer.from(b.blob).toString('hex'), 'BLOB'); names.set(Buffer.from(b.R).toString('hex'), 'R');
const out = {};
for (const spec of (process.env.WIT ?? 'committed').split(',')) {
  const w = await witnessFor(spec);
  const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
  out[spec] = {nq: w.nq, inputs: []};
  for (const mode of ['standard', 'consensus']) for (let i = 0; i < 4; i++) {
    const tr = VM_UNLIMITED[mode].debug({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const cache = new WeakMap(); const nameOf = (ins) => { if (!ins) return '?'; if (!cache.has(ins)) cache.set(ins, names.get(Buffer.from(encodeAuthenticationInstructions(ins)).toString('hex')) ?? `anon(${ins.length})`); return cache.get(ins); };
    const rc = b.info.roleCode[i]; const offs = []; { let o = 0; for (const x of decodeAuthenticationInstructions(rc)) { offs.push(o); o += encodeAuthenticationInstruction(x).length; } }
    const mk = b.info.marks.filter((m) => m.role === i).sort((x, y) => x.off - y.off);
    const sectOf = (ip) => { const off = offs[Math.max(0, ip - 1)] ?? 0; let n = 'start'; for (const m of mk) if (m.off <= off) n = m.name.replace(/^r\d:end:/, 'after-'); return n; };
    const by = {}, calls = {}; let prev = 0, prevIns = null;
    for (const s of tr) { const c = s.metrics?.operationCost ?? 0; let k = nameOf(s.instructions); if (k === 'ROLE' + i) k = 'ROLE' + i + ':' + sectOf(s.ip);
      if (s.ip === 0 && s.instructions !== prevIns) calls[k] = (calls[k] ?? 0) + 1; prevIns = s.instructions;
      by[k] = (by[k] ?? 0) + c - prev; prev = c; }
    const rec = {i, mode, op: prev, U: un[i].length, budget: budgetOf(un[i]), err: tr.at(-1).error ?? null, by, calls};
    if (mode === 'standard') out[spec].inputs.push(rec); else out[spec].inputs[i].consensusOp = prev;
  }
  for (const x of out[spec].inputs) console.log(spec, 'nq', w.nq, 'in' + x.i, 'U', x.U, 'op std', x.op, 'cons', x.consensusOp, 'budget', x.budget, 'margin', (100 * (1 - x.op / x.budget)).toFixed(2) + '%');
}
out.pushes = [0, 1, 2, 3].map((h) => pushesOf(h).map((p) => ({...p, hdr: p.size === null ? null : hdrLen(p.size)})));
out.funcSizes = Object.fromEntries([...b.info.ctx.funcs].filter(([, f]) => f.code).map(([n, f]) => [n, f.code.length]));
out.roleSizes = b.info.roleCode.map((c) => c.length); out.blob = b.blob.length; out.R = b.R.length; out.marks = b.info.marks;
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 1));
