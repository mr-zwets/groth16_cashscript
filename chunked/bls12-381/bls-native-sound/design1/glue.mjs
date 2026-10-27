// Calibration for native-bls-design1 (read-only): per-input op by (function/section, opcode), and every step >= 1k op.
//   WIT=all15 node design1/glue.mjs out.json
import {writeFileSync} from 'node:fs';
import {encodeAuthenticationInstructions, decodeAuthenticationInstructions, encodeAuthenticationInstruction, disassembleAuthenticationInstruction, OpcodesBch} from '@bitauth/libauth';
import {buildAll} from '../script.mjs';
import {txPushes} from '../protocol.mjs';
import {witnessFor} from '../measure.mjs';
import {p2sh32, txOf, unlockingsFor, VM_UNLIMITED} from '../vm.mjs';
const b = buildAll();
const names = new Map(); for (const [n, f] of b.info.ctx.funcs) if (f.code) names.set(Buffer.from(f.code).toString('hex'), n);
b.info.roleCode.forEach((c, i) => names.set(Buffer.from(c).toString('hex'), 'ROLE' + i)); names.set(Buffer.from(b.blob).toString('hex'), 'BLOB'); names.set(Buffer.from(b.R).toString('hex'), 'R');
const out = {};
for (const spec of (process.env.WIT ?? 'all15').split(',')) {
  const w = await witnessFor(spec);
  const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
  out[spec] = [];
  for (let i = 0; i < 4; i++) {
    const tr = VM_UNLIMITED.standard.debug({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const cache = new WeakMap(); const nameOf = (ins) => { if (!ins) return '?'; if (!cache.has(ins)) cache.set(ins, names.get(Buffer.from(encodeAuthenticationInstructions(ins)).toString('hex')) ?? `anon(${ins.length})`); return cache.get(ins); };
    const rc = b.info.roleCode[i]; const offs = []; { let o = 0; for (const x of decodeAuthenticationInstructions(rc)) { offs.push(o); o += encodeAuthenticationInstruction(x).length; } }
    const mk = b.info.marks.filter((m) => m.role === i).sort((x, y) => x.off - y.off);
    const sectOf = (ip) => { const off = offs[Math.max(0, ip - 1)] ?? 0; let n = 'start'; for (const m of mk) if (m.off <= off) n = m.name.replace(/^r\d:end:/, 'after-'); return n; };
    const agg = {}; const big = []; let prev = 0;
    for (const s of tr) { const c = s.metrics?.operationCost ?? 0; let k = nameOf(s.instructions); if (k === 'ROLE' + i) k = 'ROLE' + i + ':' + sectOf(s.ip);
      const ins = s.instructions?.[s.ip - 1]; let op = ins ? disassembleAuthenticationInstruction(OpcodesBch, ins).split(' ')[0].replace(/^OP_/, '') : '?';
      if (/^PUSHBYTES|^PUSHDATA|^[0-9]+$|^1NEGATE/.test(op)) op = 'push';
      const d = c - prev; const key = k + '|' + op; agg[key] = agg[key] ?? [0, 0]; agg[key][0] += d; agg[key][1]++;
      if (d >= 1000 && !/MUL|MOD|ADD|SUB/.test(op)) big.push([k, op, d]); prev = c; }
    out[spec].push({i, op: prev, agg, big});
    console.log(spec, 'in' + i, prev);
  }
}
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out));
