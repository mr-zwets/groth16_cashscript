// Diagnostics: per-input op by opcode (instruction executed = instructions[ip-1] of each traced state).
//   WIT=all15 node breakdown/opcodes.mjs
import {disassembleAuthenticationInstruction, OpcodesBch} from '@bitauth/libauth';
import {buildAll} from '../script.mjs';
import {txPushes} from '../protocol.mjs';
import {witnessFor} from '../measure.mjs';
import {p2sh32, txOf, unlockingsFor, VM_UNLIMITED} from '../vm.mjs';
const b = buildAll();
for (const spec of (process.env.WIT ?? 'all15').split(',')) {
  const w = await witnessFor(spec); const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
  for (let i = 0; i < 4; i++) {
    const tr = VM_UNLIMITED.standard.debug({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const by = {}; let prev = 0, n = 0; const big = {};
    for (const s of tr) { const c = s.metrics?.operationCost ?? 0; const ins = s.instructions?.[s.ip - 1];
      let k = ins ? disassembleAuthenticationInstruction(OpcodesBch, ins).split(' ')[0].replace(/^OP_/, '') : '?';
      if (/^PUSHBYTES|^PUSHDATA|^[0-9]+$|^1NEGATE/.test(k)) k = 'push';
      by[k] = (by[k] ?? 0) + c - prev; if (c - prev > 1000 && /SPLIT|ROLL|PICK|CAT|DUP|OVER|SWAP|ROT|FROMALT|TOALT|INPUTBYTECODE|SHA256|BIN2NUM|NUM2BIN/.test(k)) big[k] = (big[k] ?? 0) + c - prev; prev = c; n++; }
    const arith = ['MUL', 'MOD', 'ADD', 'SUB', 'NEGATE', 'DIV', 'LESSTHAN', 'NUMEQUAL', 'MAX', 'NOT'].reduce((s, k) => s + (by[k] ?? 0), 0);
    console.log(`${spec} in${i} total ${(prev / 1e6).toFixed(3)}M steps ${n}; arith ${(arith / 1e6).toFixed(3)}M; ` + Object.entries(by).sort((a, b2) => b2[1] - a[1]).slice(0, 16).map(([k, v]) => `${k} ${(v / 1e3).toFixed(0)}k`).join(', '));
    console.log('   big (>1k op per step) data moves: ' + Object.entries(big).sort((a, b2) => b2[1] - a[1]).map(([k, v]) => `${k} ${(v / 1e3).toFixed(0)}k`).join(', '));
  }
}
