// Per-instruction op profile of one shared function over a dense-witness run (diagnostics): node fnprof.mjs AFFDBL [input]
import {encodeAuthenticationInstructions, decodeAuthenticationInstructions, disassembleAuthenticationInstruction, OpcodesBch} from '@bitauth/libauth';
const D = './';
const {buildAll} = await import(D + 'script.mjs'); const {txPushes} = await import(D + 'protocol.mjs'); const {witnessFor} = await import(D + 'measure.mjs');
const {p2sh32, txOf, unlockingsFor, VM_UNLIMITED} = await import(D + 'vm.mjs');
const b = buildAll(); const FN = process.argv[2] ?? 'AFFDBL', IN = Number(process.argv[3] ?? 1);
const code = b.info.ctx.funcs.get(FN).code; const hex = Buffer.from(code).toString('hex');
const w = witnessFor('dense'); const un = unlockingsFor(txPushes(w, b.blob), b.R); const ctx = txOf(un, un.map(() => p2sh32(b.R)));
const tr = VM_UNLIMITED.standard.debug({inputIndex: IN, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
const cache = new WeakMap(); const isF = (ins) => { if (!ins) return false; if (!cache.has(ins)) cache.set(ins, Buffer.from(encodeAuthenticationInstructions(ins)).toString('hex') === hex); return cache.get(ins); };
const ins = decodeAuthenticationInstructions(code); const per = new Array(ins.length).fill(0); let prev = 0, calls = 0;
for (const s of tr) { const c = s.metrics?.operationCost ?? 0; if (isF(s.instructions) && s.ip > 0) per[s.ip - 1] += c - prev; if (isF(s.instructions) && s.ip === 0) calls++; prev = c; }
// group consecutive instructions in windows of 10
let tot = 0; for (let i = 0; i < ins.length; i += 10) { const sl = per.slice(i, i + 10); const sm = sl.reduce((a, x) => a + x, 0); tot += sm; console.log(String(i).padStart(4), (sm / calls / 1000).toFixed(1).padStart(6) + 'k', ins.slice(i, i + 10).map((x) => disassembleAuthenticationInstruction(OpcodesBch, x).replace(/^OP_/, '').slice(0, 14)).join(' ')); }
console.log('calls', calls, 'avg per call', (tot / calls / 1000).toFixed(1) + 'k (excluding callee functions)');
