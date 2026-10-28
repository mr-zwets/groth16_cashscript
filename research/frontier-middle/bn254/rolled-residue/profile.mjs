// Op-cost profile (committed proof, budget-loosened BCH 2026): cumulative op-cost at each STOP label of the
// generator, and the per-call cost of each shared local function measured in isolation (sampled operands).
import {Asm, Kernel, OP, pushNum} from '../sigls-dproj/asm.mjs';
import {buildPartial, buildRedeem, kDbl, kAdd, kMulSparse, kSqr, kJDbl, kJAdd} from './script.mjs';
import {bare} from './vm.mjs';
import {VEC, p, mod} from './math.mjs';
import {prove} from './protocol.mjs';
const w = prove({proof: VEC.proof, publicInputs: VEC.publicInputs});
let prev = 0; const rows = [];
for (const label of ['parsed', 'vkx', 'preloop', 'postloop', 'endpoint', 'termlines', 'pfin', 'p1']) {
  const {code} = buildPartial(label); const res = bare(code, [w.W]); rows.push([label, res.opCost, res.opCost - prev]); prev = res.opCost;
}
for (const [l, c, d] of rows) console.log(l.padEnd(10), String(c).padStart(11), ('+' + d).padStart(11));
// per-call: a program that pushes sampled 32-byte operands and runs the kernel once (inline, as inside the local function)
const rnd = (i) => mod(BigInt('0x' + (BigInt(i + 1) * 0x9e3779b97f4a7c15n).toString(16).repeat(4).slice(0, 64)));
const once = (name, K, outs) => { const ins = [...K.inputs]; const a = new Asm([]); a.push(p, 'p'); ins.forEach((n, i) => a.push(rnd(i), n)); const before = bare(a.code, []).opCost;
  a.kernel(K, outs, {iters: 3000}); const r = bare(a.code, []); console.log(name.padEnd(10), 'kernel op', r.opCost - before, 'bytes', a.code.length); };
once('sqr', kSqr(), Array.from({length: 12}, (_, i) => 'o' + i));
once('mull', kMulSparse([0, 1, 3, 6, 7, 9], 'L', false), Array.from({length: 12}, (_, i) => 'o' + i));
once('mulc', kMulSparse([0, 1, 2, 3, 4, 5], 'G', true), Array.from({length: 12}, (_, i) => 'o' + i));
once('dbl', kDbl(), Array.from({length: 12}, (_, i) => 'o' + i));
once('add', kAdd(), Array.from({length: 12}, (_, i) => 'o' + i));
once('jdbl', kJDbl(), ['a', 'b', 'c']); once('jadd', kJAdd(), ['a', 'b', 'c']);
