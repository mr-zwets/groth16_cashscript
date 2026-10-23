// Differential test of every compiled kernel: random inputs, VM result vs SSA interpreter.
import {build} from './hotloop.mjs'; import {makeWitness} from './witness.mjs'; import {run, asm, interpret, vmToBig, mod} from './sscomp.mjs';
import {createHash} from 'node:crypto';
let c = 0; const rnd = () => mod(BigInt('0x' + createHash('sha256').update('kt' + c++).digest('hex')));
const B = build(makeWitness(0, Number(process.argv[2] ?? 20)), {f1From: Number(process.argv[3] ?? 40)});
for (const [k, x] of Object.entries(B.K)) {
  if (!x.inputs || /ABDBL|ABADD|SC/.test(k)) continue; // checked kernels need consistent data (covered end-to-end)
  const env = Object.fromEntries(x.inputs.map((n) => [n, n === 'P' ? 21888242871839275222246405745257275088696311157297823662689037894645226208583n : n === 's' ? 1n : rnd()]));
  const e = interpret(x.prog, env);
  const vals = x.inputs.map((n) => env[n]);
  const r = run(vals, x.code);
  const top = r.stack.slice(-x.outputs.length).map(vmToBig);
  const exp = x.outputs.map((o) => e.has(o) ? e.get(o) : env[o]);
  const ok = r.stack.length === 1 + x.outputs.length && top.every((v, i) => v === exp[i]);
  console.log(k.padEnd(10), ok ? 'ok' : 'MISMATCH', r.stack.length - 1, x.outputs.length, r.err && !/unexpected/.test(r.err) ? r.err : '');
}
