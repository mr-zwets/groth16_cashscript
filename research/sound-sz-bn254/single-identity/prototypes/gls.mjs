// GT-GLS fold, grouped evaluation: measured on bch-spec (standard).
// Witness for the fold: two fixed-width 65-byte nibble strings N_k (byte e = bits 64-e of |e_{k,0..3}|,
// bit i of the byte = sub-scalar i) and one sign byte (bit 4k+i = e_{k,i} < 0). All hashed into h0.
// Per proof: tables TP_k[n] = prod_{i in n} v_{k,i}(+z), TM_k[n] = same at -z (v already sign-adjusted:
// R(s z)), TB_k[n] = sum_{i in n} s_{k,i} pi_i (exact integers).
// Per event: i_k = byte; F+ <- F+ TP_0[i_0] TP_1[i_1]; F- likewise; acc_k <- 2 acc_k + TB_k[i_k].
// End: acc_k mod r == n_k (exact binding  sum_i e_{k,i} (p^i mod r) == n_k mod r).
//   node gls.mjs
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {Asm} from './asm.mjs';
import {OP, P, pushNum, runBody, Kernel, measureKernel} from './dsl.mjs';
const r = bn254.fields.Fr.ORDER;
const md = (x, m = P) => ((x % m) + m) % m;
let ctr = 0; const rnd = () => BigInt('0x' + createHash('sha256').update('gls:' + ctr++).digest('hex')) % P;
const out = {};

// ---- per-event loop: 65 events, both groups ----
const TP = [0, 1].map(() => Array.from({length: 16}, rnd)), TM = [0, 1].map(() => Array.from({length: 16}, rnd));
const pis = [1n, P % r, (P * P) % r, (P ** 3n) % r];
const signs = Array.from({length: 8}, (_, i) => (i % 3 === 0 ? -1n : 1n));
const TB = [0, 1].map((k) => Array.from({length: 16}, (_, n) => [0, 1, 2, 3].reduce((s, i) => s + ((n >> i) & 1 ? signs[4 * k + i] * pis[i] : 0n), 0n)));
const nib = [0, 1].map(() => Uint8Array.from(Array.from({length: 65}, () => Number(rnd() % 16n))));
const names = ['p'];
for (const k of [0, 1]) for (const T of ['TB', 'TM', 'TP']) for (let n = 15; n >= 0; n--) names.push(`${T}${k}[${n}]`);
names.push('acc0', 'acc1', 'ns0', 'ns1', 'Fp', 'Fm');
const vals = [P]; for (const k of [0, 1]) for (const T of [TB, TM, TP]) for (let n = 15; n >= 0; n--) vals.push(T[k][n]);
vals.push(0n, 0n, nib[0], nib[1], rnd(), rnd());
function event(a) {
  for (const k of [0, 1]) { a.roll(`ns${k}`).push(1n, 'one').op(OP.SPLIT, 2, `b${k}`, `ns${k}`).roll(`b${k}`).op(OP.BIN2NUM, 1, `i${k}`); }
  for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
    a.pick('i0', 'x').lookup(`${T}0`, 'u').pick('i1', 'x').lookup(`${T}1`, 'v').bin(OP.MUL, 'uv').roll(F).bin(OP.MUL, 'w').pick('p').bin(OP.MOD, F);
  }
  for (const k of [0, 1]) { a.roll(`acc${k}`).pick(`acc${k}`, 'dup').bin(OP.ADD, 'a2').roll(`i${k}`).lookup(`TB${k}`, 'tb').bin(OP.ADD, `acc${k}`); }
  a.arrange(['acc0', 'acc1', 'ns0', 'ns1', 'Fp', 'Fm']);
}
const evBytes = (() => { const a = new Asm(names); event(a); return a.code.length; })();
// expected values
let [Fp, Fm, acc0, acc1] = vals.slice(-2).concat([0n, 0n]);
for (let e = 0; e < 65; e++) {
  const i0 = nib[0][e], i1 = nib[1][e];
  Fp = md(Fp * TP[0][i0] * TP[1][i1]); Fm = md(Fm * TM[0][i0] * TM[1][i1]);
  acc0 = 2n * acc0 + TB[0][i0]; acc1 = 2n * acc1 + TB[1][i1];
}
// 65 unrolled events; then drop the (now empty) nibble strings
const loop = (tail) => { const b = new Asm(names); for (let e = 0; e < 65; e++) event(b); b.roll('ns0').drop().roll('ns1').drop(); tail(b); return b.bytes(); };
const op = runBody(loop((b) => b.arrange(['acc0', 'acc1', 'Fp', 'Fm'])), vals, [acc0, acc1, Fp, Fm], {remain: names.length - 6});
// the binding accumulators exceed p, so check them exactly in a second run
runBody(loop((b) => { b.roll('Fp').drop().roll('Fm').drop(); b.arrange(['acc0', 'acc1']); }), vals, [acc0, acc1], {remain: names.length - 6, exact: true});
out.glsEventLoop65 = {opCost: op, perEvent: Math.round(op / 65), bytesPerEventUnrolled: evBytes, note: 'two 4-bit table lookups per sign per event, lazy double product, binding Horner'};
console.log('GLS event loop, 65 events:', op, 'op  (per event', Math.round(op / 65), ') ; per-event code', evBytes, 'B (unrolled; as a function: called 65x)');

// ---- table build: per group, per sign: 16 entries from 4 values (11 products), as one DSL kernel ----
{
  const k = new Kernel(['p'], ['v0', 'v1', 'v2', 'v3']);
  const v = ['v0', 'v1', 'v2', 'v3'].map((n) => k.I(n)); const ent = Array(16);
  ent[0] = k.c(1n); for (let n = 1; n < 16; n++) { const lo = n & -n; ent[n] = n === lo ? v[Math.log2(lo)] : k.mm(ent[n ^ lo], v[Math.log2(lo)]); }
  k.output(ent.slice().reverse()); // entry [n] at depth n from the top after the kernel... (layout as in the loop)
  const m = measureKernel(k, [P], [rnd(), rnd(), rnd(), rnd()], {iters: 3000, label: 'GLS table (16 entries, one sign, one group)'});
  out.glsTable = {opCost: m.opCost, bytes: m.bytes, builds: 4};
  console.log(m.label, m.opCost, 'op', m.bytes, 'B  (x4 builds)');
}
// ---- factor evaluation: monic degree-6 R at x and -x from baked coefficients: Ev +- Od ----
{
  const k = new Kernel(['p', 'x', 'x2', 'x3', 'x4', 'x5', 'x6'], ['c0', 'c1', 'c2', 'c3', 'c4', 'c5']);
  const E = k.E.bind(k), I = k.I.bind(k), mul = k.mul.bind(k);
  const ev = k.mod(k.sum(I('c0'), mul(I('c2'), E('x2')), mul(I('c4'), E('x4')), E('x6')));
  const od = k.mod(k.sum(mul(I('c1'), E('x')), mul(I('c3'), E('x3')), mul(I('c5'), E('x5'))));
  k.output([k.add(ev, od), k.sub(ev, od)]);
  const m = measureKernel(k, [P, ...Array.from({length: 6}, rnd)], Array.from({length: 6}, rnd), {iters: 3000, label: 'monic deg-6 eval at +-x (6 consts pushed)'});
  out.repEval = {opCost: m.opCost, bytes: m.bytes, uses: '8 factor evals (R_k0,R_k1 at z and eta z, k=0,1) + S_c at z, eta z + 33 states (in state kernel)'};
  console.log(m.label, m.opCost, 'op', m.bytes, 'B');
}
// ---- TB tables (exact integers) and binding check: acc mod r == n, 0 <= n < r ----
{
  const names2 = ['r', 'pi1', 'pi2', 'pi3', 'sgn', 'n0', 'acc0'];
  const b = new Asm(names2);
  // signed pis from sign byte bits (4 per group): s_i pi_i ; build 16 sums (11 adds) -- measured for one group
  const sgn = 0b1010n;
  // spi_i = pi_i * (1 - 2 bit_i): bit_i = (sgn >> i) & 1 via (sgn / 2^i) % 2
  for (const i of [0, 1, 2, 3]) {
    b.pick('sgn').push(1n << BigInt(i)).op(0x96 /* DIV */, 2, 'q').push(2n).bin(OP.MOD, 'bit').push(2n).bin(OP.MUL, 'b2').push(1n).roll('b2').bin(OP.SUB, 's');
    if (i === 0) b.rename(`spi${i}`); else b.pick(`pi${i}`).bin(OP.MUL, `spi${i}`);
  }
  for (let n = 1; n < 16; n++) { const lo = n & -n; if (n !== lo) b.pick(`TB[${n ^ lo}]`).pick(`spi${Math.log2(lo)}`).bin(OP.ADD, `TB[${n}]`); else b.pick(`spi${Math.log2(lo)}`, `TB[${n}]`); }
  const tbOps = b.code.length;
  // binding: acc0 mod r == n0, n0 in [0, r)
  b.pick('acc0').pick('r').bin(OP.MOD, 'm').pick('r').bin(OP.ADD, 'm2').pick('r').bin(OP.MOD, 'm3').pick('n0').op(OP.NUMEQUALVERIFY, 2);
  b.pick('n0').push(0n).pick('r').op(OP.WITHIN, 3, 'ok').op(OP.VERIFY, 1);
  const extra = b.st.length - names2.length;
  for (let i = 0; i < extra; i++) b.emit(OP.DROP);
  const n0 = 12345n, acc = n0 + 7n * r;
  const op = runBody(b.bytes(), [r, pis[1], pis[2], pis[3], sgn, n0, acc], [], {remain: names2.length});
  out.glsSignsTBandBinding = {opCost: op, bytes: b.code.length, note: 'one group; x2'};
  console.log('GLS signed pi + TB table + binding check (one group):', op, 'op', b.code.length, 'B');
}
writeFileSync(new URL('./gls.json', import.meta.url), JSON.stringify(out, null, 1));
