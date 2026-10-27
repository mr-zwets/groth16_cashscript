// End-to-end VM prototype of a worker input's event segment (BLS12-381): events [from, to) with B doubling,
// baked delta lines read from a constant blob, B additions with c^-1, the GT-GLS nibble lookups and the state
// boundaries (state decode + range check, evaluation at +-z, R update). Run on a real proof: the VM's final
// (T, F+, F-, R) must equal the protocol mirror. Reports op cost and code size of the segment.
//   node proto_worker.mjs [from=1] [to=17] [seed=1]
import assert from 'node:assert/strict';
import {encodeDataPush, bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';
import {Asm, OP, pushNum} from './asm.mjs';
import {p, mod, F2, peval, pneg, BITS} from './blsmath.mjs';
import {prove, randProof, VKC, glsFactorPoly, uniformBounds, le} from './protocol.mjs';
import * as K from './kernels.mjs';

import {createVirtualMachineBchSpec} from '@bitauth/libauth';
const spec = createVirtualMachineBchSpec(false);
export function segment(pr, FROM, TO, {bounds = uniformBounds(2), z = mod(0x1234567890abcdefn ** 5n), rho = mod(0xfeedbeefn ** 7n), R0 = mod(0xabcdefn ** 9n)} = {}) {
const {st, sched, Sc, states, N} = pr; const zm = mod(-z);

// ---- reference (mirror) ----
const kOf = (e) => bounds.findIndex((b) => b > e); // chunk index of event e
const Sfull = [pneg(Sc), ...states]; // S_0 = S_c(-X), S_1.. (monic, 7 coeffs)
const startK = kOf(FROM); assert.ok(FROM === 0 || bounds[startK - 1] === FROM, 'segment must start at a chunk boundary');
let Fp_ = peval(Sfull[startK], z), Fm_ = peval(Sfull[startK], zm), Rr = R0; let kk = startK;
const cpv = peval(pneg(Sc), z), cmv = peval(pneg(Sc), zm);
for (let e = FROM; e < TO; e++) {
  const ev = sched.events[e]; if (e) { Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_); }
  for (const f of ev.fs) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
  if (ev.add) { Fp_ = mod(Fp_ * cpv); Fm_ = mod(Fm_ * cmv); }
  if (e + 1 === bounds[kk]) { const S = Sfull[kk + 1]; const Sp = peval(S, z), Sm = peval(S, zm); Rr = mod(Rr * rho + Fp_ * Sm - Fm_ * Sp); Fp_ = Sp; Fm_ = Sm; kk++; }
}
const Tin = FROM ? sched.events[FROM - 1].Tafter : null, Tout = sched.events[TO - 1].Tafter;

// ---- data blobs ----
const W = (x) => le(mod(x), 48);
const dLines = VKC.lines.filter((l) => l.e >= FROM && l.e < TO);
const DD = Buffer.concat(dLines.flatMap((l) => [W(l.c.c0), W(l.c.c1), W(l.lam.c0), W(l.lam.c1)]));
const nStates = bounds.filter((b) => b > FROM && b <= TO).length;
const SS = Buffer.concat(Sfull.slice(startK + 1, startK + 1 + nStates).flatMap((s) => s.slice(0, 6).map(W)));
const NB = [0, 1].map((k) => Buffer.from(N[k].slice(FROM, TO)));
// ---- environment (computed in the input's setup on chain; pushed here) ----
const z2 = mod(z * z), z3 = mod(z2 * z), z4 = mod(z2 * z2), z5 = mod(z4 * z), z6 = mod(z3 * z3), t = mod(z6 - 1n);
const xz2 = mod(st.xA * z2), yz3 = mod(st.yA * z3), cz2 = mod(st.xC * z2), ycz3 = mod(st.yC * z3);
const envVals = {t, xz2, xz2t: mod(xz2 * t), xz23: mod(3n * xz2), xz23t: mod(3n * xz2 * t), yz3, yz3t: mod(yz3 * t), cz2, cz2t: mod(cz2 * t), ycz3, rho,
  z, z2, z3, z4, z5, z6, xq0: st.xB.c0, xq1: st.xB.c1, yq0: st.yB.c0, yq1: st.yB.c1, cp: cpv, cm: cmv};
const tables = {};
for (const k of [0, 1]) { const vp = [0, 1, 2, 3].map((i) => peval(glsFactorPoly(k, i), z)), vm = [0, 1, 2, 3].map((i) => peval(glsFactorPoly(k, i), zm));
  for (const [nm, v] of [[`TP${k}`, vp], [`TM${k}`, vm]]) for (let n = 15; n >= 0; n--) { let a = 1n; for (let b = 0; b < 4; b++) if ((n >> b) & 1) a = mod(a * v[b]); tables[`${nm}_${n}`] = a; } }
const T0 = Tin ?? [st.xB, st.yB, F2.ONE];
const state = {X0: T0[0].c0, X1: T0[0].c1, Y0: T0[1].c0, Y1: T0[1].c1, Z0: T0[2].c0, Z1: T0[2].c1, Fp: peval(Sfull[startK], z), Fm: peval(Sfull[startK], zm), R: R0};
const names = ['p', ...Object.keys(envVals), ...Object.keys(tables), 'DD', 'SS', 'N0', 'N1', ...Object.keys(state)];
const pushes = [bigIntToVmNumber(p), ...Object.values(envVals).map((v) => bigIntToVmNumber(v)), ...Object.values(tables).map((v) => bigIntToVmNumber(v)), DD, SS, NB[0], NB[1], ...Object.values(state).map((v) => bigIntToVmNumber(v))];

// ---- the segment program ----
const a = new Asm(names);
const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
const RD = (blob, out) => { a.roll(blob).push(48).op(OP.SPLIT, 2, 'w', blob).roll('w'); U(out); a.pick(out).pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); };
const RC = (blob, out) => { a.roll(blob).push(48).op(OP.SPLIT, 2, 'w', blob).roll('w').op(OP.BIN2NUM, 1, out); }; // hash-pinned constants: < 2^381, sign bit clear
const lookup = (tbl, idx, out) => { assert.equal(a.top(), idx); a.st.pop(); const d0 = a.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(a.depth(`${tbl}_${n}`), d0 + n); a.emit(...pushNum(d0), OP.ADD, OP.PICK); a.st.push(out); };
const dline = () => { a.roll('DD').push(192).op(OP.SPLIT, 2, 'ln', 'DD').roll('ln'); for (const n of ['c0', 'c1', 'l0']) RC('ln', n); a.roll('ln').op(OP.BIN2NUM, 1, 'l1'); a.kernel(K.kDBaked(), ['Fp', 'Fm']); };
const marks = []; const mark = (n) => marks.push([n, a.code.length]);
for (let e = FROM; e < TO; e++) {
  mark('dbl' + e);
  if (e) a.kernel(K.kBDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm']);
  if (e) dline();
  if (e && BITS[e]) { a.kernel(K.kBAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm']); dline(); }
  mark('gls' + e);
  for (const k of [0, 1]) { a.roll('N' + k).push(1).op(OP.SPLIT, 2, 'b', 'N' + k).roll('b').op(OP.BIN2NUM, 1, 'i' + k); }
  for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) { a.pick('i0', 'x'); lookup(T + '0', 'x', 'u'); a.pick('i1', 'x'); lookup(T + '1', 'x', 'v'); a.rename(F, 'F'); a.kernel(K.kGlsMul(), [F]); }
  a.drop('i0').drop('i1');
  if (bounds.includes(e + 1)) {
    mark('bnd' + e);
    a.roll('SS').push(288).op(OP.SPLIT, 2, 'S', 'SS'); for (let j = 0; j < 6; j++) RD('S', 'in' + j); a.drop('S');
    for (const n of ['z', 'z2', 'z3', 'z4', 'z5', 'z6']) a.pick(n, 'x' + n); for (let j = 0; j < 6; j++) a.rename('x' + ['z', 'z2', 'z3', 'z4', 'z5', 'z6'][j], 'in' + (6 + j));
    a.kernel(K.kEval(), ['Sp', 'Sm']); a.kernel(K.kBoundary(), ['Fp', 'Fm', 'R']);
  }
}
const code = a.bytes();
// ---- run ----
const unl = Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(b)]));
const prog = (lock) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: lock, valueSatoshis: 1000n}], transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unl}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}});
// the BCH 2026 VM enforces the 10,000-byte script and budget limits: measure with bch-spec (identical op accounting)
const base = spec.evaluate(prog(Uint8Array.of())), res = spec.evaluate(prog(code)); const vm = null;
assert.ok(res.error === undefined || /unexpected number of items/.test(res.error), res.error);
const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false}); const top = res.stack.slice(-9).map(num).map((x) => mod(x));
const exp = [Tout[0].c0, Tout[0].c1, Tout[1].c0, Tout[1].c1, Tout[2].c0, Tout[2].c1, Fp_, Fm_, Rr].map((x) => mod(x));
const got = {}; ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm', 'R'].forEach((n) => (got[n] = mod(num(res.stack[a.st.lastIndexOf(n)]))));
assert.deepEqual(Object.values(got), exp, 'VM state differs from the mirror');
const op = res.metrics.operationCost - base.metrics.operationCost;
const nAdd = BITS.slice(Math.max(1, FROM), TO).filter((b) => b).length;
void top; void marks; void vm; void prog;
return {from: FROM, to: TO, events: TO - FROM, additions: nAdd, boundaries: nStates, deltaLines: dLines.length, op, code: code.length, perEvent: Math.round(op / (TO - FROM)), dataBytes: DD.length + SS.length + 2 * (TO - FROM)};
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [FROM, TO, SEED] = [Number(process.argv[2] ?? 1), Number(process.argv[3] ?? 17), Number(process.argv[4] ?? 1)];
  console.log(JSON.stringify(segment(prove(randProof(SEED), {bounds: uniformBounds(2)}), FROM, TO)));
}
