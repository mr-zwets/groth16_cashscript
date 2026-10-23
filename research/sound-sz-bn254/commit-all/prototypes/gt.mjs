// GT block of commit-all, measured on the bch-spec VM.
// (a) FROB: exact Frobenius image phi^j(m + X) of a 6-limb class representative (Fp2 coefficients
//     A0, A1, A2 of 1, v, v^2) evaluated at +-z. Checked against noble's frobeniusMap.
// (b) GTE: per-event decode of one 16-bit word (8 two-bit codes, 01 = +1, 10 = -1, 11 rejected),
//     ONE signed digit per (i,j) used for both the fold (U+- *= g_ij(+-z), swapped for -1) and the
//     linear accumulator S_i = 2 S_i + sum_j d_ij * (p^j mod r) (so S_i = sum_j K_ij (p^j mod r)),
//     after the event's squaring (weight 2^(NE-1-e)). Words are split off the 130-B digit blob.
//     End: (S_i - n_i) mod r == 0 (sign-safe). Run over all 65 events for fixture 0 and dense cases.
// Usage: node gt.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {builder, evaluator, compile, run, mod, P, R, num, push, pushNum, OP, defineFn, invoke, vmNum, opCounts} from './lib.mjs';
import {decompose} from './gt-decomp.mjs';
const F2 = bn254.fields.Fp2, F6 = bn254.fields.Fp6, F12 = bn254.fields.Fp12;
const X_BN = 4965661367192848881n;
const digits = []; for (let n = 6n * X_BN + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) digits.unshift(0); else if ((n & 3n) === 3n) { digits.unshift(-1); n++; } else digits.unshift(1); }
const NE = digits.length;
const z = mod(BigInt('0x' + 'beef'.repeat(15)) * 7n), u = mod(z ** 6n - 9n);
// ---------------- (a) FROB ----------------
const mk12 = (slots) => F12.create({c0: F6.create({c0: slots[0], c1: slots[1], c2: slots[2]}), c1: F6.create({c0: slots[3], c1: slots[4], c2: slots[5]})});
const Z2 = F2.ZERO, O2 = F2.ONE;
const ORDER = [0, 2, 4, 1, 3, 5];
const toPoly = (t) => { const s = [t.c0.c0, t.c0.c1, t.c0.c2, t.c1.c0, t.c1.c1, t.c1.c2], out = Array(12).fill(0n); ORDER.forEach((d, i) => { out[d] = mod(s[i].c0 - 9n * s[i].c1); out[d + 6] = mod(s[i].c1); }); return out; };
const evalP = (a, x) => a.reduceRight((acc, c) => mod(acc * x + c), 0n);
// gamma constants: phi^j(v^k) = g[j][k] v^k (slots 0,1,2), phi^j(w) = gw[j] w
const gam = [1, 2, 3].map((j) => [0, 1, 2].map((kk) => { const s = [Z2, Z2, Z2, Z2, Z2, Z2]; s[kk] = O2; return F12.frobeniusMap(mk12(s), j)[`c0`][`c${kk}`]; }));
const gw = [1, 2, 3].map((j) => F12.frobeniusMap(mk12([Z2, Z2, Z2, O2, Z2, Z2]), j).c1.c0);
// kernel: inputs A0..A2 (6 limbs), basis bu=u, b2=z^2, b2u, b4, b4u; constant odd value ow = eps(gw)*z (per j, shared)
function kFrob(k, S, j) {
  const conj = j % 2 === 1;
  const A = [[S.a0, S.a1], [S.a2, S.a3], [S.a4, S.a5]].map(([x, y]) => (conj ? [x, k.neg(y)] : [x, y]));
  const B = A.map((a, kk) => { if (kk === 0) return a; const g = gam[j - 1][kk];
    if (g.c1 === 0n) return [k.mulc(a[0], g.c0), k.mulc(a[1], g.c0)];
    return [k.sub(k.mulc(a[0], g.c0), k.mulc(a[1], g.c1)), k.add(k.mulc(a[0], g.c1), k.mulc(a[1], g.c0))]; });
  // even(z) = eps(B0) + eps(B1) z^2 + eps(B2) z^4 ; B1, B2 unreduced (64 B) -> one MOD at the end
  const ev = k.mod(k.add(k.add(k.add(B[0][0], k.mul(B[0][1], S.bu)), k.add(k.mul(B[1][0], S.b2), k.mul(B[1][1], S.b2u))), k.add(k.mul(B[2][0], S.b4), k.mul(B[2][1], S.b4u))));
  return [k.add(ev, S.ow), k.sub(ev, S.ow)];
}
const frobIn = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5'], frobFrame = ['P', 'bu', 'b2', 'b2u', 'b4', 'b4u', 'ow'];
const basis = {P, bu: u, b2: mod(z * z), b2u: mod(z * z * u), b4: mod(z ** 4n), b4u: mod(z ** 4n * u)};
const frobRes = {};
for (const j of [1, 2, 3]) {
  const kb = builder(); const S = Object.fromEntries([...frobFrame, ...frobIn].map((n) => [n, n]));
  const outs = kFrob(kb, S, j);
  const code = compile({frame: [...frobFrame, ...frobIn], prog: kb.prog, out: [...frobFrame, ...outs], pMode: 'pick'});
  // test vector: random class rep m + X
  const rnd = (s) => mod(BigInt('0x' + createHash('sha256').update(s).digest('hex')));
  const A = [0, 1, 2].map((kk) => F2.fromBigTuple([rnd('a' + kk + j), rnd('b' + kk + j)]));
  const elem = mk12([A[0], A[1], A[2], O2, Z2, Z2]);
  const ow = mod((gw[j - 1].c0 + gw[j - 1].c1 * u) * z);
  const vals = {...basis, ow, a0: A[0].c0, a1: A[0].c1, a2: A[1].c0, a3: A[1].c1, a4: A[2].c0, a5: A[2].c1};
  const ref = toPoly(F12.frobeniusMap(elem, j));
  const want = [evalP(ref, z), evalP(ref, mod(-z))];
  const got = kFrob(evaluator(), vals, j).map(mod);
  assert.deepEqual(got, want, 'frob math j=' + j);
  const pushes = [...frobFrame, ...frobIn].flatMap((n) => pushNum(vals[n]));
  const a = run({code: [...pushes, ...code]}), b = run({code: pushes});
  const top = a.stack.slice(-2).map(vmNum).map(mod); assert.deepEqual(top, want, 'frob VM j=' + j);
  frobRes['j' + j] = {op: a.consensus - b.consensus, bytes: code.length, ops: opCounts(kb.prog)};
}
// plain 6-limb evaluation at +-z of a class rep (j = 0, chat, K, states)
{
  const kb = builder(); const S = Object.fromEntries([...frobFrame, ...frobIn].map((n) => [n, n]));
  const ev = kb.mod(kb.add(kb.add(kb.add(S.a0, kb.mul(S.a1, S.bu)), kb.add(kb.mul(S.a2, S.b2), kb.mul(S.a3, S.b2u))), kb.add(kb.mul(S.a4, S.b4), kb.mul(S.a5, S.b4u))));
  const outs = [kb.add(ev, 'ow'), kb.sub(ev, 'ow')];
  const code = compile({frame: [...frobFrame, ...frobIn], prog: kb.prog, out: [...frobFrame, ...outs], pMode: 'pick'});
  const vals = {...basis, ow: z, a0: 11n, a1: 12n, a2: 13n, a3: 14n, a4: 15n, a5: 16n};
  const pushes = [...frobFrame, ...frobIn].flatMap((n) => pushNum(vals[n]));
  const a = run({code: [...pushes, ...code]}), b = run({code: pushes});
  frobRes.eval6pm = {op: a.consensus - b.consensus, bytes: code.length};
}
// ---------------- (b) GTE ----------------
const pj = [1n, P % R, (P * P) % R, (P ** 3n) % R];
const nafDigits = (kk) => { const out = []; let a = kk < 0n ? -kk : kk; const s = kk < 0n ? -1 : 1; while (a > 0n) { if (a & 1n) { const d = (a & 3n) === 3n ? -1 : 1; out.push(d * s); a -= BigInt(d); } else out.push(0); a >>= 1n; } return out; };
// frame: P, R, c1..c3, g{t}p, g{t}m (t = 0..7), S0, S1, Up, Um, blob ; per event: blob -> word w on top
const gNames = Array.from({length: 8}, (_, t) => [`g${t}p`, `g${t}m`]).flat();
const gFrame = ['P', 'R', 'c1', 'c2', 'c3', ...gNames, 'S0', 'S1', 'Up', 'Um'];
// branch body for (t, sign): Up,Um *= g (swapped for -1); S_i += sign * c_j ; frame + [blob, w] passthrough
function branchCode(t, sign) {
  const i = t >> 2, j = t & 3; const kb = builder();
  const [gp, gm] = sign > 0 ? [`g${t}p`, `g${t}m`] : [`g${t}m`, `g${t}p`];
  const Up = kb.mod(kb.mul('Up', gp)), Um = kb.mod(kb.mul('Um', gm));
  const Si = j === 0 ? (sign > 0 ? kb.add(`S${i}`, kb.konst(1)) : kb.sub(`S${i}`, kb.konst(1))) : (sign > 0 ? kb.add(`S${i}`, `c${j}`) : kb.sub(`S${i}`, `c${j}`));
  const fr = [...gFrame, 'blob', 'w'];
  const out = fr.map((n) => (n === `S${i}` ? Si : n === 'Up' ? Up : n === 'Um' ? Um : n));
  return compile({frame: fr, prog: kb.prog, out, pMode: 'pick'});
}
// event function: [.. S0 S1 Up Um blob] -> doubles S0,S1, splits w, decodes 8 codes
const body = [];
// S_i := 2 S_i  (S0 at depth 4, S1 at depth 3 relative to blob on top)
body.push(...pushNum(4), OP.ROLL, OP.DUP, OP.ADD, ...pushNum(4), OP.ROLL, OP.DUP, OP.ADD, ...pushNum(4), OP.ROLL, ...pushNum(4), OP.ROLL, ...pushNum(4), OP.ROLL);
// stack now: .. S0 S1 Up Um blob ; split 2 bytes: w = BIN2NUM(lo2 || 0x00)
body.push(...pushNum(2), OP.SPLIT, OP.SWAP, ...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM);
const IF = OP.IF, ELSE = OP.ELSE, ENDIF = OP.ENDIF;
// Unexecuted instructions still cost 100 op each under the 2025 limits, so the branch bodies are
// functions and the dispatch is computed: id = 16 + 4t + code. Code 0 -> empty function; codes 1/2
// -> multiply (+1 / swapped -1) and S_i +-= c_j; code 3 has no definition -> OP_INVOKE fails (11 rejected).
const BR = new Map();
for (let t = 0; t < 8; t++) {
  BR.set(16 + 4 * t, new Uint8Array(0)); BR.set(17 + 4 * t, branchCode(t, 1)); BR.set(18 + 4 * t, branchCode(t, -1));
  body.push(OP.DUP, ...pushNum(4), OP.MOD, ...pushNum(16 + 4 * t), OP.ADD, OP.INVOKE, ...pushNum(2), OP.RSHIFTNUM);
}
body.push(OP.DROP); // drop w (0 now)
const GTE = Uint8Array.from(body);
// final check: (S_i - n_i) mod r == 0, n_i pushed as unsigned
function gtRun(n0, n1, label) {
  const ks = [n0, n1].map((n) => decompose(n));
  const DIG = ks.map((row) => row.map(nafDigits));
  const d = (i, j, e) => DIG[i][j][NE - 1 - e] ?? 0;
  const words = Array.from({length: NE}, (_, e) => { let w = 0; for (let t = 0; t < 8; t++) { const x = d(t >> 2, t & 3, e); w |= (x === 1 ? 1 : x === -1 ? 2 : 0) << (2 * t); } return w; });
  const blob = Buffer.from(words.flatMap((w) => [w & 255, w >> 8]));
  const rnd = (s) => mod(BigInt('0x' + createHash('sha256').update(s).digest('hex')));
  const vals = {P, R, c1: pj[1], c2: pj[2], c3: pj[3], S0: 0n, S1: 0n, Up: rnd('up'), Um: rnd('um')};
  gNames.forEach((n) => (vals[n] = rnd(n)));
  // simulation
  let Up = vals.Up, Um = vals.Um; const S = [0n, 0n]; let nz = 0;
  for (let e = 0; e < NE; e++) { S[0] *= 2n; S[1] *= 2n; for (let t = 0; t < 8; t++) { const x = d(t >> 2, t & 3, e); if (!x) continue; nz++;
    const [gp, gm] = x > 0 ? [vals[`g${t}p`], vals[`g${t}m`]] : [vals[`g${t}m`], vals[`g${t}p`]]; Up = mod(Up * gp); Um = mod(Um * gm); S[t >> 2] += BigInt(x) * pj[t & 3]; } }
  assert(mod(S[0] - n0) % R === 0n || ((S[0] - n0) % R) === 0n, 'S0'); assert(((S[1] - n1) % R) === 0n, 'S1');
  const pushes = [...gFrame.flatMap((n) => pushNum(vals[n])), ...push(blob)];
  const main = []; for (let e = 0; e < NE; e++) main.push(...invoke(1));
  // after events: [.. S0 S1 Up Um blob(empty)] -> drop blob ; check S1 then S0 against n
  const fin = [OP.DROP, ...pushNum(2), OP.ROLL, ...pushNum(n1), OP.SUB, ...pushNum(R + 0n).slice(0, 0), ...pushNum(gFrame.length - 1 - gFrame.indexOf('R') + 0 + 1 - 1), OP.PICK, OP.MOD, OP.NOT, OP.VERIFY];
  // simpler, explicit final check sequence (depths computed for the frame layout)
  const finCode = [OP.DROP, // [.. S0 S1 Up Um]
    ...pushNum(2), OP.ROLL, ...pushNum(n1), OP.SUB, ...pushNum(gFrame.length - 2), OP.PICK, OP.MOD, OP.NOT, OP.VERIFY,
    ...pushNum(2), OP.ROLL, ...pushNum(n0), OP.SUB, ...pushNum(gFrame.length - 3), OP.PICK, OP.MOD, OP.NOT, OP.VERIFY];
  void fin;
  const defs = [...defineFn(1, GTE), ...[...BR].flatMap(([id, c]) => defineFn(id, c))];
  const a = run({code: [...defs, ...pushes, ...main, ...finCode], pad: 0}), b = run({code: [...defs, ...pushes], pad: 0});
  for (const r of [a]) { const er = r.err_consensus; if (er && !/clean|exactly one|unexpected number/i.test(String(er))) throw new Error(label + ': ' + er); }
  const top = a.stack.slice(-2).map(vmNum).map(mod);
  assert.deepEqual(top, [Up, Um], 'GTE VM vs sim');
  // negative test: flip one nonzero digit's sign -> must reject (S check)
  const bad = Buffer.from(blob); { const e = words.findIndex((w) => w); const t = [0, 1, 2, 3, 4, 5, 6, 7].find((tt) => (words[e] >> (2 * tt)) & 3);
    const w2 = words[e] ^ (3 << (2 * t)); bad[2 * e] = w2 & 255; bad[2 * e + 1] = w2 >> 8; } // one nonzero digit: 01 <-> 10
  const badPushes = [...gFrame.flatMap((n) => pushNum(vals[n])), ...push(bad)];
  const c = run({code: [...defs, ...badPushes, ...main, ...finCode], pad: 0});
  const rejected = !!c.err_consensus && /VERIFY/i.test(String(c.err_consensus));
  // code 11 must reject
  const bad3 = Buffer.from(blob); bad3[0] |= 3; const c3 = run({code: [...defs, ...gFrame.flatMap((n) => pushNum(vals[n])), ...push(bad3), ...main, ...finCode], pad: 0});
  return {label, nonzeroDigits: nz, op: a.consensus - b.consensus, flippedDigitRejected: rejected, code11Rejected: /undefined|Function identifier/i.test(String(c3.err_consensus))};
}
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const runs = fx.fixtures.map((f, i) => gtRun(BigInt(f.publicInputs[0]), BigInt(f.publicInputs[1]), 'fixture ' + i));
// densest of 3000 random public-input pairs
let dense = null;
for (let s = 0; s < 3000; s++) {
  const a = BigInt('0x' + createHash('sha256').update('dn' + s).digest('hex')) % R, b = BigInt('0x' + createHash('sha256').update('dm' + s).digest('hex')) % R;
  const cnt = [a, b].flatMap((n) => decompose(n)).map(nafDigits).flat().filter((x) => x).length;
  if (!dense || cnt > dense.cnt) dense = {a, b, cnt};
}
runs.push(gtRun(dense.a, dense.b, 'densest of 3000 random'));
console.log(JSON.stringify({frob: frobRes, GTE: {bytes: GTE.length, branchFnBytes: [...BR.values()].reduce((a, c) => a + c.length + 4, 0), runs}}, null, 0));
