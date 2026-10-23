// State / quotient / transcript pipeline of commit-all on the bch-spec VM:
//  - transcript: tau0 = H(tag|stmt), tau1 = H(..H(H(tau0|digits|mask)|chat)|S_1..|S_{N-1}) (hash chain,
//    exact push sizes checked), rho = BIN2NUM(tau1|0x00) mod p, tau2 = chain over the Q pieces,
//    z = BIN2NUM(tau2|0x00) mod p, z != 0;
//  - basis: u = z^6 - 9, z^2, z^2 u, z^4, z^4 u, z^3, z^3 u; chat parsed + evaluated at +-z;
//  - BND (per non-last chunk): ROLL S_c, SIZE == 192, parse 6 unsigned limbs, evaluate at +-z,
//    acc += rho^(c-1) (U+ V- - U- V+), rho power update, U := V (start of the next chunk);
//  - LAST: U *= phi(chat) phi^3(chat) K (values given), V = phi^2(chat), acc update;
//  - quotient: Horner in z^2 over the odd coefficients (descending), 8 limbs per 256-B piece,
//    then require (acc - z Q'(z^2) M(z)) mod p == 0 (here: VM result compared with a JS simulation).
// Usage: node pipeline.mjs [states=32] [oddQ=144]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {builder, compile, run, mod, P, push, pushNum, OP, defineFn, invoke, vmNum, opCounts} from './lib.mjs';
const NS = Number(process.argv[2] ?? 32), NQ = Number(process.argv[3] ?? 144);
const H = (b) => createHash('sha256').update(b).digest();
const rndB = (s, n) => { const o = []; let i = 0; while (o.length < n) o.push(...H(Buffer.from(s + ':' + i++))); return Buffer.from(o.slice(0, n)); };
const le = (b) => BigInt('0x' + (Buffer.from(b).reverse().toString('hex') || '0'));
const limbsOf = (b) => Array.from({length: b.length / 32}, (_, i) => le(b.subarray(32 * i, 32 * i + 32)));
// witness blobs
const tag = rndB('tag', 32), stmt = rndB('stmt', 320), digitsB = rndB('dig', 130), mask = rndB('mask', 9);
const chat = rndB('chat', 192), states = Array.from({length: NS}, (_, i) => rndB('S' + i, 192));
const nPieces = Math.ceil(NQ / 8); const qLimbs = Array.from({length: nPieces * 8}, (_, i) => (i < NQ ? rndB('q' + i, 32) : Buffer.alloc(32)));
const pieces = Array.from({length: nPieces}, (_, i) => Buffer.concat(qLimbs.slice(8 * i, 8 * i + 8)));
// ---- JS simulation
let tau = H(Buffer.concat([tag, stmt])); tau = H(Buffer.concat([tau, digitsB, mask])); tau = H(Buffer.concat([tau, chat]));
for (const s of states) tau = H(Buffer.concat([tau, s]));
const rho = le(Buffer.concat([tau, Buffer.of(0)])) % P;
for (const pc of pieces) tau = H(Buffer.concat([tau, pc]));
const z = le(Buffer.concat([tau, Buffer.of(0)])) % P; assert(z !== 0n);
const u = mod(z ** 6n - 9n), b = {bu: u, b2: mod(z * z), b2u: mod(z * z * u), b4: mod(z ** 4n), b4u: mod(z ** 4n * u)};
const ev = (s) => { const m = limbsOf(s); return mod(m[0] + m[1] * b.bu + m[2] * b.b2 + m[3] * b.b2u + m[4] * b.b4 + m[5] * b.b4u); };
let Up = mod(ev(chat) + z), Um = mod(ev(chat) - z), acc = 0n, rp = 1n;
for (const s of states) { const m = ev(s), Vp = mod(m + z), Vm = mod(m - z); acc = mod(acc + rp * (Up * Vm - Um * Vp)); rp = mod(rp * rho); Up = Vp; Um = Vm; }
const LV = {f1p: 101n, f1m: 102n, f3p: 103n, f3m: 104n, Kp: 105n, Km: 106n, f2p: 107n, f2m: 108n}; // phi^k(chat), K values at +-z (from gt.mjs kernels)
{ const Up2 = mod(Up * LV.f1p * LV.f3p * LV.Kp), Um2 = mod(Um * LV.f1m * LV.f3m * LV.Km); acc = mod(acc + rp * (Up2 * LV.f2m - Um2 * LV.f2p)); }
let hq = 0n; for (const q of [...qLimbs].reverse()) hq = mod(hq * b.b2 + le(q)); // descending: last limb = highest degree
const Mz = mod(z ** 12n - 18n * z ** 6n + 82n), rhs = mod(z * hq * Mz);
// ---- script
// stack (bottom..top): Q pieces (piece 0 deepest), states S_{N-1}..S_1, chat, mask, digits, stmt
const pushes = [...pieces, ...[...states].reverse(), chat, mask, digitsB, stmt];
const code = []; let depthExtra = 0; // items above the pushes
const nPush = pushes.length;
const pushIdx = (i) => nPush - 1 - i + depthExtra; // depth of push i
const SZ = (n) => [OP.SIZE, ...pushNum(n), OP.NUMEQUALVERIFY];
// tau0 = H(tag | stmt)  (stmt rolled: no longer needed after parse; parse cost counted in setup)
code.push(...push(tag), ...pushNum(pushIdx(nPush - 1) + 1), OP.PICK, ...SZ(320), OP.CAT, OP.SHA256); depthExtra = 1;
code.push(...pushNum(pushIdx(nPush - 2)), OP.PICK, ...SZ(130), OP.CAT, ...pushNum(pushIdx(nPush - 3)), OP.PICK, ...SZ(9), OP.CAT, OP.SHA256);
code.push(...pushNum(pushIdx(nPush - 4)), OP.PICK, ...SZ(192), OP.CAT, OP.SHA256);
for (let c = 0; c < NS; c++) { const idx = nPieces + (NS - 1 - c); code.push(...pushNum(pushIdx(idx)), OP.PICK, ...SZ(192), OP.CAT, OP.SHA256); }
// rho
code.push(OP.DUP, ...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM, ...push(Uint8Array.from(pushNum(P).slice(1))), OP.MOD, OP.SWAP); depthExtra = 2; // [rho tau]
for (let i = 0; i < nPieces; i++) code.push(...pushNum(pushIdx(i)), OP.PICK, ...SZ(256), OP.CAT, OP.SHA256);
code.push(...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM, ...push(Uint8Array.from(pushNum(P).slice(1))), OP.MOD, OP.DUP, OP.ZERONOTEQUAL, OP.VERIFY); // [rho z]
const hashEnd = code.length;
// basis kernel: [rho z] -> [P rho z bu b2 b2u b4 b4u z3 z3u]
const kb = builder();
const z2 = kb.mod(kb.mul('z', 'z')), z3 = kb.mod(kb.mul(z2, 'z')), z4 = kb.mod(kb.mul(z2, z2)), z6 = kb.mod(kb.mul(z3, z3));
const uu = kb.sub(z6, kb.konst(9));
const outsB = [uu, z2, kb.mod(kb.mul(z2, uu)), z4, kb.mod(kb.mul(z4, uu)), z3, kb.mod(kb.mul(z3, uu))];
code.push(...push(Uint8Array.from(pushNum(P).slice(1))), OP.ROT, OP.ROT); // [P rho z]
const basisCode = compile({frame: ['P', 'rho', 'z'], prog: kb.prog, out: ['P', 'rho', 'z', ...outsB], pMode: 'pick'});
code.push(...basisCode);
const FR = ['P', 'rho', 'z', 'bu', 'b2', 'b2u', 'b4', 'b4u', 'z3', 'z3u'];
// parse helper (inline, 6 limbs): [.. blob192] -> [.. m0..m5]
const parse6 = [];
for (let i = 0; i < 5; i++) parse6.push(...pushNum(32), OP.SPLIT, OP.SWAP, ...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM, OP.SWAP);
parse6.push(...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM);
// eval kernel: frame FR + [rp, acc, Up, Um] + m0..m5 -> V+, V-  then BND update
const mL = ['m0', 'm1', 'm2', 'm3', 'm4', 'm5'];
function evalPM(k) {
  const e = k.mod(k.add(k.add(k.add('m0', k.mul('m1', 'bu')), k.add(k.mul('m2', 'b2'), k.mul('m3', 'b2u'))), k.add(k.mul('m4', 'b4'), k.mul('m5', 'b4u'))));
  return [k.add(e, 'z'), k.sub(e, 'z')];
}
const ST = [...FR, 'rp', 'acc', 'Up', 'Um'];
// chat start: [FR rp acc] + m -> [FR rp acc Up Um]
const kc = builder(); const [cp, cm] = evalPM(kc);
const chatCode = compile({frame: [...FR, 'rp', 'acc', ...mL], prog: kc.prog, out: [...FR, 'rp', 'acc', cp, cm], pMode: 'pick'});
const kd = builder(); const [Vp, Vm] = evalPM(kd);
const accN = kd.mod(kd.add('acc', kd.mul('rp', kd.mod(kd.sub(kd.mul('Up', Vm), kd.mul('Um', Vp))))));
const rpN = kd.mod(kd.mul('rp', 'rho'));
const bndCode = compile({frame: [...ST, ...mL], prog: kd.prog, out: [...FR, rpN, accN, Vp, Vm], pMode: 'pick'});
const kl = builder();
const U2p = kl.mod(kl.mul(kl.mod(kl.mul('Up', 'f1p')), kl.mod(kl.mul('f3p', 'Kp')))), U2m = kl.mod(kl.mul(kl.mod(kl.mul('Um', 'f1m')), kl.mod(kl.mul('f3m', 'Km'))));
const accL = kl.mod(kl.add('acc', kl.mul('rp', kl.mod(kl.sub(kl.mul(U2p, 'f2m'), kl.mul(U2m, 'f2p'))))));
const LVn = Object.keys(LV);
const lastCode = compile({frame: [...ST, ...LVn], prog: kl.prog, out: [...FR, accL], pMode: 'pick'});
const kh = builder(); const hN = kh.mod(kh.add(kh.mul('hq', 'b2'), 'q'));
const hornCode = compile({frame: [...FR, 'acc', 'hq', 'rest', 'q'], prog: kh.prog, out: [...FR, 'acc', hN, 'rest'], pMode: 'pick'});
const ke = builder(); const fin = ke.mod(ke.mul(ke.mul('z', 'hq'), ke.sub(ke.add(ke.mod(ke.mul('b4', ke.mod(ke.mul('b4', 'b4')))), ke.konst(82)), ke.mulc(ke.add('bu', ke.konst(9)), 18))));
const finCode = compile({frame: [...FR, 'acc', 'hq'], prog: ke.prog, out: [...FR, 'acc', fin], pMode: 'pick'});
const defs = [...defineFn(1, bndCode), ...defineFn(2, hornCode)];
// main continues: rp = 1, acc = 0, chat
depthExtra = FR.length;
code.push(OP.TRUE ?? 0x51, 0x00); depthExtra += 2; // rp acc
code.push(...pushNum(pushIdx(nPieces + NS)), OP.ROLL, ...parse6); depthExtra -= 1; // chat consumed... pushes shift
// After rolling chat out of the pushes, recompute depths: track removed pushes
let removed = new Set([nPieces + NS]);
const dIdx = (i) => { let d = nPush - 1 - i + depthExtra; for (const r of removed) if (r > i) d -= 1; return d; };
code.push(...chatCode); depthExtra = FR.length + 4; // [.. FR rp acc Up Um]
const stateStart = code.length;
for (let c = 0; c < NS; c++) {
  const idx = nPieces + (NS - 1 - c);
  code.push(...pushNum(dIdx(idx)), OP.ROLL, ...parse6, ...invoke(1)); removed.add(idx);
}
const stateEnd = code.length;
for (const n of LVn) code.push(...pushNum(LV[n]));
code.push(...lastCode); depthExtra = FR.length + 1; // [.. FR acc]
code.push(0x00); depthExtra += 1; // hq = 0
const qStart = code.length;
for (let i = nPieces - 1; i >= 0; i--) { // descending pieces; within a piece, highest limb last -> split from the end
  code.push(...pushNum(dIdx(i)), OP.ROLL); removed.add(i); depthExtra += 1;
  // loop 8 times: split off the LAST 32 bytes (highest degree first)
  code.push(OP.BEGIN, OP.SIZE, ...pushNum(32), OP.SUB, OP.SPLIT, ...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM, ...invoke(2), OP.SIZE, OP.NOT, OP.UNTIL, OP.DROP);
  depthExtra -= 1;
}
const qEnd = code.length;
code.push(...finCode);
// leave [.. acc rhs]; drop the 3 non-hashed pushes (stmt, digits, mask) left at the bottom: not needed for measurement
const full = run({pushes, code: [...defs, ...code]}), base = run({pushes, code: [...defs]});
for (const m of ['consensus', 'standard']) { const er = full['err_' + m]; if (er && !/clean|exactly one|unexpected number/i.test(String(er))) throw new Error(m + ': ' + er); }
const top = full.stack.slice(-2).map(vmNum).map(mod);
assert.deepEqual(top, [acc, rhs], 'VM vs JS (acc, z Q M)');
// section costs by truncation
const part = (end) => { const r = run({pushes, code: [...defs, ...code.slice(0, end)]}); return {c: r.consensus, s: r.standard}; };
const p0 = {c: base.consensus, s: base.standard}, pH = part(hashEnd), pS0 = part(stateStart), pS1 = part(stateEnd), pQ0 = part(qStart), pQ1 = part(qEnd);
const d = (a, b2) => ({consensus: b2.c - a.c, standard: b2.s - a.s});
console.log(JSON.stringify({states: NS, oddQ: NQ, pieces: nPieces,
  op: {total: d(p0, {c: full.consensus, s: full.standard}), transcript: d(p0, pH), basisAndChat: d(pH, pS0), boundaries: d(pS0, pS1), perBoundary: Math.round((pS1.c - pS0.c) / NS),
    lastChunk: d(pS1, pQ0), quotientHorner: d(pQ0, pQ1), perQcoeff: Math.round((pQ1.c - pQ0.c) / (8 * nPieces)), finalCheck: d(pQ1, {c: full.consensus, s: full.standard})},
  bytes: {defs: defs.length, main: code.length, bndFn: bndCode.length, hornFn: hornCode.length, mainStatesSection: stateEnd - stateStart, mainQSection: qEnd - qStart}}));
