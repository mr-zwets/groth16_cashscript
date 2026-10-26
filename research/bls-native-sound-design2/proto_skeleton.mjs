// Skeleton prototype in a real 5-input BCH 2026 transaction: the uniform loader redeem (input count, every sibling's
// locking, hash-checked code blob, define + invoke), and in the loaded blob, for one role: layout pin, the transcript
// over all inputs by introspection (chained SHA-256 over the phase-1 slices, quotient segments), the challenges,
// the constant-blob hash check, the statement decode, the loop environment, the GT-GLS tables, c^-1 and the start
// state, the IN decode and the OUT comparison against the successor's IN; for the terminal role also the terminal:
// Rconst, Frob(S_c), endpoint (psi), Horner over the whole quotient, the final identity, the exact GLS binding, and
// the curve / range / nibble checks. The event loop itself is measured by proto_worker.mjs; here the terminal role
// takes the post-loop values (T, F+-, R) from the value-level split as constants (marked), so the final identity is
// really checked in the VM. Writes skeleton.json with the measured setup and terminal costs.
//   node proto_skeleton.mjs [layout.json=layout-rec.json] [seed=3]
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createVirtualMachineBch2026, encodeDataPush, hash256, sha256 as SHA} from '@bitauth/libauth';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {p, r, mod, ETA, GAMMA1, PSI, X_ABS, XPOW, F2} from './blsmath.mjs';
import {randProof, VKC, le, rdle} from './protocol.mjs';
import {buildSplit, TAG, W, BC_NAMES} from './split.mjs';
import * as K from './kernels.mjs';

const OPX = {INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7, INPUTBYTECODE: 0xca};
const ITERS = Number(process.env.SCHED_ITERS ?? 2000);
const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];

// model layout -> split layout (hub = 0 in the prototypes; cb slots from the model's blob placement)
export const layoutFromModel = (L) => { assert.ok((L.hub ?? 0) === 0, 'prototype assumes hub = input 0');
  return {N: L.ins.length, bcast: L.variant === 'bcast', chunks: L.ins.map((x) => x.chunks), q: L.ins.map((x) => x.q / W), pad: L.ins.map((x) => x.pad),
    cbSlots: L.ins.filter((x) => x.cb).map((x) => ({host: x.j, slot: x.cb}))}; };
// ---------------- uniform redeem (loader) ----------------
// parts: [{host, off (byte offset in the host's unlocking bytecode), len}] in blob order; the parts are concatenated,
// hashed once (SHA-256) and defined as function 0
export function buildRedeem(N, parts, cbHash) {
  const load = parts.flatMap(({host, off, len}, k) => [...pushNum(host), OPX.INPUTBYTECODE, ...pushNum(off), OP.SPLIT, OP.NIP, ...pushNum(len), OP.SPLIT, OP.DROP, ...(k ? [OP.CAT] : [])]);
  return Uint8Array.from([OPX.TXINPUTCOUNT, ...pushNum(N), OP.NUMEQUALVERIFY,
    OP[0], OP.BEGIN, OP.DUP, OPX.UTXOBYTECODE, OPX.INPUTINDEX, OPX.UTXOBYTECODE, OP.EQUALVERIFY, OP.ADD1, OP.DUP, ...pushNum(N), OP.NUMEQUAL, OP.UNTIL, OP.DROP,
    ...load, OP.DUP, OP.SHA256, ...pushData(cbHash), OP.EQUALVERIFY, OP[0], OP.DEFINE, OP[0], OP.INVOKE]);
}
// blob parts: fixed slots per host (the hosts' padding absorbs any unused slot bytes, so witness sizes never depend on the blob)
const slotsOf = (layout, opts) => layout.cbSlots ?? [{host: layout.cbHost, slot: opts.blobSlot ?? 6800}];
const layWith = (layout, slots, n) => { const parts = []; let left = n; for (const {host, slot} of slots) { const len = Math.min(slot, left); parts.push({host, len}); left -= len; }
  assert.equal(left, 0, 'blob exceeds its slots'); return {...layout, cbParts: parts, pad: layout.pad.map((x, j) => x + slots.filter((q) => q.host === j).reduce((a, q) => a + q.slot, 0) - parts.filter((q) => q.host === j).reduce((a, q) => a + q.len, 0))}; };
const redeemFor = (layout, s, blob) => buildRedeem(layout.N, s.layoutUsed.cbParts.filter((x) => x.len > 0).map(({host, len}) => ({host, off: 3 + s.offsets[host].CB, len})), SHA.hash(blob));

// ---------------- the role program (blob = prologue + code) ----------------
export function buildMain(s, layout, role, {terminal = false, stop} = {}) {
  const N = layout.N, j = role; const P1len = s.P1.map((x) => x.length), qlen = s.Qseg.map((x) => x.length), at = s.offsets;
  const a = new Asm(['W']); const marks = []; const mark = (n) => marks.push({name: n, off: a.code.length});
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  a.defLocal('P', 0, 1, (q) => q.push(p, 'p'));
  a.defLocal('RD', 1, 2, (q) => { q.push(W).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    q.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.defLocal('EV', 12, 2, (q) => q.kernel(K.kEval(), ['vp', 'vm'], {iters: ITERS}));
  a.defLocal('TM', 4, 16, (q) => q.kernel(K.kTable(), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  // decode words from a blob; long blobs are first cut into 8-word pieces, so a word split never re-pushes the whole tail
  const RDn = (blob, names, onWord) => {
    if (names.length <= 12) { for (const n of names) { a.invoke('RD', [n, blob]); if (onWord) onWord(n); } return; }
    for (let i = 0; i < names.length; i += 8) {
      const piece = names.slice(i, i + 8); const last = i + 8 >= names.length;
      if (!last) a.roll(blob).push(8 * W).op(OP.SPLIT, 2, 'pc', blob).roll('pc'); else a.roll(blob).rename(blob, 'pc');
      for (const n of piece) { a.invoke('RD', [n, 'pc']); if (onWord) onWord(n); }
      a.drop('pc');
    }
    a.push(0, blob); // the (empty) blob stays named for the caller's drop
  };
  const cut = (src, off, len, as) => { a.pick(src, as + '#s'); if (off) a.push(off).op(OP.SPLIT, 2, as + '#l', as).drop(as + '#l'); else a.rename(as + '#s', as); if (len !== undefined) a.push(len).op(OP.SPLIT, 2, as, as + '#r').drop(as + '#r'); };
  // 1. layout pin
  mark('pin'); a.emit(OP.DEPTH, ...pushNum(1), OP.NUMEQUALVERIFY);
  a.pick('W').emit(OP.SIZE); a.st.push('sz'); a.push(s.sizes[j]).op(OP.NUMEQUALVERIFY, 2).drop();
  const bcast = !!layout.bcast, hub = !bcast || j === 0; // hub: derives the challenges (every input in the base layout)
  if (hub) {
    // 2. transcript over all inputs (introspection; the same bytes for every input)
    mark('transcript'); a.pushBytes(TAG, 'h'); let haveQS = false; const keep = new Set([0]);
    for (let i = 0; i < N; i++) {
      a.push(i).op(OPX.INPUTBYTECODE, 1, 'u').push(3 + P1len[i]).op(OP.SPLIT, 2, 'hd', 'tl');
      if (qlen[i]) { a.roll('tl').push(qlen[i]).op(OP.SPLIT, 2, 'qi', 'rest').drop('rest'); if (haveQS) a.roll('QS').roll('qi').op(OP.CAT, 2, 'QS'); else a.rename('qi', 'QS'); haveQS = true; } else a.drop('tl');
      if (keep.has(i)) a.pick('hd', 'H' + i);
      if (i === j - 1) a.pick('hd', 'Hprev');
      a.roll('h').roll('hd').op(OP.CAT, 2, 'hh').op(OP.SHA256, 1, 'h');
    }
    a.pick('h').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
    if (terminal) a.pick('QS', 'QS2'); else a.rename('QS', 'QS2');
    a.roll('h').pick('rhoRaw').op(OP.CAT, 2, 'hz').roll('QS2').op(OP.CAT, 2, 'hzq').op(OP.SHA256, 1, 'zRaw');
    U('zRaw'); a.rename('zRaw', 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'nz').op(OP.VERIFY, 1);
    a.roll('rhoRaw'); U('rhoRaw'); a.rename('rhoRaw', 'rho'); a.invoke('P', ['p']);
  } else {
    // consumer (bcast): input 0's statement slice and the broadcast area, the predecessor's slice, [the quotient] by introspection
    mark('transcript');
    a.push(0).op(OPX.INPUTBYTECODE, 1, 'u0').push(3 + P1len[0]).op(OP.SPLIT, 2, 'H0', 'u0r');
    a.roll('u0r').push(at[0].BC - P1len[0]).op(OP.SPLIT, 2, 'x', 'BCb').drop('x').roll('BCb').push(BC_NAMES.length * W).op(OP.SPLIT, 2, 'BCb', 'y').drop('y');
    mark('bcast-decode'); RDn('BCb', BC_NAMES); a.drop('BCb');
    if (j - 1 === 0) a.pick('H0', 'Hprev'); else a.push(j - 1).op(OPX.INPUTBYTECODE, 1, 'uq').push(3 + P1len[j - 1]).op(OP.SPLIT, 2, 'Hprev', 'uqr').drop('uqr');
    if (terminal) { let have = false; for (let i = 0; i < N; i++) if (qlen[i]) {
      a.push(i).op(OPX.INPUTBYTECODE, 1, 'u').push(3 + at[i].Q).op(OP.SPLIT, 2, 'x', 'u').drop('x').push(qlen[i]).op(OP.SPLIT, 2, 'qi', 'y').drop('y');
      if (have) a.roll('QS').roll('qi').op(OP.CAT, 2, 'QS'); else a.rename('qi', 'QS'); have = true; } }
    a.invoke('P', ['p']);
  }
  // 3. this role's constant blob (delta lines) against its pinned hash
  mark('consts'); cut('W', at[j].K, s.K[j].length, 'Kj'); a.pick('Kj').op(OP.SHA256, 1, 'kh').pushBytes(s.Khash[j]).op(OP.EQUALVERIFY, 2); a.drop('Kj');
  // 4. statement, s^c (from input 0's slice)
  mark('statement'); a.roll('H0').push(3).op(OP.SPLIT, 2, 'hdr0', 'H0').drop('hdr0');
  RDn('H0', ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']);
  a.roll('H0').push(64).op(OP.SPLIT, 2, 'NN', 'H0').roll('H0').push(128).op(OP.SPLIT, 2, 'NIB', 'H0');
  RDn('H0', ['sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5']);
  if (terminal) { // curve checks, n < r, nibble range
    mark('global');
    for (const [x, y] of [['xA', 'yA'], ['xC', 'yC']]) { a.pick(x, 'x').pick(y, 'y'); a.kernel(K.kG1Check(), ['d']); a.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); }
    { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
      const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
      const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
      k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(4n))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.c(4n))));
      a.kernel(k, ['tw0', 'tw1'], {iters: 300}); a.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); }
    a.push(r, 'r');
    for (const n of ['n0', 'n1']) { a.roll('NN').push(32).op(OP.SPLIT, 2, 'w', 'NN').roll('w'); U('w'); a.rename('w', n); a.pick(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
    a.drop('NN');
    a.pick('NIB', 'Nc'); a.pushBytes(Buffer.alloc(128, 0x0f)).op(OP.AND, 2, 'Nm').pick('NIB').op(OP.EQUALVERIFY, 2);
  } else { a.drop('NN'); a.drop('NIB'); }
  // 5. loop environment: z powers, the eta z powers, point/env products
  if (hub) {
  mark('env'); for (const n of ['xA', 'yA', 'xC', 'yC']) a.pick(n, n + 'k'); for (const n of ['xA', 'yA', 'xC', 'yC']) a.rename(n + 'k', n) && 0;
  // (kPowers consumes xA yA xC yC: the copies just made carry those names, the originals are renamed out of the way)
  a.kernel(K.kPowers(), ['z2', 'z3', 'z4', 'z5', 'z6', 't', 'xz2', 'xz2t', 'xz23', 'xz23t', 'yz3', 'yz3t', 'cz2', 'cz2t', 'ycz3'], {iters: ITERS});
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y); const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n));
    k.output(m(mul(eta, k.env('z'))), m(mul(eta2, k.env('z2'))), k.neg(k.env('z3')), k.neg(m(mul(eta, k.env('z4')))), k.neg(m(mul(eta2, k.env('z5')))));
    a.kernel(k, ['ez', 'ez2', 'ez3', 'ez4', 'ez5'], {iters: 300}); }
  // 6. GT-GLS tables TP_k / TM_k (R_{k,0}, R_{k,1} baked; R_{k,2/3} at eta z)
  mark('tables');
  for (const k of [0, 1]) {
    for (const i of [0, 1]) for (let jj = 0; jj < 6; jj++) a.push(VKC.R[k][i][jj], `R${k}${i}_${jj}`);
    for (const i of [0, 1, 2, 3]) { for (let jj = 0; jj < 6; jj++) (i < 2 ? a.pick.bind(a) : a.roll.bind(a))(`R${k}${i % 2}_${jj}`); for (const n of i < 2 ? ZP : EZP) a.pick(n); a.invoke('EV', [`vp${i}`, `vm${i}`]); }
    a.arrange(['vp0', 'vp1', 'vp2', 'vp3']).invoke('TM', Array.from({length: 16}, (_, n) => `TP${k}_${15 - n}`));
    a.arrange(['vm0', 'vm1', 'vm2', 'vm3']).invoke('TM', Array.from({length: 16}, (_, n) => `TM${k}_${15 - n}`));
  }
  // 7. c^-1 at +-z and the start state
  mark('start'); for (let jj = 0; jj < 6; jj++) a.pick('sc' + jj, 'in' + jj); for (let i = 0; i < 6; i++) a.pick(ZP[i], 'in' + (6 + i)); a.invoke('EV', ['Scp', 'Scm']);
  if (bcast) { // the hub checks the claimed broadcast area against what it computed (exact, canonical words)
    mark('bcast-check'); cut('W', at[0].BC, BC_NAMES.length * W, 'BCb');
    // (computed - claimed) mod p == 0: computed values may be unreduced or negative; claimed words are canonical (RD)
    RDn('BCb', BC_NAMES.map((n) => 'c#' + n), (cn) => { const n = cn.slice(2); a.roll(cn).pick(n === 'cp' ? 'Scm' : n === 'cm' ? 'Scp' : n).op(OP.SUB, 2, 'df').pick('p').op(OP.MOD, 2, 'dm').op(OP.NOT, 1, 'eq').op(OP.VERIFY, 1); });
    a.drop('BCb');
  }
  }
  mark('start2');
  if (j === 0) { a.pick('Scm', 'Fp').pick('Scp', 'Fm'); }
  else { a.roll('Hprev').push(3 + P1len[j - 1] - 6 * W).op(OP.SPLIT, 2, 'hl', 'Sst').drop('hl'); RDn('Sst', ['in0', 'in1', 'in2', 'in3', 'in4', 'in5']); a.drop('Sst');
    for (let i = 0; i < 6; i++) a.pick(ZP[i], 'in' + (6 + i)); a.invoke('EV', ['Fp', 'Fm']); }
  // 8. IN decode (T, R from the predecessor)
  mark('handoff');
  if (j > 0) { cut('W', at[j].IN, 7 * W, 'INb'); RDn('INb', ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'R']); a.drop('INb'); }
  else { for (const n of ['X0', 'X1', 'Y0', 'Y1']) a.pick(n.replace('X', 'xB').replace('Y', 'yB'), n); a.push(1, 'Z0').push(0, 'Z1').push(0, 'R'); }
  if (stop === 'preloop') return finish();
  // ---- (the event loop runs here: proto_worker.mjs) ----
  // the post-loop state is taken from the value-level split (constants) so that the following checks are real
  const tr = s.trace[j]; const post = {X0: tr.T[0].c0, X1: tr.T[0].c1, Y0: tr.T[1].c0, Y1: tr.T[1].c1, Z0: tr.T[2].c0, Z1: tr.T[2].c1, Fp: tr.F[0], Fm: tr.F[1], R: tr.R};
  mark('post-loop-constants'); for (const n of Object.keys(post)) { a.drop(n); a.push(post[n], n); }
  // 9. OUT: compare (T, R) with the successor's IN (exact, canonical words)
  mark('out');
  if (j + 1 < N) {
    a.push(j + 1).op(OPX.INPUTBYTECODE, 1, 'u').push(3 + at[j + 1].IN).op(OP.SPLIT, 2, 'ul', 'u').drop('ul').push(7 * W).op(OP.SPLIT, 2, 'nx', 'ur').drop('ur');
    // (computed - claimed) mod p == 0: the loop's values may be unreduced or negative; the successor's words are canonical (RD)
    for (const n of ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'R']) { a.invoke('RD', ['v', 'nx']); a.roll('v').roll(n).op(OP.SUB, 2, 'df').pick('p').op(OP.MOD, 2, 'dm').op(OP.NOT, 1, 'eq').op(OP.VERIFY, 1); }
    a.drop('nx');
  }
  if (terminal) {
    // 10. terminal: F *= Rconst(+-z); R <- R rho + F+ Fr(-z) - F- Fr(z), Fr = Frob(S_c); endpoint T == -psi(B), Z != 0
    mark('terminal');
    for (let jj = 0; jj < 6; jj++) a.push(VKC.Rconst[jj], 'in' + jj); for (let i = 0; i < 6; i++) a.pick(ZP[i], 'in' + (6 + i)); a.invoke('EV', ['rp', 'rm']);
    { const k = new Kernel(); k.output(k.mod(k.mul(k.in('Fp'), k.in('rp'))), k.mod(k.mul(k.in('Fm'), k.in('rm')))); a.kernel(k, ['Fp', 'Fm'], {iters: 200}); }
    { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      // c_j = Phi(gamma1^j)(z) = g_j0 + g_j1 t, gamma1^j from the baked gamma1
      const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]]; const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
      for (let jj = 2; jj <= 5; jj++) g.push(fm(...g[jj - 2], ...g[0]));
      const cj = [null, ...g.map(([g0, g1]) => m(k.add(g0, mul(g1, E('t')))))];
      const sc = [0, 1, 2, 3, 4, 5].map((jj) => I('sc' + jj)); const sj = [null, ...[1, 2, 3, 4, 5].map((jj) => m(mul(sc[jj], cj[jj])))];
      const ev = m(k.sum(sc[0], k.c(2n), k.neg(E('z6')), mul(sj[2], E('z2')), mul(sj[4], E('z4')))), od = m(k.sum(mul(sj[1], E('z')), mul(sj[3], E('z3')), mul(sj[5], E('z5'))));
      k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), k.sub(ev, od))), mul(I('Fm'), k.add(ev, od)))));
      a.kernel(k, ['R'], {iters: 1500}); }
    { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.in(n)); const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => k.in(n));
      const cm = (a0, a1, g) => [k.mod(k.add(k.mul(a0, k.c(g.c0)), k.mul(a1, k.c(g.c1)))), k.mod(k.sub(k.mul(a0, k.c(g.c1)), k.mul(a1, k.c(g.c0))))]; // conj(a) g
      const [px0, px1] = cm(x0, x1, PSI.x), [py0, py1] = cm(y0, y1, PSI.y);
      const fs = (a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
      const [u0, u1] = fs(px0, px1, Z0, Z1), [v0, v1] = fs(py0, py1, Z0, Z1);
      k.output(k.mod(k.sub(X0, u0)), k.mod(k.sub(X1, u1)), k.mod(k.add(Y0, v0)), k.mod(k.add(Y1, v1)), k.mod(Z0), k.mod(Z1));
      a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1', 'ez0', 'ez1'], {iters: 800});
      a.op(OP.BOOLOR, 2, 'znz').op(OP.VERIFY, 1); for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
    // 11. quotient: Q(z) = z q(z^2), Horner over the whole quotient (highest word first), 4 words per step, each word < p
    mark('horner');
    { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
    a.roll('QS').push(0, 'acc'); // loop-carried items on top: the body then restores its entry layout without moving the rest
    a.loop((q) => {
      q.roll('QS').push(4 * W).op(OP.SPLIT, 2, 'Q4', 'QS').roll('Q4');
      for (let jj = 0; jj < 4; jj++) q.invoke('RD', ['q' + jj, 'Q4']);
      q.drop('Q4');
      const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
      k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); q.kernel(k, ['acc'], {iters: 300});
      q.pick('QS', 'QSc').op(OP.SIZE, 1, 'QSc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
    });
    a.drop('QS');
    { const k = new Kernel(); const z6 = k.env('z6'); const Mz = k.add(k.sub(k.mul(z6, z6), k.mul(k.c(2n), z6)), k.c(2n));
      k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
    a.op(OP.NOT, 1, 'idok').op(OP.VERIFY, 1);
    // 12. GT-GLS binding, exact integers: sum_e 2^(63-e) TB[N_k[e]] == n_k, TB[n] = sum_{i in n} |x|^i
    mark('binding');
    { const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.c(XPOW[i])); const T = [k.c(0n)];
      for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : k.add(T[n ^ lo], v[b]); }
      k.output(...T.slice().reverse()); a.kernel(k, Array.from({length: 16}, (_, n) => `TB_${15 - n}`), {iters: 50}); }
    a.roll('NIB').push(64).op(OP.SPLIT, 2, 'N0', 'N1');
    for (const kk of [0, 1]) {
      a.roll('N' + kk).push(0, 'gacc');
      a.loop((q) => {
        q.roll('N' + kk).push(1).op(OP.SPLIT, 2, 'b', 'N' + kk).roll('b').op(OP.BIN2NUM, 1, 'x');
        assert.equal(q.top(), 'x'); q.st.pop(); const d0 = q.depth('TB_0'); for (let n = 1; n < 16; n++) assert.equal(q.depth('TB_' + n), d0 + n); q.emit(...pushNum(d0), OP.ADD, OP.PICK); q.st.push('tb');
        q.roll('gacc').op(OP.DUP, 0); q.st.push('gacc2'); q.op(OP.ADD, 2, 'g2').roll('tb').op(OP.ADD, 2, 'gacc');
        q.pick('N' + kk, 'Nc').op(OP.SIZE, 1, 'Nc', 'ns').op(OP.NIP, 2, 'ns').op(OP.NOT, 1, 'done');
      });
      a.drop('N' + kk); a.roll('gacc').roll('n' + kk).op(OP.NUMEQUALVERIFY, 2);
    }
  }
  return finish();
  function finish() {
    mark('cleanup'); a.push(1, 'result'); a.op(OP.TOALT, 1); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result'];
    const pro = a.prologue(); return {blob: Uint8Array.from([...pro, ...a.code]), marks: marks.map((m) => ({...m, off: m.off + pro.length})), prologue: pro.length};
  }
}

// ---------------- assemble the transaction and run one role ----------------
const vms = {cons: createVirtualMachineBch2026(false), std: createVirtualMachineBch2026(true)};
const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
// transaction builder for rejection tests: the honest 5-input transaction for `role`'s blob, plus an evaluator
export function prepare(layout, seed, role, opts = {}) {
  const slots = slotsOf(layout, opts); const lay = (n) => layWith(layout, slots, n);
  let blobLen = 3000, built, s;
  for (let it = 0; it < 4; it++) { s = buildSplit(randProof(seed), lay(blobLen), {blob: Buffer.alloc(blobLen, 0x61)}); built = buildMain(s, lay(blobLen), role, opts); if (built.blob.length === blobLen) break; blobLen = built.blob.length; }
  s = buildSplit(randProof(seed), lay(blobLen), {blob: Buffer.from(built.blob)}); s.layoutUsed = lay(blobLen); const blob = built.blob;
  const R = redeemFor(layout, s, blob); const lock = p2sh32(R);
  const unlOf = (Wj, red = R) => Wj.map((x) => Uint8Array.from([...encodeDataPush(x), ...encodeDataPush(red)]));
  const txOf = (unl) => ({version: 2, locktime: 0, inputs: unl.map((u, i) => ({outpointIndex: i, outpointTransactionHash: new Uint8Array(32).fill(i + 1), sequenceNumber: 0, unlockingBytecode: u})), outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]});
  const srcOf = (n, lk = lock) => Array.from({length: n}, () => ({lockingBytecode: lk, valueSatoshis: 1000n}));
  const evalInput = (i, tx, src, mode = 'std') => { const st = vms[mode].evaluate({inputIndex: i, sourceOutputs: src, transaction: tx}); return st.error ?? 'accepted'; };
  return {s, blob, R, lock, Wj: s.Wj.map((x) => Buffer.from(x)), unlOf, txOf, srcOf, evalInput};
}

export function runRole(layout, seed, role, opts = {}) {
  // fixed point: the blob's size enters the holder's witness size (a pushed constant in the blob)
  // the holder's padding absorbs the blob length so every witness size (and so the transcript) is independent of it
  const slots = slotsOf(layout, opts); const lay = (n) => layWith(layout, slots, n);
  let blobLen = 3000, built, s;
  for (let it = 0; it < 4; it++) {
    s = buildSplit(randProof(seed), lay(blobLen), {blob: Buffer.alloc(blobLen, 0x61)});
    built = buildMain(s, lay(blobLen), role, opts); if (built.blob.length === blobLen) break; blobLen = built.blob.length;
  }
  s = buildSplit(randProof(seed), lay(blobLen), {blob: Buffer.from(built.blob)}); s.layoutUsed = lay(blobLen); const built2 = buildMain(s, lay(blobLen), role, opts);
  assert.deepEqual(built2.blob, built.blob, 'blob fixed point'); const blob = built.blob;
  const R = redeemFor(layout, s, blob);
  const lock = p2sh32(R);
  const unl = s.Wj.map((x) => Uint8Array.from([...encodeDataPush(x), ...encodeDataPush(R)]));
  unl.forEach((u, j) => assert.equal(u[0], 0x4d, 'PUSHDATA2 header for W_' + j));
  const tx = {version: 2, locktime: 0, inputs: unl.map((u, i) => ({outpointIndex: i, outpointTransactionHash: new Uint8Array(32).fill(i + 1), sequenceNumber: 0, unlockingBytecode: u})), outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]};
  const src = unl.map(() => ({lockingBytecode: lock, valueSatoshis: 1000n}));
  const out = {role, blob: blob.length, redeem: R.length, unlocking: unl[role].length, prologue: built.prologue};
  for (const m of ['cons', 'std']) {
    const st = vms[m].evaluate({inputIndex: role, sourceOutputs: src, transaction: tx});
    out[m] = {op: st.metrics.operationCost, budget: (41 + unl[role].length) * 800, error: st.error ?? null};
    if (m === 'std') { // per-section op (debug trace)
      const trace = vms.std.debug({inputIndex: role, sourceOutputs: src, transaction: tx}); const sec = {}; let prev = 0, cur = 'loader';
      const blobFn = (stt) => stt.instructions?.length; // section by instruction pointer inside the blob
      const offs = built.marks.slice().sort((x, y) => x.off - y.off);
      for (const stt of trace) { const c = stt.metrics?.operationCost ?? 0; const d = c - prev; prev = c;
        const instr = stt.instructions; let name = cur;
        if (instr && instr.length && stt.ip !== undefined) { const ip = stt.ip; const byteOff = instr.slice(0, ip).reduce((acc, ins) => acc + 1 + (ins.data ? ins.data.length + (ins.data.length < 76 ? 0 : ins.data.length < 256 ? 1 : 2) : 0), 0);
          if (instr.length > 200) { name = 'blob:prologue'; for (const mm of offs) if (mm.off <= byteOff) name = 'blob:' + mm.name; cur = name; } }
        sec[name] = (sec[name] ?? 0) + d; void blobFn;
        if (process.env.PROF && name === 'blob:' + process.env.PROF && stt.ip !== undefined && instr) { if (process.env.PROFDUMP) { out.acc_ = (out.acc_ ?? 0) + d; const oc = instr[stt.ip - 1]?.opcode; if (oc === 0x66) { (out.iters ??= []).push(out.acc_); out.acc_ = 0; } { const kk2 = (oc ?? -1).toString(16); (out.cnt ??= {})[kk2] = (out.cnt[kk2] ?? 0) + 1; } if (oc === 0x7a && d > 1000 && (out.big = (out.big ?? 0) + 1) < 12) console.log('    big roll', d, 'ip', stt.ip, 'depth', stt.stack.length, 'top len', stt.stack.at(-1)?.length); if (oc === 0x7a || oc === 0x95 || oc === 0x97) { const kk = oc.toString(16); (out.byop ??= {})[kk] = (out.byop[kk] ?? 0) + d; } } const prevIns = instr[stt.ip - 1]; const key = prevIns ? prevIns.opcode.toString(16) : '?'; (out.prof ??= {})[key] = ((out.prof ??= {})[key] ?? 0) + d; } }
      out.sections = sec;
    }
  }
  out.verify = vms.std.verify({sourceOutputs: src, transaction: tx});
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const L = JSON.parse(readFileSync(process.argv[2] ?? 'layout-rec.json'));
  const layout = layoutFromModel(L);
  const seed = Number(process.argv[3] ?? 3); const res = [];
  for (let role = 0; role < layout.N; role++) {
    const terminal = role === layout.N - 1; const o = runRole(layout, seed, role, {terminal}); res.push(o);
    console.log(`role ${role}${terminal ? ' (terminal)' : ''}: blob ${o.blob} B, redeem ${o.redeem} B, unlocking ${o.unlocking} B; op cons ${o.cons.op} std ${o.std.op} (budget ${o.std.budget}) ${o.std.error ?? 'ok'}`);
    if (o.cnt) console.log('    counts', JSON.stringify(o.cnt));
    if (o.iters) console.log('    iters', o.iters.map((x) => Math.round(x / 1000)).join(' '), JSON.stringify(o.byop));
    if (o.prof) console.log('    prof', Object.entries(o.prof).sort((x, y) => y[1] - x[1]).slice(0, 12).map(([k, v]) => `${k}:${Math.round(v / 1000)}k`).join(' '));
    console.log('   ', Object.entries(o.sections).filter(([, v]) => v > 1000).map(([k, v]) => `${k} ${Math.round(v / 1000)}k`).join(', '));
  }
  writeFileSync('skeleton-runs.json', JSON.stringify(res, null, 1));
}
void F2; void X_ABS; void le; void rdle;
