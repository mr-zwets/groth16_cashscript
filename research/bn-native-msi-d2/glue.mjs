// MSI-GLS glue prototype (design 2): the shared dispatcher, the per-input transcript reconstruction by
// introspection, and the handover read / write checks, assembled with the SI-GLS symbolic assembler.
// This is a MEASUREMENT prototype for the design document, not the verifier: the Miller segment of each
// input is replaced by a stand-in (the inbound handover words are used as the "computed" outbound values).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {encodeDataPush} from '@bitauth/libauth';
import {Asm, OP, pushNum, pushData} from '../../chunked/bn254/sound-si-gls/asm.mjs';
import {p} from '../../chunked/bn254/sound-si-gls/math.mjs';

export const OPX = {INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7, INPUTBYTECODE: 0xca};
export const TAG = Buffer.from('MSIGLS/1');
export const WS_SIZE = 6978, NQ_FIXED = 132, WQ_SIZE = 32 * NQ_FIXED, T_SIZE = WS_SIZE + WQ_SIZE;
export const H_WORDS = 7, H_SIZE = 32 * H_WORDS; // handover: X0 X1 Y0 Y1 Z0 Z1 (projective B, Fp2) and R
export const K_ID = 17;                          // function id of the per-input program (SI-GLS functions use 1..16)
export const hdr = (n) => [...encodeDataPush(new Uint8Array(n))].slice(0, -n || undefined); // push header bytes for a size-n push
export const sha = (...b) => createHash('sha256').update(Buffer.concat(b.map((x) => Buffer.from(x)))).digest();

// ---------------- the shared redeem (identical for every input; P2SH32-locked) ----------------
// unlocking of input i: <D_i> <H_i> <K_i> <Delta>.  Delta: exactly 3 items; exactly n inputs; every input's
// UTXO locking equals mine (so every input runs Delta); SHA256(K_i) == table[OP_INPUTINDEX]; define and invoke K_i.
export function dispatcher(kHashes) {
  const n = kHashes.length; const c = [];
  c.push(OP.DEPTH, ...pushNum(3), OP.NUMEQUALVERIFY);
  c.push(OPX.TXINPUTCOUNT, ...pushNum(n), OP.NUMEQUALVERIFY);
  c.push(OPX.INPUTINDEX, OPX.UTXOBYTECODE);
  for (let j = 0; j < n; j++) c.push(...pushNum(j), OPX.UTXOBYTECODE, OP.OVER, OP.EQUALVERIFY);
  c.push(OP.DROP);
  c.push(OP.DUP, OP.SHA256, ...pushData(Buffer.concat(kHashes)), OPX.INPUTINDEX, ...pushNum(32), OP.MUL, OP.SPLIT, OP.NIP, ...pushNum(32), OP.SPLIT, OP.DROP, OP.EQUALVERIFY);
  c.push(...pushNum(K_ID), OP.DEFINE, ...pushNum(K_ID), OP.INVOKE);
  return Uint8Array.from(c);
}

// ---------------- per-input program skeleton ----------------
// seg: data segment sizes d_0..d_{n-1} (sum T_SIZE); i: this input; segment(a): emits the Miller segment
// (stand-in here). Returns {code, info}.
export function inputProgram({seg, i, padCode = 0, standIn = true}) {
  const n = seg.length; assert.equal(seg.reduce((a, b) => a + b, 0), T_SIZE);
  const last = i === n - 1;
  const a = new Asm(['D', 'H']);
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  a.defLocal('RD', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  const marks = {}; const mk = (name) => { marks[name] = a.code.length; };
  // own layout: |D_i| = d_i, |H_i| = 224 (0 for the last input)
  a.pick('D').op(OP.SIZE, 1, 'D_', 'sz').op(OP.NIP, 2, 'sz').push(seg[i]).op(OP.NUMEQUALVERIFY, 2);
  a.pick('H').op(OP.SIZE, 1, 'H_', 'sz').op(OP.NIP, 2, 'sz').push(last ? 0 : H_SIZE).op(OP.NUMEQUALVERIFY, 2);
  a.roll('D').drop();
  mk('transcript');
  // ---- transcript: T = D_0 || ... || D_{n-1} read from the inputs' unlocking bytecode at fixed offsets ----
  let have = 0; let acc = null; let wsDone = false;
  for (let j = 0; j < n; j++) {
    const hD = hdr(seg[j]);
    a.push(j).op(OPX.INPUTBYTECODE, 1, 'Uj');
    const wantH = (j === i - 1); // the previous input's handover
    const take = hD.length + seg[j] + (wantH ? hdr(H_SIZE).length + H_SIZE : 0);
    a.push(take).op(OP.SPLIT, 2, 'pre', 'rest').drop('rest');
    if (wantH) { a.push(hD.length + seg[j]).op(OP.SPLIT, 2, 'pre', 'Hb').roll('Hb').push(hdr(H_SIZE).length).op(OP.SPLIT, 2, 'hh', 'Hin').roll('hh').pushBytes(hdr(H_SIZE)).op(OP.EQUALVERIFY, 2).roll('pre'); }
    a.push(hD.length).op(OP.SPLIT, 2, 'hd', 'Dj').roll('hd').pushBytes(hD).op(OP.EQUALVERIFY, 2);
    if (acc === null) { a.rename('Dj', 'T'); acc = 'T'; } else { a.roll('T').roll('Dj').op(OP.CAT, 2, 'T'); }
    have += seg[j];
    if (!wsDone && have >= WS_SIZE) { // split WS off as soon as it is complete (stack items are capped at 10,000 B)
      a.roll('T').push(WS_SIZE).op(OP.SPLIT, 2, 'WS', 'T'); wsDone = true; }
  }
  a.rename('T', 'WQ');
  a.pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(WQ_SIZE).op(OP.NUMEQUALVERIFY, 2);
  a.pushBytes(TAG, 'tag').pick('WS').op(OP.CAT, 2, 'tw').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').pick('WQ').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
  a.invoke('P', ['p']);
  a.roll('zRaw'); U('zRaw'); a.pick('p').op(OP.MOD, 2, 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  mk('handover-in');
  // ---- handover in: 7 canonical words of the previous input ----
  const HN = ['hX0', 'hX1', 'hY0', 'hY1', 'hZ0', 'hZ1', 'hR'];
  if (i > 0) { for (const nm of HN) a.roll('Hin').invoke('RD', [nm, 'Hin']); a.drop('Hin'); }
  mk('segment');
  // ---- Miller segment (stand-in): "computed" outbound values = inbound ones (input 0: dummy constants) ----
  const OUT = HN.map((x) => 'o' + x);
  if (standIn) { if (i > 0) HN.forEach((nm) => a.pick(nm, 'o' + nm)); else OUT.forEach((nm, k) => a.push(BigInt(k + 1), nm)); }
  if (padCode) a.pushBytes(Buffer.alloc(padCode, 0x5a), 'pad').drop('pad');
  mk('handover-out');
  // ---- handover out: H_i word k canonical and == computed value k (mod p) ----
  if (!last) {
    for (let k = 0; k < H_WORDS; k++) {
      a.roll('H').invoke('RD', ['hv', 'H']);
      a.roll(OUT[k]).roll('hv').op(OP.SUB, 2, 'df').pick('p').op(OP.MOD, 2, 'dm').op(OP.NOT, 1, 'eq').op(OP.VERIFY, 1);
    }
    a.drop('H');
  } else { a.drop('H'); OUT.forEach((nm) => a.drop(nm)); }
  mk('cleanup');
  a.push(1, 'result').toAlt('result'); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result']; a.alt = [];
  const pro = a.prologue();
  const code = Uint8Array.from([...pro, ...a.code]);
  for (const k in marks) marks[k] += pro.length;
  return {code, marks, prologue: pro.length};
}
