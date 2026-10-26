// Per-input setup prototype v2 (the design's layout) in a REAL 3-input bch-2026 transaction (libauth BCH_2026 VM,
// standard mode). Differences from v1 (setup.mjs, where every input hashes every input's data):
//   - a 96-byte digest list D = d0 || d1 || d2 sits in input 0; h0 = SHA256(TAG || D); input j checks
//     D[j] == SHA256(its own committed data) on its OWN stack items, so no input hashes another input's data;
//   - each input carries its own delta-slope slice, authenticated by a per-role SHA256 constant in the library.
//   identical P2SH32 redeem R in every input -> loads the library blob from the holder input by
//   OP_INPUTBYTECODE, checks its SHA256 against the constant in R, OP_DEFINEs and OP_INVOKEs it;
//   the library pins the input's own push layout, pins the graph (input count, every input locked by the
//   same P2SH32), reads every input's committed data by byte range of the raw unlocking bytecode, derives
//   h0 / rho / z, authenticates the delta-slope blob (hash chained from the library), decodes the statement
//   words, runs the owner checks (input 0), decodes the incoming handover, and checks the outgoing one
//   against the next input's handover field.
// The GT-GLS tables, powers of z and loop environment are NOT included here: their cost is measured in situ in
// SI-GLS (profile.mjs: powers 0.119M, gls-tables 0.358M, loop-setup 0.046M) and added by the model.
//
//   node research/sound-bn254-native/prototypes/setup.mjs
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createVirtualMachineBch2026, encodeDataPush, hash256} from '@bitauth/libauth';
import {Asm, Kernel, OP, pushNum, pushData} from '../../../chunked/bn254/sound-si-gls/asm.mjs';
import {p, r, mod, B_TWIST, DIGITS, NE} from '../../../chunked/bn254/sound-si-gls/math.mjs';
import {le32, isBoundary} from '../../../chunked/bn254/sound-si-gls/protocol.mjs';
import {fixtureData} from './loop.mjs';

const IX = {INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7, INPUTBYTECODE: 0xca};
const sha = (b) => createHash('sha256').update(b).digest();
const enc = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
const hdr = (len) => encodeDataPush(new Uint8Array(len)).length - len;
const rnd = (s) => mod(BigInt(s) ** 37n + 4242n);
const TAG = Buffer.from('SIGLS-MX/1');

// ---------------- layout (the model's best layout, fixture 0) ----------------
export const RANGES = JSON.parse(process.env.RANGES ?? '[[0,22],[22,50],[50,65]]');
const NQ = Number(process.env.NQ ?? 114);
const data = fixtureData(0);
const stream = (a, b, terminal) => { // chunk records: inverse-norm witnesses of the chunk's B steps, then its state
  const out = [];
  for (let e = a; e < b; e++) { for (const t of data.norms[e]) out.push(le32(t)); if (isBoundary(e)) for (let j = 0; j < 6; j++) out.push(le32(rnd(100 + 6 * e + j))); }
  if (terminal) out.push(le32(rnd(7)), le32(rnd(8))); // the two terminal B additions
  return Buffer.concat(out);
};
const STREAM = RANGES.map(([a, b], i) => stream(a, b, i === 2));
const STMT = Buffer.concat([...['x', 'y'].map((c) => le32(data.A[c])), le32(data.B.x.c0), le32(data.B.x.c1), le32(data.B.y.c0), le32(data.B.y.c1),
  le32(data.C.x), le32(data.C.y), le32(rnd(11) % r), le32(rnd(12) % r), Buffer.from(data.N[0]), Buffer.from(data.N[1]), ...Array.from({length: 6}, (_, j) => le32(rnd(20 + j)))]);
assert.equal(STMT.length, 642);
const WQ = Buffer.concat(Array.from({length: NQ}, (_, j) => le32(rnd(300 + j) || 1n)));
const HAND = [null, Buffer.concat(Array.from({length: 5}, (_, j) => le32(rnd(50 + j)))), Buffer.concat(Array.from({length: 5}, (_, j) => le32(rnd(60 + j))))];
const DBLOB = Buffer.concat(data.lams.slice(0, 88).flatMap((l) => [le32(l.c0), le32(l.c1)]));
const LIB_SIZE = Number(process.env.LIB ?? 5800); // code + constants (estimate)
const FILL = [0, 0, 0].map((_, i) => Number(process.env['FILL' + i] ?? 0));
// push lists per input (R appended later): input 0 [STMT, STREAM0, WQ, FILL], 1 [HAND1, STREAM1, DBLOB, FILL], 2 [HAND2, STREAM2, LIB, FILL]
const LIB_HOLDER = 2, D_HOLDER = 1;

// ---------------- library (role code) ----------------
// Layout (minimal pushes, R last):
//   input 0: [D 96] [STMT 642] [S0] [DS0] [FILL] [WQ] [R]      d0 = SHA256(STMT || S0); z-tail = raw pushes FILL, WQ
//   input 1: [S1] [HAND1 160] [DS1] [FILL] [R]                  d1 = SHA256(S1)
//   input 2: [S2] [HAND2 160] [DS2] [LIB] [FILL] [R]            d2 = SHA256(S2); LIB read by every R
const DS = RANGES.map(([a, b], i) => DBLOB.subarray(64 * data.jAt[a], 64 * (data.jAt[b] + (i === 2 ? 2 : 0))));
const ITEMS = [['D', 'STMT', 'S', 'DS', 'FILL', 'WQ'], ['S', 'HAND', 'DS', 'FILL'], ['S', 'HAND', 'DS', 'LIB', 'FILL']];
const SIZES = (i) => ({D: 96, STMT: 642, S: STREAM[i].length, DS: DS[i].length, HAND: 160, LIB: LIB_SIZE});
function roleCode(i, ctx, off) {
  const items = ITEMS[i]; const sz = SIZES(i);
  const a = new Asm(items, ctx);
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  const hdrOf = (n) => { a.pick(n, 's').push(76).op(OP.LESSTHAN, 2, 'l1').op(OP.NOT, 1, 'g1').pick(n, 's2').push(256).op(OP.LESSTHAN, 2, 'l2').op(OP.NOT, 1, 'g2').op(OP.ADD, 2, 'h').op(OP.ADD1, 1, 'h').op(OP.ADD, 2, n); };
  // 1. own layout (top item first)
  a.emit(OP.DEPTH, ...pushNum(items.length), OP.NUMEQUALVERIFY);
  let nvar = 0;
  for (const n of items.slice().reverse()) {
    if (n === 'WQ') { a.op(OP.SIZE, 1, n, 'qs').drop(n).pick('qs', 'q').push(32).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
      a.pick('qs', 'q').push(32).push(32 * 132 + 1).op(OP.WITHIN, 3, 'ok').op(OP.VERIFY, 1); hdrOf('qs'); a.toAlt('qs'); nvar++; continue; }
    if (n === 'FILL') { a.op(OP.SIZE, 1, n, 'fs').pick('fs', 'fs2').push(0).op(OP.SWAP, 2, 'z0', 'fs2').op(OP.NUM2BIN, 2, 'zz').roll(n).op(OP.EQUALVERIFY, 2); hdrOf('fs'); a.toAlt('fs'); nvar++; continue; }
    a.op(OP.SIZE, 1, n, 's').push(sz[n]).op(OP.NUMEQUALVERIFY, 2);
    if (n === 'DS') { a.pick(n, 'c').op(OP.SHA256, 1, 'h').pushBytes(sha(DS[i]), 'K').op(OP.EQUALVERIFY, 2); a.toAlt(n); }
    else if (n === 'LIB') a.drop(n);
    else a.toAlt(n); // D, STMT, S, HAND: kept (altstack)
  }
  // own commitment digest d_i
  const kept = items.filter((n) => !['WQ', 'FILL', 'LIB', 'DS'].includes(n));
  for (const n of kept.slice().reverse().filter(() => false)) a.fromAlt(n);
  // (altstack top-down now: reverse order of toAlt) -> bring back in order
  const altOrder = items.filter((n) => n !== 'WQ' && n !== 'FILL' && n !== 'LIB').reverse(); // pushed order (first pushed = deepest)
  const pulled = altOrder.slice().reverse(); for (const n of pulled) a.fromAlt(n);
  if (i === 0) a.pick('STMT', 'c').pick('S', 'c2').op(OP.CAT, 2, 'c').op(OP.SHA256, 1, 'di'); else a.pick('S', 'c').op(OP.SHA256, 1, 'di');
  // 2. graph: 3 inputs, all locked by this same P2SH32 redeem
  a.emit(IX.TXINPUTCOUNT); a.st.push('n'); a.push(3).op(OP.NUMEQUALVERIFY, 2);
  a.emit(IX.INPUTINDEX); a.st.push('ix'); a.op(IX.UTXOBYTECODE, 1, 'mine');
  for (let j = 0; j < 3; j++) { a.push(j).op(IX.UTXOBYTECODE, 1, 'u').pick('mine').op(OP.EQUALVERIFY, 2); }
  a.drop('mine');
  // 3. own raw size (minimal pushes): fixed part + the variable pushes' encodings
  a.emit(IX.INPUTINDEX); a.st.push('ix'); a.op(IX.INPUTBYTECODE, 1, 'self');
  a.op(OP.SIZE, 1, 'self', 'usz'); a.push(off.fixedRaw[i], 'fx'); for (let k = 0; k < nvar; k++) a.fromAlt('v').op(OP.ADD, 2, 'fx'); a.op(OP.NUMEQUALVERIFY, 2);
  if (i !== 0) a.drop('self');
  // 4. input 0's unlocking: the digest list, the statement, the z-tail (raw FILL and WQ pushes)
  if (i !== 0) { a.push(0).op(IX.INPUTBYTECODE, 1, 'U0'); } else a.rename('self', 'U0');
  a.op(OP.SIZE, 1, 'U0', 'usz').push(off.rPush).op(OP.SUB, 2, 'e').op(OP.SPLIT, 2, 'U0', 'x').drop('x');      // drop the redeem push
  a.push(off.ztail).op(OP.SPLIT, 2, 'U0', 'ZT');
  if (i !== 0) { a.roll('U0').push(off.dOff).op(OP.SPLIT, 2, 'x', 'U0').op(OP.NIP, 2, 'U0').push(96).op(OP.SPLIT, 2, 'D', 'U0').push(off.stmtGap).op(OP.SPLIT, 2, 'x', 'U0').op(OP.NIP, 2, 'U0').push(642).op(OP.SPLIT, 2, 'STMT', 'x').drop('x'); }
  else a.drop('U0');
  // D[i] == d_i
  a.pick('D', 'c').push(32 * i).op(OP.SPLIT, 2, 'x', 'c').op(OP.NIP, 2, 'c').push(32).op(OP.SPLIT, 2, 'c', 'x').drop('x').roll('di').op(OP.EQUALVERIFY, 2);
  // challenges
  a.pushBytes(TAG, 'tag').roll('D').op(OP.CAT, 2, 't').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').roll('ZT').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
  a.push(p, 'p');
  a.roll('zRaw'); U('zRaw'); a.pick('p').op(OP.MOD, 2, 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  // 5. statement words used by every input (A, B, C), the residue root, this input's nibbles
  if (!ctx.funcs.has('RDW')) a.defLocal('RDW', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v').roll('rest'); });
  a.roll('STMT');
  for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) a.invoke('RDW', [n, 'STMT']);
  a.push(64).op(OP.SPLIT, 2, 'nn', 'STMT').roll('nn');
  if (i === 0) { a.invoke('RDW', ['n0', 'nn']); a.invoke('RDW', ['n1', 'nn']); a.drop('nn'); } else a.drop('nn');
  a.roll('STMT').push(130).op(OP.SPLIT, 2, 'G', 'STMT');
  for (let j = 0; j < 6; j++) a.invoke('RDW', ['sc' + j, 'STMT']);
  a.drop('STMT');
  if (i === 0) { // owner checks: ranges, nibble mask, curve checks
    for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC', 'sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5']) a.pick(n, 'c').pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1);
    a.push(r, 'r'); for (const n of ['n0', 'n1']) a.roll(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); a.drop('r');
    a.pick('G', 'Gc'); a.pushBytes(Buffer.alloc(130, 0x0f), 'mk').op(OP.AND, 2, 'Gm').pick('G', 'G2').op(OP.EQUALVERIFY, 2);
    for (const [x, y] of [['xA', 'yA'], ['xC', 'yC']]) { const k = new Kernel(); const X = k.env(x), Y = k.env(y); k.output(k.mod(k.sub(k.mul(Y, Y), k.add(k.mul(k.mul(X, X), X), k.c(3n))))); a.kernel(k, ['d'], {iters: 200}); a.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); }
    { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
      const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
      const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
      k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(B_TWIST.c0))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.c(B_TWIST.c1))));
      a.kernel(k, ['tw0', 'tw1'], {iters: 300}); a.op(OP.BOOLOR, 2, 'bad').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); }
  }
  { const [e0, e1] = RANGES[i]; a.roll('G').push(e0).op(OP.SPLIT, 2, 'x', 'G').op(OP.NIP, 2, 'G').push(e1 - e0).op(OP.SPLIT, 2, 'N0', 'G').push(65 - e1 + e0).op(OP.SPLIT, 2, 'x', 'G').op(OP.NIP, 2, 'G')
      .push(e1 - e0).op(OP.SPLIT, 2, 'N1', 'x').drop('x'); }
  // 6. incoming handover (own HAND item): B point x0 x1 y0 y1 and R, range-checked
  if (i > 0) { a.roll('HAND'); for (const n of ['hx0', 'hx1', 'hy0', 'hy1', 'hR']) { a.invoke('RDW', [n, 'HAND']); a.pick(n, 'c').pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); } a.drop('HAND'); }
  // 7. outgoing handover: encode the computed (x0 x1 y0 y1 R) (here: the expected values) and compare with the next input's HAND
  if (i < 2) {
    for (const [k, v] of [0, 1, 2, 3, 4].map((k) => [k, BigInt('0x' + Buffer.from(HAND[i + 1].subarray(32 * k, 32 * k + 32)).reverse().toString('hex')) - p])) a.push(v, 'o' + k);
    for (let k = 0; k < 5; k++) { a.roll('o' + k).pick('p').op(OP.ADD, 2, 'v').pick('p').op(OP.MOD, 2, 'v').push(33).op(OP.NUM2BIN, 2, 'b').push(32).op(OP.SPLIT, 2, 'b', 'x').drop('x'); if (k) a.op(OP.CAT, 2, 'ob'); else a.rename('ob'); }
    a.push(i + 1).op(IX.INPUTBYTECODE, 1, 'Un').push(off.handIn[i + 1]).op(OP.SPLIT, 2, 'x', 'Un').op(OP.NIP, 2, 'Un').push(160).op(OP.SPLIT, 2, 'Hn', 'x').drop('x').op(OP.EQUALVERIFY, 2);
  }
  a.emit(OP.BEGIN, OP.DEPTH, OP.IF, OP.DROP, OP.ENDIF, OP.DEPTH, OP.NOT, OP.UNTIL, OP.TRUE); a.st = ['ok'];
  return a.code;
}

function build() {
  const R_LEN = 57, rPush = R_LEN + hdr(R_LEN);
  const enc1 = (len) => hdr(len) + len;
  const off = {rPush, dOff: hdr(96), stmtGap: hdr(642),
    ztail: enc1(96) + enc1(642) + enc1(STREAM[0].length) + enc1(DS[0].length),
    handIn: [null, enc1(STREAM[1].length) + hdr(160), enc1(STREAM[2].length) + hdr(160)],
    libIn: enc1(STREAM[2].length) + enc1(160) + enc1(DS[2].length) + hdr(LIB_SIZE)};
  off.fixedRaw = [off.ztail + rPush, enc1(STREAM[1].length) + enc1(160) + enc1(DS[1].length) + rPush, off.libIn + LIB_SIZE + rPush];
  const ctx = {funcs: new Map(), nextId: 2, defs: []};
  const roles = [0, 1, 2].map((i) => roleCode(i, ctx, off));
  const pro = []; for (const f of [...ctx.defs].sort((x, y) => x.id - y.id)) pro.push(...pushData(f.code), ...pushNum(f.id), OP.DEFINE);
  const body = Uint8Array.from([...pro, IX.INPUTINDEX, OP.DUP, OP.NOT, OP.IF, OP.DROP, ...roles[0], OP.ELSE, ...pushNum(1), OP.NUMEQUAL, OP.IF, ...roles[1], OP.ELSE, ...roles[2], OP.ENDIF, OP.ENDIF]);
  assert.ok(body.length <= LIB_SIZE, 'library body ' + body.length);
  const LIB = Buffer.concat([Buffer.from(body), Buffer.alloc(LIB_SIZE - body.length, 0x5a)]);
  const R = Uint8Array.from([...pushNum(LIB_HOLDER), IX.INPUTBYTECODE, ...pushNum(off.libIn), OP.SPLIT, OP.NIP, ...pushNum(LIB_SIZE), OP.SPLIT, OP.DROP,
    OP.DUP, OP.SHA256, ...pushData(sha(LIB)), OP.EQUALVERIFY, ...pushNum(body.length), OP.SPLIT, OP.DROP, ...pushNum(1), OP.DEFINE, ...pushNum(1), OP.INVOKE]);
  assert.equal(R.length, R_LEN, `R length ${R.length}`);
  const lock = Uint8Array.from([0xaa, 0x20, ...hash256(R), 0x87]);
  const D = Buffer.concat([sha(Buffer.concat([STMT, STREAM[0]])), sha(STREAM[1]), sha(STREAM[2])]);
  const unl = [
    enc([D, STMT, STREAM[0], DS[0], Buffer.alloc(FILL[0]), WQ, R]),
    enc([STREAM[1], HAND[1], DS[1], Buffer.alloc(FILL[1]), R]),
    enc([STREAM[2], HAND[2], DS[2], LIB, Buffer.alloc(FILL[2]), R]),
  ];
  return {R, LIB, body, roles: roles.map((x) => x.length), lock, unl};
}

const vm = createVirtualMachineBch2026(true);
const {R, body, roles, lock, unl} = build();
const tx = {version: 2, locktime: 0, inputs: unl.map((u, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32).fill(7), sequenceNumber: 0, unlockingBytecode: u})),
  outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]};
const src = unl.map(() => ({lockingBytecode: lock, valueSatoshis: 1000n}));
console.log(`redeem ${R.length} B, library body ${body.length} B (role code ${roles.join(' / ')} B)`);
for (let i = 0; i < 3; i++) {
  const st = vm.evaluate({inputIndex: i, sourceOutputs: src, transaction: tx});
  const budget = 800 * (41 + unl[i].length);
  console.log(`input ${i}: unlocking ${unl[i].length} B, setup op ${st.metrics.operationCost} (${(st.metrics.operationCost / budget * 100).toFixed(1)}% of ${budget}), error: ${st.error ?? 'none'}`);
}
if (process.env.PROF) { // op cost by opcode for one input
  const i = Number(process.env.PROF); const tr = vm.debug({inputIndex: i, sourceOutputs: src, transaction: tx});
  const by = new Map(); let prev = 0;
  for (const s of tr) { const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c; const ins = s.instructions?.[s.ip - 1]; const k = ins ? ins.opcode.toString(16) : '?'; by.set(k, (by.get(k) ?? 0) + d); }
  console.log([...by].sort((x, y) => y[1] - x[1]).slice(0, 15).map(([k, v]) => `${k}:${v}`).join(' '));
}
