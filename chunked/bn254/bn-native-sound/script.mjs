// bn-native-sound (SI-MX3) program generator: one code blob (function 1) that every input runs, dispatched on
// OP_INPUTINDEX into 3 role programs, and the 3-input redeem R that loads, authenticates and runs it.
// See README.md for the protocol, the layout and the soundness argument. Every item is named on the
// assembler's symbolic stack (asm.mjs); shared code lives in OP_DEFINE functions.
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {kADblN, kAAddN, kDStep, kEval, kTable} from './kernels.mjs';
import {p, r, ETA, GAMMA1, PSI, B_TWIST, VKC, PI_SUM_OFFSET} from '../sound-si-gls/math.mjs';
import {ROLES, NROLES, DS, DSTATE, SCHEDULE, TAG, STMT_SIZE, D_SIZE, HAND_SIZE, F_MAX, NQ_MAX, pushLen, hdrOf, sha} from './protocol.mjs';

export const IX = {INPUTINDEX: 0xc0, TXINPUTCOUNT: 0xc3, UTXOBYTECODE: 0xc7, INPUTBYTECODE: 0xca};
const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const D_PIECE = 8; // delta slopes per pile piece (512 B)

// ---------------- layout ----------------
// input 0: [S_0] [DS_0] [C_0] [FILL_0] [R]
// input 1: [S_1] [HAND_1 224] [DS_1] [C_1] [FILL_1] [R]
// input 2: [DG 96] [STMT 642] [S_2] [HAND_2 224] [DS_2] [FILL_2] [WQ] [R]
// Every byte range another input reads (DG, STMT, HAND_i, C_i, the z-tail ZT) starts before any variable-length push.
export const CODE_HOSTS = [0, 1];
export function layoutFor(codeLens, rLen) {
  const fixed = [
    [['S', ROLES[0].streamSize], ['DS', DS[0].length], ['C', codeLens[0]]],
    [['S', ROLES[1].streamSize], ['HAND', HAND_SIZE], ['DS', DS[1].length], ['C', codeLens[1]]],
    [['DG', D_SIZE], ['STMT', STMT_SIZE], ['S', ROLES[2].streamSize], ['HAND', HAND_SIZE], ['DS', DS[2].length]],
  ];
  const pushR = pushLen(rLen);
  const off = fixed.map((items) => { let o = 0; const m = {}; for (const [n, sz] of items) { m[n] = {data: o + pushLen(sz) - sz, size: sz, hdr: hdrOf(sz)}; o += pushLen(sz); } m.end = o; return m; });
  return {fixed, off, pushR, rLen, codeLens, rawFixed: off.map((m) => m.end + pushR), zt: off[2].end};
}
// the redeem: concatenate the code pieces (fixed ranges of the hosts' unlocking bytecode), check the digest, define and run
export function redeemFor(lay, Kcode) {
  const b = [];
  CODE_HOSTS.forEach((h, k) => { b.push(...pushNum(h), IX.INPUTBYTECODE, ...pushNum(lay.off[h].C.data), OP.SPLIT, OP.NIP, ...pushNum(lay.codeLens[k]), OP.SPLIT, OP.DROP); if (k) b.push(OP.CAT); });
  b.push(OP.DUP, OP.SHA256, ...pushData(Kcode), OP.EQUALVERIFY, ...pushNum(1), OP.DEFINE, ...pushNum(1), OP.INVOKE);
  return Uint8Array.from(b);
}

// ---------------- loop window (the items above the delta pile Dp during the event loop) ----------------
const TABLES = [0, 1].flatMap((k) => ['TP', 'TM'].flatMap((T) => Array.from({length: 16}, (_, n) => `${T}${k}_${15 - n}`)));
const ENV = ['z', 'z2', 'z4', 'z5', 'z6', 'ez', 'ez2', 'ez3', 'ez4', 'ez5'];
const HOT = ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'nyB0', 'nyB1', 'Scp', 'Scm', 'yC', 'cz', 'czt', 'z3t', 'yP', 'xz', 'xzt', 'z3', 'p'];
const STATE0 = ['R', 'SCH', 'N0', 'N1', 'BND', 'd', 'X0', 'X1', 'Y0', 'Y1', 'W', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'];
const SETUP_OUT = [...TABLES, ...ENV, ...HOT];
const STMT_OUT = ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC', 'n0', 'n1', 'r', 'G', 'sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5'];
const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
const OMEGA = (ETA * ETA) % p; // -psi^2(x, y) = (omega x, y)
assert.equal(OMEGA, PSI[1].x.c0); assert.equal(PSI[1].x.c1, 0n); assert.equal(PSI[1].y.c0, p - 1n); assert.equal(PSI[1].y.c1, 0n);

const U = (a, x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x); // unsigned LE decode of the top item
const lookup = (s, tbl, idx, out) => {
  assert.equal(s.top(), idx); s.st.pop(); const d0 = s.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(s.depth(`${tbl}_${n}`), d0 + n, 'table layout ' + tbl);
  s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push(out);
};
const conjMul = (k, a0, a1, g0, g1) => [k.mod(k.add(k.mul(a0, g0), k.mul(a1, g1))), k.mod(k.sub(k.mul(a0, g1), k.mul(a1, g0)))]; // conj(a) * g

// ---------------- shared functions ----------------
function defineFunctions(a, WIN) {
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  // RD: [blob] -> [v, rest]: split one 32-byte LE word, decode unsigned (BIN2NUM(w || 0x00)), require v < p
  a.defLocal('RD', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w'); U(s, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  a.defLocal('TM', 4, 16, (s) => s.kernel(kTable(true), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('TA', 4, 16, (s) => s.kernel(kTable(false), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('G1C', 2, 0, (s) => { const k = new Kernel(); const x = k.in('in0'), y = k.in('in1'); k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(3n))))); s.kernel(k, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  // PLEN: [n] -> [length of the minimal push of n bytes] = n + 1 + (n >= 76) + (n >= 256)   (n <= 10,000)
  a.defLocal('PLEN', 1, 1, (s) => { s.pick('in0', 'c').push(76).op(OP.GREATERTHANOREQUAL, 2, 'b1').pick('in0', 'c').push(256).op(OP.GREATERTHANOREQUAL, 2, 'b2')
    .op(OP.ADD, 2, 'b').op(OP.ADD1, 1, 'b').op(OP.ADD, 2, 'len'); });
  // FILL: [filler] -> [its push length]; the filler must be all zero (byte-exact, not a BIN2NUM test) and <= F_MAX
  a.defLocal('FILL', 1, 1, (s) => { s.op(OP.SIZE, 1, 'in0', 'fs').pick('fs', 'c').push(F_MAX + 1).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1)
    .push(0, 'z0').pick('fs', 'c').op(OP.NUM2BIN, 2, 'zz').roll('in0').op(OP.EQUALVERIFY, 2).invoke('PLEN', ['len']); });
  // GRAPH: exactly NROLES inputs, every spent output has this input's locking bytecode
  a.defLocal('GRAPH', 0, 0, (s) => {
    s.emit(IX.TXINPUTCOUNT); s.st.push('n'); s.push(NROLES).op(OP.NUMEQUALVERIFY, 2);
    s.emit(IX.INPUTINDEX); s.st.push('ix'); s.op(IX.UTXOBYTECODE, 1, 'mine');
    for (let j = 0; j < NROLES; j++) { s.push(j).op(IX.UTXOBYTECODE, 1, 'u'); (j < NROLES - 1 ? s.pick('mine') : s.roll('mine')); s.op(OP.EQUALVERIFY, 2); }
  });
  // TRANS: [DG, ZT] -> [rho, z]: h0 = SHA256(TAG || DG), rho_raw = SHA256(h0 || "rho"), z_raw = SHA256(h0 || rho_raw || ZT),
  // rho, z = BIN2NUM(raw || 0x00) mod p, z != 0
  a.defLocal('TRANS', 2, 2, (s) => {
    s.pushBytes(TAG, 'tag').roll('in0').op(OP.CAT, 2, 'tw').op(OP.SHA256, 1, 'h0');
    s.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
    s.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').roll('in1').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
    s.invoke('P', ['p']);
    s.roll('zRaw'); U(s, 'zRaw'); s.pick('p').op(OP.MOD, 2, 'z'); s.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
    s.roll('rhoRaw'); U(s, 'rhoRaw'); s.roll('p').op(OP.MOD, 2, 'rho'); s.arrange(['rho', 'z']);
  });
  // STMT: [STMT 642] -> words, every coordinate and s^c word < p, n_k < r, every nibble <= 0x0f (local decoding in every role)
  a.defLocal('STMT', 1, STMT_OUT.length, (s) => {
    s.rename('in0', 'S');
    for (const n of STMT_OUT.slice(0, 8)) s.invoke('RD', [n, 'S']);
    s.push(r, 'r');
    for (const n of ['n0', 'n1']) { s.roll('S').push(32).op(OP.SPLIT, 2, 'w', 'S').roll('w'); U(s, n); s.pick(n, 'c').pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
    s.roll('S').push(130).op(OP.SPLIT, 2, 'G', 'S').roll('G').pick('G', 'Gc');
    s.pushBytes([0x0f, 0x0f], 'mk'); for (let i = 0; i < 6; i++) s.pick('mk', 'mk2').op(OP.CAT, 2, 'mk');
    s.pushBytes([0x0f, 0x0f]).op(OP.CAT, 2, 'mk').op(OP.AND, 2, 'Gm').pick('G', 'Gc2').op(OP.EQUALVERIFY, 2);
    s.roll('S'); for (let j = 0; j < 6; j++) s.invoke('RD', ['sc' + j, 'S']);
    s.drop('S'); s.arrangeAbove('__floor', STMT_OUT);
  });
  // HDEC: [HAND 224] -> x_T.c0, x_T.c1, y_T.c0, y_T.c1, F+, F-, R (each < p)
  a.defLocal('HDEC', 1, 7, (s) => { s.rename('in0', 'H'); for (const n of ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'R']) s.invoke('RD', [n, 'H']); s.drop('H'); });
  // HENC: [7 values, p] -> 224-byte canonical encoding ((v mod p) as 32-byte LE)
  a.defLocal('HENC', 8, 1, (s) => {
    for (let k = 0; k < 7; k++) { s.roll('in' + k).pick('in7').op(OP.ADD, 2, 'v').pick('in7').op(OP.MOD, 2, 'v').push(33).op(OP.NUM2BIN, 2, 'b').push(32).op(OP.SPLIT, 2, 'b', 'x').drop('x'); if (k) s.op(OP.CAT, 2, 'o'); else s.rename('o'); }
    s.drop('in7');
  });
  // SETUP: [sc0..sc5, z, xA, yA, xB0, xB1, yB0, yB1, xC, yC, p] -> TABLES, ENV, HOT (see the window above)
  a.defLocal('SETUP', 16, SETUP_OUT.length, (s) => {
    ['sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5', 'z', 'xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC', 'p'].forEach((n, i) => s.rename('in' + i, n));
    { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
      const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); // eta^2 = eta - 1, eta^3 = -1
      k.output(z2, z3, z4, z5, z6, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))));
      s.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 'ez', 'ez2', 'ez3', 'ez4', 'ez5'], {iters: 1500}); }
    for (let j = 0; j < 6; j++) s.roll('sc' + j); for (const n of ZP) s.pick(n); s.invoke('EV', ['Scp', 'Scm']);
    for (const k of [0, 1]) {
      for (const i of [0, 1]) for (let j = 0; j < 6; j++) s.push(VKC.R[k][i][j], `R${k}${i}_${j}`);
      for (const i of [0, 1, 2, 3]) {
        for (let j = 0; j < 6; j++) (i < 2 ? s.pick.bind(s) : s.roll.bind(s))(`R${k}${i % 2}_${j}`);
        for (const n of i < 2 ? ZP : EZP) s.pick(n);
        s.invoke('EV', [`vp${i}`, `vm${i}`]);
      }
      s.arrange(['vp0', 'vp1', 'vp2', 'vp3']).invoke('TM', Array.from({length: 16}, (_, n) => `TP${k}_${15 - n}`));
      s.arrange(['vm0', 'vm1', 'vm2', 'vm3']).invoke('TM', Array.from({length: 16}, (_, n) => `TM${k}_${15 - n}`));
    }
    { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const t = k.sub(k.env('z6'), k.c(9n)), z3 = k.env('z3'), z = k.env('z');
      const yP = k.neg(k.in('yA')); const xz = m(mul(k.in('xA'), z)), cz = m(mul(k.in('xC'), z));
      k.output(m(mul(z3, t)), yP, xz, m(mul(xz, t)), cz, m(mul(cz, t)));
      s.kernel(k, ['z3t', 'yP', 'xz', 'xzt', 'cz', 'czt'], {iters: 500}); }
    s.pick('yB0').op(OP.NEGATE, 1, 'nyB0').pick('yB1').op(OP.NEGATE, 1, 'nyB1');
    s.push(VKC.deltaAff.x.c0, 'xd0').push(VKC.deltaAff.x.c1, 'xd1');
    s.arrangeAbove('__floor', SETUP_OUT);
  });
  // ---- bound functions (the event loop and its steps) ----
  const readT = (s) => { s.roll('W'); s.invoke('RD', ['t', 'W']); };
  a.defBound('BDBL', (s) => { readT(s); s.kernel(kADblN(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('BADD', (s) => { readT(s); s.kernel(kAAddN(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('DSTEP', (s) => {
    s.roll('D').emit(OP.SIZE); s.st.push('dsz'); s.op(OP.NOT, 1, 'dempty').ifElse((t) => { t.drop('D').pileTake('Dp', 'D'); });
    s.push(64).op(OP.SPLIT, 2, 'lb', 'D').roll('lb').push(32).op(OP.SPLIT, 2, 'w0', 'w1');
    s.op(OP.BIN2NUM, 1, 'n1').roll('w0').op(OP.BIN2NUM, 1, 'n0'); // baked slopes (authenticated by K_DS): < p < 2^254, nonnegative LE numbers
    s.kernel(kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS});
  });
  // ADDSTEP: the addition of Q = d_e B (d_e from the altstack) with its line, the residue-root factor and the delta step;
  // BNDSTEP: a chunk boundary (read the state, R <- R rho + F+ S'(-z) - F- S'(z), F+- <- S'(+-z), take the next record).
  // Both are functions so that an event without them skips 2 instructions instead of the whole body.
  a.defBound('ADDSTEP', (t) => {
    t.pick('d', 'dt').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse(
      (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('nyB0', 'yq0').pick('nyB1', 'yq1').pick('Scp', 'cp').pick('Scm', 'cm'); },
      (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('yB0', 'yq0').pick('yB1', 'yq1').pick('Scm', 'cp').pick('Scp', 'cm'); });
    t.invoke('BADD'); for (const n of ['yq1', 'yq0', 'xq1', 'xq0']) t.drop(n);
    t.pick('xd0', 's0').pick('xd1', 's1'); callBound(t, 'DSTEP');
  });
  a.defBound('BNDSTEP', (t) => {
    t.roll('W');
    for (let j = 0; j < 6; j++) t.invoke('RD', ['s' + j, 'W']);
    t.op(OP.SIZE, 1, 'W', 'ws').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('W'); // the record ends with the state
    for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
    const k = new Kernel(); const R = k.in('R');
    k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
    t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500});
    t.altPileTake('W'); // the next chunk record (the role's last boundary takes the final piece)
  });
  // LOOP: events of the role's range, driven by the role's baked schedule (alt: SCH digits, BND boundary flags)
  a.defBound('LOOP', (s0) => s0.loop((s) => {
    s.invoke('BDBL');
    s.pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP');
    s.pick('d', 'dt').ifElse((t) => t.invoke('ADDSTEP'));
    s.drop('d').roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
    s.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
    s.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
    for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
      s.pick('i0', 'x'); lookup(s, T + '0', 'x', 'u'); s.pick('i1', 'x'); lookup(s, T + '1', 'x', 'v');
      s.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
    }
    s.drop('i0').drop('i1');
    s.roll('BND').push(1).op(OP.SPLIT, 2, 'fb', 'BND').roll('fb').op(OP.BIN2NUM, 1, 'bnd');
    s.ifElse((t) => t.invoke('BNDSTEP'));
    s.pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
  }, {onExit: (nat) => { const w = nat.slice(nat.length - WIN.length); if (w.join() !== WIN.join()) throw {retryWIN: w}; }}));
}

// ---------------- role programs ----------------
const sizeIs = (a, name, n) => a.roll(name).op(OP.SIZE, 1, name, 'sz').push(n).op(OP.NUMEQUALVERIFY, 2);
// read fixed byte ranges of another input's unlocking bytecode; the push header in front of every range is checked
// (segs sorted by offset); with zt, also the z-tail: from lay.zt up to the redeem push
function remote(a, lay, host, segs, zt = false) {
  a.push(host).op(IX.INPUTBYTECODE, 1, 'U');
  if (zt) a.op(OP.SIZE, 1, 'U', 'us').push(lay.pushR).op(OP.SUB, 2, 'e').op(OP.SPLIT, 2, 'U', 'rp').drop('rp');
  let cur = 0;
  for (const g of segs) {
    const start = g.data - g.hdr.length; assert.ok(start >= cur);
    if (start > cur) a.push(start - cur).op(OP.SPLIT, 2, 'j', 'U').op(OP.NIP, 2, 'U');
    a.push(g.hdr.length).op(OP.SPLIT, 2, 'hb', 'U').roll('hb').pushBytes(g.hdr).op(OP.EQUALVERIFY, 2);
    a.push(g.size).op(OP.SPLIT, 2, g.name, 'U'); cur = g.data + g.size;
  }
  if (zt) { assert.ok(lay.zt >= cur); if (lay.zt > cur) a.push(lay.zt - cur).op(OP.SPLIT, 2, 'j', 'U').op(OP.NIP, 2, 'U'); a.rename('U', 'ZT'); }
  else a.drop('U');
}
// call a bound function at a site outside its first context: bring the items above Dp into its compiled layout
function callBound(a, name) {
  const f = a.ctx.funcs.get(name); assert.ok(f.id !== null, name + ' not compiled yet');
  a.arrangeAbove('Dp', f.entry.slice(f.entry.lastIndexOf('Dp') + 1)); a.invoke(name);
}
const cleanup = (a) => { assert.equal(a.alt.length, 0); assert.equal(a.piles.size, 0);
  a.toAlt('result'); while (a.st.length >= 2) { a.emit(OP.TWODROP); a.st.length -= 2; } if (a.st.length) a.drop(); a.fromAlt('result'); assert.deepEqual(a.st, ['result']); };

function roleProgram(i, ctx, lay, WIN) {
  const RL = ROLES[i], SC = SCHEDULE[i], last = i === NROLES - 1;
  const items = [['S', 'DS', 'C', 'FILL'], ['S', 'HAND', 'DS', 'C', 'FILL'], ['DG', 'STMT', 'S', 'HAND', 'DS', 'FILL', 'WQ']][i];
  const a = new Asm(items, ctx); a.mark('layout');
  // ---- 1. own layout: item count, every size, filler all-zero, quotient length rules, raw unlocking size ----
  a.emit(OP.DEPTH, ...pushNum(items.length), OP.NUMEQUALVERIFY);
  if (last) {
    a.op(OP.SIZE, 1, 'WQ', 'qs');
    a.pick('qs', 'c').push(32).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
    a.pick('qs', 'c').push(32).push(32 * NQ_MAX + 1).op(OP.WITHIN, 3, 'ok').op(OP.VERIFY, 1);
    a.invoke('PLEN', ['ql']);
    a.pick('WQ', 'c').push(32).op(OP.SPLIT, 2, 'q0', 'x').drop('x'); U(a, 'q0'); a.op(OP.ZERONOTEQUAL, 1, 'nz').op(OP.VERIFY, 1); // canonical n_q
  }
  a.roll('FILL').invoke('FILL', ['fl']);
  if (!last) { sizeIs(a, 'C', lay.codeLens[i]); a.drop('C'); }
  sizeIs(a, 'DS', DS[i].length); a.pick('DS', 'c').op(OP.SHA256, 1, 'h').pushBytes(sha(DS[i])).op(OP.EQUALVERIFY, 2); // K_DS[i]
  if (i > 0) sizeIs(a, 'HAND', HAND_SIZE);
  sizeIs(a, 'S', RL.streamSize);
  if (last) { sizeIs(a, 'STMT', STMT_SIZE); sizeIs(a, 'DG', D_SIZE); }
  a.emit(IX.INPUTINDEX); a.st.push('ix'); a.op(IX.INPUTBYTECODE, 1, 'U').op(OP.SIZE, 1, 'U', 'us');
  a.push(lay.rawFixed[i], 'ex').roll('fl').op(OP.ADD, 2, 'ex'); if (last) a.roll('ql').op(OP.ADD, 2, 'ex');
  a.op(OP.NUMEQUALVERIFY, 2);
  if (last) a.op(OP.SIZE, 1, 'U', 'us').push(lay.pushR).op(OP.SUB, 2, 'e').op(OP.SPLIT, 2, 'U', 'rp').drop('rp').push(lay.zt).op(OP.SPLIT, 2, 'j', 'U').op(OP.NIP, 2, 'ZT');
  else a.drop('U');
  // ---- 2. graph ----
  a.mark('graph').invoke('GRAPH', []);
  // ---- 3. remote reads ----
  a.mark('remote');
  const o2 = lay.off[2], dgst = [{name: 'DG', ...o2.DG}, {name: 'STMT', ...o2.STMT}];
  if (i === 0) { remote(a, lay, 1, [{name: 'Hn', ...lay.off[1].HAND}]); remote(a, lay, 2, dgst, true); }
  if (i === 1) remote(a, lay, 2, [...dgst, {name: 'Hn', ...o2.HAND}], true);
  // ---- 4. transcript: own digest d_i, then h0, rho, z ----
  a.mark('transcript');
  if (last) a.pick('STMT', 'c').pick('S', 'c2').op(OP.CAT, 2, 'c').op(OP.SHA256, 1, 'd'); else a.pick('S', 'c').op(OP.SHA256, 1, 'd');
  a.pick('DG', 'c'); if (i) a.push(32 * i).op(OP.SPLIT, 2, 'x', 'c').op(OP.NIP, 2, 'c'); if (!last) a.push(32).op(OP.SPLIT, 2, 'c', 'x').drop('x');
  a.op(OP.EQUALVERIFY, 2);
  a.arrange(['DG', 'ZT']).invoke('TRANS', ['rho', 'z']);
  // ---- 5. statement (decoded and range-checked by every role) ----
  a.mark('statement');
  a.roll('STMT').invoke('STMT', STMT_OUT);
  if (!last) for (const n of ['n0', 'n1', 'r']) a.drop(n);
  if (i === 0) { // owner checks: A, C on y^2 = x^3 + 3; B on the twist y^2 = x^3 + b'
    a.pick('xA').pick('yA').invoke('G1C', []); a.pick('xC').pick('yC').invoke('G1C', []);
    const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
    const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
    const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
    k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(B_TWIST.c0))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.c(B_TWIST.c1))));
    a.kernel(k, ['tw0', 'tw1'], {iters: 300}); a.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
  }
  if (last) { // psi(B) = (conj(xB) gamma^2, conj(yB) gamma^3), kept for the terminal addition and the endpoint
    const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const g2 = PSI[0].x, g3 = PSI[0].y;
    k.output(...conjMul(k, x0, x1, k.c(g2.c0), k.c(g2.c1)), ...conjMul(k, y0, y1, k.c(g3.c0), k.c(g3.c1)));
    a.kernel(k, ['px0', 'px1', 'py0', 'py1'], {iters: 300});
  }
  // ---- 6. the role's nibble slices, stream records, schedule ----
  a.mark('slices');
  { const A = RL.a, B = RL.b; (last ? a.pick.bind(a) : a.roll.bind(a))('G', 'g');
    if (A) a.push(A).op(OP.SPLIT, 2, 'x', 'g').op(OP.NIP, 2, 'g');
    a.push(B - A).op(OP.SPLIT, 2, 'N0', 'g').push(65 + A - B).op(OP.SPLIT, 2, 'x', 'g').op(OP.NIP, 2, 'g').push(B - A).op(OP.SPLIT, 2, 'N1', 'g').drop('g'); }
  { a.roll('S'); const n = RL.records.length;
    if (RL.terminal) a.push(RL.streamSize - RL.terminal).op(OP.SPLIT, 2, 'S', 'f').toAlt('f'); else a.push(0, 'f').toAlt('f');
    for (let k = n - 1; k >= 1; k--) a.push(RL.records.slice(0, k).reduce((x, y) => x + y, 0)).op(OP.SPLIT, 2, 'S', 'rec').toAlt('rec');
    a.rename('S', 'W'); a.alt.splice(-n, n); a.pushAltPile('WSp', n); }
  if (i === 0) a.push(0, 'R'); else a.roll('HAND').invoke('HDEC', ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'R']);
  a.pushBytes(SC.sch, 'SCH').pushBytes(SC.bnd, 'BND').push(SC.d0, 'd');
  // ---- 7. the delta pile (first piece on top), setup, start state ----
  a.mark('setup');
  { const nP = DS[i].length / (64 * D_PIECE); assert.ok(Number.isInteger(nP));
    a.roll('DS'); for (let k = nP - 1; k >= 1; k--) a.push(64 * D_PIECE * k).op(OP.SPLIT, 2, 'DS', 'pk' + k).roll('DS');
    a.st.splice(-nP, nP); a.st.push('Dp'); a.piles.set('Dp', nP); }
  const keep = last ? ['sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5'] : [];
  for (const n of ['sc0', 'sc1', 'sc2', 'sc3', 'sc4', 'sc5', 'z', 'xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) (keep.includes(n) ? a.pick(n) : a.roll(n));
  a.invoke('P', ['p']).invoke('SETUP', SETUP_OUT);
  if (i === 0) a.pick('xB0', 'X0').pick('xB1', 'X1').pick('yB0', 'Y0').pick('yB1', 'Y1').pick('Scm', 'Fp').pick('Scp', 'Fm');
  { const ds = DSTATE[RL.a]; a.push(0, 'D').push(ds.x.c0, 'dx0').push(ds.x.c1, 'dx1').push(ds.c.c0, 'dc0').push(ds.c.c1, 'dc1').push(ds.l.c0, 'dl0').push(ds.l.c1, 'dl1'); }
  a.arrangeAbove('Dp', WIN);
  a.piles.set('Dp', null); a.piles.set('WSp', null);
  // ---- 8. the event loop ----
  a.mark('loop').invoke('LOOP'); a.mark('post');
  // after the loop every delta piece and every stream record has been taken (fixed by the schedule)
  a.piles.set('Dp', 0); a.piles.set('WSp', 0);
  if (!last) {
    a.roll('D').op(OP.SIZE, 1, 'D', 'ds').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('D'); a.pileDone('Dp');
    a.roll('W').op(OP.SIZE, 1, 'W', 'ws').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('W');
    for (const n of ['d', 'BND', 'N1', 'N0', 'SCH']) a.drop(n);
    a.pileDone('WSp');
    // ---- 9. outgoing handover: canonical encoding of (T, F+, F-, R) == HAND_{i+1} of input i+1 ----
    a.arrange(['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'R', 'p']).invoke('HENC', ['HO']).roll('Hn').op(OP.EQUALVERIFY, 2);
    a.push(1, 'result'); a.mark('cleanup'); cleanup(a); return a;
  }
  // ---- 9'. terminal (last role) ----
  a.mark('terminal');
  const piles0 = () => { a.piles.set('Dp', 0); a.piles.set('WSp', 0); };
  a.pick('px0', 'xq0').pick('px1', 'xq1').pick('py0', 'yq0').pick('py1', 'yq1').push(1, 'cp').push(1, 'cm'); callBound(a, 'BADD'); piles0();
  for (const n of ['yq1', 'yq0', 'xq1', 'xq0']) a.drop(n);
  a.push(VKC.deltaPsi.x.c0, 's0').push(VKC.deltaPsi.x.c1, 's1'); callBound(a, 'DSTEP'); piles0();
  { const k = new Kernel(); k.output(k.mod(k.mul(k.env('xB0'), k.c(OMEGA))), k.mod(k.mul(k.env('xB1'), k.c(OMEGA)))); a.kernel(k, ['xq0', 'xq1'], {iters: 50}); }
  a.pick('yB0', 'yq0').pick('yB1', 'yq1').push(1, 'cp').push(1, 'cm'); callBound(a, 'BADD'); piles0();
  for (const n of ['yq1', 'yq0', 'xq1', 'xq0']) a.drop(n);
  a.pick('dx0', 's0').pick('dx1', 's1'); callBound(a, 'DSTEP'); piles0(); // s is irrelevant for the last delta line
  a.roll('D').op(OP.SIZE, 1, 'D', 'ds').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('D'); a.pileDone('Dp'); // all 88 delta slopes consumed
  a.roll('W').op(OP.SIZE, 1, 'W', 'ws').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('W');                   // every witness consumed
  // endpoint: T == -psi^3(B) = (omega px, py), exactly (affine, reduced): lambda(psi)(B) = O, so B is in G2
  { const k = new Kernel(); const [X0, X1, Y0, Y1, px0, px1, py0, py1] = ['X0', 'X1', 'Y0', 'Y1', 'px0', 'px1', 'py0', 'py1'].map((n) => k.in(n));
    k.output(k.mod(k.sub(X0, k.mul(k.c(OMEGA), px0))), k.mod(k.sub(X1, k.mul(k.c(OMEGA), px1))), k.mod(k.sub(Y0, py0)), k.mod(k.sub(Y1, py1)));
    a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1'], {iters: 500}); for (let j = 0; j < 4; j++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
  for (const n of ['d', 'BND', 'N1', 'N0', 'SCH']) a.drop(n);
  a.pileDone('WSp');
  // F *= Rconst(+-z) * S_c(+-eta z)
  for (let j = 0; j < 6; j++) a.push(VKC.Rconst[j]); for (const n of ZP) a.pick(n); a.invoke('EV', ['rp', 'rm']);
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of EZP) a.pick(n); a.invoke('EV', ['ep', 'em']);
  { const k = new Kernel(); k.output(k.mod(k.mul(k.mul(k.in('Fp'), k.in('rp')), k.in('ep'))), k.mod(k.mul(k.mul(k.in('Fm'), k.in('rm')), k.in('em')))); a.kernel(k, ['Fp', 'Fm'], {iters: 200}); }
  // c_j = Phi(gamma1^j)(z) = g0 + g1 (z^6 - 9), j = 1..5 (Frob(X^j) = Phi(gamma1^j) X^j)
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y); const t = k.sub(k.env('z6'), k.c(9n)); const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]];
    const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
    for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
    k.output(...g.map(([g0, g1]) => m(k.add(g0, mul(g1, t))))); a.kernel(k, ['c1', 'c2', 'c3', 'c4', 'c5'], {iters: 800}); }
  // W(+-z) = Frob(S_c)(+-z) Frob(S_c)(+-eta z);  R <- R rho + F+ W(-z) - F- W(+z)
  { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j)); const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], I('c' + j))))];
    const fr = (x) => { const ev = m(k.sum(sc[0], k.c(18n), k.neg(E(x[5])), mul(sj[2], E(x[1])), mul(sj[4], E(x[3])))); const od = m(k.sum(mul(sj[1], E(x[0])), mul(sj[3], E(x[2])), mul(sj[5], E(x[4])))); return [k.add(ev, od), k.sub(ev, od)]; };
    const [a1, a2] = fr(ZP), [b1, b2] = fr(EZP);
    k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), m(mul(a2, b2)))), mul(I('Fm'), m(mul(a1, b1))))));
    a.kernel(k, ['R'], {iters: 1500}); }
  a.mark('binding');
  // ---- GT-GLS binding (exact integers): acc_k = sum_e 2^(64-e) TB[N_k[e]] = sum_i u_{k,i} pi_i;  (acc_k - 2^64 sum pi_i - n_k) mod r == 0 ----
  a.push(1, 'pi0').pick('p').pick('r').op(OP.SUB, 2, 'pi1').pick('pi1').pick('pi1').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'pi2')
    .pick('pi1').pick('pi2').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'pi3').invoke('TA', Array.from({length: 16}, (_, n) => `TB_${15 - n}`));
  a.roll('G').push(65).op(OP.SPLIT, 2, 'B0', 'B1').push(0, 'acc0').push(0, 'acc1');
  a.loop((s) => {
    for (const k of [0, 1]) { s.roll('B' + k).push(1).op(OP.SPLIT, 2, 'b', 'B' + k).roll('b').op(OP.BIN2NUM, 1, 'x'); lookup(s, 'TB', 'x', 'tb'); s.roll('acc' + k).op(OP.DUP, 1, 'acc', 'acc2').op(OP.ADD, 2, 'acc').op(OP.ADD, 2, 'acc' + k); }
    s.pick('B0', 'Bc').op(OP.SIZE, 1, 'Bc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'done');
  });
  a.drop('B0').drop('B1'); for (let n = 0; n < 16; n++) a.drop(`TB_${n}`);
  a.push(PI_SUM_OFFSET, 'pso');
  for (const k of [0, 1]) a.roll('acc' + k).roll('n' + k).op(OP.SUB, 2, 'dn').pick('pso').op(OP.SUB, 2, 'dn2').pick('r').op(OP.MOD, 2, 'dr').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
  a.drop('pso').drop('r');
  a.mark('quotient');
  // ---- quotient: Q(z) = z q(z^2), Horner over WQ (highest first), 4 words per step, each word < p ----
  a.push(0).push(96).op(OP.NUM2BIN, 2, 'zeros').push(128).pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(128).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
    .push(128).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
  { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
  a.push(0, 'acc');
  a.loop((s) => {
    s.roll('WQ').push(128).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
    for (let j = 0; j < 4; j++) s.invoke('RD', ['q' + j, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQ', 'WQc').op(OP.SIZE, 1, 'WQc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQ');
  { const k = new Kernel(); const z6 = k.env('z6');
    const Mz = k.add(k.sub(k.mul(z6, z6), k.mul(k.c(18n), z6)), k.c(82n));
    k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
  a.op(OP.NOT, 1, 'result');
  a.mark('cleanup'); cleanup(a); return a;
}

// ---------------- the program ----------------
// body = definitions of every function (ids 2..N) and of the role programs (ids ROLE_ID + i), then
// OP_INPUTINDEX <ROLE_ID> OP_ADD OP_INVOKE: each input runs only its own role (an unexecuted branch would still
// cost 100 per skipped instruction); an input index without a role program fails (undefined function)
function genBody(lay, WIN) {
  const ctx = {funcs: new Map(), nextId: 2, defs: []};
  const a0 = new Asm([], ctx); defineFunctions(a0, WIN);
  const roles = [0, 1, 2].map((i) => roleProgram(i, ctx, lay, WIN));
  const pro = []; for (const f of [...ctx.defs].sort((x, y) => x.id - y.id)) pro.push(...pushData(f.code), ...pushNum(f.id), OP.DEFINE);
  const ROLE_ID = ctx.nextId; const offs = [];
  roles.forEach((x, i) => { const pd = pushData(x.code); offs.push(pro.length + pd.length - x.code.length); pro.push(...pd, ...pushNum(ROLE_ID + i), OP.DEFINE); });
  const code = Uint8Array.from([...pro, IX.INPUTINDEX, ...pushNum(ROLE_ID), OP.ADD, OP.INVOKE]);
  const marks = roles.flatMap((x, i) => x.marks.map((m) => ({name: `r${i}:${m.name}`, off: offs[i] + m.off, role: i, roff: m.off})));
  const funcCodes = Object.fromEntries([...ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, Uint8Array.from(f.code)]));
  roles.forEach((x, i) => { funcCodes['role' + i] = Uint8Array.from(x.code); });
  return {code, marks, roles: roles.map((x) => x.code.length), roleId: ROLE_ID, prologue: pro.length, funcs: Object.fromEntries([...ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, {id: f.id, bytes: f.code.length}])), funcCodes};
}
// code piece split: input 0 and input 1 host the code; by default balance their unlocking content
const SPLIT0 = process.env.CODE_SPLIT0 ? Number(process.env.CODE_SPLIT0) : null;
const splitLens = (total) => { const c0 = ROLES[0].streamSize + DS[0].length, c1 = ROLES[1].streamSize + DS[1].length + HAND_SIZE;
  const L0 = SPLIT0 ?? Math.max(256, Math.min(total - 256, Math.round((total + c1 - c0) / 2))); return [L0, total - L0]; };
export function buildProgram() {
  let WIN = [...SETUP_OUT, 'rho', ...STATE0];
  let lens = [3000, 3000]; const rLen0 = redeemFor(layoutFor(lens, 0), Buffer.alloc(32)).length;
  for (let it = 0; it < 20; it++) {
    const lay = layoutFor(lens, rLen0);
    let body;
    try { body = genBody(lay, WIN); } catch (e) { if (e.retryWIN) { WIN = e.retryWIN; continue; } throw e; }
    const nl = splitLens(body.code.length);
    if (nl[0] === lens[0] && nl[1] === lens[1]) {
      const Kcode = sha(body.code); const R = redeemFor(lay, Kcode); assert.equal(R.length, rLen0);
      const pieces = [body.code.subarray(0, lens[0]), body.code.subarray(lens[0])];
      return {code: body.code, pieces, R, Kcode, lay, marks: body.marks, funcCodes: body.funcCodes, info: {roles: body.roles, prologue: body.prologue, funcs: body.funcs, WIN}};
    }
    lens = nl;
  }
  throw new Error('layout did not converge');
}
