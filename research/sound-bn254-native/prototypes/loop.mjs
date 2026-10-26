// Event-loop prototype for one input of the multi-input design: events [a, b) of the 65-event Miller schedule,
// in SI-GLS layout, with either the SI projective B kernels ('proj', for calibration against the measured
// SI-GLS profile) or the affine witnessed-slope kernels ('affine'). Runs in libauth on fixture 0's real B
// trajectory (so every slope check passes); states and GT tables are arbitrary field values (op cost does not
// depend on them). The binding accumulators acc_k are not in the loop (computed once elsewhere).
//
//   node research/sound-bn254-native/prototypes/loop.mjs [proj|affine] [a] [b]
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
import {Asm, Kernel, OP, pushNum} from '../../../chunked/bn254/sound-si-gls/asm.mjs';
import {kBDbl, kBAdd, kDStep} from '../../../chunked/bn254/sound-si-gls/script.mjs';
import {p, r, mod, F2, f2, B3, DIGITS, NE, VKC, FIXTURES, g1, g2, glsDecompose, GLS_OFFSET, GLS_BITS} from '../../../chunked/bn254/sound-si-gls/math.mjs';
import {isBoundary, le32} from '../../../chunked/bn254/sound-si-gls/protocol.mjs';
import {kADbl, kAAdd, kADblN, kAAddN} from './kernels.mjs';
import {Fp} from '../../../chunked/bn254/sound-si-gls/math.mjs';
import {VMS, numPush} from './vm26.mjs';
import {encodeDataPush} from '@bitauth/libauth';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const D_PIECE = 8, B_PIECE = 8, WS_PIECE = 4;

// ---------------- fixture-0 data ----------------
export function fixtureData(fi = 0) {
  const fx = FIXTURES.fixtures[fi];
  const A = g1(fx.proof.a).toAffine(), Bp = g2(fx.proof.b), B = Bp.toAffine(), C = g1(fx.proof.c).toAffine();
  const ns = fx.publicInputs.map(BigInt); const us = ns.map((n) => glsDecompose(mod(n, r)).map((v) => v + GLS_OFFSET));
  const N = us.map((u) => Array.from({length: NE}, (_, ev) => u.reduce((s, v, i) => s | (Number((v >> BigInt(GLS_BITS - 1 - ev)) & 1n) << i), 0)));
  // affine B trajectory with slopes; T_e = point before event e
  const T = [], slopes = [], norms = []; let P = Bp;
  const slopeDbl = (t) => F2.div(F2.mul(f2(3n, 0n), F2.sqr(t.x)), F2.add(t.y, t.y));
  const slopeAdd = (t, q) => F2.div(F2.sub(q.y, t.y), F2.sub(q.x, t.x));
  for (let e = 0; e < NE; e++) {
    T.push(P.toAffine()); const ev = [], nv = []; const N2 = (a) => mod(a.c0 * a.c0 + a.c1 * a.c1);
    ev.push(slopeDbl(P.toAffine())); nv.push(Fp.inv(mod(2n * N2(P.toAffine().y)))); P = P.double();
    if (DIGITS[e]) { const Q = DIGITS[e] < 0 ? Bp.negate() : Bp; ev.push(slopeAdd(P.toAffine(), Q.toAffine())); nv.push(Fp.inv(N2(F2.sub(P.toAffine().x, Q.toAffine().x)))); P = P.add(Q); }
    slopes.push(ev); norms.push(nv);
  }
  T.push(P.toAffine());
  // projective trajectory as the SI script computes it (for proj mode starting points)
  // delta recursion state before each event: (x_j, c_{j-1}, lambda_{j-1}), j = delta step index
  const d = VKC.deltaAff; const all = [...VKC.lams, VKC.frob2.lam]; const dState = []; const jAt = [];
  { let x = d.x, c = d.y, l = F2.ZERO, j = 0;
    const step = (s) => { const cj = F2.sub(F2.mul(F2.add(l, all[j]), x), c); const nx = F2.sub(F2.sub(F2.sqr(all[j]), x), s); c = cj; l = all[j]; x = nx; j++; };
    for (let e = 0; e < NE; e++) { dState.push({x, c, l}); jAt.push(j); step(x); if (DIGITS[e]) step(d.x); }
    dState.push({x, c, l}); jAt.push(j); }
  return {A, B, C, N, T, slopes, norms, dState, jAt, lams: all};
}

// ---------------- generator ----------------
export function buildLoop(mode, a, b, data) {
  let L0 = null;
  for (let attempt = 0; attempt < 8; attempt++) { try { return gen(mode, a, b, data, L0); } catch (e) { if (e.retryL0) { L0 = e.retryL0; continue; } throw e; } }
  throw new Error('loop layout did not converge');
}
const TBL = ['TP0', 'TM0', 'TP1', 'TM1'];
function gen(mode, a, b, data, L0guess) {
  const aff = mode.startsWith('affine'); const dblN = mode === 'affineN', addN = mode === 'affineN' || mode === 'affineAN';
  const nD = data.jAt[b] - data.jAt[a]; const nDp = Math.ceil(nD / D_PIECE);
  const nBs = data.slopes.slice(a, b).flat().length; const nBp = Math.ceil(nBs / B_PIECE);
  const nWSp = streamPieces(mode, a, b, data).length - 1;
  const HOT = aff ? ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'nyB0', 'nyB1', 'Scp', 'Scm', 'yC', 'cz', 'czt', 'z3t', 'yP', 'xz', 'xzt', 'z3', 'p']
    : ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'nyB0', 'nyB1', 'Scp', 'Scm', 'yC', 'cz', 'czt', 'b30', 'b31', 'z3t', 'yP', 'yPt', 'xz', 'xzt', 'xz3', 'xz3t', 'z3', 'p'];
  const STATE = [...(aff ? ['X0', 'X1', 'Y0', 'Y1'] : ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1']), 'W', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'];
  const tables = TBL.flatMap((t) => Array.from({length: 16}, (_, n) => `${t}_${15 - n}`));
  const ENV = ['z', 'z2', 'z3_', 'z4', 'z5', 'z6', 'rho'];
  const initial = ['Dp', ...tables, ...ENV, ...HOT, ...STATE, 'd', 'N1', 'N0', 'SCH', 'R', 'WSp'];
  const asm = new Asm(initial);
  asm.piles.set('Dp', nDp); asm.piles.set('WSp', nWSp);
  for (let i = 0; i < nWSp; i++) asm.emit(OP.TOALT); asm.st.pop(); asm.pushAltPile('WSp', nWSp);
  for (const n of ['R', 'SCH', 'N0', 'N1', 'd']) asm.toAlt(n);
  const preLen = asm.code.length;
  const ZP = ['z', 'z2', 'z3_', 'z4', 'z5', 'z6'];
  asm.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  asm.defLocal('RD', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  asm.defLocal('EV', 12, 2, (s) => { const k = new Kernel(); const sv = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
    const ev = k.mod(k.sum(sv[0], k.mul(sv[2], x[1]), k.mul(sv[4], x[3]), x[5])); const od = k.mod(k.sum(k.mul(sv[1], x[0]), k.mul(sv[3], x[2]), k.mul(sv[5], x[4])));
    s.kernel(k.output(k.add(ev, od), k.sub(ev, od)), ['vp', 'vm'], {iters: ITERS}); });
  // read the next witnessed B slope (l0, l1) from the B-slope pile, range-checked
  const readSlope = (s) => {
    s.roll('W').push(64).op(OP.SPLIT, 2, 'lb', 'W').roll('lb'); s.invoke('RD', ['l0', 'lb']); s.invoke('RD', ['l1', 'lb']); s.drop('lb');
  };
  if (aff) {
    const readT = (s) => { s.roll('W'); s.invoke('RD', ['t', 'W']); };
    if (dblN) asm.defBound('BDBL', (s) => { readT(s); s.kernel(kADblN(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
    else asm.defBound('BDBL', (s) => { readSlope(s); s.kernel(kADbl(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'ch0', 'ch1'], {iters: ITERS});
      s.op(OP.BOOLOR, 2, 'ch').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
    if (addN) asm.defBound('BADD', (s) => { readT(s); s.kernel(kAAddN(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
    else asm.defBound('BADD', (s) => { readSlope(s); s.kernel(kAAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Fp', 'Fm', 'ch0', 'ch1', 'ex0', 'ex1'], {iters: ITERS});
      s.op(OP.BOOLOR, 2, 'ex').op(OP.VERIFY, 1).op(OP.BOOLOR, 2, 'ch').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  } else {
    asm.defBound('BADD', (s) => s.kernel(kBAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS}));
  }
  asm.defBound('DSTEP', (s) => {
    s.roll('D').emit(OP.SIZE); s.st.push('dsz'); s.op(OP.NOT, 1, 'dempty').ifElse((t) => { t.drop('D').pileTake('Dp', 'D'); });
    s.push(64).op(OP.SPLIT, 2, 'lb', 'D').roll('lb').push(32).op(OP.SPLIT, 2, 'w0', 'w1');
    s.op(OP.BIN2NUM, 1, 'n1').roll('w0').op(OP.BIN2NUM, 1, 'n0');
    s.kernel(kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS});
  });
  const moved = new Set([...HOT, ...STATE]);
  const L0 = L0guess ?? [...asm.st.filter((x) => !moved.has(x)), ...HOT, ...STATE];
  asm.arrangeAll(L0);
  asm.piles.set('Dp', null); asm.piles.set('WSp', null);
  const setupEnd = asm.code.length;
  const lookup = (s, tbl, idx, out) => {
    assert.equal(s.top(), idx); s.st.pop(); const d0 = s.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(s.depth(`${tbl}_${n}`), d0 + n, 'table layout ' + tbl);
    s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push(out);
  };
  asm.loop((s) => {
    s.mark('bdbl'); if (aff) s.invoke('BDBL'); else s.kernel(kBDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS});
    s.mark('dstep').pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP');
    s.mark('add'); s.peekAlt('dt').ifElse((t) => {
      t.peekAlt('dt').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse(
        (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('nyB0', 'yq0').pick('nyB1', 'yq1').pick('Scp', 'cp').pick('Scm', 'cm'); },
        (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('yB0', 'yq0').pick('yB1', 'yq1').pick('Scm', 'cp').pick('Scp', 'cm'); });
      t.invoke('BADD'); if (aff) for (const n of ['yq1', 'yq0', 'xq1', 'xq0']) t.drop(n);
      t.pick('xd0', 's0').pick('xd1', 's1').invoke('DSTEP');
    });
    s.mark('digit'); for (const n of ['d', 'N1', 'N0', 'SCH']) s.fromAlt(n);
    s.drop('d').roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
    s.mark('gls');
    s.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
    s.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
    for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
      s.pick('i0', 'x'); lookup(s, T + '0', 'x', 'u'); s.pick('i1', 'x'); lookup(s, T + '1', 'x', 'v');
      s.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
    }
    s.drop('i0').drop('i1');
    // boundary flag: one byte per event in BND (pushed with the schedule): here derived from SCH like SI-GLS
    s.mark('bnd');
    if (b === NE) s.pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').pick('m').push(2).op(OP.MOD, 2, 'odd').roll('m').op(OP.NOT, 1, 'last').op(OP.BOOLOR, 2, 'bnd');
    else { assert.equal(b % 2, 0); s.pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').push(2).op(OP.MOD, 2, 'odd').op(OP.NOT, 1, 'bnd'); }
    s.ifElse((t) => {
      t.fromAlt('R'); t.roll('W').push(192).op(OP.SPLIT, 2, 'S', 'W0'); t.drop('W0'); // the chunk record ends with its state
      for (let j = 0; j < 6; j++) t.invoke('RD', ['s' + j, 'S']);
      t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
      const k = new Kernel(); const R = k.in('R');
      k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
      t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500}); t.altPileTake('W'); t.toAlt('R');
    });
    s.mark('loopend').pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
    for (const n of ['SCH', 'N0', 'N1', 'd']) s.toAlt(n);
    s.roll('last');
  }, {onExit: (nat) => { if (nat.join() !== L0.join()) throw {retryL0: nat}; }});
  const code = Uint8Array.from([...asm.prologue(), ...asm.code]);
  return {code, prologue: asm.prologue().length, preLen, setupEnd, marks: asm.marks, initial, funcs: Object.fromEntries([...asm.ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]))};
}

// ---------------- witness / stack for a range ----------------
// the input's witness stream in consumption order, one piece per chunk: B slopes of each event (affine), then the state
export function streamPieces(mode, a, b, data) {
  const out = []; let cur = [];
  for (let e = a; e < b; e++) {
    if (mode.startsWith('affine')) data.slopes[e].forEach((l, k) => {
      const useN = k === 0 ? mode === 'affineN' : (mode === 'affineN' || mode === 'affineAN');
      if (useN) cur.push(le32(data.norms[e][k])); else cur.push(le32(l.c0), le32(l.c1)); });
    if (isBoundary(e)) { cur.push(...Array.from({length: 6}, (_, j) => le32(rnd(1000 + 6 * e + j)))); out.push(Buffer.concat(cur)); cur = []; }
  }
  if (cur.length) out.push(Buffer.concat(cur));
  out.push(Buffer.alloc(0)); // empty last piece: the refill after the input's last boundary
  return out;
}
const rnd = (s) => mod(BigInt(s) ** 37n + 98765n);
const pieces = (bufs, per) => { const out = []; for (let i = 0; i < bufs.length; i += per) out.push(Buffer.concat(bufs.slice(i, i + per))); return out; };
export function pushesFor(mode, a, b, data, initial) {
  const aff = mode === 'affine'; const {A, B, C, N, T, slopes, dState, jAt, lams} = data;
  const z = rnd(3), t = mod(z ** 6n - 9n), z3 = mod(z ** 3n), yP = mod(-A.y), xz = mod(A.x * z), cz = mod(C.x * z);
  const v = {z, z2: mod(z * z), z3_: z3, z4: mod(z ** 4n), z5: mod(z ** 5n), z6: mod(z ** 6n), rho: rnd(4),
    xd0: VKC.deltaAff.x.c0, xd1: VKC.deltaAff.x.c1, xB0: B.x.c0, xB1: B.x.c1, yB0: B.y.c0, yB1: B.y.c1, nyB0: -B.y.c0, nyB1: -B.y.c1,
    Scp: rnd(5), Scm: rnd(6), yC: C.y, cz, czt: mod(cz * t), b30: B3.c0, b31: B3.c1, z3t: mod(z3 * t), yP, yPt: mod(yP * t), xz, xzt: mod(xz * t),
    xz3: mod(3n * xz), xz3t: mod(3n * xz * t), z3, p,
    X0: T[a].x.c0, X1: T[a].x.c1, Y0: T[a].y.c0, Y1: T[a].y.c1, Z0: 1n, Z1: 0n, B: 0n, D: 0n,
    dx0: dState[a].x.c0, dx1: dState[a].x.c1, dc0: dState[a].c.c0, dc1: dState[a].c.c1, dl0: dState[a].l.c0, dl1: dState[a].l.c1, Fp: rnd(7), Fm: rnd(8), R: rnd(9), W: 0n};
  TBL.forEach((tb, i) => { for (let n = 0; n < 16; n++) v[`${tb}_${n}`] = n === 0 ? 1n : rnd(100 + 16 * i + n); });
  const enc = (x) => numPush(x);
  const pushes = [];
  for (const name of initial) {
    if (name === 'Dp') { const ls = lams.slice(jAt[a], jAt[b]).map((l) => Buffer.concat([le32(l.c0), le32(l.c1)])); pushes.push(...pieces(ls, D_PIECE).reverse()); continue; }
    if (name === 'WSp') { pushes.push(...streamPieces(mode, a, b, data).slice(1)); continue; }
    if (name === 'W') { pushes.push(streamPieces(mode, a, b, data)[0]); continue; }
    if (name === 'SCH') { const ds = DIGITS.slice(a + 1, b).map((d) => (d < 0 ? 0x81 : d)).concat([0]); pushes.push(Buffer.from(ds)); continue; }
    if (name === 'N0' || name === 'N1') { pushes.push(Buffer.from(N[name === 'N0' ? 0 : 1].slice(a, b))); continue; }
    if (name === 'd') { pushes.push(enc(DIGITS[a])); continue; }
    assert.ok(name in v, 'no value for ' + name); pushes.push(enc(v[name]));
  }
  return pushes;
}

export function measureRange(mode, a, b, data = fixtureData(0)) {
  const g = buildLoop(mode, a, b, data); const pushes = pushesFor(mode, a, b, data, g.initial);
  const enc = (ps) => Uint8Array.from(ps.flatMap((x) => [...encodeDataPush(Uint8Array.from(x))]));
  const prog = (lock) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: lock, valueSatoshis: 1000n}], transaction: {version: 2, locktime: 0,
    inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: enc([new Uint8Array(60000), ...pushes])}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
  const vm = VMS.spec; // same op-cost model as bch-2026; large budget so a whole range can be measured in one run
  const full = vm.evaluate(prog(g.code));
  if (full.error && !/unexpected number of items/.test(full.error)) throw new Error(`${mode} [${a},${b}): ${full.error} at ip ${full.ip}`);
  const pre = vm.evaluate(prog(g.code.slice(0, g.prologue + g.setupEnd)));
  return {mode, a, b, loopOp: full.metrics.operationCost - pre.metrics.operationCost, prologueBytes: g.prologue, loopBytes: g.code.length - g.prologue - g.setupEnd, funcs: g.funcs};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [mode = 'affine', a = '0', b = '65'] = process.argv.slice(2);
  console.log(measureRange(mode, Number(a), Number(b)));
}
