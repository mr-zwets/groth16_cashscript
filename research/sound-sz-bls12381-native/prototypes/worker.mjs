// VM prototype of one Miller input's work (chunks [j0, j1)): setup (z powers, line env, GLS tables, S_c evaluations),
// the events (B affine witnessed-slope or projective steps, delta steps, GLS lookups), the chunk boundaries and, for the
// last chunk, the terminal (Rconst, W = Frob(S_c), endpoint). Code is straight-line (kernels inlined) for measurement;
// the outputs (partial sum R_i, end point T) are checked against protocol.mjs. Reports op cost by section.
//   node worker.mjs [j0 j1] [aff|proj]
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum} from './asm.mjs';
import * as K from './kernels.mjs';
import {VM, pushes, program, num} from './vm.mjs';
import {p, mod, F2, ETA, FROB, PSI, AX, NEV} from './math.mjs';
import {mintProof, prove, finish, verifySplit, VKC, NCHUNK, chunkEvents, isAdd, le} from './protocol.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 1500);
const nameRange = (b, n) => Array.from({length: n}, (_, i) => b + i);

export function buildWorker(j0, j1, affOf) {
  const evs = []; for (let j = j0; j < j1; j++) evs.push(...chunkEvents(j));
  const gpos = (j0 === 0 ? [0] : []).concat(evs); // GLS positions handled here
  // delta step index before the first event of the range
  let dIdx = 0; for (let e = 1; e < evs[0]; e++) dIdx += isAdd(e) ? 2 : 1;
  const nDsl = evs.reduce((s, e) => s + (isAdd(e) ? 2 : 1), 0);
  const nBsl = evs.filter((e) => affOf(e)).reduce((s, e) => s + (isAdd(e) ? 2 : 1), 0);
  const nSt = j1 - j0 - (j1 === NCHUNK ? 1 : 0); // states consumed at ends of chunks (the last chunk compares to W)
  const base = ['WSt', 'BSl', 'DSl', 'p', 'z', 'rho', 'xA', 'yA', 'xC', 'yC', 'xB0', 'xB1', 'yB0', 'yB1', ...nameRange('sc', 6), 'N0', 'N1',
    ...[0, 1].flatMap((k) => [0, 1].flatMap((i) => nameRange(`R${k}${i}_`, 6))), ...(j0 > 0 ? nameRange('S0_', 6) : []), 'x0', 'x1', 'y0', 'y1'];
  const a = new Asm(base); a.piles.set('WSt', nSt); a.piles.set('BSl', nBsl); a.piles.set('DSl', nDsl);
  const marks = []; const section = (n) => marks.push({n, off: a.code.length});
  const ev = (coef, pw, outs) => { [...coef, ...pw].forEach((c, i) => a.pick(c, 'in' + i)); a.kernel(K.kEval(), outs, {iters: 300}); };
  const RD = (src, out) => { // split one 48-byte LE word from the top of `src`, unsigned decode, require < p
    a.roll(src).push(48).op(OP.SPLIT, 2, out + 'w', src).roll(out + 'w').pushBytes([0]).op(OP.CAT, 2, out + 'w0').op(OP.BIN2NUM, 1, out);
    a.pick(out).pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); };
  section('env');
  { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3)), t = k.sub(z6, k.c(1n));
    const eta = k.c(ETA), eta2 = k.c(mod(ETA * ETA));
    const xz2 = m(mul(k.env('xA'), z2)), cz2 = m(mul(k.env('xC'), z2));
    k.output(z2, z3, z4, z5, z6, t, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))),
      xz2, m(mul(xz2, t)), k.neg(m(mul(k.env('yA'), z3))), cz2, m(mul(cz2, t)), m(mul(k.env('yC'), z3)));
    a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 't', 'ez', 'ez2', 'ez3', 'ez4', 'ez5', 'xz2', 'xz2t', 'nyz3', 'cz2', 'cz2t', 'cy3'], {iters: 1500}); }
  const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
  section('tables');
  for (const k of [0, 1]) {
    for (const i of [0, 1, 2, 3]) ev(nameRange(`R${k}${i % 2}_`, 6), i < 2 ? ZP : EZP, [`vp${i}`, `vm${i}`]);
    for (const i of [0, 1]) for (let j = 0; j < 6; j++) a.drop(`R${k}${i}_${j}`);
    ['vp0', 'vp1', 'vp2', 'vp3'].forEach((n, i) => a.roll(n).rename(n, 'in' + i)); a.kernel(K.kTable(true), nameRange(`TP${k}_`, 16).reverse(), {iters: 300});
    ['vm0', 'vm1', 'vm2', 'vm3'].forEach((n, i) => a.roll(n).rename(n, 'in' + i)); a.kernel(K.kTable(true), nameRange(`TM${k}_`, 16).reverse(), {iters: 300});
  }
  section('sc');
  ev(nameRange('sc', 6), ZP, ['Scp', 'Scm']);
  section('start');
  const look = (tbl, idxName, out) => { assert.equal(a.top(), idxName); a.st.pop(); const d0 = a.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(a.depth(`${tbl}_${n}`), d0 + n); a.emit(...pushNum(d0), OP.ADD, OP.PICK); a.st.push(out); };
  const nib = (k, out) => { a.roll('N' + k).push(1).op(OP.SPLIT, 2, out + 'b', 'N' + k).roll(out + 'b').op(OP.BIN2NUM, 1, out); };
  const gls = () => { // F+- *= TP0[n0] TP1[n1] (TM at -z)
    nib(0, 'i0'); nib(1, 'i1');
    for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) { a.pick('i0', 'x'); look(T + '0', 'x', 'u'); a.pick('i1', 'x'); look(T + '1', 'x', 'v'); a.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F); }
    a.drop('i0').drop('i1'); };
  if (j0 === 0) { a.pick('Scm', 'Fp').pick('Scp', 'Fm'); gls(); }
  else { ev(nameRange('S0_', 6), ZP, ['Fp', 'Fm']); for (let j = 0; j < 6; j++) a.drop(`S0_${j}`); }
  a.push(0, 'R');
  // delta state at dIdx: (x_j, c_{j-1}, lam_{j-1})
  { const d = VKC.deltaAff; let x = d.x, c = d.y, l = F2.ZERO; let T = [d.x, d.y];
    for (let j = 0, e = 1; j < dIdx; e++) { const step = (s) => { const lam = VKC.lams[j]; const cj = F2.sub(F2.mul(F2.add(l, lam), x), c); const nx = F2.sub(F2.sub(F2.sqr(lam), x), s); c = cj; l = lam; x = nx; j++; }; step(x); if (isAdd(e)) step(d.x); }
    a.push(x.c0, 'dx0').push(x.c1, 'dx1').push(c.c0, 'dc0').push(c.c1, 'dc1').push(l.c0, 'dl0').push(l.c1, 'dl1'); a.push(d.x.c0, 'xd0').push(d.x.c1, 'xd1'); }
  a.pick('yB0').op(OP.NEGATE, 1, 'nyB0').pick('yB1').op(OP.NEGATE, 1, 'nyB1');
  let proj = false;
  const sec = {};
  for (let jj = j0; jj < j1; jj++) {
    for (const e of chunkEvents(jj)) {
      section('ev-dbl');
      if (affOf(e)) {
        a.pileTake('BSl', 'L'); RD('L', 'l0'); RD('L', 'l1'); a.drop('L');
        a.kernel(K.kADbl(), ['r0', 'r1', 'x0', 'x1', 'y0', 'y1', 'Fp', 'Fm'], {iters: ITERS});
        a.roll('r0').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1).roll('r1').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1);
      } else {
        if (!proj) { a.rename('x0', 'X0').rename('x1', 'X1').rename('y0', 'Y0').rename('y1', 'Y1').push(1, 'Z0').push(0, 'Z1'); proj = true; }
        if (!a.has('yz3')) { a.pick('nyz3').op(OP.NEGATE, 1, 'yz3'); a.pick('yz3').pick('t').op(OP.MUL, 2, 'q').pick('p').op(OP.MOD, 2, 'yz3t'); }
        a.kernel(K.kBDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS});
      }
      section('ev-dstep');
      const dstep = (sx0, sx1) => { a.pick(sx0, 's0').pick(sx1, 's1'); a.pileTake('DSl', 'D'); RDc('D', 'n0'); RDc('D', 'n1'); a.drop('D');
        a.kernel(K.kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS}); };
      function RDc(src, out) { a.roll(src).push(48).op(OP.SPLIT, 2, out + 'w', src).roll(out + 'w').op(OP.BIN2NUM, 1, out); } // baked: < p < 2^381, no sign/range issue
      dstep('dx0', 'dx1');
      if (isAdd(e)) {
        section('ev-add');
        a.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('yB0', 'yq0').pick('yB1', 'yq1').pick('Scm', 'cp').pick('Scp', 'cm');
        if (affOf(e)) {
          a.pileTake('BSl', 'L'); RD('L', 'l0'); RD('L', 'l1'); a.drop('L');
          a.kernel(K.kAAdd(), ['r0', 'r1', 'dxa', 'dxb', 'x0', 'x1', 'y0', 'y1', 'Fp', 'Fm'], {iters: ITERS});
          a.roll('dxa').roll('dxb').op(OP.BOOLOR, 2, 'nz').op(OP.VERIFY, 1);
          a.roll('r0').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1).roll('r1').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1);
        } else a.kernel(K.kBAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS});
        section('ev-dstep');
        dstep('xd0', 'xd1');
      }
      section('ev-gls'); gls();
    }
    // chunk end
    if (jj < NCHUNK - 1) {
      section('bound');
      a.pileTake('WSt', 'S'); for (let j = 0; j < 6; j++) RD('S', 's' + j); a.drop('S');
      ev(nameRange('s', 6), ZP, ['Sp', 'Sm']); for (let j = 0; j < 6; j++) a.drop('s' + j);
      a.kernel(K.kBound(), ['Fp', 'Fm', 'R'], {iters: 300});
    } else {
      section('terminal');
      // F *= Rconst(+-z)
      for (let j = 0; j < 6; j++) a.push(VKC.Rconst[j], 'rc' + j); ev(nameRange('rc', 6), ZP, ['rp', 'rm']); for (let j = 0; j < 6; j++) a.drop('rc' + j);
      // W(x) = (s0 + 2) - x^6 + sum_j s_j c_j x^j, c_j = alpha_j + beta_j z^6 (same at +-z)
      const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
      const sc = [0, 1, 2, 3, 4, 5].map((j) => E('sc' + j)); const cj = [null, ...[1, 2, 3, 4, 5].map((j) => m(k.add(k.c(FROB.alpha[j]), mul(k.c(FROB.beta[j]), E('z6')))))];
      const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], cj[j])))];
      const evn = m(k.sum(sc[0], k.c(2n), k.neg(E('z6')), mul(sj[2], E('z2')), mul(sj[4], E('z4')))); const odd = m(k.sum(mul(sj[1], E('z')), mul(sj[3], E('z3')), mul(sj[5], E('z5'))));
      const Wp = k.add(evn, odd), Wm = k.sub(evn, odd);
      const Fp = m(mul(I('Fp'), I('rp'))), Fm = m(mul(I('Fm'), I('rm')));
      k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(Fp, m(Wm))), mul(Fm, m(Wp)))));
      a.kernel(k, ['R'], {iters: 1500});
      // endpoint: T == -psi(B) = (conj(xB) PX, -conj(yB) PY)
      section('endpoint');
      const e2 = new Kernel(); const cm = (a0, a1, g) => [e2.add(e2.mul(a0, e2.c(g.c0)), e2.mul(a1, e2.c(g.c1))), e2.sub(e2.mul(a0, e2.c(g.c1)), e2.mul(a1, e2.c(g.c0)))]; // conj(a) * g
      const [px0, px1] = cm(e2.env('xB0'), e2.env('xB1'), PSI.PX), [py0, py1] = cm(e2.env('yB0'), e2.env('yB1'), PSI.PY);
      if (proj) { const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => e2.in(n)); const mm = (a0, a1, b0, b1) => [e2.sub(e2.mul(a0, b0), e2.mul(a1, b1)), e2.add(e2.mul(a0, b1), e2.mul(a1, b0))];
        const pxm = [e2.mod(px0), e2.mod(px1)], pym = [e2.mod(py0), e2.mod(py1)]; const [u0, u1] = mm(...pxm, Z0, Z1), [v0, v1] = mm(...pym, Z0, Z1);
        e2.output(e2.mod(e2.sub(X0, u0)), e2.mod(e2.sub(X1, u1)), e2.mod(e2.add(Y0, v0)), e2.mod(e2.add(Y1, v1)), e2.mod(Z0), e2.mod(Z1));
        a.kernel(e2, ['e0', 'e1', 'e2', 'e3', 'z0', 'z1'], {iters: 500}); a.op(OP.BOOLOR, 2, 'nz').op(OP.VERIFY, 1);
      } else {
        e2.output(e2.mod(e2.sub(e2.in('x0'), px0)), e2.mod(e2.sub(e2.in('x1'), px1)), e2.mod(e2.add(e2.in('y0'), py0)), e2.mod(e2.add(e2.in('y1'), py1)));
        a.kernel(e2, ['e0', 'e1', 'e2', 'e3'], {iters: 500});
      }
      for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1);
    }
  }
  section('end');
  // leave R on top (for the check), plus T if not terminal
  a.roll('R');
  return {code: a.bytes(), stackNames: base, marks, piles: {nSt, nBsl, nDsl}, evs, gpos, dIdx, proj};
}

// run a worker for proof `pf` on chunks [j0, j1); returns op by section
export function runWorker(pf, j0, j1, affOf, {quiet} = {}) {
  const w = prove(pf, {affOf}); const fin = finish(w, affOf);
  const ref = verifySplit(w, fin, [[j0, j1]], affOf); const Rref = ref.parts[0].R;
  const B = buildWorker(j0, j1, affOf);
  // values
  const st = w.st; const evs = B.evs;
  // B-walk slopes for this range: index of the first affine slope at evs[0]
  let si = 0; for (let e = 1; e < evs[0]; e++) if (affOf(e)) si += isAdd(e) ? 2 : 1;
  const bsl = w.slopes.slice(si, si + B.piles.nBsl).map((l) => Buffer.concat([le(l.c0), le(l.c1)]));
  const dsl = VKC.lams.slice(B.dIdx, B.dIdx + B.piles.nDsl).map((l) => Buffer.concat([le(l.c0), le(l.c1)]));
  const sts = w.states.slice(j0, j0 + B.piles.nSt).map((s) => Buffer.concat(s.slice(0, 6).map((x) => le(x))));
  // start point T at the range start (affine): replay the walk in JS
  let T = [st.xB, st.yB]; { let j = 0; for (let e = 1; e < evs[0]; e++) { assert.ok(affOf(e), 'prototype: projective events only after the range start'); T = stepAff(T, w.slopes[j++]); if (isAdd(e)) T = addAff(T, [st.xB], w.slopes[j++]); } }
  function stepAff([x, y], lam) { const nx = F2.sub(F2.sqr(lam), F2.add(x, x)); return [nx, F2.sub(F2.mul(lam, F2.sub(x, nx)), y)]; }
  function addAff([x, y], [xq], lam) { const nx = F2.sub(F2.sub(F2.sqr(lam), x), xq); return [nx, F2.sub(F2.mul(lam, F2.sub(x, nx)), y)]; }
  const val = {p, z: fin.z, rho: fin.rho, xA: st.xA, yA: st.yA, xC: st.xC, yC: st.yC, xB0: st.xB.c0, xB1: st.xB.c1, yB0: st.yB.c0, yB1: st.yB.c1,
    N0: Uint8Array.from(B.gpos.map((g) => w.N[0][g])), N1: Uint8Array.from(B.gpos.map((g) => w.N[1][g])), x0: T[0].c0, x1: T[0].c1, y0: T[1].c0, y1: T[1].c1};
  w.Sc.slice(0, 6).forEach((x, j) => (val['sc' + j] = x));
  [0, 1].forEach((k) => [0, 1].forEach((i) => VKC.R[k][i].slice(0, 6).forEach((x, j) => (val[`R${k}${i}_${j}`] = x))));
  if (j0 > 0) w.states[j0 - 1].slice(0, 6).forEach((x, j) => (val['S0_' + j] = x));
  const items = []; for (const n of B.stackNames) {
    if (n === 'WSt') items.push(...sts.slice().reverse()); else if (n === 'BSl') items.push(...bsl.slice().reverse()); else if (n === 'DSl') items.push(...dsl.slice().reverse());
    else items.push(val[n] instanceof Uint8Array ? val[n] : val[n]); }
  const u = pushes(items.map((x) => (x instanceof Uint8Array || Buffer.isBuffer(x) ? Uint8Array.from(x) : x)));
  const prog = program(B.code, u); const vm = VM.spec;
  const trace = vm.debug(prog); const last = trace.at(-1);
  const err = last.error && !/unexpected number of items/.test(last.error) ? last.error : undefined;
  assert.equal(err, undefined, 'VM error: ' + err);
  const Rgot = mod(num(last.stack.at(-1)));
  assert.equal(Rgot, Rref, 'partial sum R_i matches the reference');
  // op by section (unlocking pushes excluded)
  const nUnlock = trace.findIndex((s) => s.ip === 0 && s.instructions.length === 0) ; // not used
  const ins = decodeOffsets(B.code); const by = {}; let prev = null;
  for (const s of trace) {
    if (s.instructions.length !== ins.count) { prev = s.metrics.operationCost; continue; }
    const c = s.metrics.operationCost; if (prev === null) { prev = c; continue; } const off = ins.offs[Math.max(0, s.ip - 1)];
    let name = 'pre'; for (const m of B.marks) if (m.off <= off) name = m.n; by[name] = (by[name] ?? 0) + c - prev; prev = c;
  }
  const total = Object.values(by).reduce((x, y) => x + y, 0);
  if (!quiet) { console.log(`chunks [${j0},${j1}) events ${evs.length} (${evs[0]}..${evs.at(-1)}) adds ${evs.filter(isAdd).length} code ${B.code.length} B total op ${total}`); for (const [k, v] of Object.entries(by)) console.log('  ', k.padEnd(12), v); }
  return {total, by, nEvents: evs.length, nAdds: evs.filter(isAdd).length, nChunks: j1 - j0, terminal: j1 === NCHUNK, firstChunk: j0 === 0, nSlopes: B.piles.nBsl, nDsl: B.piles.nDsl, nSt: B.piles.nSt};
}
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
function decodeOffsets(code) { const ins = decodeAuthenticationInstructions(code); const offs = []; let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } return {count: ins.length, offs}; }

if (import.meta.url === `file://${process.argv[1]}`) {
  const j0 = Number(process.argv[2] ?? 0), j1 = Number(process.argv[3] ?? 4); const mode = process.argv[4] ?? 'aff';
  const affOf = mode === 'aff' ? () => true : mode === 'proj' ? () => false : (e) => e <= Number(mode);
  runWorker(mintProof(123n, 456n), j0, j1, affOf);
}
