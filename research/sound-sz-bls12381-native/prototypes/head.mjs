// VM prototype of the head input's own work (no Miller chunks): transcript tree over the n commit regions + WQ,
// challenges and their claims, statement parsing (canonical ranges, nibble mask), curve/twist checks, the GT-GLS
// binding loop, the Horner loop over the quotient and the final batched identity over the workers' partial sums.
// Checked against protocol.mjs (accepts the honest witness; the final residue must be 0). Reports op by section.
//   node head.mjs
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum} from './asm.mjs';
import * as K from './kernels.mjs';
import {VM, pushes, program, num} from './vm.mjs';
import {p, r, mod, PI, PI_SUM_OFFSET, NEV} from './math.mjs';
import {mintProof, prove, finish, verifySplit, NCHUNK, NQ_MAX_FOR, TAG, le} from './protocol.mjs';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';

export function buildHead(nReg, owners, NQ_MAX) {
  const workers = owners.map((o, i) => ({i, j1: o[1]})).filter((x, i) => owners[i][1] > owners[i][0]);
  const base = [...Array.from({length: nReg}, (_, i) => 'REG' + i), 'WQ', 'zc', 'rhoc', ...workers.map((w) => 'Rt' + w.i)];
  const a = new Asm(base); const marks = []; const section = (n) => marks.push({n, off: a.code.length});
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  const RDw = (src, out, n = 48, lim = 'p') => { a.roll(src).push(n).op(OP.SPLIT, 2, out + 'w', src).roll(out + 'w'); U(out); a.pick(out).pick(lim).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); };
  section('transcript');
  a.push(p, 'p').push(r, 'r');
  a.pushBytes(TAG, 'tr');
  for (let i = 0; i < nReg; i++) { a.pick('REG' + i, 'g').op(OP.SHA256, 1, 'hg').op(OP.CAT, 2, 'tr'); }
  a.op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  // WQ: size multiple of 48, 1..NQ_MAX words, leading word nonzero (signed test; the Horner range check makes it exact)
  a.pick('WQ', 'w').op(OP.SIZE, 1, 'w', 'qs').op(OP.NIP, 2, 'qs').pick('qs').push(48).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1);
  a.push(48).push(48 * NQ_MAX + 1).op(OP.WITHIN, 3, 'k').op(OP.VERIFY, 1);
  a.pick('WQ', 'w').push(48).op(OP.SPLIT, 2, 'q0', 'qr').drop('qr').op(OP.BIN2NUM, 1, 'q0').op(OP.VERIFY, 1);
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').pick('WQ', 'w').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
  U('zRaw'); a.pick('p').op(OP.MOD, 2, 'z'); a.pick('z').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  // claims: the workers read z and rho from these 48-byte fields
  for (const [v, c] of [['z', 'zc'], ['rho', 'rhoc']]) a.pick(v).push(48).op(OP.NUM2BIN, 2, 'b').roll(c).op(OP.EQUALVERIFY, 2);
  section('statement');
  a.roll('REG0');
  for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) RDw('REG0', n);
  for (const n of ['n0', 'n1']) RDw('REG0', n, 32, 'r');
  a.roll('REG0').push(128).op(OP.SPLIT, 2, 'G', 'REG0').roll('G').pick('G', 'Gc');
  a.pushBytes(Array(128).fill(0x0f), 'mk').op(OP.AND, 2, 'Gm').pick('G', 'Gc2').op(OP.EQUALVERIFY, 2);
  for (let j = 0; j < 6; j++) RDw('REG0', 'sc' + j);
  a.drop('REG0');
  section('curves');
  { const k = new Kernel(); const m = (x) => k.mod(x); const [xa, ya, xc, yc] = ['xA', 'yA', 'xC', 'yC'].map((n) => k.env(n));
    const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n));
    const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
    const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
    k.output(m(k.sub(k.mul(ya, ya), k.add(k.mul(m(k.mul(xa, xa)), xa), k.c(4n)))), m(k.sub(k.mul(yc, yc), k.add(k.mul(m(k.mul(xc, xc)), xc), k.c(4n)))),
      m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.c(4n))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.c(4n))));
    a.kernel(k, ['ca', 'cc', 'cb0', 'cb1'], {iters: 800}); for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'k').op(OP.VERIFY, 1); }
  section('binding');
  // pi_i = x^i mod r = p^i mod r (derived), TB[n] = sum_{i in n} pi_i ; acc_k = sum_g 2^(63-g) TB[N_k[g]]
  a.push(1, 'in0').pick('p').pick('r').op(OP.MOD, 2, 'in1').pick('in1').pick('in1').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'in2').pick('in1').pick('in2').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'in3');
  a.kernel(K.kTable(false), Array.from({length: 16}, (_, n) => `TB_${15 - n}`), {iters: 200});
  a.roll('G').push(64).op(OP.SPLIT, 2, 'N0', 'N1');
  for (const k of [0, 1]) {
    a.push(0, 'acc');
    a.loop((s) => {
      s.roll('N' + k).push(1).op(OP.SPLIT, 2, 'nb', 'N' + k).roll('nb').op(OP.BIN2NUM, 1, 'ix');
      s.roll('acc').op(OP.DUP, 1, 'acc', 'acc2').op(OP.ADD, 2, 'acc'); s.roll('ix'); s.st.pop();
      const d0 = s.depth('TB_0'); s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push('tb'); s.op(OP.ADD, 2, 'acc');
      s.pick('N' + k, 'Nc').op(OP.SIZE, 1, 'Nc', 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'done');
    });
    a.drop('N' + k);
    a.roll('acc').roll('n' + k).op(OP.SUB, 2, 'd').push(PI_SUM_OFFSET).op(OP.SUB, 2, 'd').pick('r').op(OP.MOD, 2, 'd').op(OP.NOT, 1, 'k').op(OP.VERIFY, 1);
  }
  for (let n = 0; n < 16; n++) a.drop('TB_' + n);
  section('horner');
  { const k = new Kernel(); const z = k.env('z'); const z2 = k.mod(k.mul(z, z)), z4 = k.mod(k.mul(z2, z2)), z6 = k.mod(k.mul(z4, z2)), z8 = k.mod(k.mul(z4, z4));
    k.output(z2, z4, z6, z8); a.kernel(k, ['z2', 'z4', 'z6', 'z8'], {iters: 100}); }
  // left-pad WQ to a multiple of 4 words (4 words per Horner step)
  a.push(0).push(144).op(OP.NUM2BIN, 2, 'zeros').push(192).pick('WQ', 'w').op(OP.SIZE, 1, 'w', 'qs').op(OP.NIP, 2, 'qs').push(192).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
    .push(192).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
  a.push(0, 'acc');
  a.loop((s) => {
    s.roll('WQ').push(192).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
    for (let j = 0; j < 4; j++) { s.roll('Q4').push(48).op(OP.SPLIT, 2, 'w', 'Q4').roll('w'); s.pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'q' + j); s.pick('q' + j).pick('p').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQ', 'w').op(OP.SIZE, 1, 'w', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQ');
  section('final');
  { const k = new Kernel(); const rho = k.env('rho'); const pw = {}; const powOf = (e) => { if (e === 0) return null; if (e === 1) return rho; if (pw[e] !== undefined) return pw[e]; const h = powOf(e >> 1); let v = k.mod(k.mul(h, h)); if (e & 1) v = k.mod(k.mul(v, rho)); return (pw[e] = v); };
    const terms = workers.map((w) => { const e = NCHUNK - w.j1; const P = powOf(e); return P === null ? k.in('Rt' + w.i) : k.mul(k.in('Rt' + w.i), P); });
    const z6 = k.env('z6'); const Mz = k.add(k.sub(k.mul(z6, z6), k.small(z6, 2)), k.c(2n));
    k.output(k.mod(k.sub(k.sum(...terms), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz)))));
    a.kernel(k, ['fin'], {iters: 500}); }
  a.op(OP.NOT, 1, 'result');
  section('end');
  return {code: a.bytes(), base, marks, workers};
}

export function runHead(pf, owners, affOf = () => true, {quiet} = {}) {
  const w = prove(pf, {affOf}); const fin = finish(w, affOf, owners);
  const v = verifySplit(w, fin, owners.filter((o) => o[1] > o[0]), affOf); assert.ok(v.ok);
  const H = buildHead(owners.length, owners, NQ_MAX_FOR(affOf));
  const vals = {WQ: fin.WQ, zc: le(fin.z), rhoc: le(fin.rho)}; fin.regions.forEach((g, i) => (vals['REG' + i] = g));
  let wi = 0; for (const wk of H.workers) vals['Rt' + wk.i] = v.parts[wi++].R;
  const items = H.base.map((n) => vals[n]).map((x) => (Buffer.isBuffer(x) ? Uint8Array.from(x) : x));
  const trace = VM.spec.debug(program(H.code, pushes(items))); const last = trace.at(-1);
  const err = last.error && !/unexpected number of items/.test(last.error) ? last.error : undefined; assert.equal(err, undefined, 'VM: ' + err);
  assert.equal(num(last.stack.at(-1)), 1n, 'head accepts');
  const ins = decodeAuthenticationInstructions(H.code); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
  const by = {}; let prev = null; for (const s of trace) { if (s.instructions.length !== ins.length) { prev = s.metrics.operationCost; continue; } const c = s.metrics.operationCost; if (prev === null) { prev = c; continue; }
    const off = offs[Math.max(0, s.ip - 1)]; let name = 'pre'; for (const m of H.marks) if (m.off <= off) name = m.n; by[name] = (by[name] ?? 0) + c - prev; prev = c; }
  const total = Object.values(by).reduce((x, y) => x + y, 0);
  if (!quiet) { console.log(`head: regions ${owners.length} nq ${fin.nq} WQ ${fin.WQ.length} B, code ${H.code.length} B, op ${total}`); for (const [k, x] of Object.entries(by)) console.log('  ', k.padEnd(12), x); }
  return {total, by, nq: fin.nq, code: H.code.length, regions: fin.regions.map((g) => g.length)};
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const owners = [[0, 0], [0, 8], [8, 16], [16, 24], [24, 32]];
  runHead(mintProof(123n, 456n), owners);
  runHead(mintProof(r - 98765432123456789n, 2n ** 250n + 12345n, 17n, 7n), owners);
}
