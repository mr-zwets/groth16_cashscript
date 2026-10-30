// Today's standard rules: the verifier as a chain of P2SH32 inputs of one transaction (each unlocking <= 10,000 B,
// each budget (41 + unlocking) * 800), in the pattern of chunked/bn254/bn-native-sound (SI-MX3):
//   - one shared redeem R in every input: it reads the code blob from input 0 (OP_INPUTBYTECODE), checks its SHA256,
//     defines it as function 1 and invokes it; the blob defines the shared functions and one role function per input,
//     and dispatches on OP_INPUTINDEX;
//   - graph pin: OP_TXINPUTCOUNT == N and every OP_UTXOBYTECODE(j) equals the own one;
//   - data another input reads lies in fixed-size pushes at the start of an unlocking; the push header in front of
//     every remote range is checked;
//   - a role hands its state to its successor byte-exactly: it encodes its end state canonically (32-byte LE < p)
//     and requires it to equal the successor's HAND push, which the successor decodes as its start state.
// Roles: ST (statement, transcript, Fr, scalars, P_right; publishes G0 = uRaw || s'_q || P_right and hosts WS),
//   MJ / MA (MSM windows, Jacobian / affine with witnessed slopes), SI (Miller events, terminal, quotient).
// The MSM tables cannot be handed over (608-640 stack items), so they are published once:
//   TV (variable bases, entries 2..16) is checked in its host input by exact chord/tangent equations (no slopes);
//   TF (fixed bases, entries 2..16) is a VK constant checked by SHA256. Every MSM role loads both.
import assert from 'node:assert/strict';
import {encodeDataPush, hash256} from '@bitauth/libauth';
import {createHash} from 'node:crypto';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {p, r, mod, inv, ETA, GAMMA1, DIGITS, NE, GLV, OFFSET, aff, G1, F2, peval, pneg, psubst, frob1Monic, M as MPOLY} from './math.mjs';
import {W, TBL, NW, NWR, baseNames, corr, le32, be32, sha, recode, verifyPlonk, jdbl, jmadd, proofLen, bsbOff, HTF_DST, PROOF_PTS} from './plonk.mjs';
import {TAG, WS_SIZE, NQ_MAX, NSTATES, BOUNDS, chains, proveSI, factorSchedule} from './si.mjs';
import {kAffAdd, kAffDbl, kJDbl, kJMAdd, kConv, kEvent, kEval, EV_OUTS, digitOffset, SL_PIECE} from './script.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 2500);
const FIXED = ['Ql', 'Qr', 'Qm', 'Qo', 'Qk', 'S3', 'S1', 'S2', 'G', 'Qcp0', 'Qcp1', 'Qcp2', 'Qcp3']; // BSB22: Qcp_j are VK constants (TF)
const VKP = (vk) => ['S1', 'S2', 'S3', 'Ql', 'Qr', 'Qm', 'Qo', 'Qk', ...vk.qcpNames]; // GV = "gamma" || these points
// byte offset in PROOF of a proof base (BSB22: Bsb_j after the qcp_j(zeta) scalars)
const proofOff = (vk, nm) => (nm.startsWith('Bsb') ? bsbOff(vk, Number(nm.slice(3))) : PROOF_PTS[nm]);
const hdr = (len) => Buffer.from(encodeDataPush(new Uint8Array(len))).subarray(0, encodeDataPush(new Uint8Array(len)).length - len);
const WQ_SIZE = 32 * NQ_MAX; // fixed-size quotient (leading zero words allowed): fixed offsets for remote reads

// ---------------- the plan ----------------
// MSM windows 50..0: MJ roles (Jacobian, no slopes) then MA roles (affine, slopes). SI events split at even cuts.
export function makePlan(vk, {mj = [[50, 46], [45, 45], [44, 40]], ma = [[39, 30], [29, 20], [19, 10], [9, 0]], si = [[0, 34], [34, 65]], c1 = 3600} = {}) {
  const names = baseNames(vk), nbm = names.length - 1, k = vk.nbPublic;
  const fixed = names.slice(0, nbm).filter((n) => FIXED.includes(n)), vari = names.slice(0, nbm).filter((n) => !FIXED.includes(n));
  const roles = [];
  roles.push({kind: 'MJ', hi: mj[0][0], lo: mj[0][1], start: true, code: true});
  roles.push({kind: 'ST'});
  roles.push({kind: 'MJ', hi: mj[1][0], lo: mj[1][1], host: 'TV'});
  roles.push({kind: 'MJ', hi: mj[2][0], lo: mj[2][1], host: 'TF'});
  ma.forEach(([hi, lo], i) => roles.push({kind: 'MA', hi, lo, conv: i === 0, corr: i === ma.length - 1}));
  si.forEach(([e0, e1], i) => roles.push({kind: 'SI', e0, e1, first: i === 0, last: i === si.length - 1, hostWQ: i === 0}));
  const iC1 = roles.length - 1;
  // chain order (successor of each role)
  const order = [0, 2, 3, ...ma.map((_, i) => 4 + i), ...si.map((_, i) => 4 + ma.length + i)];
  order.forEach((ix, j) => { roles[ix].next = order[j + 1] ?? null; });
  const idx = (pred) => roles.findIndex(pred);
  const plan = {iC1, c1Target: c1, names, nbm, fixed, vari, k, roles, N: roles.length, iST: 1, iTV: idx((x) => x.host === 'TV'), iTF: idx((x) => x.host === 'TF'), iWQ: idx((x) => x.hostWQ)};
  plan.G0_SIZE = 32 + 32 * nbm + 64; plan.TV_SIZE = 960 * vari.length; plan.TF_SIZE = 960 * fixed.length;
  // fixed-size pushes at the start of each unlocking (name, size); CODE size is filled in after compilation
  for (const ro of roles) {
    const f = [];
    if (ro.code) f.push(['CODE', null]);
    if (ro.kind === 'ST') f.push(['G0', plan.G0_SIZE], ['X', 128], ['PI', 32 * k], ['PROOF', proofLen(vk)], ['WS', WS_SIZE]);
    if (ro.kind === 'MJ' && !ro.start) f.push(['HAND', 96]);
    if (ro.host === 'TV') f.push(['TV', plan.TV_SIZE]); if (ro.host === 'TF') f.push(['TF', plan.TF_SIZE]);
    if (ro.kind === 'MA') { f.push(['HAND', ro.conv ? 96 : 64]); if (ro.conv) f.push(['ZI', 32]); }
    if (ro.kind === 'SI') { f.push(['HAND', ro.first ? 64 : 17 * 32]); if (ro.hostWQ) f.push(['WQ', WQ_SIZE]); f.push(['DS', null]); if (ro.last) f.push(['C1', null]); } // C1 last: no offset read by a role depends on its size
    ro.fixed = f; ro.slopes = ro.kind === 'MA';
  }
  // SI step slices: steps per event (1 or 2), the terminal adds 2 to the last role
  for (const ro of roles.filter((x) => x.kind === 'SI')) { let s = 0; for (let e = ro.e0; e < ro.e1; e++) s += DIGITS[e] ? 2 : 1; if (ro.last) s += 2; ro.steps = s; }
  { let j = 0; for (const ro of roles.filter((x) => x.kind === 'SI')) { ro.j0 = j; j += ro.steps; } assert.equal(j, 88); }
  for (const ro of roles.filter((x) => x.kind === 'SI')) ro.fixed.find((x) => x[0] === 'DS')[1] = 128 * ro.steps;
  return plan;
}
const offsetOf = (ro, name) => { let o = 0; for (const [n, L] of ro.fixed) { const h = hdr(L).length; if (n === name) return {off: o + h, len: L, h, hdr: hdr(L)}; o += h + L; } throw new Error('no push ' + name); };

// ---------------- program generation ----------------
export function buildMulti(vk, plan) {
  const {names, nbm, fixed, vari, k, roles, N} = plan;
  const CH = chains(vk);
  const ctx = {funcs: new Map(), nextId: 2, defs: []};
  const root = new Asm([], ctx);
  // ---- shared local functions ----
  root.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  root.defLocal('R', 0, 1, (s) => s.push(r, 'r'));
  const dec = (s, lim, be) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w'); if (be) s.op(OP.REVERSEBYTES, 1, 'w'); s.pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    if (lim) s.pick('v').invoke(lim, ['m']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); s.roll('rest'); };
  root.defLocal('DBP', 1, 2, (s) => dec(s, 'P', true)); root.defLocal('DBR', 1, 2, (s) => dec(s, 'R', true));
  root.defLocal('DLP', 1, 2, (s) => dec(s, 'P', false)); root.defLocal('DLR', 1, 2, (s) => dec(s, 'R', false));
  root.defLocal('DLN', 1, 2, (s) => dec(s, null, false)); // LE word, no range check (published data checked elsewhere, or s')
  root.defLocal('BMR', 1, 1, (s) => { s.op(OP.REVERSEBYTES, 1, 'w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v').invoke('R', ['r']).op(OP.MOD, 2, 'x'); });
  root.defLocal('ENC', 1, 1, (s) => { s.invoke('P', ['p']).op(OP.MOD, 2, 'x').invoke('P', ['p']).op(OP.ADD, 2, 'x').invoke('P', ['p']).op(OP.MOD, 2, 'x').push(32).op(OP.NUM2BIN, 2, 'w'); });
  root.defLocal('G1C', 2, 0, (s) => { const kk = new Kernel(); const x = kk.in('in0'), y = kk.in('in1'); kk.output(kk.mod(kk.sub(kk.mul(y, y), kk.add(kk.mul(kk.mul(x, x), x), kk.c(3n))))); s.kernel(kk, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  const slope = (s) => { s.emit(OP.FROMALT, OP.SIZE, OP.NOT, OP.IF, OP.DROP, OP.FROMALT, OP.ENDIF, ...pushNum(32), OP.SPLIT, OP.TOALT); s.st.push('lw');
    s.pushBytes([0]).op(OP.CAT, 2, 'lw0').op(OP.BIN2NUM, 1, 'l').pick('l').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); };
  root.defLocal('ADD', 4, 2, (s) => { slope(s); s.kernel(kAffAdd(), ['x3', 'y3', 'chk', 'ex'], {iters: ITERS}); s.op(OP.ZERONOTEQUAL, 1, 'q').op(OP.VERIFY, 1).op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  root.defLocal('DBL', 2, 2, (s) => { slope(s); s.kernel(kAffDbl(), ['x3', 'y3', 'chk'], {iters: ITERS}); s.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  root.defLocal('JDBL', 3, 3, (s) => s.kernel(kJDbl(), ['X', 'Y', 'Z'], {iters: ITERS}));
  root.defLocal('JMADD', 5, 3, (s) => s.kernel(kJMAdd(), ['X', 'Y', 'Z'], {iters: ITERS}));
  root.defLocal('CONV', 4, 2, (s) => { s.kernel(kConv(), ['x', 'y', 'chk'], {iters: 300}); s.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  root.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  root.defLocal('BETA', 0, 1, (s) => s.push(GLV.beta, 'beta'));
  root.defLocal('GV', 0, 1, (s) => s.pushBytes(Buffer.concat([Buffer.from('gamma'), vk.rawAll]), 'GV'));
  // chord / tangent check of a published table entry (no slope): x3, y3 equal P1 + P2 (or 2 P1)
  root.defLocal('CHK_ADD', 6, 0, (s) => { const kk = new Kernel(); const [x1, y1, x2, y2, x3, y3] = [0, 1, 2, 3, 4, 5].map((i) => kk.in('in' + i)); const m = (x) => kk.mod(x);
    const dx = kk.sub(x2, x1), dy = kk.sub(y2, y1);
    kk.output(m(kk.sub(kk.mul(kk.add(kk.add(x3, x1), x2), m(kk.mul(dx, dx))), kk.mul(dy, dy))), m(kk.sub(kk.mul(kk.add(y3, y1), dx), kk.mul(dy, kk.sub(x1, x3)))), m(dx));
    s.kernel(kk, ['c1', 'c2', 'ex'], {iters: 600}); s.op(OP.ZERONOTEQUAL, 1, 'q').op(OP.VERIFY, 1).op(OP.NOT, 1, 'q').op(OP.VERIFY, 1).op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  root.defLocal('CHK_DBL', 4, 0, (s) => { const kk = new Kernel(); const [x1, y1, x3, y3] = [0, 1, 2, 3].map((i) => kk.in('in' + i)); const m = (x) => kk.mod(x);
    const t = kk.small(m(kk.mul(x1, x1)), 3), y2 = kk.small(y1, 2);
    kk.output(m(kk.sub(kk.mul(kk.add(x3, kk.small(x1, 2)), m(kk.mul(y2, y2))), kk.mul(t, t))), m(kk.sub(kk.mul(kk.add(y3, y1), y2), kk.mul(t, kk.sub(x1, x3)))));
    s.kernel(kk, ['c1', 'c2'], {iters: 600}); s.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1).op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); });
  // CHK15: [bx, by, piece] -> []: the 15 published entries 2B..16B of base (bx, by): each word < p, tangent / chord equations
  root.defLocal('CHK15', 3, 0, (s) => { s.rename('in0', 'bx').rename('in1', 'by').rename('in2', 'pc');
    for (let kx = 2; kx <= TBL; kx++) {
      s.roll('pc').invoke('DLP', ['ex', 'pc']).invoke('DLP', ['ey', 'pc']);
      if (kx === 2) s.pick('bx').pick('by').pick('ex').pick('ey').invoke('CHK_DBL', []);
      else { s.roll('px').roll('py').pick('bx').pick('by').pick('ex').pick('ey').invoke('CHK_ADD', []); }
      s.rename('ex', 'px').rename('ey', 'py');
    }
    s.roll('pc').op(OP.SIZE, 1, 'pc', 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1);
    s.drop('px').drop('py').drop('bx').drop('by'); });
  // LD15: a 960-byte table piece -> the 30 numbers x_2, y_2, .., x_16, y_16 (LE words, range checked by the host)
  root.defLocal('LD15', 1, 30, (s) => { for (let i = 0; i < 30; i++) s.invoke('DLN', ['v' + i, 'in0']); s.roll('in0').op(OP.SIZE, 1, 'in0', 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1); });

  const rread = (a, ix, push, name) => { const ro = roles[ix]; const {off, len, h, hdr: hd} = offsetOf(ro, push);
    a.push(ix).op(OP.INPUTBYTECODE, 1, 'ib').push(off - h).op(OP.SPLIT, 2, 'x', 'ib').drop('x').push(h).op(OP.SPLIT, 2, 'hh', 'ib').roll('hh').pushBytes(hd).op(OP.EQUALVERIFY, 2)
      .push(len).op(OP.SPLIT, 2, name, 'x').drop('x'); };
  // ---- big-I/O shared functions with explicit layouts (compiled once; callers present exactly these items on top) ----
  const fn = (name, ins, outs, piles, body) => {
    const s = new Asm(['__floor', ...ins], ctx); s.localFloor = 0; for (const [n, c] of piles) s.piles.set(n, c);
    body(s); if (outs === null) outs = s.st.slice(1); assert.deepEqual(s.st.slice(1), outs, name + ': exit layout ' + s.st.slice(1).join(','));
    const f = {kind: 'raw', id: ctx.nextId++, code: s.code, ins, outs, piles}; ctx.funcs.set(name, f); ctx.defs.push(f); return f;
  };
  const call = (a, name) => { const f = ctx.funcs.get(name); assert.deepEqual(a.st.slice(-f.ins.length), f.ins, 'call ' + name + ': ' + a.st.slice(-f.ins.length).join(','));
    a.emit(...pushNum(f.id), OP.INVOKE); a.st.splice(a.st.length - f.ins.length); a.st.push(...f.outs); for (const [n, c] of f.piles) if (f.outs.includes(n)) a.piles.set(n, c); return a; };
  const TBN = 2 * TBL * nbm;
  const SC = Array.from({length: nbm}, (_, q) => 'sc' + q);
  // LOADT: [PRF (proof 768 + 96 m B), LAMB (Lambda' 64 B BE), TVb, TFb] -> TB (tables b = 0..nbm-1, entries 1..16, x then y)
  fn('LOADT', ['PRF', 'LAMB', 'TVb', 'TFb'], ['TB'], [['TB', TBN]], (s) => {
    s.invoke('GV', ['GVc']);
    // pieces, in reverse base order so that base 0's piece is on top: the PICK/ROLL depths stay small
    const order = Array.from({length: nbm}, (_, b) => b);
    const cnt = {TVb: 0, TFb: 0}; const pieceOf = order.map((b) => { const bl = FIXED.includes(names[b]) ? 'TFb' : 'TVb'; return [bl, cnt[bl]++]; });
    for (const bl of ['TVb', 'TFb']) { for (let i = 0; i < cnt[bl]; i++) { s.roll(bl).push(960).op(OP.SPLIT, 2, `${bl}_${i}`, bl); } s.roll(bl).op(OP.SIZE, 1, bl, 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1); }
    for (let b = nbm - 1; b >= 0; b--) { const [bl, i] = pieceOf[b]; s.roll(`${bl}_${i}`).rename(`${bl}_${i}`, 'pc' + b); }
    for (let b = 0; b < nbm; b++) { const nm = names[b];
      if (nm === 'G') s.push(1, 'x1').push(2, 'y1');
      else if (FIXED.includes(nm)) { const i = VKP(vk).indexOf(nm); s.pick('GVc', 'vb').push(5 + 64 * i).op(OP.SPLIT, 2, 'x', 'vb').drop('x').invoke('DBP', ['x1', 'vb']).invoke('DBP', ['y1', 'vb']).drop('vb'); }
      else if (nm === 'Lam') s.pick('LAMB', 'vb').invoke('DBP', ['x1', 'vb']).invoke('DBP', ['y1', 'vb']).drop('vb');
      else { const off = proofOff(vk, nm); s.pick('PRF', 'vb').push(off).op(OP.SPLIT, 2, 'x', 'vb').drop('x').invoke('DBP', ['x1', 'vb']).invoke('DBP', ['y1', 'vb']).drop('vb'); }
      s.roll('pc' + b).invoke('LD15', Array.from({length: 30}, (_, i) => 'e' + i));
      const items = s.st.splice(s.st.length - 32); assert.equal(items[0], 'x1'); s.st.push('NEW' + b); s.piles.set('NEW' + b, 32);
    }
    // the inputs sit below the 18 new piles: drop them from below (one ROLL each of a small item), then merge the piles
    for (const n of ['GVc', 'PRF', 'LAMB']) s.drop(n);
    const first = s.st.indexOf('NEW0'); s.st.splice(first, nbm, 'TB'); for (let b = 0; b < nbm; b++) s.piles.delete('NEW' + b); s.piles.set('TB', TBN);
  });
  // window loops: [TB, sc0..sc_{nb-1}, acc, sh, shStop] -> [TB, sc.., acc]; tables at bd = 32 (nb - 1 - q) below TB's top
  const winFn = (name, jac, nb, tbName, tbCount, sc) => {
    const X = jac ? ['aX', 'aY', 'aZ'] : ['ax', 'ay'];
    fn(name, [tbName, ...sc, ...X, 'sh', 'shStop'], [tbName, ...sc, ...X], [[tbName, tbCount]], (a) => {
      a.loop((s) => {
        for (let i = 0; i < W; i++) { s.arrange(X); s.invoke(jac ? 'JDBL' : 'DBL', X); }
        s.push(0, 'bd');
        s.loop((t) => {
          t.pick('bd', 'j').push(5).op(OP.RSHIFTNUM, 2, 'j');
          const D = t.depth(sc[nb - 1]); t.push(D - 1).op(OP.ADD, 2, 'dep'); t.emit(OP.PICK); t.st[t.st.length - 1] = 'sv';
          t.pick('sh').op(OP.RSHIFTNUM, 2, 'sv').push(32).op(OP.MOD, 2, 'b').push(16).op(OP.SUB, 2, 'd');
          t.pick('d').op(OP.ZERONOTEQUAL, 1, 'nz').ifElse((u) => {
            u.pick('d').push(0).op(OP.LESSTHAN, 2, 'neg').roll('d').op(OP.ABS, 1, 'k');
            u.emit(OP.DUP, OP.ADD); u.st[u.st.length - 1] = 'k2'; u.pick('bd').op(OP.SWAP, 2, 'bd_', 'k2').op(OP.SUB, 2, 'off');
            const dTB = u.depth(tbName); u.push(dTB + 2 * TBL + 1).op(OP.ADD, 2, 'dep');
            u.emit(OP.DUP, OP.PICK, OP.SWAP, OP.SUB1, OP.PICK); u.st.splice(u.st.length - 1, 1, 'tx', 'ty');
            u.roll('neg').ifElse((v) => { v.invoke('P', ['p']).roll('ty').op(OP.SUB, 2, 'ty'); });
            u.arrange([...X, 'tx', 'ty']).invoke(jac ? 'JMADD' : 'ADD', X);
          }, (u) => { u.drop('d'); });
          t.roll('bd').push(32).op(OP.ADD, 2, 'bd').pick('bd').push(32 * nb).op(OP.NUMEQUAL, 2, 'done');
        });
        s.drop('bd');
        s.roll('sh').push(5).op(OP.SUB, 2, 'sh').pick('sh').pick('shStop').op(OP.NUMEQUAL, 2, 'done');
      });
      a.drop('sh').drop('shStop');
    });
  };
  winFn('WINJ', true, nbm, 'TB', TBN, SC); winFn('WINA', false, nbm, 'TB', TBN, SC);
  winFn('WINR', true, 2, 'TR', 2 * TBL * 2, ['sr0', 'sr1']);
  // the SI event loop over the role's schedule: SCH = 2 bytes per event (digit code, boundary flag); digit codes
  // 0, 1, 0x81 (= -1), 2 (terminal step 1: s = x(psi(Q)), times 1), 3 (terminal step 2: times 1)
  const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'];
  const HOT = ['xqa0', 'xqa1', 'xqb0', 'xqb1', 'pqa0', 'pqa1', 'pqb0', 'pqb1', 'Scp', 'Scm', 'ya', 'cza', 'czta', 'yb', 'czb', 'cztb', 'z3t', 'rho', ...ZP, 'p'];
  const STATE = EV_OUTS; // chain a (6), chain b (6), Fp, Fm
  const SIL_IN = [...HOT, 'D', 'SCH', 'WSs', 'R', ...STATE];
  fn('SIL', SIL_IN, [...HOT, 'R', ...STATE], [], (a) => {
    const readStep = (s) => { s.roll('D').push(128).op(OP.SPLIT, 2, 'lb', 'D').roll('lb');
      for (const n of ['n0a', 'n1a', 'n0b']) { s.push(32).op(OP.SPLIT, 2, n + 'w', 'lb').roll(n + 'w').op(OP.BIN2NUM, 1, n); s.roll('lb'); }
      s.op(OP.BIN2NUM, 1, 'n1b'); };
    a.defBound('EVD', (s) => { readStep(s); s.kernel(kEvent(true), EV_OUTS, {iters: ITERS}); });
    a.defBound('EVA', (s) => { readStep(s); s.kernel(kEvent(false), EV_OUTS, {iters: ITERS}); });
    const L0 = a.st.slice();
    a.loop((s) => {
      s.roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('SCH').push(1).op(OP.SPLIT, 2, 'bb', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
      s.pick('d').push(2).op(OP.LESSTHAN, 2, 'isEv'); const LB = s.st.slice(0, -1); s.ifElse((t) => {   // a Miller event (doubling, then the addition if d != 0)
        t.pick('dx0a', 's0a').pick('dx1a', 's1a').pick('dx0b', 's0b').pick('dx1b', 's1b').invoke('EVD').arrangeAll(LB); // same layout at every EVA call site
        t.pick('d').op(OP.ZERONOTEQUAL, 1, 'nz').ifElse((u) => {
          u.pick('d').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse((v) => { v.pick('Scp', 'cp').pick('Scm', 'cm'); }, (v) => { v.pick('Scm', 'cp').pick('Scp', 'cm'); });
          u.pick('xqa0', 's0a').pick('xqa1', 's1a').pick('xqb0', 's0b').pick('xqb1', 's1b').invoke('EVA');
        });
      }, (t) => {   // terminal step: s = x(psi(Q)) (d = 2) or s = anything (d = 3), times 1
        t.push(1, 'cp').push(1, 'cm');
        t.pick('d').push(2).op(OP.NUMEQUAL, 2, 't1').ifElse((u) => { u.pick('pqa0', 's0a').pick('pqa1', 's1a').pick('pqb0', 's0b').pick('pqb1', 's1b'); },
          (u) => { u.pick('dx0a', 's0a').pick('dx1a', 's1a').pick('dx0b', 's0b').pick('dx1b', 's1b'); });
        t.invoke('EVA');
      });
      s.drop('d').roll('bb').op(OP.BIN2NUM, 1, 'bnd').ifElse((t) => {
        t.roll('WSs').push(192).op(OP.SPLIT, 2, 'S', 'WSs').roll('S');
        for (let j = 0; j < 6; j++) t.invoke('DLP', ['s' + j, 'S']);
        t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EV', ['Sp', 'Sm']);
        const kk = new Kernel(); const R = kk.in('R');
        kk.output(kk.in('Sp'), kk.in('Sm'), kk.mod(kk.sub(kk.add(kk.mul(R, kk.env('rho')), kk.mul(kk.in('Fp'), kk.in('Sm'))), kk.mul(kk.in('Fm'), kk.in('Sp')))));
        t.kernel(kk, ['Fp', 'Fm', 'R'], {iters: 500});
      });
      s.pick('SCH', 'Sc_').op(OP.SIZE, 1, 'Sc_', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
    });
    for (const n of ['D', 'SCH', 'WSs']) a.roll(n).op(OP.SIZE, 1, n, 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1);
    a.arrangeAll(['__floor', ...HOT, 'R', ...STATE]);
  });

  // SIPRE: [WQb, PLx, PLy] -> transcript (h0, rho, z), z powers, S_c(+-z), line environments, chain constants
  fn('SIPRE', ['WQb', 'PLx', 'PLy'], null, [], (a) => siPre(a, vk, plan, {rread: (...x) => rread(...x), CH, ZP}));
  // ---- role programs ----
  const own = (a, ro, slopes) => { // own layout: fixed pushes, [slope pieces], FILL (all zero); graph pin
    const nf = ro.fixed.length;
    a.roll('FILL').op(OP.SIZE, 1, 'FILL', 'fs').push(0).op(OP.SWAP, 2, 'z0', 'fs').op(OP.NUM2BIN, 2, 'zz').op(OP.EQUALVERIFY, 2);
    if (slopes) { a.emit(OP['0'], OP.TOALT, OP.BEGIN, OP.SIZE, OP.DUP, OP.ZERONOTEQUAL, OP.VERIFY, ...pushNum(32), OP.MOD, OP.NOT, OP.VERIFY, OP.TOALT, OP.DEPTH, ...pushNum(nf), OP.NUMEQUAL, OP.UNTIL);
      a.st.splice(a.st.indexOf('SLb'), 1); a.alt.push('SLSTREAM'); }
    a.emit(OP.DEPTH, ...pushNum(nf), OP.NUMEQUALVERIFY);
    for (const [n, L] of ro.fixed) if (L !== null && n !== 'CODE') a.pick(n, n + '_').op(OP.SIZE, 1, n + '_', 'sz').op(OP.NIP, 2, 'sz').push(L).op(OP.NUMEQUALVERIFY, 2);
    a.emit(OP.TXINPUTCOUNT, ...pushNum(N), OP.NUMEQUALVERIFY);
    for (let j = 0; j < N; j++) a.emit(...pushNum(j), OP.UTXOBYTECODE, OP.INPUTINDEX, OP.UTXOBYTECODE, OP.EQUALVERIFY);
  };
  const finish = (a) => { // clear the main stack (its size is known: symbolic items and sized piles), then leave TRUE
    let n = 0; for (const x of a.st) n += a.piles.has(x) ? a.piles.get(x) : 1; assert.equal(a.alt.length, 0, 'altstack not empty');
    if (n >= 16) { a.emit(...pushNum(Math.floor(n / 8)), OP.BEGIN, OP.TOALT, OP.TWODROP, OP.TWODROP, OP.TWODROP, OP.TWODROP, OP.FROMALT, OP.SUB1, OP.DUP, OP.NOT, OP.UNTIL, OP.DROP); n %= 8; }
    for (; n >= 2; n -= 2) a.emit(OP.TWODROP); if (n) a.emit(OP.DROP); a.emit(OP.TRUE); a.st = ['ok']; a.piles = new Map(); };
  const handOut = (a, ro, items) => { // encode canonically, require equality with the successor's HAND
    items.forEach((n, i) => { a.roll(n).invoke('ENC', ['w' + i]); if (i) a.op(OP.CAT, 2, 'w' + i); });
    a.st[a.st.length - 1] = 'hout'; rread(a, ro.next, 'HAND', 'hnext'); a.op(OP.EQUALVERIFY, 2); };
  const handIn = (a, names_) => { a.pick('HAND', 'hb'); for (const n of names_) a.invoke('DLP', [n, 'hb']); a.drop('hb'); };
  const scalars = (a) => { rread(a, plan.iST, 'G0', 'g0'); a.push(32).op(OP.SPLIT, 2, 'x', 'g0').drop('x'); for (let q = 0; q < nbm; q++) a.invoke('DLN', [SC[q], 'g0']); a.drop('g0'); };
  const tables = (a, ro) => {
    rread(a, plan.iST, 'PROOF', 'PRF'); rread(a, plan.iST, 'X', 'LAMB'); a.push(64).op(OP.SPLIT, 2, 'LAMB', 'x').drop('x');
    if (ro.host === 'TV') a.pick('TV', 'TVb'); else rread(a, plan.iTV, 'TV', 'TVb');
    if (ro.host === 'TF') a.pick('TF', 'TFb'); else rread(a, plan.iTF, 'TF', 'TFb');
    call(a, 'LOADT');
  };
  const bodies = [];
  for (const [ix, ro] of roles.entries()) {
    const init = [...(ro.slopes ? ['SLb'] : []), ...ro.fixed.map((x) => x[0])];
    // unlocking order: fixed pushes first (bottom), then the slope pieces, then FILL
    const st0 = [...ro.fixed.map((x) => x[0]), ...(ro.slopes ? ['SLb'] : []), 'FILL'];
    const a = new Asm(st0, ctx);
    if (ro.slopes) a.piles.set('SLb', null);
    own(a, ro, ro.slopes);
    if (ro.code) a.drop('CODE');
    if (ro.kind === 'SI' && ro.last) a.drop('C1');
    if (ro.kind === 'ST') stRole(a, ro);
    else if (ro.kind === 'MJ' || ro.kind === 'MA') mRole(a, ro, ix);
    else siRole(a, ro, ix);
    finish(a); bodies.push(a.code);
  }
  function mRole(a, ro, ix) {
    if (ro.host === 'TV') tvCheck(a);
    if (ro.host === 'TF') a.pick('TF', 'tfh').op(OP.SHA256, 1, 'tfh').pushBytes(sha(tfBlob(vk, plan))).op(OP.EQUALVERIFY, 2);
    tables(a, ro); scalars(a);
    const jac = ro.kind === 'MJ';
    if (ro.start) { const o = aff(OFFSET); a.push(o[0], 'aX').push(o[1], 'aY').push(1, 'aZ'); }
    else if (ro.conv) { handIn(a, ['aX', 'aY', 'aZ']); a.pick('ZI', 'zb').invoke('DLP', ['zi', 'zb']).drop('zb').arrange(['aX', 'aY', 'aZ', 'zi']).invoke('CONV', ['ax', 'ay']); }
    else handIn(a, jac ? ['aX', 'aY', 'aZ'] : ['ax', 'ay']);
    const X = jac ? ['aX', 'aY', 'aZ'] : ['ax', 'ay'];
    a.arrange(['TB', ...SC, ...X]); a.push(W * ro.hi, 'sh').push(W * (ro.lo - 1), 'shStop'); call(a, jac ? 'WINJ' : 'WINA');
    if (ro.corr) { const cr = aff(corr(NW)); a.push(cr[0], 'cx').push(cr[1], 'cy').arrange(['ax', 'ay', 'cx', 'cy']).invoke('ADD', ['ax', 'ay']); }
    if (ro.slopes) { a.emit(OP.FROMALT, OP.SIZE, OP.NOT, OP.VERIFY, OP.DROP, OP.FROMALT, OP.SIZE, OP.NOT, OP.VERIFY, OP.DROP); a.alt.pop(); }
    handOut(a, ro, X);
  }
  function tvCheck(a) { // TV entries 2..16 of every variable base: < p, 2B by the tangent, (k+1)B = kB + B by the chord
    rread(a, plan.iST, 'PROOF', 'PRF'); rread(a, plan.iST, 'X', 'LAMB');
    a.pick('TV', 'tv');
    for (const nm of vari) {
      if (nm === 'Lam') a.pick('LAMB', 'vb'); else { const off = proofOff(vk, nm); a.pick('PRF', 'vb').push(off).op(OP.SPLIT, 2, 'x', 'vb').drop('x'); }
      a.invoke('DBP', ['bx', 'vb']).invoke('DBP', ['by', 'vb']).drop('vb');
      a.roll('tv').push(960).op(OP.SPLIT, 2, 'pc', 'tv').arrange(['bx', 'by', 'pc']).invoke('CHK15', []);
    }
    a.roll('tv').op(OP.SIZE, 1, 'tv', 'sz').op(OP.NIP, 2, 'sz').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('PRF').drop('LAMB');
  }
  function stRole(a, ro) { statement(a, vk, plan, call); }
  function siRole(a, ro, ix) { siProgram(a, vk, plan, ro, ix, {call, rread, handIn, handOut, CH, HOT, STATE, SIL_IN, ZP}); }
  // ---- the code: two blobs (each <= 10,000 B): C1 (hosted in the last input) defines a share of the functions; C0 (input 0)
  // defines the rest and the role functions, then dispatches on the input index. R defines and runs C1 (function 0), then C0 (1).
  const roleBase = ctx.nextId; bodies.forEach(() => ctx.nextId++);
  const defs = [...ctx.defs].sort((x, y) => y.code.length - x.code.length); const in1 = new Set(); let sz1 = 0;
  for (const f of defs) if (sz1 + f.code.length + 4 <= plan.c1Target) { in1.add(f); sz1 += f.code.length + 4; }
  const def = (f) => [...pushData(f.code), ...pushNum(f.id), OP.DEFINE];
  const c1 = Buffer.from(defs.filter((f) => in1.has(f)).flatMap(def));
  const pro = defs.filter((f) => !in1.has(f)).flatMap(def);
  bodies.forEach((b, i) => pro.push(...pushData(b), ...pushNum(roleBase + i), OP.DEFINE));
  const code = Buffer.from([...pro, OP.INPUTINDEX, ...pushNum(roleBase), OP.ADD, OP.INVOKE]);
  roles[0].fixed[0][1] = code.length; roles[plan.iC1].fixed.find((x) => x[0] === 'C1')[1] = c1.length;
  const o0 = offsetOf(roles[0], 'CODE'), o1 = offsetOf(roles[plan.iC1], 'C1');
  const load = (ix, o, blob, id) => [...pushNum(ix), OP.INPUTBYTECODE, ...pushNum(o.off), OP.SPLIT, OP.NIP, ...pushNum(o.len), OP.SPLIT, OP.DROP, OP.DUP, OP.SHA256, ...pushData(sha(blob)), OP.EQUALVERIFY, ...pushNum(id), OP.DEFINE, ...pushNum(id), OP.INVOKE];
  const redeem = Buffer.from([...load(plan.iC1, o1, c1, 0), ...load(0, o0, code, 1)]);
  return {code, c1, redeem, bodies: bodies.map((b) => b.length), funcs: Object.fromEntries([...ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]))};
}

// ---------------- ST: statement, transcript, Fr, scalars s', P_right; publishes G0 ----------------
function statement(a, vk, plan, call) {
  const {names, nbm, k} = plan; const m = vk.m;
  a.pick('PROOF', 'pb');
  for (const n of ['Lx', 'Ly', 'Rx', 'Ry', 'Ox', 'Oy', 'H0x', 'H0y', 'H1x', 'H1y', 'H2x', 'H2y']) a.invoke('DBP', [n, 'pb']);
  for (const n of ['l', 'rr', 'o', 's1', 's2']) a.invoke('DBR', [n, 'pb']);
  a.invoke('DBP', ['Zx', 'pb']).invoke('DBP', ['Zy', 'pb']).invoke('DBR', ['zu', 'pb']);
  for (const n of ['Wzx', 'Wzy', 'Wzwx', 'Wzwy']) a.invoke('DBP', [n, 'pb']);
  for (let j = 0; j < m; j++) a.invoke('DBR', ['qcp' + j, 'pb']);
  for (let j = 0; j < m; j++) a.invoke('DBP', ['Bsb' + j + 'x', 'pb']).invoke('DBP', ['Bsb' + j + 'y', 'pb']);
  a.drop('pb');
  a.pick('PI', 'pib'); for (let i = 0; i < k; i++) a.invoke('DBR', ['pub' + i, 'pib']); a.drop('pib');
  a.pick('X', 'xb'); a.invoke('DBP', ['Lamx', 'xb']).invoke('DBP', ['Lamy', 'xb']).invoke('DLR', ['invP', 'xb']).invoke('DLP', ['ziR', 'xb']).drop('xb');
  const BS = Array.from({length: m}, (_, j) => 'Bsb' + j);
  for (const P of ['L', 'R', 'O', 'H0', 'H1', 'H2', 'Z', 'Wz', 'Wzw', 'Lam', ...BS]) a.pick(P + 'x').pick(P + 'y').invoke('G1C', []);
  for (const P of ['L', 'R', 'O', 'H0', 'H1', 'H2', 'Z', 'Lam', ...BS]) a.drop(P + 'x').drop(P + 'y');
  // transcript
  a.invoke('GV', ['GV']).pick('GV', 'h').pick('PI').op(OP.CAT, 2, 'h').pick('PROOF').push(192).op(OP.SPLIT, 2, 'lro', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'gRaw');
  a.pushBytes(Buffer.from('beta')).pick('gRaw').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'bRaw');
  a.pushBytes(Buffer.from('alpha')).pick('bRaw').op(OP.CAT, 2, 'h');
  if (m > 0) a.pick('PROOF').push(bsbOff(vk, 0)).op(OP.SPLIT, 2, 'x', 'bsb').drop('x').op(OP.CAT, 2, 'h'); // BSB22: alpha binds Bsb22_j before Z
  a.pick('PROOF').push(544).op(OP.SPLIT, 2, 'x', 'zz').drop('x').push(64).op(OP.SPLIT, 2, 'zr', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'aRaw');
  a.pushBytes(Buffer.from('zeta')).pick('aRaw').op(OP.CAT, 2, 'h').pick('PROOF').push(192).op(OP.SPLIT, 2, 'x', 'hh').drop('x').push(192).op(OP.SPLIT, 2, 'hr', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'zRaw');
  a.roll('gRaw').invoke('BMR', ['gamma']).roll('bRaw').invoke('BMR', ['beta']).roll('aRaw').invoke('BMR', ['alpha']).roll('zRaw').invoke('BMR', ['zeta']);
  { const dstp = [...HTF_DST, HTF_DST.length]; // BSB22 hash-to-field, as script.mjs 3b
    for (let j = 0; j < m; j++) {
      a.push(0).push(64).op(OP.NUM2BIN, 2, 'zpad');
      a.pick('PROOF').push(bsbOff(vk, j)).op(OP.SPLIT, 2, 'x', 'cm').drop('x').push(64).op(OP.SPLIT, 2, 'cm', 'x').drop('x').op(OP.CAT, 2, 'h');
      a.pushBytes([0, 48, 0, ...dstp]).op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'b0');
      a.pick('b0').pushBytes([1, ...dstp]).op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'b1');
      a.roll('b0').pick('b1').op(OP.XOR, 2, 'bx').pushBytes([2, ...dstp]).op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'b2');
      a.push(16).op(OP.SPLIT, 2, 'b2h', 'x').drop('x').roll('b1').roll('b2h').op(OP.CAT, 2, 'u48').invoke('BMR', ['hc' + j]);
    } }
  a.invoke('R', ['r']);
  { const kk = new Kernel(); const E = (n) => kk.env(n), I = (n) => kk.in(n), M = (x) => kk.modr(x), mul = (x, y) => kk.mul(x, y), add = (x, y) => kk.add(x, y), sub = (x, y) => kk.sub(x, y), c = (v) => kk.c(v);
    const canon = (x) => M(add(M(x), E('r')));
    const zeta = E('zeta'), alpha = E('alpha'), beta = E('beta'), gamma = E('gamma');
    let zn = zeta; for (let i = 0; i < vk.log2n; i++) zn = M(mul(zn, zn));
    const zh = sub(zn, c(1n)); const dens = vk.denPow.map((w) => sub(zeta, c(w)));
    let prod = dens[0]; for (let i = 1; i < dens.length; i++) prod = M(mul(prod, dens[i]));
    const invP = I('invP'); const chk = M(sub(mul(prod, invP), c(1n)));
    const invDens = dens.map((_, i) => { let x = invP; dens.forEach((d, j) => { if (j !== i) x = M(mul(x, d)); }); return x; });
    const zhn = M(mul(zh, c(vk.nInv)));
    let pi = null; for (let i = 0; i < k + m; i++) { const tI = M(mul(M(mul(zhn, invDens[i])), c(vk.denPow[i]))); const term = mul(tI, E(i < k ? 'pub' + i : 'hc' + (i - k))); pi = pi ? add(pi, term) : term; }
    pi = M(pi);
    const a2l1 = M(mul(M(mul(alpha, alpha)), M(mul(zhn, invDens[0]))));
    const t1 = add(add(E('l'), M(mul(beta, E('s1')))), gamma), t2 = add(add(E('rr'), M(mul(beta, E('s2')))), gamma); const t12 = M(mul(t1, t2));
    const r0 = canon(sub(sub(a2l1, pi), M(mul(M(mul(M(mul(t12, add(E('o'), gamma))), alpha)), E('zu')))));
    const s1c = M(mul(M(mul(M(mul(t12, beta)), alpha)), E('zu'))); const bz = M(mul(beta, zeta));
    const f1 = add(add(E('l'), bz), gamma), f2v = add(add(E('rr'), M(mul(bz, c(vk.k)))), gamma), f3 = add(add(E('o'), M(mul(bz, c(mod(vk.k * vk.k, r))))), gamma);
    const s2c = M(sub(a2l1, M(mul(M(mul(M(mul(f1, f2v)), f3)), alpha)))); const zn2 = M(mul(zn, M(mul(zeta, zeta))));
    kk.output(chk, r0, s1c, s2c, M(zh), zn2); a.kernel(kk, ['chkInv', 'r0', 's1c', 's2c', 'zh', 'zn2'], {iters: 3000}); }
  a.roll('chkInv').op(OP.NOT, 1, 'q').op(OP.VERIFY, 1);
  const be32n = (n) => { a.pick(n).push(32).op(OP.NUM2BIN, 2, 'b').op(OP.REVERSEBYTES, 1, n + 'BE'); };
  a.pushBytes(Buffer.from('gamma')); be32n('zeta'); a.op(OP.CAT, 2, 'h').pick('X').push(64).op(OP.SPLIT, 2, 'lam', 'x').drop('x').op(OP.CAT, 2, 'h');
  a.pick('PROOF').push(192).op(OP.SPLIT, 2, 'lro', 'x').drop('x').op(OP.CAT, 2, 'h');
  a.pick('GV', 's12').push(5).op(OP.SPLIT, 2, 'x', 's12').drop('x').push(128).op(OP.SPLIT, 2, 's12', 'x').drop('x').op(OP.CAT, 2, 'h');
  if (m > 0) a.pick('GV', 'qv').push(5 + 512).op(OP.SPLIT, 2, 'x', 'qv').drop('x').op(OP.CAT, 2, 'h'); // digests .. S1 S2 Qcp_j (the GV tail)
  a.drop('GV');
  be32n('r0'); a.op(OP.CAT, 2, 'h').pick('PROOF').push(384).op(OP.SPLIT, 2, 'x', 'ev').drop('x').push(160).op(OP.SPLIT, 2, 'ev', 'x').drop('x').op(OP.CAT, 2, 'h');
  if (m > 0) a.pick('PROOF').push(768).op(OP.SPLIT, 2, 'x', 'qe').drop('x').push(32 * m).op(OP.SPLIT, 2, 'qe', 'x').drop('x').op(OP.CAT, 2, 'h'); // claimed qcp_j(zeta)
  a.pick('PROOF').push(608).op(OP.SPLIT, 2, 'x', 'zub').drop('x').push(32).op(OP.SPLIT, 2, 'zub', 'x').drop('x').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'vRaw');
  a.pick('vRaw').invoke('BMR', ['v']);
  a.pushBytes(Buffer.from('u')).roll('vRaw').op(OP.CAT, 2, 'h').pick('PROOF').push(640).op(OP.SPLIT, 2, 'x', 'ww').drop('x');
  if (m > 0) a.push(128).op(OP.SPLIT, 2, 'ww', 'x').drop('x'); // W_zeta || W_zetaOmega only
  a.op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'uRaw');
  a.pick('uRaw', 'ub').push(8).op(OP.SPLIT, 2, 'b1', 'ub').roll('b1').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'u1');
  a.roll('ub').push(8).op(OP.SPLIT, 2, 'b2', 'ub').roll('b2').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'u2');
  a.roll('ub').pushBytes([0]).op(OP.CAT, 2, 'b').op(OP.BIN2NUM, 1, 'tp');
  a.push(digitOffset(NW), 'Cdig');
  { const kk = new Kernel(); const E = (n) => kk.env(n), M = (x) => kk.modr(x), mul = (x, y) => kk.mul(x, y), add = (x, y) => kk.add(x, y), sub = (x, y) => kk.sub(x, y), c = (v) => kk.c(v);
    const canon = (x) => M(add(M(x), E('r')));
    const v = E('v'), tp = E('tp'), u = M(add(E('u1'), mul(c(GLV.lambda), E('u2')))), nt = sub(c(0n), tp);
    const vs = [c(1n), v]; for (let i = 2; i < 6 + m; i++) vs.push(M(mul(vs[i - 1], v)));
    const e = M(kk.sum(E('r0'), mul(v, E('l')), mul(vs[2], E('rr')), mul(vs[3], E('o')), mul(vs[4], E('s1')), mul(vs[5], E('s2')), ...Array.from({length: m}, (_, j) => mul(vs[6 + j], E('qcp' + j)))));
    const zh = E('zh'), zn2 = E('zn2'), zz = M(mul(zh, zn2));
    const S = {Ql: mul(nt, E('l')), Qr: mul(nt, E('rr')), Qm: mul(nt, M(mul(E('l'), E('rr')))), Qo: mul(nt, E('o')), Qk: nt, S3: mul(nt, E('s1c')), Z: add(mul(nt, E('s2c')), u),
      H0: mul(tp, zh), H1: mul(tp, zz), H2: mul(tp, M(mul(zz, zn2))), Lam: add(c(1n), tp), L: v, R: vs[2], O: vs[3], S1: vs[4], S2: vs[5],
      G: sub(c(0n), add(e, M(mul(u, E('zu'))))), Wz: E('zeta'), Wzw: mul(M(mul(u, E('zeta'))), c(vk.omega))};
    for (let j = 0; j < m; j++) { S['Bsb' + j] = mul(nt, E('qcp' + j)); S['Qcp' + j] = vs[6 + j]; }
    kk.output(...names.slice(0, nbm).map((nm) => kk.add(canon(S[nm]), E('Cdig'))));
    a.kernel(kk, names.slice(0, nbm).map((_, q) => 'sc' + q), {iters: 3000}); }
  a.drop('Cdig');
  // G0 = uRaw || s'_q (LE 32) || P_right
  a.pick('uRaw', 'g0'); for (let q = 0; q < nbm; q++) a.roll('sc' + q).push(32).op(OP.NUM2BIN, 2, 'w').op(OP.CAT, 2, 'g0');
  // P_right = -(Wz + u1 Wzw + u2 phi(Wzw)), Jacobian over all NWR windows; Wzw's table from TV (checked in its host)
  { const ro = plan.roles[plan.iTV]; const {off, len, h, hdr: hd} = offsetOf(ro, 'TV'); const vi = plan.vari.indexOf('Wzw');
    a.push(plan.iTV).op(OP.INPUTBYTECODE, 1, 'ib').push(off + 960 * vi).op(OP.SPLIT, 2, 'x', 'ib').drop('x').push(960).op(OP.SPLIT, 2, 'pc', 'x').drop('x'); }
  a.pick('Wzwx', 'x1').pick('Wzwy', 'y1').roll('pc').invoke('LD15', Array.from({length: 30}, (_, i) => 'e' + i));
  { const it = a.st.splice(a.st.length - 32); assert.equal(it[0], 'x1'); a.st.push('TW'); a.piles.set('TW', 32); }
  const one = [...pushNum(31), OP.PICK, ...a.invokeBytes('BETA'), OP.MUL, ...a.invokeBytes('P'), OP.MOD, ...pushNum(31), OP.PICK];
  for (let kx = 0; kx < TBL; kx++) a.emit(...one);
  a.st[a.st.length - 1] = 'TR'; a.piles.delete('TW'); a.piles.set('TR', 64);
  a.pick('u1').push(digitOffset(NWR)).op(OP.ADD, 2, 'sr0').pick('u2').push(digitOffset(NWR)).op(OP.ADD, 2, 'sr1');
  const o = aff(OFFSET); a.push(o[0], 'aX').push(o[1], 'aY').push(1, 'aZ').arrange(['TR', 'sr0', 'sr1', 'aX', 'aY', 'aZ']);
  a.push(W * (NWR - 1), 'sh').push(-W, 'shStop'); call(a, 'WINR');
  const cr = aff(corr(NWR)); a.push(cr[0], 'cx').push(cr[1], 'cy').arrange(['aX', 'aY', 'aZ', 'cx', 'cy']).invoke('JMADD', ['aX', 'aY', 'aZ']);
  a.pick('Wzx', 'cx').pick('Wzy', 'cy').arrange(['aX', 'aY', 'aZ', 'cx', 'cy']).invoke('JMADD', ['aX', 'aY', 'aZ']);
  a.roll('ziR').arrange(['aX', 'aY', 'aZ', 'ziR']).invoke('CONV', ['PRx', 'PRy0']);
  a.invoke('P', ['p']).roll('PRy0').op(OP.SUB, 2, 'PRy');
  a.roll('g0').roll('PRx').invoke('ENC', ['w']).op(OP.CAT, 2, 'g0').roll('PRy').invoke('ENC', ['w']).op(OP.CAT, 2, 'g0');
  a.pick('G0').op(OP.EQUALVERIFY, 2);
}

// ---------------- SI roles ----------------
function siPre(a, vk, plan, {rread, CH, ZP}) {
  rread(a, plan.iST, 'G0', 'g0'); a.push(32).op(OP.SPLIT, 2, 'uRaw', 'g0').push(32 * plan.nbm).op(OP.SPLIT, 2, 'x', 'g0').drop('x').roll('g0');
  a.invoke('DLP', ['PRx', 'g0']).invoke('DLP', ['PRy', 'g0']).drop('g0');
  rread(a, plan.iST, 'WS', 'WSb');
  a.pushBytes(TAG, 'tag').roll('uRaw').op(OP.CAT, 2, 'h').pick('WSb').op(OP.CAT, 2, 'h').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').pick('WQb').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRawS');
  a.invoke('P', ['p']);
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x);
  a.roll('zRawS'); U('zRawS'); a.pick('p').op(OP.MOD, 2, 'z'); a.pick('z').op(OP.ZERONOTEQUAL, 1, 'znz').op(OP.VERIFY, 1);
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  a.pick('WSb', 'wsb'); for (let j = 0; j < 6; j++) a.invoke('DLP', ['sc' + j, 'wsb']); a.drop('wsb');
  { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
    const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); const t = k.sub(z6, k.c(9n)); const g = [[k.c(GAMMA1.c0), k.c(GAMMA1.c1)]];
    const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
    for (let j = 2; j <= 5; j++) g.push(fm(...g[j - 2], ...g[0]));
    const cj = g.map(([g0, g1]) => m(k.add(g0, mul(g1, t))));
    k.output(z2, z3, z4, z5, z6, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))), ...cj, m(mul(z3, t)));
    a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 'ez', 'ez2', 'ez3', 'ez4', 'ez5', 'c1', 'c2', 'c3', 'c4', 'c5', 'z3t'], {iters: 1500}); }
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of ZP) a.pick(n); a.invoke('EV', ['Scp', 'Scm']);
  for (const n of ['PLx', 'PLy']) a.pick(n, n + 'c');
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y); const t = k.sub(k.env('z6'), k.c(9n)), z = k.env('z');
    const cza = m(mul(k.in('PLxc'), z)), czb = m(mul(k.in('PRx'), z));
    k.output(k.in('PLyc'), cza, m(mul(cza, t)), k.in('PRy'), czb, m(mul(czb, t)));
    a.kernel(k, ['ya', 'cza', 'czta', 'yb', 'czb', 'cztb'], {iters: 300}); }
  a.push(CH.a.aff.x.c0, 'xqa0').push(CH.a.aff.x.c1, 'xqa1').push(CH.b.aff.x.c0, 'xqb0').push(CH.b.aff.x.c1, 'xqb1');
  a.push(CH.a.psi1x.c0, 'pqa0').push(CH.a.psi1x.c1, 'pqa1').push(CH.b.psi1x.c0, 'pqb0').push(CH.b.psi1x.c1, 'pqb1');
}
function siProgram(a, vk, plan, ro, ix, {call, rread, handIn, handOut, CH, HOT, STATE, SIL_IN, ZP}) {
  a.pick('DS', 'dsh').op(OP.SHA256, 1, 'dsh').pushBytes(sha(dsSlice(CH, ro))).op(OP.EQUALVERIFY, 2);
  if (ro.hostWQ) a.pick('WQ', 'WQb'); else rread(a, plan.iWQ, 'WQ', 'WQb');
  if (ro.first) handIn(a, ['PLx', 'PLy']); else handIn(a, ['PLx', 'PLy', ...STATE, 'R']);
  a.arrange(['WQb', 'PLx', 'PLy']); call(a, 'SIPRE');
  if (ro.first) { for (const [t, C] of [['a', CH.a], ['b', CH.b]]) a.push(C.aff.x.c0, 'dx0' + t).push(C.aff.x.c1, 'dx1' + t).push(C.aff.y.c0, 'dc0' + t).push(C.aff.y.c1, 'dc1' + t).push(0, 'dl0' + t).push(0, 'dl1' + t);
    a.pick('Scm', 'Fp').pick('Scp', 'Fm').push(0, 'R'); }
  a.pick('DS', 'D').pushBytes(schedule(ro), 'SCH');
  // the role's states: boundaries after events e with e + 1 in BOUNDS, e in [e0, e1)
  { const ks = BOUNDS.map((b, kk) => [b, kk]).filter(([b]) => b > ro.e0 && b <= ro.e1).map(([, kk]) => kk);
    a.pick('WSb', 'WSs').push(192 * (1 + ks[0])).op(OP.SPLIT, 2, 'x', 'WSs').drop('x').push(192 * ks.length).op(OP.SPLIT, 2, 'WSs', 'x').drop('x'); }
  a.arrange(SIL_IN); call(a, 'SIL');
  if (!ro.last) { handOut(a, ro, ['PLx', 'PLy', ...STATE, 'R']); return; }
  // terminal: F *= S_c(+-eta z); R <- R rho + F+ W(-z) - F- W(+z); quotient; final identity
  const EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of EZP) a.pick(n); a.invoke('EV', ['ep', 'em']);
  { const k = new Kernel(); k.output(k.mod(k.mul(k.in('Fp'), k.in('ep'))), k.mod(k.mul(k.in('Fm'), k.in('em')))); a.kernel(k, ['Fp', 'Fm'], {iters: 100}); }
  { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j)); const sj = [null, ...[1, 2, 3, 4, 5].map((j) => m(mul(sc[j], E('c' + j))))];
    const fr = (x) => { const ev = m(k.sum(sc[0], k.c(18n), k.neg(E(x[5])), mul(sj[2], E(x[1])), mul(sj[4], E(x[3])))); const od = m(k.sum(mul(sj[1], E(x[0])), mul(sj[3], E(x[2])), mul(sj[5], E(x[4])))); return [k.add(ev, od), k.sub(ev, od)]; };
    const [a1, a2] = fr(ZP), [b1, b2] = fr(EZP);
    k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), m(mul(a2, b2)))), mul(I('Fm'), m(mul(a1, b1))))));
    a.kernel(k, ['R'], {iters: 1500}); }
  { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
  a.roll('WQb').push(0, 'acc');
  a.loop((s) => {
    s.roll('WQb').push(128).op(OP.SPLIT, 2, 'Q4', 'WQb').roll('Q4');
    for (let j = 0; j < 4; j++) s.invoke('DLP', ['q' + j, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQb', 'WQc').op(OP.SIZE, 1, 'WQc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQb');
  { const k = new Kernel(); const z6 = k.env('z6'); const Mz = k.add(k.sub(k.mul(z6, z6), k.mul(k.c(18n), z6)), k.c(82n));
    k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
  a.op(OP.NOT, 1, 'res').op(OP.VERIFY, 1);
}
// the role's event schedule: 2 bytes per event (digit code, boundary flag), plus the two terminal steps in the last role
function schedule(ro) { const b = []; for (let e = ro.e0; e < ro.e1; e++) b.push(DIGITS[e] < 0 ? 0x81 : DIGITS[e], BOUNDS.includes(e + 1) ? 1 : 0); if (ro.last) b.push(2, 0, 3, 0); return Buffer.from(b); }
function dsSlice(CH, ro) { const le = (x) => le32(mod(x)); const out = []; for (let j = ro.j0; j < ro.j0 + ro.steps; j++) out.push(...[CH.a.lams[j], CH.b.lams[j]].flatMap((l) => [le(l.c0), le(l.c1)])); return Buffer.concat(out); }
const tableBlob = (pts) => Buffer.concat(pts.flatMap((P) => { const o = []; for (let k = 2; k <= TBL; k++) { const [x, y] = aff(P.multiply(BigInt(k))); o.push(le32(x), le32(y)); } return o; }));
function tfBlob(vk, plan) { return tableBlob(plan.fixed.map((nm) => (nm === 'G' ? G1.BASE : vk.pt[nm]))); }
export {tfBlob, dsSlice, schedule, offsetOf, hdr, WQ_SIZE};

// ---------------- honest witness for the chain ----------------
// SI value mirror (as SI-GLS verifyValues): F+-, R and the chain states at every cut
function chainStateAt(C, j) { // (x_j, c_{j-1}, lambda_{j-1}) after j steps (kernel state), per the event schedule
  let x = C.aff.x, c = C.aff.y, l = F2.ZERO, jj = 0; const sOf = []; for (let e = 0; e < NE; e++) { sOf.push('dbl'); if (DIGITS[e]) sOf.push(C.aff.x); } sOf.push(C.psi1x, 'dbl');
  for (; jj < j; jj++) { const n = C.lams[jj]; const nc = F2.sub(F2.mul(F2.add(l, n), x), c); const sx = sOf[jj] === 'dbl' ? x : sOf[jj]; const nx = F2.sub(F2.sub(F2.sqr(n), x), sx); c = nc; l = n; x = nx; }
  return [x.c0, x.c1, c.c0, c.c1, l.c0, l.c1].map((v) => mod(v));
}
export function multiWitness(vk, plan, built, proofHex, pubHex, {lam} = {}) {
  const {names, nbm, roles} = plan; const CH = chains(vk);
  const V = verifyPlonk(vk, proofHex, pubHex, lam ? {lam} : {});
  const ptOf = (nm) => V.bases[names.indexOf(nm)];
  const TV = tableBlob(plan.vari.map(ptOf)), TF = tfBlob(vk, plan);
  const sp = names.slice(0, nbm).map((nm) => V.S[nm] + digitOffset(NW));
  // P_right: Jacobian windows, madd corr, madd Wz, conv
  const T = (P) => [aff(P), ...Array.from({length: TBL - 1}, (_, i) => aff(P.multiply(BigInt(i + 2))))];
  const tW = T(ptOf('Wzw')), tPhi = tW.map(([x, y]) => [mod(GLV.beta * x), y]);
  const jrun = (tables, scal, nw, from, to, J0) => { let A = J0; const dig = scal.map((s) => recode(s - digitOffset(nw), nw));
    for (let i = from; i >= to; i--) { for (let k = 0; k < W; k++) A = jdbl(A); for (let q = tables.length - 1; q >= 0; q--) { const d = dig[q][i]; if (!d) continue; let [x, y] = tables[q][Math.abs(d) - 1]; if (d < 0) y = mod(-y); A = jmadd(A, [x, y]); } } return A; };
  let JR = jrun([tW, tPhi], [V.u1 + digitOffset(NWR), V.u2 + digitOffset(NWR)], NWR, NWR - 1, 0, [...aff(OFFSET), 1n]);
  JR = jmadd(JR, aff(corr(NWR))); JR = jmadd(JR, aff(ptOf('Wz')));
  const ziR = inv(JR[2]); const PR = [mod(JR[0] * ziR * ziR), mod(-JR[1] * ziR * ziR * ziR)];
  assert.deepEqual(PR, aff(V.Pright));
  const G0 = Buffer.concat([V.uRaw, ...sp.map(le32), le32(PR[0]), le32(PR[1])]);
  // main MSM: MJ roles (Jacobian) then MA roles (affine, slopes)
  const tabs = names.slice(0, nbm).map((nm) => T(ptOf(nm)));
  const hands = new Map(); const slopesOf = new Map(); let A = [...aff(OFFSET), 1n], zi = null, Aff = null;
  for (const [ix, ro] of roles.entries()) {
    if (ro.kind === 'MJ') { A = jrun(tabs, sp, NW, ro.hi, ro.lo, A); hands.set(ro.next, Buffer.concat(A.map((v) => le32(mod(v))))); }
    if (ro.kind === 'MA') {
      if (ro.conv) { zi = inv(A[2]); Aff = [mod(A[0] * zi * zi), mod(A[1] * zi * zi * zi)]; }
      const sl = []; const add = (P, Q) => { const l = mod((Q[1] - P[1]) * inv(Q[0] - P[0])); sl.push(l); const x3 = mod(l * l - P[0] - Q[0]); return [x3, mod(l * (P[0] - x3) - P[1])]; };
      const dbl = (P) => { const l = mod(3n * P[0] * P[0] * inv(2n * P[1])); sl.push(l); const x3 = mod(l * l - 2n * P[0]); return [x3, mod(l * (P[0] - x3) - P[1])]; };
      const dig = sp.map((s) => recode(s - digitOffset(NW), NW));
      for (let i = ro.hi; i >= ro.lo; i--) { for (let k = 0; k < W; k++) Aff = dbl(Aff); for (let q = nbm - 1; q >= 0; q--) { const d = dig[q][i]; if (!d) continue; let [x, y] = tabs[q][Math.abs(d) - 1]; if (d < 0) y = mod(-y); Aff = add(Aff, [x, y]); } }
      if (ro.corr) Aff = add(Aff, aff(corr(NW)));
      slopesOf.set(ix, sl); hands.set(ro.next, Buffer.concat(Aff.map(le32)));
    }
  }
  assert.deepEqual(Aff, aff(V.Pstar), 'chain MSM P*');
  // SI
  const S = proveSI(CH, Aff, PR, V.uRaw);
  const WQ = Buffer.concat([Buffer.alloc(WQ_SIZE - S.WQ.length), S.WQ]);
  const h0 = sha(TAG, V.uRaw, S.WS), rhoRaw = sha(h0, Buffer.from('rho')); const rho = BigInt('0x' + Buffer.from(rhoRaw).reverse().toString('hex')) % p;
  const z = BigInt('0x' + Buffer.from(sha(h0, rhoRaw, WQ)).reverse().toString('hex')) % p; const zm = mod(-z);
  const scP = [...S.Sc.slice(0, 6), 1n]; let Fp = peval(pneg(scP), z), Fm = peval(pneg(scP), zm), R = 0n, kst = 0;
  const sis = roles.map((ro, ix) => [ro, ix]).filter(([ro]) => ro.kind === 'SI');
  S.sched.events.forEach((ev, e) => {
    Fp = mod(Fp * Fp); Fm = mod(Fm * Fm);
    for (const f of ev.fs) { Fp = mod(Fp * peval(f, z)); Fm = mod(Fm * peval(f, zm)); }
    if (ev.cSign) { const cp = ev.cSign > 0 ? pneg(scP) : scP; Fp = mod(Fp * peval(cp, z)); Fm = mod(Fm * peval(cp, zm)); }
    if (BOUNDS.includes(e + 1)) { const Wn = [...S.states[kst].slice(0, 6), 1n]; const Wp = peval(Wn, z), Wm = peval(Wn, zm); R = mod(R * rho + Fp * Wm - Fm * Wp); Fp = Wp; Fm = Wm; kst++; }
    for (const [ro] of sis) if (!ro.last && ro.e1 === e + 1) {
      const st = [...chainStateAt(CH.a, ro.j0 + ro.steps), ...chainStateAt(CH.b, ro.j0 + ro.steps)];
      hands.set(ro.next, Buffer.concat([Aff[0], Aff[1], ...st, Fp, Fm, R].map((v) => le32(mod(v))))); }
  });
  // unlockings
  const X = Buffer.concat([be32(V.lamAff[0]), be32(V.lamAff[1]), le32(V.invProd), le32(ziR)]);
  const PI = Buffer.concat(pubHex.map((h) => Buffer.from(h, 'hex'))); const PROOF = Buffer.from(proofHex, 'hex');
  const data = {CODE: built.code, C1: built.c1, G0, X, PI, PROOF, WS: S.WS, TV, TF, WQ};
  const pushes = roles.map((ro, ix) => {
    const fx = ro.fixed.map(([n]) => (n === 'HAND' ? hands.get(ix) : n === 'ZI' ? le32(zi) : n === 'DS' ? dsSlice(CH, ro) : data[n]));
    fx.forEach((b, i) => assert.ok(b && (ro.fixed[i][1] === null || b.length === ro.fixed[i][1]), `role ${ix} push ${ro.fixed[i][0]}`));
    const pieces = []; if (ro.slopes) { const sl = slopesOf.get(ix).map(le32); for (let i = 0; i < sl.length; i += SL_PIECE) pieces.push(Buffer.concat(sl.slice(i, i + SL_PIECE))); }
    return [...fx, ...pieces];
  });
  return {V, S, pushes, accept: V.ok && S.accept};
}
