// Generalized code generator (Track 8 S5/S6): CashVM (BCH 2026) verifier for Plonky3 p3-batch-stark proofs in p3b-v1
// with N tables, several LDE heights (Merkle injection, per-height alpha' ladders, FRI roll-ins), preprocessed columns,
// periodic columns, LogUp (lookup PoW, bus challenges, permutation columns, terminals), ZK or not, Merkle cap 0.
// It follows modeln.mjs step by step. gen.mjs (S4: one table, one height) is left as it was; the shared field
// helpers (PB, mulE, packed slots) are imported from it and its other building blocks are copied here.
//
// Programs ("roles"):
//   full   layout b: one input runs everything (statement, transcript, AIR, all Q queries, Merkle)
//   p0     layout b2 input 0: statement, transcript, AIR, queries [0, QA), their Merkle paths; pins the transaction
//   p1     layout b2 input 1: reads input 0's transcript part (OP_INPUTBYTECODE), re-derives the transcript and the
//          DEEP/FRI constants, queries [QA, Q), their Merkle paths; pins the transaction
// Stack at entry of a role's main (bottom first):
//   L_{n-1} .. L_0   query blobs of the role's queries (per input tree: group preimages tallest first, then the B
//                    bottom siblings; per FRI round: siblings (+ salt); one hint per height)
//   R<t>_<i>         Merkle record groups of the role's queries, tree by tree
//   full/p0: ROOTS [TERM] [LPOW] OOD [BPOW] FROOTS [CPOW] FIN [QPOW], then the statement items:
//            pool mode: NF [CTXW (harness)]; witness mode: [PIW]
//   p1:      TAIL (input 0's unlocking bytecode after its query data: the pushes of the items above)
import {asm, fresh, Stk} from './lib/asm.mjs';
import {compileSlp, V, K, op, chk, call, add, sub, mul, modp, sum, ex} from './lib/slp.mjs';
import {mulE, sqE, mulU, PB, SK, SB} from './gen.mjs';
import {P, pw, inv, g2, rev, le8, OPS} from './modeln.mjs';
import {ctxCode} from './ctx.mjs';
import {encodeDataPush} from '@bitauth/libauth';

const B0 = Uint8Array.of(0);
const R = (x) => modp(x, P);
const names = (b, n) => Array.from({length: n}, (_, i) => b + i);
void sqE; void call;

function localFn(args, build) {
  const s = new Stk(args);
  const outs = build(s);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length || s.st.length !== outs.length) throw new Error('local function leaves ' + (extra.join(',') || s.st.join(',')));
  s.arrange(outs);
  return s.bytes();
}
const slpFn = (args, prog, outs) => localFn(args, (s) => { compileSlp(s, prog, {keep: outs}); return outs; });
const unpackCode = (n, sb, red = false) => [sb * n, 'NUM2BIN', ...Array(n - 1).fill([sb, 'SPLIT']), ...Array.from({length: n}, () => [n - 1, 'ROLL', 'BIN2NUM', ...(red ? [P, 'MOD'] : [])])].flat();
function rotColumns(D, bn, sb) {
  let col = bn.map((x) => V(x));
  const cols = [];
  for (let k = 0; k < D; k++) { cols.push(sum(...col.map((t, j) => (j === 0 ? t : op('LSHIFTNUM', t, K(8 * sb * j)))))); col = mulU(D, col); }
  return cols;
}
function pairkBody(D) {
  const BIAS = Array.from({length: D}, (_, k) => (P << 137n) << BigInt(8 * SK * k)).reduce((x, y) => x + y);
  const st = new Stk([...names('R', D), 'xi', 's', ...names('d', D)]);
  st.code.push(...asm('2DUP', 'ADD', 'ROT', 'ROT', 'SUB', BIAS, 'ADD', ...unpackCode(D, SK, true)));
  for (let k = D - 1; k >= 0; k--) {
    if (k < D - 1) st.roll('d' + k);
    st.roll('R' + k); st.raw(['MUL'], 2, ['p' + k]);
    if (k < D - 1) st.raw(['ADD'], 2, ['p' + k]);
    st.rename(st.top(), 'T');
  }
  st.roll('xi'); st.raw(['MUL'], 2, ['xT']); st.raw(['ADD'], 2, ['o']);
  return st.bytes();
}
const pushPrefix = (len) => Buffer.from(encodeDataPush(new Uint8Array(len))).subarray(0, -len || undefined);

// stmt: {mode: 'pool' | 'witness', root: [4 bigint] (pool), ctx: 'tx' | 'witness' (pool)}
export function makeGenN(vk, stmt, opts = {}) {
  const D = vk.D, h = vk.h, Q = vk.Q, e8 = 8 * D, NR = vk.logArities.length;
  const RG = opts.recGroup ?? 2;
  const fns = new Map(); let nextId = 16;
  const defFn = (name, body, id) => {
    if (fns.has(name)) throw new Error('function defined twice: ' + name);
    id ??= nextId++;
    if (id >= 100 && id <= 113 && !name.startsWith('D_')) throw new Error('function id range');
    if (nextId >= 100) throw new Error('too many functions');
    fns.set(name, {id, body: Uint8Array.from(body)}); return id;
  };
  // define, or reuse a function with the same body (roles share the query function when their bodies are identical)
  const defShared = (name, body) => { const b = Buffer.from(body); for (const [, f] of fns) if (Buffer.from(f.body).equals(b)) return f.id; return defFn(name, body); };
  const marks = [];
  const mark = (stk, label) => { marks.push([label, stk.code.length]); if (opts.markers) stk.emit('NOP'); };
  const F = {};
  const GH = vk.L >= 256 ? 8 : Math.min(4, vk.L), GG = vk.L / GH;
  const pool = stmt.mode === 'pool';
  const inTrees = vk.trees.filter((t) => t.kind === 'in');
  const nH = vk.heights.length;

  // ---------------- shared functions (as gen.mjs) ----------------
  F.MM = defFn('MM', asm('MUL', P, 'MOD'));
  {
    const SL = 17, SH = 8 * SL;
    F.MULE = defFn('MULE', asm(3, 'ROLL', SH, 'LSHIFTNUM', 4, 'ROLL', 'ADD', SH, 'LSHIFTNUM', 4, 'ROLL', 'ADD',
      'TUCK', 'MUL', SH, 'LSHIFTNUM', 'OVER', 3, 'ROLL', 'MUL', 'ADD', SH, 'LSHIFTNUM', 'ROT', 'ROT', 'MUL', 'ADD',
      5 * SL, 'NUM2BIN', SL, 'SPLIT', SL, 'SPLIT', SL, 'SPLIT', SL, 'SPLIT',
      'BIN2NUM', 'SWAP', 'BIN2NUM', '2DUP', 'ADD', 4, 'ROLL', 'BIN2NUM', 'ADD', P, 'MOD', 'TOALTSTACK',
      3, 'ROLL', 'BIN2NUM', 'ADD', P, 'MOD', 'ROT', 'BIN2NUM', 'ROT', 'ADD', P, 'MOD', 'FROMALTSTACK', 'SWAP'));
    F.SQE = defFn('SQE', asm(2, 'PICK', 2, 'PICK', 2, 'PICK', F.MULE, 'INVOKE'));
  }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(mul(V(x), V('s')), 'c' + i)); F.MULF = defFn('MULF', slpFn([...names('a', D), 's'], b.prog, names('c', D))); }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(add(V(x), V('b' + i)), 'c' + i)); F.ADDE = defFn('ADDE', slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D))); }
  { const b = new PB(D); names('a', D).forEach((x, i) => b.red(add(sub(V(x), V('b' + i)), K(2n * P)), 'c' + i)); F.SUBE = defFn('SUBE', slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D))); }
  F.POP8 = defFn('POP8', asm('SIZE', 'NOT', 'IF', 'DROP', 'SHA256', 'DUP', 'ENDIF', 'SIZE', 8, 'SUB', 'SPLIT', 'REVERSEBYTES', B0, 'CAT', 'BIN2NUM'));
  F.POPB = defFn('POPB', asm(F.POP8, 'INVOKE', 'DUP', P, 'LESSTHAN', 'VERIFY', 'ROT', 'ROT'));
  {
    const Z = new Uint8Array(SK - 8);
    const expand = [...Array.from({length: D - 1}, (_, k) => [8 + k * SK, 'SPLIT', Z, 'SWAP', 'CAT', 'CAT']).flat(), B0, 'CAT'];
    F.PKL = defFn('PKL', asm('BEGIN', e8, 'SPLIT', 'SWAP', ...expand, 'BIN2NUM', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'));
  }
  F.PAIRK = defFn('PAIRK', pairkBody(D));
  { const cb = new PB(D); rotColumns(D, names('b', D), SK).forEach((x, k) => cb.let(x, 'R' + k)); F.COLSK = defFn('COLSK', slpFn(names('b', D), cb.prog, names('R', D))); }
  F.ENC = defFn('ENC', asm(Array.from({length: D}, (_, k) => [k === 0 ? D - 1 : D - k, 'ROLL', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP', ...(k ? ['CAT'] : [])]).flat()));
  // RDV: a byte string of n F_p^D values (24 bytes each) -> 3n numbers (first deepest)
  F.RDV = defFn('RDV', asm('BEGIN', 8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'));
  const tblFn = (la) => {
    const key = 'TBL' + la; if (F[key]) return F[key];
    const s = new Stk(['G']);
    const b = new PB(D, F);
    const m = ['G']; for (let i = 1; i < la; i++) m.push(b.mm(m[i - 1], m[i - 1]));
    compileSlp(s, b.prog, {keep: m});
    s.push(1, 'T0');
    for (let bb = 0; bb < la; bb++) { const mult = m[la - 1 - bb], n = 1 << bb; for (let i = 0; i < n; i++) { s.pick('T' + i); s.pick(mult); s.raw([F.MM, 'INVOKE'], 2, ['T' + (n + i)]); } }
    for (const x of m) s.drop(x);
    s.arrange(names('T', 1 << la));
    return (F[key] = defFn(key, s.bytes()));
  };
  // compile a straight-line program without consuming anything that was on the stack before (plus `keep`)
  const cs = (S, prog, keep = []) => compileSlp(S, prog, {keep: [...S.st, ...keep]});

  const zeta = names('ze', D), alpha = names('al', D), alphaP = names('ap', D);
  const la0 = vk.logArities[0], hf0 = vk.logH - la0, nT = Math.ceil(hf0 / 4);
  const arities = [...new Set(vk.logArities)];
  const g = {vk, D, h, Q, F, fns, defFn, defShared, marks, mark, GG, GH, tblFn, dagStats: []};

  // ---------------- statement ----------------
  // full/p0: sizes of the PT and statement items, NF lanes (pool) or every public value (witness) < p, CTX bytes
  g.statement = (S, role) => {
    if (role !== 'p1') for (const [x, len] of vk.ptItems) { S.pick(x); S.raw(['SIZE', 'NIP', len, 'NUMEQUALVERIFY'], 1); }
    if (pool) {
      if (role !== 'p1') {
        S.pick('NF'); S.raw(['SIZE', 'NIP', 32, 'NUMEQUALVERIFY'], 1);
        S.pick('NF'); S.raw(['BEGIN', 8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'], 1, names('nf', 4));
      }
      if (stmt.ctx === 'witness') {
        S.roll('CTXW'); S.raw(['SIZE', 32, 'NUMEQUALVERIFY', ...[0, 1, 2, 3].map((k) => ['DUP', 8 * k + 7, 'SPLIT', 'NIP', 1, 'SPLIT', 'DROP', B0, 'EQUALVERIFY']).flat()], 1, ['CTXB']);
      } else S.raw([{raw: ctxCode()}], 0, ['CTXB']);
    } else if (vk.nPub && role !== 'p1') {
      S.pick('PIW'); S.raw(['SIZE', 'NIP', 8 * vk.nPub, 'NUMEQUALVERIFY'], 1);
      S.pick('PIW'); S.raw(['BEGIN', 8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'], 1, names('pi', vk.nPub));
    }
    mark(S, 'entry');
  };
  // the statement and PT items in push order (input 0's tail)
  g.tailItems = () => [...vk.ptItems, ...(pool ? [['NF', 32], ...(stmt.ctx === 'witness' ? [['CTXW', 32]] : [])] : (vk.nPub ? [['PIW', 8 * vk.nPub]] : []))];
  // p1: TAIL -> the items (push prefixes checked)
  g.parseTail = (S) => {
    for (const [x, len] of g.tailItems()) {
      const pfx = pushPrefix(len);
      S.roll('TAIL'); S.raw([pfx.length, 'SPLIT', 'SWAP', Uint8Array.from(pfx), 'EQUALVERIFY', len, 'SPLIT'], 1, [x, 'TAIL']);
    }
    S.roll('TAIL'); S.raw([new Uint8Array(0), 'EQUALVERIFY'], 1);
  };

  // ---------------- phase 1: transcript ----------------
  g.transcript = (S) => {
    const obs = (parts) => {
      S.drop('r'); S.roll('d');
      for (const p of parts) { if (typeof p === 'string') S.roll(p); else S.push(p); S.raw(['CAT'], 2, ['d']); }
      S.raw(['SHA256', 'DUP'], 1, ['d', 'r']);
    };
    const sampleExt = (base) => { for (let k = 0; k < D; k++) S.raw([F.POPB, 'INVOKE'], 2, [base + k, 'd', 'r']); return names(base, D); };
    const powCheck = (wname, bits) => { obs([wname]); S.raw([F.POP8, 'INVOKE', 1n << BigInt(bits), 'MOD', 0, 'NUMEQUALVERIFY'], 2, ['d', 'r']); };
    const capSlice = (name, out, to = null) => {   // ROOTS[off .. off + h) (or to the end)
      const off = vk.capOff[name];
      S.pick('ROOTS'); S.raw([...(off ? [off, 'SPLIT', 'NIP'] : []), ...(to === 'end' ? [] : [h, 'SPLIT', 'DROP'])], 1, [out]);
    };
    // batch seed ‖ degree_bits ‖ main cap ‖ public values ‖ [preprocessed cap]
    S.push(vk.SO.batch, 'd'); capSlice('trace', 'x'); S.raw(['CAT'], 2, ['d']);
    if (pool) {
      S.push(Buffer.concat(stmt.root.map(le8)), 'x'); S.raw(['CAT'], 2, ['d']);
      S.roll('NF'); S.raw(['CAT'], 2, ['d']); S.roll('CTXB'); S.raw(['CAT'], 2, ['d']);
    } else if (vk.nPub) { S.roll('PIW'); S.raw(['CAT'], 2, ['d']); }
    if (vk.hasPre) { S.push(vk.preCap, 'x'); S.raw(['CAT'], 2, ['d']); }
    S.raw(['SHA256', 'DUP'], 1, ['d', 'r']);
    if (vk.hasLookups) {
      if (vk.lpow) powCheck('LPOW', vk.lpow);
      sampleExt('la'); sampleExt('lb');
      capSlice('permutation', 'rp'); S.pick('TERM', 'tm2');
      obs(['rp', 'tm2']);
    }
    sampleExt('al');
    capSlice('quotient', 'rq', 'end');
    obs(['rq']);
    sampleExt('ze');
    S.pick('OOD', 'ood2');
    obs([vk.SO.pcs, 'ood2']);
    if (vk.bpow) powCheck('BPOW', vk.bpow);
    sampleExt('ap');
    if (vk.cpow) S.roll('CPOW');
    for (let r = 0; r < NR; r++) {
      S.pick('FROOTS'); S.raw([...(r ? [r * h, 'SPLIT', 'NIP'] : []), ...(r < NR - 1 ? [h, 'SPLIT', 'DROP'] : [])], 1, ['fr']);
      obs(r === 0 ? [vk.SO.fri, 'fr'] : ['fr']);
      if (vk.cpow) {
        if (r < NR - 1) { S.roll('CPOW'); S.raw([8, 'SPLIT', 'SWAP'], 1, ['CPOW', 'cw']); } else { S.roll('CPOW'); S.rename('CPOW', 'cw'); }
        powCheck('cw', vk.cpow);
      }
      sampleExt(`be${r}_`);
    }
    S.pick('FIN', 'fin2');
    obs(['fin2']);
    if (vk.qpow) powCheck('QPOW', vk.qpow);
    S.raw([Q, 'TOALTSTACK', 'BEGIN', F.POP8, 'INVOKE', 1n << BigInt(vk.logH), 'MOD', 'ROT', 'ROT', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], 2, [...names('idx', Q), 'd', 'r']);
    S.drop('r'); S.drop('d');
    mark(S, 'transcript');
  };
  // OOD values [k, k + n) -> numbers ov<k>_<c>
  const extractVals = (S, k, n) => {
    S.pick('OOD'); S.raw([...(k ? [k * e8, 'SPLIT', 'NIP'] : []), n * e8, 'SPLIT', 'DROP', F.RDV, 'INVOKE'], 1, Array.from({length: n * D}, (_, i) => `ov${k + Math.floor(i / D)}_${i % D}`));
    return Array.from({length: n}, (_, j) => names(`ov${k + j}_`, D));
  };

  // ---------------- phase 2: AIR identity at zeta, per instance ----------------
  g.air = (S) => {
    mark(S, 'air-start');
    const subBase = (b, A, c) => [b.red(add(sub(ex(A[0]), K(c)), K(P))), ...A.slice(1)];
    const nonzero = (b, A) => b.chk(chk('VERIFY', A.slice(1).reduce((acc, x) => op('BOOLOR', acc, ex(x)), ex(A[0]))));
    // zeta^(2^i), shared; LogUp challenges
    const b = new PB(D, F);
    const maxLogN = Math.max(...vk.inst.map((I) => I.logN));
    const zp = {0: zeta}; let cur = zeta;
    for (let i = 1; i <= maxLogN; i++) { cur = b.sq(cur); zp[i] = cur; }
    const needZ = new Set(); for (const I of vk.inst) { needZ.add(I.logN); for (const pc of I.periodic) needZ.add(I.logN - pc.lm); }
    const D1 = subBase(b, zeta, 1n);
    let chal = null;
    if (vk.hasLookups) {
      // gamma = lb^maxW (square and multiply), prefix_k = la + (k + 1) gamma
      const lb = names('lb', D), la = names('la', D);
      let acc = null, base = lb; let e = vk.lookups.maxW;
      while (e > 0) { if (e & 1) acc = acc ? b.mul(acc, base) : base; e >>= 1; if (e) base = b.sq(base); }
      const gamma = acc;
      const prefix = Array.from({length: vk.lookups.numBuses}, (_, k) => b.add(la, b.mulF(gamma, K(k + 1))));
      chal = {prefix, lb};
    }
    cs(S, b.prog, [...[...needZ].flatMap((k) => zp[k]), ...D1, ...(chal ? chal.prefix.flat() : [])]);
    for (let i = 1; i <= maxLogN; i++) if (!needZ.has(i) && zp[i].every((x) => S.has(x))) zp[i].forEach((x) => S.drop(x));
    if (chal) for (const x of names('la', D)) S.drop(x);
    // terminals as numbers
    if (vk.hasLookups) {
      S.roll('TERM'); S.raw([F.RDV, 'INVOKE'], 1, vk.termInst.flatMap((i) => names(`tm${i}_`, D)));
      // LogUp: the terminals of the whole batch sum to zero
      const bt = new PB(D);
      for (let c = 0; c < D; c++) bt.chk(chk('NUMEQUALVERIFY', R(sum(...vk.termInst.map((i) => V(`tm${i}_${c}`)))), K(0)));
      cs(S, bt.prog);
    }
    mark(S, 'air-shared');
    for (const I of vk.inst) {
      const before = new Set(S.st);
      const bi = new PB(D, F);
      const zN = zp[I.logN];
      const zh = subBase(bi, zN, 1n);
      nonzero(bi, zh);
      if (vk.zk) nonzero(bi, [bi.red(add(ex(zN[0]), K(1))), ...zN.slice(1)]);
      const D2 = subBase(bi, zeta, inv(I.gN));
      const Dd = bi.mul(D1, D2);
      const selN = {is_first_row: bi.mul(zh, D2), is_last_row: bi.mul(zh, D1), is_transition: bi.mul(Dd, D2)};
      cs(S, bi.prog, [...zh, ...Dd, ...Object.values(selN).flat()]);
      for (const x of D2) if (S.has(x) && !before.has(x)) S.drop(x);
      // periodic columns (as gen.mjs: a loop over the period with run-time packed coefficients)
      const per = [];
      const lms = [...new Set(I.periodic.map((c) => c.lm))];
      for (const lm of lms) {
        const cols = I.periodic.map((c, k) => [c, k]).filter(([c]) => c.lm === lm);
        const m = 1 << lm, nC = cols.length, y = zp[I.logN - lm];
        for (let k = m - 1; k >= 0; k--) S.push(Buffer.concat(cols.map(([c]) => le8(c.coef[k]))), `ck${lm}_${k}`);
        for (let c = 0; c < D; c++) S.push(0, 'pk' + c);
        S.push(1, 'pc0'); S.push(0, 'pc1'); S.push(0, 'pc2');
        y.forEach((x, c) => S.pick(x, 'py' + c));
        const state = [...names('pk', D), ...names('pc', D), ...names('py', D)];
        const key = `PER${lm}_${nC}`;
        if (!F[key]) {
          F[key] = defFn(key, localFn(['ck', ...state], (s) => {
            s.roll('ck');
            s.raw([new Uint8Array(0), 'SWAP', ...Array.from({length: nC}, () => [8, 'SPLIT', 'SWAP', new Uint8Array(SB - 8), 'CAT', 'ROT', 'SWAP', 'CAT', 'SWAP']).flat(), 'DROP', 'BIN2NUM'], 1, ['K']);
            for (let c = 0; c < D; c++) { s.pick('pc' + c); s.pick('K'); s.raw(['MUL'], 2, ['t']); s.roll('pk' + c); s.raw(['ADD'], 2, ['pk' + c]); }
            s.drop('K');
            const bb = new PB(D, F); bb.mul(names('pc', D), names('py', D), names('pn', D)); compileSlp(s, bb.prog, {keep: names('py', D)});
            names('pn', D).forEach((x, c) => s.rename(x, 'pc' + c));
            s.arrange(state);
            return state;
          }));
        }
        S.raw([m, 'TOALTSTACK', 'BEGIN', F[key], 'INVOKE', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], m + state.length, state);
        for (const x of [...names('pc', D), ...names('py', D)]) S.drop(x);
        const acc = cols.map(([, k]) => names(`pa${I.i}_${k}_`, D));
        for (let c = 0; c < D; c++) {
          S.roll('pk' + c);
          S.raw([SB * nC, 'NUM2BIN', ...Array(nC - 1).fill([SB, 'SPLIT']).flat()], 1, cols.map((_, j) => `ps${j}`));
          for (let j = 0; j < nC; j++) { S.roll(`ps${j}`); S.raw(['BIN2NUM', P, 'MOD'], 1, [acc[j][c]]); }
        }
        cols.forEach(([, k], j) => { per[k] = acc[j]; });
      }
      mark(S, `air${I.i}-periodic`);
      // opened values this instance's DAG reads (and its quotient chunks)
      const used = new Set(I.dag.nodes.map((nd) => `${nd.op}:${nd.row ?? ''}`));
      const ovv = {};
      const ext = (key, base, n) => { if (base === null) return; ovv[key] = extractVals(S, base, n); };
      if (used.has('main:0')) ext('tl', I.ov.tl, I.width);
      if (used.has('main:1')) ext('tn', I.ov.tn, I.width);
      if (used.has('pre:0')) ext('pl', I.ov.pl, I.preWidth);
      if (used.has('pre:1')) ext('pn', I.ov.pn, I.preWidth);
      const chunks = I.ov.ch.map((v0) => extractVals(S, v0, D));
      // permutation columns: ext elements recomposed from D base-flattened openings
      const permN = {};
      if (I.numLookups) {
        const bp = new PB(D);
        for (const row of [0, 1]) {
          if (!used.has(`perm:${row}`)) continue;
          const vals = extractVals(S, row ? I.ov.mn : I.ov.ml, I.permWidth);
          for (let c = 0; c < I.permWidth / D; c++) {
            let acc = null;
            for (let k = 0; k < D; k++) { let t = vals[D * c + k].map((x) => V(x)); for (let j = 0; j < k; j++) t = mulU(D, t); acc = acc ? acc.map((x, j) => add(x, t[j])) : t; }
            permN[`${row}:${c}`] = acc.map((x, j) => bp.red(x, `pm${I.i}_${row}_${c}_${j}`));
          }
        }
        compileSlp(S, bp.prog, {keep: Object.values(permN).flat()});
      }
      // ext constants
      const ecN = new Map();
      I.dag.nodes.forEach((nd, k) => { if (nd.op === 'ext_const') { const nm = names(`ec${I.i}_${k}_`, D); nd.v.forEach((x, c) => S.push(((BigInt(x) % P) + P) % P, nm[c])); ecN.set(k, nm); } });
      const leafOf = (nd, k) => {
        switch (nd.op) {
          case 'main': return {ext: ovv[nd.row === 0 ? 'tl' : 'tn'][nd.col]};
          case 'pre': return {ext: ovv[nd.row === 0 ? 'pl' : 'pn'][nd.col]};
          case 'periodic': return {ext: per[nd.col]};
          case 'is_first_row': case 'is_last_row': case 'is_transition': return {ext: selN[nd.op]};
          case 'perm': return {ext: permN[`${nd.row}:${nd.col}`]};
          case 'challenge': return {ext: nd.col % 2 ? names('lb', D) : chal.prefix[vk.lookups.busIds[I.i][nd.col >> 1]]};
          case 'perm_value': return {ext: names(`tm${I.i}_`, D)};
          case 'ext_const': return {ext: ecN.get(k)};
          case 'public': {
            const j = I.pubOff + nd.col;
            if (!pool) return {base: `pi${j}`};
            if (j < 4) return {k: stmt.root[j]};
            if (j < 8) return {base: `nf${j - 4}`};
            throw new Error('DAG reads CTX: the pool statement layer expects CTX unconstrained by the AIR');
          }
          case 'const': return {k: BigInt(nd.v)};
          default: return null;
        }
      };
      const res = dagProgram(S, I, leafOf, {alpha, Dd});
      mark(S, `air${I.i}-dag`);
      // quotient recomposition; check acc = q zh Dd^maxScale
      const b2 = new PB(D, F);
      const Zj = Array.from({length: I.C}, (_, j) => { const m = b2.mulF(zN, K(I.kc[j])); return [b2.red(add(sub(ex(m[0]), K(1)), K(P))), ...m.slice(1)]; });
      const pre = [null]; for (let k = 1; k < I.C; k++) pre.push(pre[k - 1] ? b2.mul(pre[k - 1], Zj[k - 1]) : Zj[k - 1]);
      const suf = []; suf[I.C - 1] = null; for (let k = I.C - 2; k >= 0; k--) suf[k] = suf[k + 1] ? b2.mul(Zj[k + 1], suf[k + 1]) : Zj[k + 1];
      let q = null;
      for (let k = 0; k < I.C; k++) {
        const zpk = pre[k] && suf[k] ? b2.mul(pre[k], suf[k]) : (pre[k] ?? suf[k]);
        let ch = null;
        for (let c = 0; c < D; c++) { let t = chunks[k][c].map((x) => V(x)); for (let j = 0; j < c; j++) t = mulU(D, t); ch = ch ? ch.map((x, j) => add(x, t[j])) : t; }
        const chN = ch.map((x) => b2.red(x));
        const term = zpk ? b2.mulF(b2.mul(zpk, chN), K(I.zpConst[k])) : (I.zpConst[k] === 1n ? chN : b2.mulF(chN, K(I.zpConst[k])));
        q = q ? b2.add(q, term) : term;
      }
      let rhs = b2.mul(q, zh);
      for (let k = 0; k < I.maxScale; k++) rhs = b2.mul(rhs, Dd);
      res.acc.forEach((x, c) => b2.chk(chk('NUMEQUALVERIFY', V(x), V(rhs[c]))));
      compileSlp(S, b2.prog, {keep: [...before]});
      for (const x of [...S.st].reverse()) if (!before.has(x)) S.drop(x);
      mark(S, `air${I.i}-quotient`);
    }
    // drop the shared AIR values
    for (const x of [...Object.values(zp).slice(1).flat(), D1[0], ...alpha, ...(chal ? [...chal.prefix.flat(), ...names('lb', D)] : []),
      ...vk.termInst.flatMap((i) => names(`tm${i}_`, D)), ...(pool ? names('nf', 4) : names('pi', vk.nPub))]) if (S.has(x)) S.drop(x);
    mark(S, 'air-end');
  };

  // ---------------- DEEP and FRI constants ----------------
  g.consts = (S) => {
    {
      const b = new PB(D, F);
      vk.points.forEach((pt, pi) => {
        const z = pt.logN === null ? zeta : b.mulF(zeta, K(g2(pt.logN)));
        const cols = [z]; for (let k = 1; k < D; k++) cols.push(mulU(D, cols[k - 1].map(ex)).map((x) => b.red(x)));
        const M = (i, j) => V(cols[j][i]);
        b.red(add(add(M(0, 0), M(1, 1)), M(2, 2)), `nt${pi}`);
        const m2 = (i, j) => add(mul(M(i, i), M(j, j)), K(P * P)), s2 = (i, j) => mul(M(i, j), M(j, i));
        b.red(sub(add(add(m2(0, 1), m2(0, 2)), m2(1, 2)), add(add(s2(0, 1), s2(0, 2)), s2(1, 2))), `nc${pi}`);
        const minor = (a, bb, c, d) => sub(add(mul(M(a[0], a[1]), M(bb[0], bb[1])), K(P * P)), mul(M(c[0], c[1]), M(d[0], d[1])));
        const det = sub(add(add(mul(M(0, 0), R(minor([1, 1], [2, 2], [1, 2], [2, 1]))), mul(M(0, 2), R(minor([1, 0], [2, 1], [1, 1], [2, 0])))), K(P * P)), mul(M(0, 1), R(minor([1, 0], [2, 2], [1, 2], [2, 0]))));
        b.red(det, `nd${pi}`);
        b.red(add(sub(V(z[0]), V(`nt${pi}`)), K(P)), `nB${pi}_0`); b.let(V(z[1]), `nB${pi}_1`); b.let(V(z[2]), `nB${pi}_2`);
        const z2 = b.sq(z); const tz = b.mulF(z, `nt${pi}`);
        const cc = b.sub(z2, tz);
        b.red(add(V(cc[0]), V(`nc${pi}`)), `nC${pi}_0`); b.let(V(cc[1]), `nC${pi}_1`); b.let(V(cc[2]), `nC${pi}_2`);
      });
      const keepN = vk.points.flatMap((_, pi) => [`nt${pi}`, `nc${pi}`, `nd${pi}`, ...names(`nB${pi}_`, D), ...names(`nC${pi}_`, D)]);
      compileSlp(S, b.prog, {keep: [...S.st.filter((x) => !zeta.includes(x)), ...keepN]});
    }
    for (const x of zeta) if (S.has(x)) S.drop(x);
    mark(S, 'deep-points');
    // per height: alpha' powers, A_{h,pt} and the packed row keys, in loops over that height's opened values (read
    // from a byte string of the height's claims, in observation order). State: A_<pt> (lazy sums), zq = alpha'^k,
    // alpha', the byte string. Each step adds zq v to A_pt and sends K = sum_c zq_c 2^(8 SB (D pt + c)) to the altstack.
    const Kname = new Map(); let kseq = 0;
    for (const hh of vk.heights) {
      const m = vk.hp[hh].length;
      const cl = vk.claims.filter((c) => c.logH === hh);
      // the height's byte string: claim ranges (adjacent ones merged)
      const ranges = []; for (const c of cl) { const l = ranges[ranges.length - 1]; if (l && l.v0 + l.n === c.v0) l.n += c.width; else ranges.push({v0: c.v0, n: c.width}); }
      ranges.forEach((rg, i) => {
        S.pick('OOD'); S.raw([...(rg.v0 ? [rg.v0 * e8, 'SPLIT', 'NIP'] : []), ...(rg.v0 + rg.n < vk.numVals ? [rg.n * e8, 'SPLIT', 'DROP'] : [])], 1, [i ? 'hz2' : 'hz']);
        if (i) S.raw(['CAT'], 2, ['hz']);
      });
      const st = [...Array.from({length: m}, (_, p) => names(`A${p}_`, D)).flat(), ...names('zq', D), ...names('za', D), 'hz'];
      S.roll('hz');
      for (let k = 0; k < m * D; k++) S.push(0, st[k]);
      S.push(1, 'zq0'); S.push(0, 'zq1'); S.push(0, 'zq2');
      alphaP.forEach((x, i) => S.pick(x, 'za' + i));
      S.roll('hz');
      const segs = []; cl.forEach((c) => { const l = segs[segs.length - 1]; if (l && l.ptl === c.ptl) l.n += c.width; else segs.push({ptl: c.ptl, n: c.width}); });
      for (const sg of segs) {
        const key = `AZ${m}_${sg.ptl}`;
        if (!F[key]) {
          F[key] = defFn(key, localFn([...st, 'n'], (s) => {
            s.roll('hz'); s.raw([e8, 'SPLIT', 'SWAP', F.RDV, 'INVOKE'], 1, ['hz', ...names('vv', D)]);
            const bb = new PB(D, F);
            const t = bb.mul(names('zq', D), names('vv', D));
            t.forEach((x, c) => bb.let(add(V(`A${sg.ptl}_${c}`), V(x)), `A${sg.ptl}_${c}`));
            bb.let(sum(...names('zq', D).map((x, c) => { const sh = 8 * SB * (D * sg.ptl + c); return sh ? op('LSHIFTNUM', V(x), K(sh)) : V(x); })), 'kk');
            compileSlp(s, bb.prog, {keep: [...names('zq', D)]});
            s.roll('kk'); s.raw(['TOALTSTACK'], 1);
            const b3 = new PB(D, F); b3.mul(names('zq', D), names('za', D), names('zn', D)); compileSlp(s, b3.prog, {keep: names('za', D)});
            names('zn', D).forEach((x, i) => s.rename(x, 'zq' + i));
            s.roll('n'); s.raw(['1SUB'], 1, ['n']);
            s.arrange([...st, 'n']);
            return [...st, 'n'];
          }));
        }
        S.raw([sg.n, 'BEGIN', F[key], 'INVOKE', 'DUP', 'NOT', 'UNTIL', 'DROP'], st.length, st);
      }
      S.roll('hz'); S.raw([new Uint8Array(0), 'EQUALVERIFY'], 1);
      for (const x of [...names('zq', D), ...names('za', D)]) S.drop(x);
      for (let p = 0; p < m; p++) names(`A${p}_`, D).forEach((x, c) => { S.roll(x); S.raw([P, 'MOD'], 1, [`nA${hh}_${p}_${c}`]); });
      for (const c of cl) for (let j = 0; j < c.width; j++) Kname.set(`${c.ri}:${c.mi}:${c.p}:${j}`, 'K' + kseq++);
    }
    // the K parts back from the altstack (last first), then the row keys per height: kr = sum over the matrix's points
    const Kn = Array.from({length: kseq}, (_, k) => 'K' + k);
    S.raw(Array(kseq).fill('FROMALTSTACK'), 0, [...Kn].reverse());
    g.rowList = {};
    for (const hh of vk.heights) {
      const rl = []; vk.rounds.forEach((r, bi) => r.matrices.forEach((m, mi) => { if (m.logH === hh) for (let j = 0; j < m.width; j++) rl.push([bi, mi, j, m.points]); }));
      g.rowList[hh] = rl;
      rl.forEach(([bi, mi, j, npt], ri) => {
        const ks = Array.from({length: npt}, (_, p) => Kname.get(`${bi}:${mi}:${p}:${j}`));
        S.roll(ks[0]); for (const x of ks.slice(1)) { S.roll(x); S.raw(['ADD'], 2, [ks[0]]); }
        S.rename(ks[0], `kr${hh}_${ri}`);
      });
    }
    if (Kn.some((x) => S.has(x))) throw new Error('row keys: unused key parts');
    for (const x of alphaP) S.drop(x);
    S.drop('OOD');
    mark(S, 'deep-consts');
    // fold columns: per round r, level l: packed rotation columns of beta_r^(2^l); roll-in rounds: beta_r^(2^la)
    {
      const b = new PB(D, F);
      for (let r = 0; r < NR; r++) {
        let be = names(`be${r}_`, D);
        for (let l = 0; l < vk.logArities[r]; l++) { if (l) be = b.sq(be); b.call(F.COLSK, be, D, names(`fc${r}_${l}_`, D)); }
        if (vk.rollIn[r] !== null) b.sq(be, names(`bpa${r}_`, D));
      }
      compileSlp(S, b.prog, {keep: []});
    }
    for (let k = 0; k < nT; k++) { const Gk = g2(vk.logH - (hf0 - 4 - 4 * k)); S.push(Gk, 'G'); S.raw([tblFn(4), 'INVOKE'], 1, names(`T${k}_`, 16)); }
    for (const la of arities) { S.push(g2(la), 'G'); S.raw([tblFn(la), 'INVOKE'], 1, names(`W${la}_`, 1 << la)); }
    mark(S, 'tables');
  };
  g.unpack = (S) => {
    const Z = new Uint8Array(SB - 8);
    const expand = [8, 'SPLIT', 8, 'SPLIT', Z, 'CAT', 'SWAP', Z, 'CAT', 'SWAP', 'CAT', 'SWAP', Z, 'CAT', 'SWAP', 'CAT'];
    const Pn = names('PF', GG);
    S.raw([GG, 'BEGIN', 0, 'SWAP', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0, Pn);
    S.roll('FIN');
    const CH = Math.min(16, vk.L);
    S.raw(['BEGIN', CH * e8, 'SPLIT', 'SWAP',
      'BEGIN', e8, 'SPLIT', 'SWAP', ...expand, GG + 2, 'ROLL', 'SWAP', 'CAT', 'ROT', 'ROT', 'SIZE', 'NOT', 'UNTIL', 'DROP',
      'SIZE', 'NOT', 'UNTIL', 'DROP'], GG + 1, Pn);
    S.raw([GG, 'TOALTSTACK', 'BEGIN', GG - 1, 'ROLL', B0, 'CAT', 'BIN2NUM', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], GG, Pn);
    mark(S, 'unpack');
  };
  g.merkleFns = () => {
    const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256'];
    const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
    defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4);
    defFn('F8', asm(OPS.F4, 'INVOKE', 'DROP', OPS.F4, 'INVOKE'), OPS.F8);
    defFn('F16', asm(OPS.F8, 'INVOKE', 'DROP', OPS.F8, 'INVOKE'), OPS.F16);
    const m = new Stk(['k', 'cur', 'rb']);
    m.raw(['FROMALTSTACK', 'FROMALTSTACK'], 0, ['pk', 'pd']);
    m.pick('k'); m.raw([1, 'RSHIFTNUM'], 1, ['kh']);
    const b = new PB(D);
    b.chk(chk('NUMEQUALVERIFY', add(V('pk'), V('k')), add(mul(V('kh'), K(4)), K(1))));
    b.let(sub(V('k'), mul(V('kh'), K(2))), 'bit');
    compileSlp(m, b.prog, {keep: ['kh']});
    m.arrange(['kh', 'rb', 'cur', 'pd', 'bit']);
    m.raw(['ROLL', 'CAT', 'SHA256'], 3, ['cur']);
    m.arrange(['kh', 'cur', 'rb']); m.push(0);
    defFn('MERGE', m.bytes(), OPS.MERGE);
    const d = new Stk(['k', 'cur', 'rb']);
    d.raw(['FROMALTSTACK'], 0, ['pk']); d.pick('k'); d.raw(['NUMEQUALVERIFY'], 2);
    d.raw(['FROMALTSTACK'], 0, ['pd']); d.pick('cur'); d.raw(['EQUALVERIFY'], 2); d.push(0);
    defFn('DUPM', d.bytes(), OPS.DUPM);
    const pk = new Stk(['k', 'cur', 'rb']);
    pk.roll('cur'); pk.raw(['TOALTSTACK'], 1); pk.roll('k'); pk.raw(['TOALTSTACK'], 1); pk.push(1);
    defFn('PARK', pk.bytes(), OPS.PARK);
    const rt = new Stk(['root', 'acc', 'k', 'cur', 'rb']);
    rt.roll('cur'); rt.pick('root'); rt.raw(['EQUALVERIFY'], 2); rt.roll('k'); rt.raw([1, 'NUMEQUALVERIFY'], 1); rt.push(1);
    defFn('ROOT', rt.bytes(), OPS.ROOT);
  };

  // ---------------- constraint DAG interpreter (as gen.mjs; leaves now include LogUp values and ext constants) ----------------
  function dagProgram(S, I, leafOf, {alpha: al, Dd}) {
    const ID = {LD: 100, LDB: 101, CK1: 102, CK8: 103, ADD: 104, SUB: 105, NEG: 106, MUL: 107, MK1: 108, MK8: 109, ADDL: 110, SUBL: 111, RSUBL: 112, MULL: 113};
    if (!fns.has('D_LD')) {
      const wrap = (body) => asm('TOALTSTACK', {raw: body}, 'FROMALTSTACK');
      const opnd = (n) => [n, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP', 'TOALTSTACK'];
      defFn('D_LD', asm(opnd(2), 'DEPTH', '1SUB', 'SWAP', 'SUB', 'DUP', 'PICK', 'OVER', 'PICK', 2, 'PICK', 'PICK', 3, 'ROLL', 'DROP', 'FROMALTSTACK'), ID.LD);
      defFn('D_LDB', asm(opnd(2), 'DEPTH', 2, 'SUB', 'SWAP', 'SUB', 'PICK', 0, 0, 'FROMALTSTACK'), ID.LDB);
      defFn('D_CK1', asm(opnd(1), 0, 0, 'FROMALTSTACK'), ID.CK1);
      defFn('D_CK8', asm(opnd(8), 0, 0, 'FROMALTSTACK'), ID.CK8);
      const bin = (f) => { const b = new PB(D); names('a', D).forEach((x, i) => b.red(f(V(x), V('b' + i)), 'c' + i)); return slpFn([...names('a', D), ...names('b', D)], b.prog, names('c', D)); };
      defFn('D_ADD', wrap(bin((x, y) => add(x, y))), ID.ADD);
      defFn('D_SUB', wrap(bin((x, y) => add(sub(x, y), K(P)))), ID.SUB);
      { const b = new PB(D); names('a', D).forEach((x, i) => b.red(sub(K(P), V(x)), 'c' + i)); defFn('D_NEG', wrap(slpFn(names('a', D), b.prog, names('c', D))), ID.NEG); }
      defFn('D_MUL', wrap(asm(F.MULE, 'INVOKE')), ID.MUL);
      const ldc = asm(opnd(2), 'DEPTH', '1SUB', 'SWAP', 'SUB', 'DUP', 'PICK', 'OVER', 'PICK', 2, 'PICK', 'PICK', 3, 'ROLL', 'DROP');
      defFn('D_ADDL', asm({raw: ldc}, {raw: bin((x, y) => add(x, y))}, 'FROMALTSTACK'), ID.ADDL);
      defFn('D_SUBL', asm({raw: ldc}, {raw: bin((x, y) => add(sub(x, y), K(P)))}, 'FROMALTSTACK'), ID.SUBL);
      defFn('D_RSUBL', asm({raw: ldc}, {raw: bin((x, y) => add(sub(y, x), K(P)))}, 'FROMALTSTACK'), ID.RSUBL);
      defFn('D_MULL', asm({raw: ldc}, F.MULE, 'INVOKE', 'FROMALTSTACK'), ID.MULL);
      { const b = new PB(D); names('a', D).forEach((x, i) => b.red(mul(V(x), V('k')), 'c' + i)); const body = slpFn([...names('a', D), 'k'], b.prog, names('c', D));
        defFn('D_MK1', asm(opnd(1), {raw: body}, 'FROMALTSTACK'), ID.MK1); defFn('D_MK8', asm(opnd(8), {raw: body}, 'FROMALTSTACK'), ID.MK8); }
    }
    const absOf = new Map(); const copies = [];
    const tripleAt = (t) => {
      const key = t.join('|'); if (absOf.has(key)) return absOf.get(key);
      let i = S.st.indexOf(t[0]);
      if (!(i >= 0 && S.st[i + 1] === t[1] && S.st[i + 2] === t[2])) { const cn = t.map((x) => x + '~' + I.i); t.forEach((x, k) => { S.pick(x, cn[k]); copies.push(cn[k]); }); i = S.st.length - 3; }
      absOf.set(key, i); return i;
    };
    const dag = I.dag, sc = I.scale;
    const uses = new Array(dag.nodes.length).fill(0);
    dag.nodes.forEach((nd) => { if (nd.a !== undefined) uses[nd.a]++; if (nd.b !== undefined) uses[nd.b]++; });
    const leaves = dag.nodes.map((nd, k) => leafOf(nd, k));
    leaves.forEach((l) => { if (l?.ext) tripleAt(l.ext); });
    const iAlpha = tripleAt(al), iDd = tripleAt(Dd);
    const base0 = S.st.length;
    const u16 = (x) => { if (x >= 0x7fff) throw new Error('stack index'); return [x & 0xff, x >> 8]; };
    const u64 = (v) => Array.from(le8(v));
    const instrs = [];
    const prog = {push: (...x) => { instrs.push(x); }, get length() { return instrs.reduce((a, i) => a + i.length, 0); }};
    const reg = new Map();
    let steps = 0;
    const emitK = (v) => { v = ((v % P) + P) % P; if (v < 0x80n) prog.push(ID.CK1, Number(v)); else prog.push(ID.CK8, ...u64(v)); };
    const up = (k) => { for (let i = 0; i < k; i++) prog.push(ID.MULL, ...u16(iDd)); };
    const ldIdx = (k) => (reg.has(k) ? reg.get(k) : leaves[k]?.ext ? absOf.get(leaves[k].ext.join('|')) : null);
    const constOf = (k) => (leaves[k] && leaves[k].k !== undefined ? leaves[k].k : null);
    const emit = (k, top = false) => {
      if (!top && reg.has(k)) { prog.push(ID.LD, ...u16(reg.get(k))); return; }
      const nd = dag.nodes[k], l = leaves[k];
      steps++;
      if (l) {
        if (l.ext) prog.push(ID.LD, ...u16(absOf.get(l.ext.join('|'))));
        else if (l.base) prog.push(ID.LDB, ...u16(S.st.indexOf(l.base)));
        else emitK(l.k);
        return;
      }
      switch (nd.op) {
        case 'add': case 'sub': {
          const ia = sc[k] === sc[nd.a] ? ldIdx(nd.a) : null, ib = sc[k] === sc[nd.b] ? ldIdx(nd.b) : null;
          if (ib !== null) { emit(nd.a); up(sc[k] - sc[nd.a]); prog.push(nd.op === 'add' ? ID.ADDL : ID.SUBL, ...u16(ib)); return; }
          if (ia !== null) { emit(nd.b); up(sc[k] - sc[nd.b]); prog.push(nd.op === 'add' ? ID.ADDL : ID.RSUBL, ...u16(ia)); return; }
          emit(nd.a); up(sc[k] - sc[nd.a]); emit(nd.b); up(sc[k] - sc[nd.b]); prog.push(nd.op === 'add' ? ID.ADD : ID.SUB); return;
        }
        case 'neg': emit(nd.a); prog.push(ID.NEG); return;
        case 'mul': {
          const ka = constOf(nd.a), kb = constOf(nd.b);
          const mk = (v, other) => { v = ((v % P) + P) % P; emit(other); if (v < 0x80n) prog.push(ID.MK1, Number(v)); else prog.push(ID.MK8, ...u64(v)); };
          const ia = ldIdx(nd.a), ib = ldIdx(nd.b);
          if (kb !== null) mk(kb, nd.a); else if (ka !== null) mk(ka, nd.b);
          else if (ib !== null) { emit(nd.a); prog.push(ID.MULL, ...u16(ib)); }
          else if (ia !== null) { emit(nd.b); prog.push(ID.MULL, ...u16(ia)); }
          else { emit(nd.a); emit(nd.b); prog.push(ID.MUL); }
          return;
        }
        default: throw new Error('DAG op ' + nd.op);
      }
    };
    let nReg = 0;
    dag.nodes.forEach((nd, k) => { if (uses[k] > 1 && !leaves[k]) { emit(k, true); reg.set(k, base0 + 3 * nReg); nReg++; } });
    dag.constraints.forEach((c, i) => {
      if (i) prog.push(ID.MULL, ...u16(iAlpha));
      const ic = I.maxScale === sc[c.node] ? ldIdx(c.node) : null;
      if (i && ic !== null) { prog.push(ID.ADDL, ...u16(ic)); return; }
      emit(c.node); up(I.maxScale - sc[c.node]);
      if (i) prog.push(ID.ADD);
    });
    const regNames = Array.from({length: 3 * nReg}, (_, i) => `rg${I.i}_${i}`);
    const CH = opts.dagChunk ?? 40;
    const chunks = []; { let curC = []; for (const ins of instrs) { if (curC.length && curC.length + ins.length > CH) { chunks.push(curC); curC = []; } curC.push(...ins); } if (curC.length) chunks.push(curC); }
    const idRUN = fns.get('D_RUN')?.id ?? defFn('D_RUN', asm('BEGIN', 1, 'SPLIT', 'SWAP', 'INVOKE', 'SIZE', 'NOT', 'UNTIL', 'DROP'));
    S.raw(chunks.flatMap((c) => [Uint8Array.from(c), idRUN, 'INVOKE']), 0, [...regNames, 'acc0', 'acc1', 'acc2']);
    const nDrop = S.st.length - 3 - (base0 - copies.length);
    if (S.st.slice(S.st.length - 3 - nDrop, S.st.length - 3).some((x) => !copies.includes(x) && !regNames.includes(x))) throw new Error('dag cleanup');
    S.raw(['TOALTSTACK', 'TOALTSTACK', 'TOALTSTACK', ...(nDrop ? [nDrop, 'BEGIN', 'NIP', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'] : []), 'FROMALTSTACK', 'FROMALTSTACK', 'FROMALTSTACK'], nDrop + 3, ['acc0', 'acc1', 'acc2']);
    g.dagStats.push({instance: I.i, steps, progBytes: prog.length, chunks: chunks.length, registers: nReg, leafCopies: copies.length, stackAtStart: base0, maxDepth: base0 + 3 * nReg});
    return {acc: ['acc0', 'acc1', 'acc2']};
  }

  // ---------------- one query ----------------
  g.emitQuery = (Qs) => {
    const KC = /^(kr|nA|nB|nC|nt|nc|nd|fc|bpa|T\d|W\d|PF)/;
    const keepC = () => Qs.st.filter((x) => KC.test(x));
    Qs.pick('idx', 'v'); Qs.raw([la0, 'RSHIFTNUM'], 1, ['v']);
    for (let k = 0; k < nT; k++) {
      const last = k === nT - 1;
      if (!last) Qs.raw(['DUP'], 0, ['nb']);
      const d = Qs.depth(`T${k}_0`) - 1;
      Qs.raw([...(last ? [] : [16, 'MOD']), d, 'SWAP', 'SUB', 'PICK'], 1, ['t']);
      if (k === 0) { if (last) { Qs.rename('t', 's0'); break; } Qs.raw(['SWAP', 4, 'RSHIFTNUM'], 2, ['x', 'v']); continue; }
      if (last) { Qs.raw([F.MM, 'INVOKE'], 2, ['s0']); break; }
      Qs.raw(['ROT', F.MM, 'INVOKE', 'SWAP', 4, 'RSHIFTNUM'], 3, ['x', 'v']);
    }
    const pickW = (la, posExpr, out) => {
      Qs.pick('idx', 'v'); Qs.raw([...(posExpr ? [posExpr, 'RSHIFTNUM'] : []), 1 << la, 'MOD'], 1, ['v']);
      const d = Qs.depth(`W${la}_0`) - 1;
      Qs.raw([d, 'SWAP', 'SUB', 'PICK'], 1, [out]);
    };
    pickW(la0, 0, 'w0');
    { const b = new PB(D, F); b.mm('s0', 'w0', 'xo'); b.red(mul(V('xo'), K(7)), 'x0'); compileSlp(Qs, b.prog, {keep: ['s0', 'xo']}); }
    mark(Qs, 'q-x');
    // split L
    Qs.roll('L');
    const parts = [], lens = [];
    inTrees.forEach((tr, ti) => {
      tr.groups.forEach((_, gi) => { parts.push(`gp${ti}_${gi}`); lens.push(vk.blob.trees[ti].groups[gi]); });
      if (tr.B) { parts.push(`bs${ti}`); lens.push(tr.B * h); }
    });
    vk.blob.fri.forEach((n, r) => { parts.push('fb' + r); lens.push(n); });
    parts.push('TT');
    Qs.raw(lens.flatMap((n) => [n, 'SPLIT']), 1, parts);
    Qs.pick('idx'); Qs.raw([4, 'NUM2BIN'], 1, ['kb']);
    // input trees: tallest-group digest, bottom levels with injections -> the record leaf (level B)
    inTrees.forEach((tr, ti) => {
      Qs.pick(`gp${ti}_0`); Qs.raw(['SHA256'], 1, ['dg']);
      for (let l = 1; l <= tr.B; l++) {
        if (l < tr.B) { Qs.roll(`bs${ti}`); Qs.raw([h, 'SPLIT'], 1, ['sib', `bs${ti}`]); } else { Qs.roll(`bs${ti}`); Qs.rename(`bs${ti}`, 'sib'); }
        Qs.roll('dg'); Qs.roll('sib');
        const sh = vk.logH - tr.top + l - 1;
        Qs.pick('idx'); Qs.raw([...(sh ? [sh, 'RSHIFTNUM'] : []), 2, 'MOD', 'IF', 'SWAP', 'ENDIF', 'CAT', 'SHA256'], 3, ['dg']);
        const gi = tr.groups.findIndex((gg) => gg.logH === tr.top - l);
        if (gi > 0) { Qs.pick(`gp${ti}_${gi}`); Qs.raw(['SHA256'], 1, ['ih']); Qs.roll('dg'); Qs.roll('ih'); Qs.raw(['CAT', 'SHA256'], 2, ['dg']); }
      }
      Qs.roll('kb'); Qs.roll('dg'); Qs.raw(['CAT'], 2, ['kb']);
      // row values
      tr.groups.forEach((gg, gi) => {
        Qs.roll(`gp${ti}_${gi}`);
        const outs = [], code = [];
        for (const mi of gg.mats) {
          for (let j = 0; j < tr.matW[mi]; j++) { outs.push(`rw${tr.b}_${mi}_${j}`); code.push(8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SWAP'); }
          if (vk.salt) code.push(8 * vk.salt, 'SPLIT', 'NIP');
        }
        code.push('DROP');
        Qs.raw(code, 1, outs);
      });
    });
    // hints (canonical)
    Qs.roll('TT');
    Qs.raw(Array.from({length: nH - 1}, () => [8, 'SPLIT']).flat(), 1, names('tb', nH));
    for (let hi = 0; hi < nH; hi++) { Qs.roll('tb' + hi); Qs.raw([B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY'], 1, ['tq' + hi]); }
    // ---- DEEP per height ----
    let xoPrev = 'xo', hPrev = vk.logH;
    vk.heights.forEach((hh, hi) => {
      const pts = vk.hp[hh], m = pts.length;
      const b = new PB(D, F);
      let x = 'x0';
      if (hi > 0) { let y = xoPrev; for (let i = 0; i < hPrev - hh; i++) y = b.mm(y, y); xoPrev = y; hPrev = hh; x = b.red(mul(V(y), K(7))); }
      const x2 = b.mm(x, x);
      const N = pts.map((pt) => {
        const n1 = b.red(add(mul(add(sub(V(x), V(`nt${pt}`)), K(P)), V(x)), V(`nc${pt}`)));
        const n2 = b.mm(n1, x);
        return b.red(add(sub(V(`nd${pt}`), V(n2)), K(P)));
      });
      let prod = N[0]; for (let k = 1; k < m; k++) prod = b.mm(prod, N[k]);
      if (hi === 0) { const tn = b.mm('tq0', prod); b.chk(chk('NUMEQUALVERIFY', R(mul(V(tn), V('s0'))), K(1))); b.let(V(tn), 'si0'); }
      else b.chk(chk('NUMEQUALVERIFY', R(mul(V('tq' + hi), V(prod))), K(1)));
      b.let(sum(...g.rowList[hh].map(([bi, mi, j], ri) => mul(V(`rw${bi}_${mi}_${j}`), V(`kr${hh}_${ri}`)))), 'dot');
      const roPrev = vk.heights.slice(0, hi).flatMap((_, k) => names(`ro${k}_`, D));
      compileSlp(Qs, b.prog, {keep: [...keepC(), 's0', 'xo', 'si0', xoPrev, x, x2, 'tq' + hi, ...N, ...roPrev, ...vk.heights.slice(hi + 1).map((_, k) => 'tq' + (hi + 1 + k))]});
      Qs.roll('dot'); Qs.raw(unpackCode(m * D, SB, true), 1, names('dp', m * D));
      const b2 = new PB(D, F);
      const num = pts.map((_, k) => names(`nA${hh}_${k}_`, D).map((a, c) => b2.red(add(sub(V(a), V(`dp${k * D + c}`)), K(P)))));
      const adj = pts.map((pt) => [b2.red(add(add(V(x2), mul(V(`nB${pt}_0`), V(x))), V(`nC${pt}_0`))), b2.red(add(mul(V(`nB${pt}_1`), V(x)), V(`nC${pt}_1`))), b2.red(add(mul(V(`nB${pt}_2`), V(x)), V(`nC${pt}_2`)))]);
      const ts = hi === 0 ? b2.mm('tq0', 's0') : 'tq' + hi;
      const mk = pts.map((_, k) => { let y = ts; N.forEach((Nj, j) => { if (j !== k) y = b2.mm(y, Nj); }); return y; });
      const pk = pts.map((_, k) => mulE(D, num[k], adj[k]));
      const ro = Array.from({length: D}, (_, c) => b2.red(sum(...pts.map((_, k) => mul(R(pk[k][c]), V(mk[k])))), `ro${hi}_${c}`));
      compileSlp(Qs, b2.prog, {keep: [...keepC(), 'xo', 'si0', xoPrev, ...ro, ...roPrev, ...(hi === 0 ? [] : []), ...vk.heights.slice(hi + 1).map((_, k) => 'tq' + (hi + 1 + k))]});
      for (const y of [x, x2, ...N, ts, ...mk, 'tq' + hi, ...(hi === 0 ? ['s0', 'x0'] : [])]) if (Qs.has(y) && y !== 'xo' && y !== xoPrev && !ro.includes(y)) Qs.drop(y);
    });
    if (xoPrev !== 'xo') Qs.drop(xoPrev);
    names('ro0_', D).forEach((x, c) => Qs.rename(x, 'fv' + c));
    mark(Qs, 'q-deep');
    // ---- folds (with roll-ins) ----
    let S_acc = 0;
    for (let r = 0; r < NR; r++) {
      const la = vk.logArities[r], a = 1 << la;
      for (let k = 0; k < D; k++) Qs.pick('fv' + k);
      Qs.raw([F.ENC, 'INVOKE'], D, ['fe']);
      Qs.roll('fb' + r);
      if (vk.salt) Qs.raw([((1 << la) - 1) * e8, 'SPLIT'], 1, ['blk', 'salt']); else Qs.rename('fb' + r, 'blk');
      Qs.roll('blk'); Qs.pick('idx'); Qs.raw([...(S_acc ? [S_acc, 'RSHIFTNUM'] : []), a, 'MOD', e8, 'MUL', 'SPLIT'], 2, ['bl', 'br']);
      Qs.roll('bl'); Qs.roll('fe'); Qs.raw(['CAT'], 2, ['bl']); Qs.roll('br'); Qs.raw(['CAT'], 2, ['leaf']);
      if (vk.salt) { Qs.pick('leaf'); Qs.roll('salt'); Qs.raw(['CAT', 'SHA256'], 2, ['dg']); } else { Qs.pick('leaf'); Qs.raw(['SHA256'], 1, ['dg']); }
      Qs.roll('kb'); Qs.roll('dg'); Qs.raw(['CAT'], 2, ['kb']);
      for (let k = 0; k < D; k++) Qs.drop('fv' + k);
      Qs.roll('leaf'); Qs.raw([F.PKL, 'INVOKE'], 1, names('v', a));
      const key = 'FOLD' + la;
      if (!F[key]) {
        const args = [...names('v', a), ...Array.from({length: la}, (_, l) => names(`c${l}_`, D)).flat(), 'X'];
        const b = new PB(D, F);
        const ga = g2(la);
        let cur = names('v', a), X = 'X';
        for (let l = 0; l < la; l++) {
          const half = cur.length / 2, nxt = [];
          for (let mm = 0; mm < half; mm++) {
            const cm = inv(pw(ga, rev(mm, la - 1)));
            const xi = mm === 0 ? X : b.mm(X, K(cm));
            nxt.push(b.call(F.PAIRK, [...names(`c${l}_`, D), xi, cur[2 * mm], cur[2 * mm + 1]], 1, l === la - 1 ? ['o'] : undefined)[0]);
          }
          cur = nxt;
          if (l < la - 1) X = b.mm(X, X);
        }
        F[key] = defFn(key, slpFn(args, b.prog, ['o']));
      }
      { const si = `si${r}`; const b = new PB(D, F); b.call(F[key], [...names('v', a), ...Array.from({length: la}, (_, l) => names(`fc${r}_${l}_`, D)).flat(), si], 1, ['fo']); compileSlp(Qs, b.prog, {keep: [...keepC(), si]}); }
      const ainv = inv(BigInt(a));
      Qs.roll('fo');
      Qs.raw([SK * D, 'NUM2BIN', ...Array(D - 1).fill([SK, 'SPLIT']).flat(), ...Array.from({length: D}, () => [D - 1, 'ROLL', 'BIN2NUM', P, 'MOD', ainv, F.MM, 'INVOKE']).flat()], 1, names('fv', D));
      if (vk.rollIn[r] !== null) {
        const hi = vk.heights.indexOf(vk.rollIn[r]);
        const b = new PB(D, F);
        const t = b.mul(names(`bpa${r}_`, D), names(`ro${hi}_`, D));
        b.add(names('fv', D), t, names('fw', D));
        compileSlp(Qs, b.prog, {keep: keepC()});
        names('fw', D).forEach((x, c) => Qs.rename(x, 'fv' + c));
      }
      S_acc += la;
      {
        const b = new PB(D, F);
        const sa = b.pow2k(`si${r}`, la);
        if (r + 1 < NR) {
          compileSlp(Qs, b.prog, {keep: []});
          pickW(vk.logArities[r + 1], S_acc, 'wn');
          const b3 = new PB(D, F); b3.mm(sa, 'wn', `si${r + 1}`); compileSlp(Qs, b3.prog, {keep: []});
        } else { compileSlp(Qs, b.prog, {keep: []}); Qs.drop(sa); }
      }
    }
    mark(Qs, 'q-folds');
    // ---- final polynomial at xf = xo^(2^S) ----
    {
      const b = new PB(D, F);
      const y = b.pow2k('xo', vk.S);
      compileSlp(Qs, b.prog, {keep: []});
      Qs.roll(y);
      const Yn = names('Y', GG + 1).slice(1);
      if (GG > 1) { F.PW ??= defFn('PW', asm('2DUP', 'MUL', P, 'MOD', 'SWAP')); Qs.raw(['DUP', ...Array(GG - 1).fill([F.PW, 'INVOKE']), 'DROP'], 1, Yn); } else Qs.rename(y, 'Y1');
      Qs.raw(['TOALTSTACK'], 1);
      Qs.pick('PF0', 'acc');
      for (let k = GG - 1; k >= 1; k--) { Qs.roll('Y' + k); Qs.pick('PF' + k); Qs.raw(['MUL', 'ADD'], 3, ['acc']); }
      const nsl = D * GH;
      const sl = names('sl', nsl);
      Qs.roll('acc');
      Qs.raw([SB * nsl, 'NUM2BIN', ...Array(nsl - 1).fill([SB, 'SPLIT']).flat()], 1, sl);
      Qs.raw(Array.from({length: D}, () => [D - 1, 'ROLL', 'BIN2NUM']).flat(), D, names('ra', D));
      Qs.raw(['FROMALTSTACK'], 0, ['YG']);
      if (GH > 1) {
        if (!F.HG) {
          const st = new Stk([...names('t', D), ...names('ra', D), 'YG']);
          for (let k = 0; k < D; k++) { st.roll('t' + k); st.raw(['BIN2NUM'], 1, ['u' + k]); }
          const b = new PB(D);
          for (let k = 0; k < D; k++) b.red(add(mul(V('ra' + k), V('YG')), V('u' + k)), 'o' + k);
          compileSlp(st, b.prog, {keep: ['YG']});
          st.arrange([...names('o', D), 'YG']);
          F.HG = defFn('HG', st.bytes());
        }
        for (let mm = GH - 2; mm >= 0; mm--) Qs.raw([F.HG, 'INVOKE'], 2 * D + 1, [...names('ra', D), 'YG']);
      }
      Qs.drop('YG');
      const cb = new PB(D);
      names('ra', D).forEach((x, k) => cb.chk(chk('NUMEQUALVERIFY', R(V(x)), V('fv' + k))));
      compileSlp(Qs, cb.prog);
    }
    Qs.drop('idx');
    Qs.roll('kb'); Qs.raw(['TOALTSTACK'], 1);
    mark(Qs, 'q-final');
  };
  return g;
}

// ---------------- a role's main program ----------------
// role 'full' | 'p0' | 'p1'; qs: the role's query numbers (ascending); pin: {selfIndex, otherIndex, otherLocking:
// {pre, post} (bytes around H_lib)} for b2
function buildMain(g, stmt, role, qs, pin, share = false) {
  const {vk, D, h, F, defFn, defShared, mark} = g;
  const Q = vk.Q, Qp = qs.length, RG = 2, nTrees = vk.trees.length, nRec = Math.ceil(Qp / RG);
  const pool = stmt.mode === 'pool';
  const init = [];
  for (let j = Qp - 1; j >= 0; j--) init.push('L' + j);
  for (let t = 0; t < nTrees; t++) for (let i = 0; i < nRec; i++) init.push(`R${t}_${i}`);
  if (role === 'p1') init.push('TAIL'); else init.push(...g.tailItems().map(([x]) => x));
  const S = new Stk(init);
  if (pin) {
    // the transaction graph: exactly 2 inputs, this input at its index, the other input's locking = template(H_lib)
    S.raw(['FROMALTSTACK', Uint8Array.from(pin.otherLocking.pre), 'SWAP', 'CAT', Uint8Array.from(pin.otherLocking.post), 'CAT', pin.otherIndex, 'UTXOBYTECODE', 'EQUALVERIFY',
      'TXINPUTCOUNT', 2, 'NUMEQUALVERIFY', 'INPUTINDEX', pin.selfIndex, 'NUMEQUALVERIFY'], 0);
  }
  S.emit('DEPTH', init.length, 'NUMEQUALVERIFY');
  if (role === 'p1') g.parseTail(S);
  g.statement(S, role);
  // b2: the transcript and the DEEP/FRI constants are shared functions over a canonical region on top of the stack
  const shared = (key, region, body) => {
    for (const x of region) S.roll(x);
    if (!g[key]) { const s = new Stk(region); body(s); g[key] = {id: defFn(key, s.bytes()), outs: [...s.st]}; }
    S.raw([g[key].id, 'INVOKE'], region.length, g[key].outs);
  };
  const tRegion = [...g.tailItems().map(([x]) => x).filter((x) => x !== 'CTXW'), ...(pool ? ['CTXB'] : [])];
  if (share) shared('TRANSCRIPT', tRegion, (s) => g.transcript(s)); else g.transcript(S);
  // keep this role's indices (renamed idx0 .. idx_{Qp-1}, deepest first)
  for (let q = 0; q < Q; q++) if (!qs.includes(q)) S.drop('idx' + q);
  qs.forEach((q, j) => S.rename('idx' + q, 'jdx' + j));
  qs.forEach((_, j) => S.rename('jdx' + j, 'idx' + j));
  if (role !== 'p1') g.air(S);
  else for (const x of [...(vk.hasLookups ? ['TERM'] : []), ...(pool ? [] : []), 'al0', 'al1', 'al2']) if (S.has(x)) S.drop(x);
  if (role === 'p1' && vk.hasLookups) for (const x of ['la0', 'la1', 'la2', 'lb0', 'lb1', 'lb2']) if (S.has(x)) S.drop(x);
  const cRegion = ['OOD', 'FIN', ...names('ze', D), ...names('ap', D), ...vk.logArities.flatMap((_, r) => names(`be${r}_`, D))];
  if (share) shared('CONSTS', cRegion, (s) => { g.consts(s); g.unpack(s); }); else { g.consts(S); g.unpack(S); }
  // queries
  { const lo = S.st.indexOf('idx0'); for (const x of S.st.slice(0, lo)) if (!/^(L\d|R\d|ROOTS|FROOTS)/.test(x)) S.roll(x); }
  {
    S.push(Qp, 'qcnt');
    const Qs = S.clone();
    const qWant = S.st.filter((x) => x !== 'idx' + (Qp - 1)).slice(1);
    Qs.bottom(); Qs.rename(Qs.top(), 'L');
    Qs.raw(['SIZE', vk.blob.total, 'NUMEQUALVERIFY'], 0);
    Qs.roll('idx' + (Qp - 1)); Qs.rename(Qs.top(), 'idx');
    g.emitQuery(Qs);
    if (Qs.st.length === qWant.length && Qs.st.every((x) => qWant.includes(x))) Qs.arrange(qWant);
    if (Qs.st.join('|') !== qWant.join('|')) {
      const extra = Qs.st.filter((x) => !qWant.includes(x)), missing = qWant.filter((x) => !Qs.st.includes(x));
      throw new Error(`query function leaves extra [${extra}] missing [${missing}]`);
    }
    const idQ = defShared('Q_' + role, Qs.bytes());
    S.raw(['BEGIN', idQ, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
    S.st.splice(0, Qp);
    for (let j = 0; j < Qp; j++) S.st.splice(S.st.indexOf('idx' + j), 1);
  }
  mark(S, 'queries');
  for (const x of [...S.st]) if (!/^(L\d|R\d|ROOTS|FROOTS)/.test(x)) S.drop(x);
  S.raw(Array(Qp).fill('FROMALTSTACK'), 0, names('K', Qp));
  if (!g.fns.has('MERGE')) g.merkleFns();
  {
    const MARKER = Uint8Array.of(0x00, 0x80);
    let idREC = null;
    vk.trees.forEach((tr, ti) => {
      S.raw([MARKER, 'TOALTSTACK'], 0);
      S.push(tr.shift, 'pS'); S.push(1 << tr.depth, 'pK'); S.push(4 + ti * h, 'pO');
      S.push(0, 'rbc');
      if (tr.kind === 'fri') { S.pick('FROOTS', 'root'); S.raw([...(tr.r ? [tr.r * h, 'SPLIT', 'NIP'] : []), h, 'SPLIT', 'DROP'], 0); }
      else if (tr.name === 'preprocessed') S.push(vk.preCap, 'root');
      else { const off = vk.capOff[tr.name]; S.pick('ROOTS', 'root'); S.raw([...(off ? [off, 'SPLIT', 'NIP'] : []), h, 'SPLIT', 'DROP'], 0); }
      S.push(0, 'acc'); S.push(Qp, 'cnt');
      if (idREC === null) {
        const m = S.clone();
        { const dc = m.depth('cnt'); m.roll('rbc'); m.raw(['SIZE', 'NOT', 'IF', 'DROP', dc, 'PICK', RG, 'MOD', Qp % RG, 'NUMEQUALVERIFY', 'DEPTH', '1SUB', 'ROLL', 'ENDIF'], 1, ['rb']); }
        m.raw([1, 'SPLIT', 'SWAP', 'BIN2NUM'], 1, ['rb', 'sg']);
        m.pick('sg'); m.raw([0, Qp, 'WITHIN', 'VERIFY'], 1);
        m.push(1); m.pick('sg'); m.raw(['LSHIFTNUM'], 2, ['pw']); m.roll('acc'); m.raw(['ADD'], 2, ['acc']);
        { m.roll('sg'); const dl = m.depth('K' + (Qp - 1)) - 1 + Qp - 1; m.raw([dl, 'SWAP', 'SUB', 'PICK'], 1, ['Kc']); }
        m.raw([4, 'SPLIT'], 1, ['ix', 'Kc']);
        m.pick('pO'); m.raw([4, 'SUB', 'SPLIT', 'NIP', h, 'SPLIT', 'DROP'], 2, ['cur']);
        m.roll('ix'); m.raw(['BIN2NUM'], 1, ['ix']); m.pick('pS'); m.raw(['RSHIFTNUM'], 2, ['ix']); m.pick('pK'); m.raw(['ADD'], 2, ['k']);
        m.arrange([...m.st.filter((x) => !['root', 'acc', 'k', 'cur', 'rb'].includes(x)), 'root', 'acc', 'k', 'cur', 'rb']);
        m.raw(['BEGIN', 1, 'SPLIT', 'SWAP', 'DUP', 10, 'LESSTHAN', 'VERIFY', 'INVOKE', 'UNTIL'], 3, ['rbc']);
        m.arrange(S.st);
        idREC = defFn('REC_' + role, m.bytes());
      }
      S.raw(['BEGIN', idREC, 'INVOKE', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 1);
      S.st.splice(0, nRec);
      S.roll('acc'); S.raw([(1n << BigInt(Qp)) - 1n, 'NUMEQUALVERIFY'], 1);
      S.roll('rbc'); S.raw([0, 'EQUALVERIFY'], 1);
      S.raw(['FROMALTSTACK', MARKER, 'EQUALVERIFY'], 0);
      S.drop('root'); S.drop('pO'); S.drop('pK'); S.drop('pS');
      S.emit('DEPTH', S.st.length, 'NUMEQUALVERIFY');
    });
  }
  mark(S, 'merkle');
  if (S.st.some((x) => /^(R\d|L\d|idx)/.test(x))) throw new Error('unconsumed witness items ' + S.st.filter((x) => /^(R\d|L\d|idx)/.test(x)));
  S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length);
  S.push(1);
  mark(S, 'end');
  void D; void F;
  return {main: S.bytes(), init};
}

// ---------------- layout b: one input, redeem = function definitions + main ----------------
export function buildB(vk, stmt, opts = {}) {
  const g = makeGenN(vk, stmt, opts);
  const qs = Array.from({length: vk.Q}, (_, q) => q);
  const m = buildMain(g, stmt, 'full', qs, null);
  const pro = [];
  for (const [, f] of g.fns) pro.push(...asm(f.body, f.id, 'DEFINE'));
  return {g, main: m.main, init: m.init, fns: g.fns, redeem: Uint8Array.from([...pro, ...m.main]), dagStats: g.dagStats, marks: g.marks};
}

// ---------------- layout b2: two inputs sharing one code library ----------------
// lib = records [id (1 B)][len (3 B LE)][body]; defloop defines them all. Input 0's unlocking pushes lib first (bottom),
// then its witness; its locking (P2S) authenticates lib by HASH256 and invokes MAIN0. Input 1's locking (P2S, the
// loader) reads input 0's unlocking bytecode, takes lib (first push) and the tail (input 0's PT and statement
// pushes), authenticates lib by the same hash, defines it and invokes MAIN1. MAIN0 / MAIN1 pin each other's locking
// (template around H_lib), the input count (2) and their own input index.
export const DEFLOOP = asm('BEGIN', 1, 'SPLIT', 3, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SPLIT', 'ROT', 'ROT', 'SWAP', 'DEFINE', 'SIZE', 'NOT', 'UNTIL', 'DROP');
const MAIN0 = 126, MAIN1 = 127;
export function lockingTemplates(tailLen) {
  // locking0: lib at the bottom of the stack -> top, authenticate, define, invoke MAIN0
  const l0pre = asm('DEPTH', '1SUB', 'ROLL'), l0post = asm('OVER', 'HASH256', 'OVER', 'EQUALVERIFY', 'TOALTSTACK', {raw: DEFLOOP}, MAIN0, 'INVOKE');
  // locking1 (loader): input 0's unlocking -> lib (first push, PUSHDATA2) and the tail; authenticate, define, invoke MAIN1
  const l1pre = asm(0, 'INPUTBYTECODE', 1, 'SPLIT', 'SWAP', Uint8Array.of(0x4d), 'EQUALVERIFY', 2, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'SPLIT',
    'SIZE', tailLen, 'SUB', 'SPLIT', 'NIP', 'SWAP');
  const l1post = asm('OVER', 'HASH256', 'OVER', 'EQUALVERIFY', 'TOALTSTACK', {raw: DEFLOOP}, MAIN1, 'INVOKE');
  const push32 = Uint8Array.of(0x20);
  return {
    l0: {pre: Buffer.concat([l0pre, push32]), post: Buffer.from(l0post)},
    l1: {pre: Buffer.concat([l1pre, push32]), post: Buffer.from(l1post)},
  };
}
export function buildB2(vk, stmt, QA, opts = {}) {
  const g = makeGenN(vk, stmt, opts);
  const tailLen = g.tailItems().reduce((s, [, len]) => s + pushPrefix(len).length + len, 0);
  const T = lockingTemplates(tailLen);
  const q0 = Array.from({length: QA}, (_, q) => q), q1 = Array.from({length: vk.Q - QA}, (_, q) => QA + q);
  const m0 = buildMain(g, stmt, 'p0', q0, {selfIndex: 0, otherIndex: 1, otherLocking: T.l1}, true);
  const m1 = buildMain(g, stmt, 'p1', q1, {selfIndex: 1, otherIndex: 0, otherLocking: T.l0}, true);
  g.fns.set('MAIN0', {id: MAIN0, body: m0.main}); g.fns.set('MAIN1', {id: MAIN1, body: m1.main});
  const lib = Buffer.concat([...g.fns.values()].map((f) => { const len = Buffer.alloc(3); len.writeUIntLE(f.body.length, 0, 3); return Buffer.concat([Buffer.of(f.id), len, Buffer.from(f.body)]); }));
  if (lib.length < 256 || lib.length >= 65536) throw new Error('lib length outside PUSHDATA2');
  return {g, lib, T, tailLen, init0: m0.init, init1: m1.init, q0, q1, main0: m0.main, main1: m1.main, dagStats: g.dagStats, marks: g.marks};
}
