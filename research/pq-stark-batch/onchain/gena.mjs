// Track 8 S7: layout a' (DESIGN-T8 §5 a'): M1 (Z128, Merkle cap 5) under today's standard rules: every input's
// unlocking <= 10,000 B, every stack item and function body <= 10,000 B, P2S locking <= 201 B, every transaction
// <= 100,000 B, op-cost budget (41 + unlocking) * 800 per input.
//
// Every input has the same P2S locking R (~120 B). R reads the code blobs from the CODE inputs' unlocking (first push,
// push header checked), checks each blob's SHA-256, defines it and invokes it; a blob defines its functions; the last
// blob then pins the input graph (input count per transaction kind; every input's locking = R) and invokes the role
// of (kind, input index). Inputs of one transaction (bottom first = push order):
//   0          HEAD  ROOTS (trace, quotient, random caps) OOD BPOW FROOTS (FRI cap) CPOW QPOW NF CTXW
//                    statement (NF lanes < p; CTXW = CTX of this transaction's outputs in the final transaction,
//                    canonical otherwise), transcript with every PoW check; kind 0: combines the CODE inputs'
//                    partial accumulators with the quotient: sum_j ACC_j alpha^(C - hi_j) = q zh Dd^maxScale;
//                    NFT thread (multi-transaction plans)
//   1 .. nc    CODE  BLOB_j [ACC_j]: kind 0: re-derives the transcript from HEAD's and FIN's pushes, evaluates the
//                    constraint range j of the AIR at zeta (periodic columns, selectors, DAG interpreter) and checks
//                    its own ACC_j push
//   nc + 1     FIN   FIN TBL: re-derives the transcript, computes the DEEP constants and checks its own TBL push
//                    (query indices, alpha', beta, point constants, A sums)
//   nc + 2 ..  QRY   L_q PTH_q per query q in [lo, hi): reads HEAD's caps and FIN's FIN and TBL; alpha' ladder and
//                    row keys, fold columns, tables, the final polynomial; per query: DEEP, fold, final polynomial
//                    (S5 query function), then the full path of every tree up to its cap entry
// Values cross inputs only as pushes that their own input checks (ACC by CODE, TBL by FIN, CTXW by the final HEAD);
// every reader parses them with checked push headers from OP_INPUTBYTECODE.
// Plans of T > 1 transactions are linked by Track 5's NFT thread: kind 0's input 0 holds the minting baton (returned
// to R in output 0) and mints one immutable NFT per later transaction k with commitment k ‖ SHA256(tag ‖ G ‖ k)
// (G: the final transcript digest, which binds the whole proof and the statement ROOT, NF, CTX); transaction k spends
// it in input 0 and burns it. CTX is the final transaction's outputs.
import {asm, Stk} from './lib/asm.mjs';
import {compileSlp, V, K, op, chk, add, sub, mul, modp, sum, ex} from './lib/slp.mjs';
import {PB, SB, mulU} from './gen.mjs';
import {makeGenN} from './genn.mjs';
import {P, inv, g2, sha, OPS} from './modeln.mjs';
import {ctxCode} from './ctx.mjs';
import {encodeDataPush} from '@bitauth/libauth';

export const ROLE_BASE = 1000, ID_CODE = 990;
export const TTAG = Buffer.from('pq-stark-batch/thread');
export const threadCommit = (G, k) => Buffer.concat([Buffer.from([k]), sha(TTAG, G, Uint8Array.of(k))]);
export const pushPrefix = (len) => Buffer.from(encodeDataPush(new Uint8Array(len))).subarray(0, -len || undefined);
export const pushLen = (len) => pushPrefix(len).length + len;
const B0 = Uint8Array.of(0);
const R = (x) => modp(x, P);
const names = (b, n) => Array.from({length: n}, (_, i) => b + i);
void ex; void sum;

function localFn(args, build) {
  const s = new Stk(args);
  const outs = build(s);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length || s.st.length !== outs.length) throw new Error('local function leaves ' + (extra.join(',') || s.st.join(',')));
  s.arrange(outs);
  return s.bytes();
}

// plan: {txs: [{qry: [[lo, hi], ...]}], nc (code inputs), thread?: {category (32 B, internal order)}}
export function buildA(vk, pis, plan, opts = {}) {
  { let next = 0;
    for (const tx of plan.txs) for (const r of tx.qry) {
      if (!Array.isArray(r) || r.length !== 2 || r[0] !== next || !(r[1] > r[0])) throw new Error(`plan: query ranges must partition [0, ${vk.Q}) in order; got ${JSON.stringify(r)} at ${next}`);
      next = r[1];
    }
    if (next !== vk.Q) throw new Error(`plan: query ranges cover [0, ${next})`); }
  const T = plan.txs.length, thread = plan.thread, nc = plan.nc;
  if (T > 1 && !thread) throw new Error('plan: several transactions need the NFT thread');
  const parts = plan.parts;
  if (parts.length !== nc) throw new Error('plan: one constraint range per CODE input');
  const stmt = {mode: 'pool', root: pis.slice(0, 4), ctx: 'witness'};
  const g = makeGenN(vk, stmt, {...opts, keepG: true});
  const {D, h, Q, F, fns, defFn, mark, tblFn} = g;
  const I = vk.inst[0], e8 = 8 * D, NR = vk.logArities.length;
  const zeta = names('ze', D), alpha = names('al', D);
  const FIN_IN = nc + 1, QRY0 = nc + 2;

  // ---------------- item layouts ----------------
  const hItems = [...vk.ptItems.filter(([k]) => k !== 'FIN'), ['NF', 32], ['CTXW', 32]];
  const fItems = [['FIN', vk.L * e8], ['TBL', vk.tblB]];
  const hNames = hItems.map(([k]) => k);
  const tRegion = [...vk.ptItems.map(([k]) => k), 'NF', 'CTXW'];
  const cleanup = (S) => { if (!S.st.length) S.push(0, 'z'); S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length); S.push(1); };
  const dropAllBut = (S, keep) => { for (const x of [...S.st]) if (!keep.some((k) => (k instanceof RegExp ? k.test(x) : k === x))) S.drop(x); };
  // a shared function over a region (names on top of the stack, moved into canonical order first)
  const shared = (S, key, region, body) => {
    for (const x of region) S.roll(x);
    if (!g[key]) { const s = new Stk(region); body(s); g[key] = {id: defFn(key, s.bytes()), outs: [...s.st]}; }
    S.raw([g[key].id, 'INVOKE'], region.length, g[key].outs);
  };
  // parse another input's unlocking bytecode: checked push headers, nothing after the last item
  const parser = (key, index, items) => {
    if (F[key]) return F[key];
    const s = new Stk([]);
    s.raw([index, 'INPUTBYTECODE'], 0, ['U']);
    for (const [x, len] of items) { const pf = pushPrefix(len); s.raw([pf.length, 'SPLIT', 'SWAP', Uint8Array.from(pf), 'EQUALVERIFY', len, 'SPLIT'], 1, [x, 'U']); }
    s.raw([new Uint8Array(0), 'EQUALVERIFY'], 1);
    return (F[key] = defFn(key, s.bytes()));
  };
  const parseHead = (S) => S.raw([parser('PARSE_H', 0, hItems), 'INVOKE'], 0, hNames);
  const parseFin = (S) => S.raw([parser('PARSE_F', FIN_IN, fItems), 'INVOKE'], 0, ['FIN', 'TBL']);
  // transcript: NF lanes (< p), CTX lanes (< 2^56), then the S5 transcript (keeps ROOTS OOD FROOTS FIN; G kept)
  const trn = (S) => shared(S, 'TRN', tRegion, (s) => {
    s.pick('NF'); s.raw(['BEGIN', 8, 'SPLIT', 'SWAP', B0, 'CAT', 'BIN2NUM', 'DUP', P, 'LESSTHAN', 'VERIFY', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'], 1, names('nf', 4));
    s.roll('CTXW'); s.raw(['SIZE', 32, 'NUMEQUALVERIFY', ...[0, 1, 2, 3].map((k) => ['DUP', 8 * k + 7, 'SPLIT', 'NIP', 1, 'SPLIT', 'DROP', B0, 'EQUALVERIFY']).flat()], 1, ['CTXB']);
    g.transcript(s);
  });
  const extractVals = (S, k, n, base) => {
    S.pick('OOD'); S.raw([...(k ? [k * e8, 'SPLIT', 'NIP'] : []), n * e8, 'SPLIT', 'DROP', F.RDV, 'INVOKE'], 1, Array.from({length: n * D}, (_, i) => `${base}${Math.floor(i / D)}_${i % D}`));
    return Array.from({length: n}, (_, j) => names(`${base}${j}_`, D));
  };
  const subBase = (b, A, c) => [b.red(add(sub(ex(A[0]), K(c)), K(P))), ...A.slice(1)];
  const nonzero = (b, A) => b.chk(chk('VERIFY', A.slice(1).reduce((acc, x) => op('BOOLOR', acc, ex(x)), ex(A[0]))));

  // ---------------- AIR, CODE side: everything the DAG reads (shared by the CODE roles) ----------------
  // region [OOD al ze nf0..3] -> [al nf.. Dd sel.. periodic.. opened values]
  const perNames = I.periodic.map((_, k) => names(`pa${k}_`, D));
  const used = new Set(I.dag.nodes.map((nd) => `${nd.op}:${nd.row ?? ''}`));
  const airPre = (S) => shared(S, 'AIRPRE', ['OOD', ...alpha, ...zeta, ...names('nf', 4)], (s) => {
    const b = new PB(D, F);
    const needZ = new Set([I.logN, ...I.periodic.map((pc) => I.logN - pc.lm)]);
    const zp = {0: zeta}; let cur = zeta;
    for (let i = 1; i <= I.logN; i++) { cur = b.sq(cur); zp[i] = cur; }
    const D1 = subBase(b, zeta, 1n);
    compileSlp(s, b.prog, {keep: [...s.st, ...[...needZ].flatMap((k) => zp[k]), ...D1]});
    const bi = new PB(D, F);
    const zN = zp[I.logN];
    const zh = subBase(bi, zN, 1n);
    const D2 = subBase(bi, zeta, inv(I.gN));
    const Dd = bi.mul(D1, D2, names('Dd', D));
    bi.mul(zh, D2, names('sf', D)); bi.mul(zh, D1, names('sl', D)); bi.mul(Dd, D2, names('st', D));
    compileSlp(s, bi.prog, {keep: [...s.st, ...Dd, ...names('sf', D), ...names('sl', D), ...names('st', D)]});
    // keep only what the periodic columns still need (zeta^(n / period)); D1 shares ze1, ze2 with zeta
    const perZ = new Set(I.periodic.map((pc) => I.logN - pc.lm));
    if (s.has(D1[0])) s.drop(D1[0]);
    for (const k of Object.keys(zp)) if (!perZ.has(+k)) for (const x of zp[k]) if (s.has(x)) s.drop(x);
    // periodic columns (genn: a loop over the period with run-time packed coefficients)
    const lms = [...new Set(I.periodic.map((c) => c.lm))];
    for (const lm of lms) {
      const cols = I.periodic.map((c, k) => [c, k]).filter(([c]) => c.lm === lm);
      const m = 1 << lm, nC = cols.length, y = zp[I.logN - lm];
      for (let k = m - 1; k >= 0; k--) s.push(Buffer.concat(cols.map(([c]) => le8b(c.coef[k]))), `ck${lm}_${k}`);
      for (let c = 0; c < D; c++) s.push(0, 'pk' + c);
      s.push(1, 'pc0'); s.push(0, 'pc1'); s.push(0, 'pc2');
      y.forEach((x, c) => s.pick(x, 'py' + c));
      const state = [...names('pk', D), ...names('pc', D), ...names('py', D)];
      const key = `PER${lm}_${nC}`;
      if (!F[key]) {
        F[key] = defFn(key, localFn(['ck', ...state], (t) => {
          t.roll('ck');
          t.raw([new Uint8Array(0), 'SWAP', ...Array.from({length: nC}, () => [8, 'SPLIT', 'SWAP', new Uint8Array(SB - 8), 'CAT', 'ROT', 'SWAP', 'CAT', 'SWAP']).flat(), 'DROP', 'BIN2NUM'], 1, ['K']);
          for (let c = 0; c < D; c++) { t.pick('pc' + c); t.pick('K'); t.raw(['MUL'], 2, ['t']); t.roll('pk' + c); t.raw(['ADD'], 2, ['pk' + c]); }
          t.drop('K');
          const bb = new PB(D, F); bb.mul(names('pc', D), names('py', D), names('pn', D)); compileSlp(t, bb.prog, {keep: names('py', D)});
          names('pn', D).forEach((x, c) => t.rename(x, 'pc' + c));
          t.arrange(state);
          return state;
        }));
      }
      s.raw([m, 'TOALTSTACK', 'BEGIN', F[key], 'INVOKE', 'FROMALTSTACK', '1SUB', 'DUP', 'TOALTSTACK', 'NOT', 'UNTIL', 'FROMALTSTACK', 'DROP'], m + state.length, state);
      for (const x of [...names('pc', D), ...names('py', D)]) s.drop(x);
      for (let c = 0; c < D; c++) {
        s.roll('pk' + c);
        s.raw([SB * nC, 'NUM2BIN', ...Array(nC - 1).fill([SB, 'SPLIT']).flat()], 1, cols.map((_, j) => `ps${j}`));
        cols.forEach(([, k], j) => { s.roll(`ps${j}`); s.raw(['BIN2NUM', P, 'MOD'], 1, [perNames[k][c]]); });
      }
    }
    for (const k of Object.keys(zp)) for (const x of zp[k]) if (s.has(x) && !alpha.includes(x)) s.drop(x);
    if (used.has('main:0')) extractVals(s, I.ov.tl, I.width, 'tl');
    if (used.has('main:1')) extractVals(s, I.ov.tn, I.width, 'tn');
    s.drop('OOD');
  });
  const leafOf = (nd) => {
    switch (nd.op) {
      case 'main': return {ext: names(`${nd.row === 0 ? 'tl' : 'tn'}${nd.col}_`, D)};
      case 'periodic': return {ext: perNames[nd.col]};
      case 'is_first_row': return {ext: names('sf', D)};
      case 'is_last_row': return {ext: names('sl', D)};
      case 'is_transition': return {ext: names('st', D)};
      case 'public': {
        const j = I.pubOff + nd.col;
        if (j < 4) return {k: stmt.root[j]};
        if (j < 8) return {base: `nf${j - 4}`};
        throw new Error('DAG reads CTX');
      }
      case 'const': return {k: BigInt(nd.v)};
      default: return null;
    }
  };

  // ---------------- roles ----------------
  const roles = new Map();   // `${kind}:${index}` -> body
  // HEAD
  const headRole = (kind) => {
    const S = new Stk([...hNames]);
    S.emit('DEPTH', hNames.length, 'NUMEQUALVERIFY');
    for (const [x, len] of hItems) { S.pick(x); S.raw(['SIZE', 'NIP', len, 'NUMEQUALVERIFY'], 1); }
    if (kind === T - 1) { S.pick('CTXW'); S.raw([{raw: ctxCode()}, 'EQUALVERIFY'], 1); }
    parseFin(S); S.drop('TBL');
    mark(S, 'entry');
    trn(S);
    mark(S, 'transcript');
    if (kind === 0) {
      // the CODE inputs' accumulators: the last push of their unlocking (0x18 ‖ 24 bytes; they pin DEPTH 2 and its size)
      for (let j = 1; j <= nc; j++) S.raw([j, 'INPUTBYTECODE', 'SIZE', 25, 'SUB', 'SPLIT', 'NIP', 1, 'SPLIT', 'SWAP', Uint8Array.of(0x18), 'EQUALVERIFY', F.RDV, 'INVOKE'], 0, names(`ac${j}_`, D));
      const b = new PB(D, F);
      const zp = {0: zeta}; let cur = zeta;
      for (let i = 1; i <= I.logN; i++) { cur = b.sq(cur); zp[i] = cur; }
      const zN = zp[I.logN];
      const zh = subBase(b, zN, 1n);
      nonzero(b, zh);
      nonzero(b, [b.red(add(ex(zN[0]), K(1))), ...zN.slice(1)]);
      const D1 = subBase(b, zeta, 1n), D2 = subBase(b, zeta, inv(I.gN));
      const Dd = b.mul(D1, D2);
      const chunks = I.ov.ch.map((v0, k) => extractVals(S, v0, D, `qc${k}_`));
      const Zj = Array.from({length: I.C}, (_, j) => { const m = b.mulF(zN, K(I.kc[j])); return [b.red(add(sub(ex(m[0]), K(1)), K(P))), ...m.slice(1)]; });
      const pre = [null]; for (let k = 1; k < I.C; k++) pre.push(pre[k - 1] ? b.mul(pre[k - 1], Zj[k - 1]) : Zj[k - 1]);
      const suf = []; suf[I.C - 1] = null; for (let k = I.C - 2; k >= 0; k--) suf[k] = suf[k + 1] ? b.mul(Zj[k + 1], suf[k + 1]) : Zj[k + 1];
      let q = null;
      for (let k = 0; k < I.C; k++) {
        const zpk = pre[k] && suf[k] ? b.mul(pre[k], suf[k]) : (pre[k] ?? suf[k]);
        let ch = null;
        for (let c = 0; c < D; c++) { let t = chunks[k][c].map((x) => V(x)); for (let j = 0; j < c; j++) t = mulU(D, t); ch = ch ? ch.map((x, j) => add(x, t[j])) : t; }
        const chN = ch.map((x) => b.red(x));
        const term = zpk ? b.mulF(b.mul(zpk, chN), K(I.zpConst[k])) : (I.zpConst[k] === 1n ? chN : b.mulF(chN, K(I.zpConst[k])));
        q = q ? b.add(q, term) : term;
      }
      let rhs = b.mul(q, zh);
      for (let k = 0; k < I.maxScale; k++) rhs = b.mul(rhs, Dd);
      // lhs = sum_j ACC_j alpha^(C - hi_j)
      const apow = (e) => { let acc = null, base = alpha; while (e > 0) { if (e & 1) acc = acc ? b.mul(acc, base) : base; e >>= 1; if (e) base = b.sq(base); } return acc; };
      let lhs = null;
      parts.forEach(([, hi], j) => { const e = vk.C - hi; const t = e ? b.mul(names(`ac${j + 1}_`, D), apow(e)) : names(`ac${j + 1}_`, D); lhs = lhs ? b.add(lhs, t) : t; });
      lhs.forEach((x, c) => b.chk(chk('NUMEQUALVERIFY', V(x), V(rhs[c]))));
      compileSlp(S, b.prog, {keep: S.st.filter((x) => !/^(ac\d|qc\d)/.test(x))});
      mark(S, 'air');
    }
    if (thread) {
      const CAT = thread.category;
      const commit = (k) => { S.pick('G'); S.raw([TTAG, 'SWAP', 'CAT', Uint8Array.of(k), 'CAT', 'SHA256', Uint8Array.of(k), 'SWAP', 'CAT'], 1, ['TD']); };
      if (kind === 0) {
        S.raw([0, 'UTXOTOKENCATEGORY', Buffer.concat([CAT, Uint8Array.of(2)]), 'EQUALVERIFY'], 0);
        S.raw([0, 'OUTPUTTOKENCATEGORY', Buffer.concat([CAT, Uint8Array.of(2)]), 'EQUALVERIFY', 0, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY'], 0);
        for (let k = 1; k < T; k++) {
          S.raw([k, 'OUTPUTTOKENCATEGORY', CAT, 'EQUALVERIFY', k, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY'], 0);
          commit(k); S.raw([k, 'OUTPUTTOKENCOMMITMENT', 'EQUALVERIFY'], 1);
        }
        S.raw(['TXOUTPUTCOUNT', T, 'GREATERTHAN', 'IF', 'TXOUTPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', T, 'LESSTHAN', 'UNTIL', 'DROP', 'ENDIF'], 0);
      } else {
        S.raw([0, 'UTXOTOKENCATEGORY', CAT, 'EQUALVERIFY'], 0);
        commit(kind); S.raw([0, 'UTXOTOKENCOMMITMENT', 'EQUALVERIFY'], 1);
        S.raw(['TXINPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'UTXOTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
        S.raw(['TXOUTPUTCOUNT', 'BEGIN', '1SUB', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
      }
      mark(S, 'thread');
    }
    cleanup(S);
    return S.bytes();
  };
  // CODE (kind 0): constraint range j
  const codeRole = (j) => {
    const S = new Stk(['BLOB', 'ACC']);
    S.emit('DEPTH', 2, 'NUMEQUALVERIFY');
    S.pick('ACC'); S.raw(['SIZE', 'NIP', 24, 'NUMEQUALVERIFY'], 1);
    parseHead(S); parseFin(S); S.drop('TBL');
    mark(S, 'entry');
    trn(S);
    mark(S, 'transcript');
    dropAllBut(S, ['BLOB', 'ACC', 'OOD', ...alpha, ...zeta, /^nf\d$/]);
    airPre(S);
    mark(S, 'air-pre');
    const res = g.dagProgram(S, I, leafOf, {alpha, Dd: names('Dd', D)}, {part: parts[j - 1]});
    mark(S, 'air-dag');
    S.raw([F.ENC, 'INVOKE'], D, ['ae']);
    S.roll('ACC'); S.raw(['EQUALVERIFY'], 2);
    void res;
    cleanup(S);
    return S.bytes();
  };
  // FIN: the published constants
  const finRole = () => {
    const S = new Stk(['FIN', 'TBL']);
    S.emit('DEPTH', 2, 'NUMEQUALVERIFY');
    for (const [x, len] of fItems) { S.pick(x); S.raw(['SIZE', 'NIP', len, 'NUMEQUALVERIFY'], 1); }
    parseHead(S);
    mark(S, 'entry');
    trn(S);
    mark(S, 'transcript');
    dropAllBut(S, ['TBL', 'OOD', ...zeta, ...names('ap', D), /^be\d+_\d$/, /^idx\d+$/]);
    // DEEP point constants (genn consts, first block)
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
    // A sums per height and point: A_p = sum over the height's claims at point p of alpha'^(ladder) v (genn AZ loop
    // without the row-key parts)
    for (const hh of vk.heights) {
      const m = vk.hp[hh].length;
      const cl = vk.claims.filter((c) => c.logH === hh);
      const ranges = []; for (const c of cl) { const l = ranges[ranges.length - 1]; if (l && l.v0 + l.n === c.v0) l.n += c.width; else ranges.push({v0: c.v0, n: c.width}); }
      ranges.forEach((rg, i) => {
        S.pick('OOD'); S.raw([...(rg.v0 ? [rg.v0 * e8, 'SPLIT', 'NIP'] : []), ...(rg.v0 + rg.n < vk.numVals ? [rg.n * e8, 'SPLIT', 'DROP'] : [])], 1, [i ? 'hz2' : 'hz']);
        if (i) S.raw(['CAT'], 2, ['hz']);
      });
      const st = [...Array.from({length: m}, (_, p) => names(`A${p}_`, D)).flat(), ...names('zq', D), ...names('za', D), 'hz'];
      S.roll('hz');
      for (let k = 0; k < m * D; k++) S.push(0, st[k]);
      S.push(1, 'zq0'); S.push(0, 'zq1'); S.push(0, 'zq2');
      names('ap', D).forEach((x, i) => S.pick(x, 'za' + i));
      S.roll('hz');
      const segs = []; cl.forEach((c) => { const l = segs[segs.length - 1]; if (l && l.ptl === c.ptl) l.n += c.width; else segs.push({ptl: c.ptl, n: c.width}); });
      for (const sg of segs) {
        const key = `AS${m}_${sg.ptl}`;
        if (!F[key]) {
          F[key] = defFn(key, localFn([...st, 'n'], (s) => {
            s.roll('hz'); s.raw([e8, 'SPLIT', 'SWAP', F.RDV, 'INVOKE'], 1, ['hz', ...names('vv', D)]);
            const bb = new PB(D, F);
            const t = bb.mul(names('zq', D), names('vv', D));
            t.forEach((x, c) => bb.let(add(V(`A${sg.ptl}_${c}`), V(x)), `A${sg.ptl}_${c}`));
            bb.mul(names('zq', D), names('za', D), names('zn', D));
            compileSlp(s, bb.prog, {keep: names('za', D)});
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
      for (let p = 0; p < m; p++) names(`A${p}_`, D).forEach((x, c) => S.rename(x, `nA${hh}_${p}_${c}`));
    }
    mark(S, 'a-sums');
    // serialize in TBL order and compare with the own TBL push
    S.push(new Uint8Array(0), 'tb');
    for (const [nm, n, w] of vk.tblLayout) {
      for (let i = 0; i < n; i++) {
        S.roll(n === 1 && !/_$/.test(nm) && nm !== 'idx' ? nm : `${nm}${i}`);
        S.raw(w === 8 ? [P, 'MOD', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP'] : [w, 'NUM2BIN'], 1, ['v']);
        S.raw(['CAT'], 2, ['tb']);
      }
    }
    S.roll('TBL'); S.raw(['EQUALVERIFY'], 2);
    mark(S, 'tbl');
    cleanup(S);
    return S.bytes();
  };
  // QRY: queries [lo, hi) (the role stub pushes lo hi)
  const tblNames = vk.tblLayout.flatMap(([nm, n]) => (n === 1 && !/_$/.test(nm) && nm !== 'idx' ? [nm] : names(nm, n)));
  const qryRole = () => {
    const S = new Stk(['lo', 'hi']);
    S.pick('hi'); S.pick('lo'); S.raw(['SUB', 2, 'MUL', 3, 'ADD', 'DEPTH', 'NUMEQUALVERIFY'], 2);
    parseHead(S); parseFin(S);
    dropAllBut(S, ['lo', 'hi', 'ROOTS', 'FROOTS', 'FIN', 'TBL']);
    // TBL -> numbers: Q indices (idxB bytes), then u64 values
    S.roll('TBL'); S.raw([Q * vk.idxB, 'SPLIT', 'SWAP', 'BEGIN', vk.idxB, 'SPLIT', 'SWAP', 'BIN2NUM', 'SWAP', 'SIZE', 'NOT', 'UNTIL', 'DROP'], 1, ['TB8', ...names('idx', Q)]);
    S.roll('TB8'); S.raw([F.RDV, 'INVOKE'], 1, tblNames.slice(Q));
    mark(S, 'entry');
    // alpha' ladder and the packed row keys (genn AZ loop: the row-key parts only)
    const Kname = new Map(); let kseq = 0;
    for (const hh of vk.heights) {
      const cl = vk.claims.filter((c) => c.logH === hh);
      const st = [...names('zq', D), ...names('za', D)];
      S.push(1, 'zq0'); S.push(0, 'zq1'); S.push(0, 'zq2');
      names('ap', D).forEach((x, i) => S.pick(x, 'za' + i));
      const segs = []; cl.forEach((c) => { const l = segs[segs.length - 1]; if (l && l.ptl === c.ptl) l.n += c.width; else segs.push({ptl: c.ptl, n: c.width}); });
      for (const sg of segs) {
        const key = `KR_${sg.ptl}`;
        if (!F[key]) {
          F[key] = defFn(key, localFn([...st, 'n'], (s) => {
            const bb = new PB(D, F);
            bb.let(sum(...names('zq', D).map((x, c) => { const sh = 8 * SB * (D * sg.ptl + c); return sh ? op('LSHIFTNUM', V(x), K(sh)) : V(x); })), 'kk');
            compileSlp(s, bb.prog, {keep: names('zq', D)});
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
      for (const x of st) S.drop(x);
      for (const c of cl) for (let j = 0; j < c.width; j++) Kname.set(`${c.ri}:${c.mi}:${c.p}:${j}`, 'K' + kseq++);
    }
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
    for (const x of names('ap', D)) S.drop(x);
    mark(S, 'row-keys');
    // fold columns, tables, final polynomial (genn consts / unpack)
    {
      const b = new PB(D, F);
      for (let r = 0; r < NR; r++) {
        let be = names(`be${r}_`, D);
        for (let l = 0; l < vk.logArities[r]; l++) { if (l) be = b.sq(be); b.call(F.COLSK, be, D, names(`fc${r}_${l}_`, D)); }
        if (vk.rollIn[r] !== null) b.sq(be, names(`bpa${r}_`, D));
      }
      compileSlp(S, b.prog, {keep: []});
    }
    const la0 = vk.logArities[0], hf0 = vk.logH - la0, nT = Math.ceil(hf0 / 4);
    for (let k = 0; k < nT; k++) { const Gk = g2(vk.logH - (hf0 - 4 - 4 * k)); S.push(Gk, 'G'); S.raw([tblFn(4), 'INVOKE'], 1, names(`T${k}_`, 16)); }
    for (const la of [...new Set(vk.logArities)]) { S.push(g2(la), 'G'); S.raw([tblFn(la), 'INVOKE'], 1, names(`W${la}_`, 1 << la)); }
    g.unpack(S);
    mark(S, 'consts');
    // the query loop: q from lo to hi - 1
    S.roll('hi'); S.roll('lo'); S.rename('lo', 'q');
    const QA = S.clone();
    { QA.pick('q'); const d = QA.depth('idx' + (Q - 1)) - 1 + Q - 1; QA.raw([d, 'SWAP', 'SUB', 'PICK'], 1, ['idx']); }
    QA.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', vk.blob.total, 'NUMEQUALVERIFY'], 0, ['L']);
    g.emitQuery(QA);
    QA.raw(['FROMALTSTACK'], 0, ['kb']);
    QA.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', vk.pathB, 'NUMEQUALVERIFY'], 0, ['PTH']);
    vk.trees.forEach((tr, ti) => {
      QA.pick('kb'); QA.raw([4, 'SPLIT', ...(ti ? [ti * h, 'SPLIT', 'NIP'] : []), h, 'SPLIT', 'DROP', 'SWAP', 'BIN2NUM', ...(tr.shift ? [tr.shift, 'RSHIFTNUM'] : []), 1 << tr.depth, 'ADD', 'SWAP'], 1, ['k', 'cur']);
      QA.roll('PTH');
      let d = tr.depth - tr.capH; const runs = [];
      for (const [len, id] of [[16, OPS.F16], [8, OPS.F8], [4, OPS.F4], [2, OPS.F2], [1, OPS.F1]]) while (d >= len) { runs.push(id); d -= len; }
      QA.raw(runs.flatMap((id) => [id, 'INVOKE', 'DROP']), 3, ['k', 'cur', 'PTH']);
      const [src, off] = tr.kind === 'fri' ? ['FROOTS', vk.friOff[tr.r]] : ['ROOTS', vk.capOff[tr.name]];
      QA.roll('cur'); QA.pick(src, 'cp'); QA.roll('k');
      QA.raw([1 << tr.capH, 'SUB', h, 'MUL', ...(off ? [off, 'ADD'] : []), 'SPLIT', 'NIP', h, 'SPLIT', 'DROP', 'EQUALVERIFY'], 3);
    });
    QA.roll('PTH'); QA.raw([new Uint8Array(0), 'EQUALVERIFY'], 1);
    QA.drop('kb');
    if (QA.st.length !== S.st.length || !QA.st.every((x) => S.st.includes(x))) throw new Error('QRY query function changes the shape: ' + QA.st.filter((x) => !S.st.includes(x)) + ' / ' + S.st.filter((x) => !QA.st.includes(x)));
    QA.arrange(S.st);
    const idQ = defFn('QA', QA.bytes());
    S.raw(['BEGIN', idQ, 'INVOKE', '1ADD', '2DUP', 'NUMEQUAL', 'UNTIL'], 0);
    mark(S, 'queries');
    cleanup(S);
    return S.bytes();
  };
  // fresh path runs (genn merkleFns: F1 .. F16 only)
  {
    const freshLevel = ['FROMALTSTACK', 'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'SWAP', 'TOALTSTACK', 'SWAP', 'ROLL', 'CAT', 'SHA256'];
    const freshRun = (n) => asm('TOALTSTACK', 'SWAP', 'TOALTSTACK', Array.from({length: n}, () => freshLevel), 'FROMALTSTACK', 'FROMALTSTACK', 'ROT', 'SWAP', 0);
    defFn('F1', freshRun(1), OPS.F1); defFn('F2', freshRun(2), OPS.F2); defFn('F4', freshRun(4), OPS.F4);
    defFn('F8', asm(OPS.F4, 'INVOKE', 'DROP', OPS.F4, 'INVOKE'), OPS.F8);
    defFn('F16', asm(OPS.F8, 'INVOKE', 'DROP', OPS.F8, 'INVOKE'), OPS.F16);
  }
  const roleFn = (kind, index, body) => { fns.set(`ROLE${kind}_${index}`, {id: ROLE_BASE + 100 * kind + index, body: Uint8Array.from(body)}); };
  const idFIN = defFn('FINR', finRole());
  const idQRY = defFn('QROLE', qryRole());
  const codeRoles = parts.map((_, j) => defFn('CODE' + (j + 1), codeRole(j + 1)));
  plan.txs.forEach((tx, kind) => {
    roleFn(kind, 0, headRole(kind));
    for (let i = 1; i <= nc; i++) roleFn(kind, i, kind === 0 ? asm(codeRoles[i - 1], 'INVOKE') : asm('DEPTH', 1, 'NUMEQUALVERIFY', 'DROP', 1));
    roleFn(kind, FIN_IN, asm(idFIN, 'INVOKE'));
    tx.qry.forEach(([lo, hi], j) => roleFn(kind, QRY0 + j, asm(lo, hi, idQRY, 'INVOKE')));
  });
  // ---------------- code blobs and R ----------------
  const kindCode = T === 1 ? asm(0) : asm(0, 'UTXOTOKENCATEGORY', 'SIZE', 'NIP', 33, 'NUMEQUAL', 'IF', 0, 'ELSE', 0, 'UTXOTOKENCOMMITMENT', 1, 'SPLIT', 'DROP', 'BIN2NUM', 'ENDIF');
  const inCount = plan.txs.map((tx) => QRY0 + tx.qry.length);
  const dispatch = asm({raw: kindCode},
    ...(T === 1 ? [inCount[0]] : [...[...inCount].reverse(), T, 'PICK', 'PICK', 'TOALTSTACK', ...Array(T).fill('DROP'), 'FROMALTSTACK']),
    'TXINPUTCOUNT', 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOBYTECODE', 'TXINPUTCOUNT', '1SUB',
    'BEGIN', 'DUP', 'UTXOBYTECODE', 2, 'PICK', 'EQUALVERIFY', '1SUB', 'DUP', 0, 'LESSTHAN', 'UNTIL', '2DROP',
    100, 'MUL', 'INPUTINDEX', 'ADD', ROLE_BASE, 'ADD', 'INVOKE');
  const defs = [...fns.entries()].map(([name, f]) => ({name, bytes: asm(f.body, f.id, 'DEFINE')}));
  const LIM = 10_000 - 3 - 25;   // a CODE input's unlocking: the blob push and (kind 0) its 25-byte ACC push
  const total = defs.reduce((a, d) => a + d.bytes.length, 0) + dispatch.length;
  const target = Math.min(LIM, Math.ceil(total / nc) + (opts.blobSlack ?? 200));
  const blobs = Array.from({length: nc}, () => []);
  let bi = 0, usedB = 0;
  // largest first into the emptiest blob (first fit by size), dispatch in the last blob
  const order = [...defs].sort((x, y) => y.bytes.length - x.bytes.length);
  const sizes = Array(nc).fill(0); sizes[nc - 1] = dispatch.length;
  for (const d of order) {
    let best = -1; for (let i = 0; i < nc; i++) if (sizes[i] + d.bytes.length <= (i === nc - 1 ? LIM : target) && (best < 0 || sizes[i] < sizes[best])) best = i;
    if (best < 0) for (let i = 0; i < nc; i++) if (sizes[i] + d.bytes.length <= LIM && (best < 0 || sizes[i] < sizes[best])) best = i;
    if (best < 0) throw new Error(`code does not fit ${nc} blob(s) of ${LIM} B (total ${total} B)`);
    blobs[best].push(d); sizes[best] += d.bytes.length;
  }
  void bi; void usedB;
  const code = blobs.map((b, i) => Uint8Array.from([...b.flatMap((x) => [...x.bytes]), ...(i === nc - 1 ? dispatch : [])]));
  const redeem = asm(
    code.map((c, i) => { const hd = pushPrefix(c.length); return [i + 1, 'INPUTBYTECODE', hd.length, 'SPLIT', 'SWAP', Uint8Array.from(hd), 'EQUALVERIFY', c.length, 'SPLIT', 'DROP', 'DUP', 'SHA256', sha(c), 'EQUALVERIFY', ID_CODE + i + 1, 'DEFINE']; }),
    code.map((_, i) => [ID_CODE + i + 1, 'INVOKE']));
  if (redeem.length > 201) throw new Error(`R is ${redeem.length} B > 201 (P2S)`);
  const defineBytes = code.reduce((a, c) => a + c.length, 0) + [...fns.values()].reduce((a, f) => a + f.body.length, 0);
  return {code, redeem, fns, g, nc, parts, hItems, fItems, inCount, FIN_IN, QRY0, codeTotal: total, defineBytes,
    fnSizes: [...fns.entries()].map(([n, f]) => [n, f.body.length]).sort((a, b) => b[1] - a[1])};
}
const le8b = (x) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(x)); return b; };
