// Layout (a): today's standard rules (<= 10,000 B unlocking per input, 100,000 B per transaction, budget
// (41 + unlocking) * 800 per input). Pattern of the bn-native-sound entries (groth16_cashscript chunked/bn254/
// bn-native-sound/README.md): one shared P2SH32 redeem R in every input; R reads the code blob from input 1, checks
// its hash, defines it as MAIN and invokes it. MAIN defines every function, pins the input graph (input count and
// every input's locking bytecode equal to its own) and dispatches on the input index to a role:
//   HEAD (input 0)  public transcript PT (own pushes): transcript, grinding, AIR identity at z [, NFT thread rules]
//   CODE (input 1)  the code blob (own push)
//   QRY  (2 ..)     queries [lo, hi): reads PT from HEAD (push headers checked), re-derives the transcript (no value is
//                   handed over), the DEEP/fold constants and the final polynomial, then per query: leaf blob and full
//                   Merkle paths (own pushes), the four path climbs to the roots, DEEP, folds, final polynomial.
// Every role pins its own layout (DEPTH, item sizes). P128 spans two transactions linked by an NFT thread (thread.mjs
// options): tx0 holds the minting baton in input 0, tx1 an immutable NFT whose commitment binds G.
import {asm, Stk} from './lib/asm.mjs';
import {encodeDataPush} from '@bitauth/libauth';
import {makeCtx, defineShared, emitTranscript, emitAirConsts, emitLiftTables, emitUnpack, emitQuery} from './gen.mjs';
import {sha, cat} from './field.mjs';
import {OPS} from './model.mjs';

const B0 = Uint8Array.of(0);
export const ROLE_BASE = 1000;          // role function id = ROLE_BASE + 100 * txKind + input index
export const ID_MAIN = 999;
const hdrOf = (len) => Uint8Array.from(encodeDataPush(new Uint8Array(len)).subarray(0, len < 76 ? 1 : len < 256 ? 2 : len < 65536 ? 3 : 5));

// plan: {txs: [{qry: [[lo, hi], ...]}], thread?: {category}}
export function buildA(prm, statement, plan, opts = {}) {
  const c = makeCtx(prm, opts);
  defineShared(c);
  const {e, h, r, D, trees, e8, defFn, F, fns} = c;
  const rF = Array.from({length: r - 1}, (_, i) => 'rF' + (i + 1));
  const ptOrder = ['FIN', 'rT', 'rC', 'OOD', ...rF, 'NONCE'];          // HEAD push order (FIN first: cheap remote splits)
  const ptLen = {FIN: e8 * D, rT: h, rC: h, OOD: 5 * e8, NONCE: 8}; for (const x of rF) ptLen[x] = h;
  const pathBytes = trees.reduce((t, tr) => t + tr.depth * h, 0);
  const roles = new Map();
  const roleFn = (kind, index, body) => { const id = ROLE_BASE + 100 * kind + index; fns.set(`ROLE${kind}_${index}`, {id, body: Uint8Array.from(body)}); roles.set(`${kind}:${index}`, id); };
  const cleanup = (S) => { S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length); S.push(1); };
  const thread = plan.thread;
  const TTAG = Buffer.from('pq-hash/thread');

  // ---- HEAD: own pushes PT (+ an empty pad slot) ----
  const headFor = (kind) => {
    const S = new Stk([...ptOrder, 'PAD']);
    S.emit('DEPTH', ptOrder.length + 1, 'NUMEQUALVERIFY');
    S.raw(['SIZE', 0, 'SWAP', 'NUM2BIN', 'EQUALVERIFY'], 1);   // the pad is all zero
    emitTranscript(c, S, statement, {grinding: true, lo: 0, hi: 0, keepG: !!thread});
    emitAirConsts(c, S, statement, {withAir: true, withConsts: false});
    if (thread) {
      // D = SHA256("pq-hash/thread" ‖ G ‖ 0x01)
      S.roll('G'); S.raw([TTAG, 'SWAP', 'CAT', Uint8Array.of(1), 'CAT', 'SHA256'], 1, ['TD']);
      const CAT = thread.category;
      if (kind === 0) {
        // tx0: input 0 spends the minting baton (category ‖ 0x02); outputs: 0 = the baton back to the same locking,
        // 1 = an immutable thread NFT with commitment D at the same locking; no other output carries the category
        S.raw([0, 'UTXOTOKENCATEGORY', cat(CAT, Uint8Array.of(2)), 'EQUALVERIFY'], 0);
        S.raw([0, 'OUTPUTTOKENCATEGORY', cat(CAT, Uint8Array.of(2)), 'EQUALVERIFY', 0, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY'], 0);
        S.raw([1, 'OUTPUTTOKENCATEGORY', CAT, 'EQUALVERIFY', 1, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY', 1, 'OUTPUTTOKENCOMMITMENT'], 0, ['OC']);
        S.raw(['EQUALVERIFY'], 2);
        // outputs 2.. carry no token
        S.raw(['TXOUTPUTCOUNT', 2, 'GREATERTHAN', 'IF', 'TXOUTPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', 2, 'LESSTHAN', 'UNTIL', 'DROP', 'ENDIF'], 0);
      } else {
        // tx1: input 0 holds an immutable thread NFT whose commitment is D for this G; no other input and no output
        // carries the category (the thread token is burned)
        S.raw([0, 'UTXOTOKENCATEGORY', CAT, 'EQUALVERIFY', 0, 'UTXOTOKENCOMMITMENT'], 0, ['IC']);
        S.raw(['EQUALVERIFY'], 2);
        S.raw(['TXINPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'UTXOTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
        S.raw(['TXOUTPUTCOUNT', 'BEGIN', '1SUB', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
      }
    }
    cleanup(S);
    return S.bytes();
  };

  // ---- QRY: own pushes [L_lo, PTH_lo, ..., L_hi-1, PTH_hi-1, PAD]; the role stub pushes lo hi ----
  let idQ = null, idQROLE = null;
  const qrole = () => {
    const S = new Stk(['PAD', 'lo', 'hi']);   // the own L/PTH pairs lie below and are reached with DEPTH 1SUB ROLL only
    // own layout: DEPTH == 2 (hi - lo) + 3
    S.pick('hi'); S.pick('lo'); S.raw(['SUB', 2, 'MUL', 4, 'ADD', 'DEPTH', 'NUMEQUALVERIFY'], 2);   // + the computed value itself
    S.roll('PAD'); S.raw(['SIZE', 0, 'SWAP', 'NUM2BIN', 'EQUALVERIFY'], 1);   // the pad is all zero
    // PT from HEAD's unlocking: header bytes checked before each item, then the item
    S.raw([0, 'INPUTBYTECODE'], 0, ['HU']);
    for (const x of ptOrder) {
      const hd = hdrOf(ptLen[x]);
      S.raw([hd.length, 'SPLIT', 'SWAP', hd, 'EQUALVERIFY', ptLen[x], 'SPLIT'], 1, [x, 'HU']);
    }
    S.drop('HU');   // the remainder is HEAD's pad and R (HEAD pins its own layout)
    emitTranscript(c, S, statement, {grinding: false, lo: 0, hi: 0, keepG: true});
    emitAirConsts(c, S, statement, {withAir: false, withConsts: true});
    for (const x of ['rT', 'rC', ...rF]) S.roll(x);   // roots above everything a query reads
    emitLiftTables(c, S, null);
    emitUnpack(c, S);
    S.roll('hi'); S.roll('lo'); S.rename('lo', 'q');
    // the query function
    if (idQ === null) {
      const Q = S.clone();
      const N1 = c.sizes[1];
      Q.pick('G'); Q.pick('q'); Q.raw([2, 'NUM2BIN', 'CAT', 'SHA256', 3, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', N1, 'MOD'], 2, ['idx']);
      Q.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', prm.leafBytes + 8, 'NUMEQUALVERIFY'], 0, ['L']);
      Q.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', pathBytes, 'NUMEQUALVERIFY'], 0, ['PTH']);
      const roots = ['rT', 'rC', ...rF];
      trees.forEach((tree, ti) => {
        Q.pick('idx'); Q.raw([...(tree.layer > 0 ? [c.sizes[tree.layer + 1], 'MOD'] : []), 1 << tree.depth, 'ADD'], 1, ['k']);
        Q.pick('L'); Q.raw([...(tree.off ? [tree.off, 'SPLIT', 'NIP'] : []), tree.leaf_bytes, 'SPLIT', 'DROP', Uint8Array.of(tree.tag), 'SWAP', 'CAT', 'SHA256', ...c.trunc], 1, ['cur']);
        Q.roll('PTH');
        // climb tree.depth levels: fresh-run functions on [k cur rb] (each leaves a flag 0)
        let d = tree.depth; const runs = [];
        for (const [len, id] of [[16, OPS.F16], [8, OPS.F8], [4, OPS.F4], [2, OPS.F2], [1, OPS.F1]]) while (d >= len) { runs.push(id); d -= len; }
        Q.raw(runs.flatMap((id) => [id, 'INVOKE', 'DROP']), 3, ['k', 'cur', 'PTH']);
        Q.roll('cur'); Q.pick(roots[ti]); Q.raw(['EQUALVERIFY'], 2);
        Q.roll('k'); Q.raw([1, 'NUMEQUALVERIFY'], 1);
      });
      Q.roll('PTH'); Q.raw([0, 'EQUALVERIFY'], 1);
      emitQuery(c, Q);
      if (Q.st.length !== S.st.length || !Q.st.every((x) => S.st.includes(x))) throw new Error('QRY query function changes the shape: ' + Q.st.filter((x) => !S.st.includes(x)));
      Q.arrange(S.st);
      idQ = defFn('QA', Q.bytes());
    }
    S.raw(['BEGIN', idQ, 'INVOKE', '1ADD', '2DUP', 'NUMEQUAL', 'UNTIL'], 0);
    cleanup(S);
    return S.bytes();
  };
  idQROLE = defFn('QROLE', qrole());

  // ---- roles per transaction kind ----
  const kinds = plan.txs.length;
  plan.txs.forEach((tx, kind) => {
    roleFn(kind, 0, headFor(kind));
    roleFn(kind, 1, asm('DEPTH', 1, 'NUMEQUALVERIFY', 'DROP', 1));
    tx.qry.forEach(([lo, hi], j) => roleFn(kind, 2 + j, asm(lo, hi, idQROLE, 'INVOKE')));
  });
  // ---- MAIN: define everything, pin the graph, dispatch ----
  const main = [];
  for (const [, f] of fns) main.push(...asm(f.body, f.id, 'DEFINE'));
  const kindCode = kinds === 1 ? asm(0) : asm(0, 'UTXOTOKENCATEGORY', 'SIZE', 'NIP', 33, 'NUMEQUAL', 'NOT');   // 0: baton (33 B), 1: thread NFT
  const inCount = plan.txs.map((tx) => 2 + tx.qry.length);
  main.push(...asm(
    {raw: kindCode},                                                               // [kind]
    'TXINPUTCOUNT', ...(kinds === 1 ? [inCount[0]] : ['OVER', 'IF', inCount[1], 'ELSE', inCount[0], 'ENDIF']), 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOBYTECODE', 'TXINPUTCOUNT', '1SUB',
    'BEGIN', 'DUP', 'UTXOBYTECODE', 2, 'PICK', 'EQUALVERIFY', '1SUB', 'DUP', 0, 'LESSTHAN', 'UNTIL', '2DROP',
    100, 'MUL', 'INPUTINDEX', 'ADD', ROLE_BASE, 'ADD', 'INVOKE'));
  const code = Uint8Array.from(main);
  if (code.length > 10_000) throw new Error('code blob over 10,000 B: ' + code.length);
  const kcode = sha(code);
  const hd = hdrOf(code.length);
  const redeem = asm(1, 'INPUTBYTECODE', hd.length, 'SPLIT', 'SWAP', hd, 'EQUALVERIFY', code.length, 'SPLIT', 'DROP', 'DUP', 'SHA256', kcode, 'EQUALVERIFY', ID_MAIN, 'DEFINE', ID_MAIN, 'INVOKE');
  return {code, redeem, ptOrder, pathBytes, fns, c};
}
