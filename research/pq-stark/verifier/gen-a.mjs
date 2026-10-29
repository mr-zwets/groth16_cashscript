// Layout (a): today's standard rules (<= 10,000 B unlocking per input, <= 10,000 B stack items, 100,000 B per
// transaction, budget (41 + unlocking) * 800 per input). Pattern of the Track 4 layout (a)
// (research/pq-hash/verifier/gen-a.mjs): one shared P2SH32 redeem R in every input; R reads the code blobs from
// inputs 1..nc, checks their hashes, defines and invokes them. The code defines every function, pins the input graph
// (input count and every input's locking bytecode equal to its own) and dispatches on the transaction kind and the
// input index to a role:
//   HEAD (input 0)       the transcript part PT of the proof (own pushes): transcript, PoW checks, AIR identity at
//                        zeta [, NFT thread rules]
//   CODE (1 .. nc)       one code blob each (own push)
//   QRY  (nc+1 ..)       queries [lo, hi): reads PT from HEAD (push headers checked), re-derives the transcript (no
//                        value is handed over), the DEEP/fold constants and the final polynomial; then per query its
//                        blob L_q and full Merkle paths PTH_q (own pushes): DEEP, folds, final polynomial, path climbs.
// Every role pins its own layout (DEPTH, item sizes, zero pads). Plans of T > 1 transactions are linked by an NFT
// thread: tx0 holds the minting baton in input 0 and mints one immutable NFT per later transaction k with commitment
// k ‖ SHA256("pq-stark/thread" ‖ G ‖ k) (G: the final transcript digest); tx k spends it in input 0 and burns it.
import {asm, Stk} from './lib/asm.mjs';
import {encodeDataPush} from '@bitauth/libauth';
import {makeGen} from './gen.mjs';
import {sha, OPS} from './model.mjs';

export const ROLE_BASE = 1000;          // role function id = ROLE_BASE + 100 * kind + input index
export const ID_CODE = 990;             // code blob i is defined as ID_CODE + i
export const TTAG = Buffer.from('pq-stark/thread');
const hdrOf = (len) => Uint8Array.from(encodeDataPush(new Uint8Array(len)).subarray(0, len < 76 ? 1 : len < 256 ? 2 : len < 65536 ? 3 : 5));
export const threadCommit = (G, k) => Buffer.concat([Buffer.from([k]), sha(TTAG, G, Uint8Array.of(k))]);

// plan: {txs: [{qry: [[lo, hi], ...]}], thread?: {category}}
export function buildA(vk, pis, plan, opts = {}) {
  const g = makeGen(vk, pis, opts);
  const {D, h, Q, F, fns, defFn, trunc} = g;
  g.merkleFns();
  const NR = vk.logArities.length, e8 = 8 * D;
  const ptOrder = ['FIN', 'ROOTS', 'OOD', ...(vk.bpow ? ['BPOW'] : []), 'FROOTS', ...(vk.cpow ? ['CPOW'] : []), ...(vk.qpow ? ['QPOW'] : [])];
  const ptLen = {ROOTS: 1 + vk.nRoots * h, OOD: vk.oodVals * e8, BPOW: 8, FROOTS: NR * h, CPOW: 8 * NR, FIN: vk.L * e8, QPOW: 8};
  const pathBytes = vk.trees.reduce((t, tr) => t + tr.depth * h, 0);
  const T = plan.txs.length, thread = plan.thread;
  const nc = opts.codeBlobs ?? 1;
  const cleanup = (S) => { S.raw(['BEGIN', 'DROP', 'DEPTH', 'NOT', 'UNTIL'], S.st.length); S.push(1); };
  const rootSrc = vk.trees.map((tr) => (tr.kind === 'fri' ? ['FROOTS', tr.r * h] : ['ROOTS', (vk.zk ? [2, 0, 1][tr.b] : tr.b) * h]));
  const headerCheck = (S) => { S.roll('ROOTS'); S.raw([1, 'SPLIT', 'SWAP', Uint8Array.of(vk.degreeBits), 'EQUALVERIFY'], 1, ['ROOTS']); };

  // outline a phase into a defined function: compiled on [__B, ...region] (the region = the names on top it may
  // touch); the caller's region is replaced by the function's result (items below the region are never reached)
  const outline = (S, name, region, emit) => {
    const at = S.st.length - region.length;
    if (S.st.slice(at).join('|') !== region.join('|')) throw new Error(`${name}: region is not on top`);
    const sub = new Stk(['__B', ...region]);
    emit(sub);
    if (sub.st[0] !== '__B' || sub.st.filter((x) => x === '__B').length !== 1) throw new Error(`${name} reaches below its region`);
    const id = F[name] ?? (F[name] = defFn(name, sub.bytes()));
    S.raw([id, 'INVOKE'], region.length, sub.st.slice(1));
  };
  const trn = (S) => outline(S, 'TRN', [...ptOrder], (X) => { headerCheck(X); g.transcript(X, {pow: true, keepG: !!thread}); });

  // ---- HEAD: own pushes PT (+ a zero pad) ----
  const headFor = (kind) => {
    const S = new Stk([...ptOrder, 'PAD']);
    S.emit('DEPTH', ptOrder.length + 1, 'NUMEQUALVERIFY');
    S.raw(['SIZE', 0, 'SWAP', 'NUM2BIN', 'EQUALVERIFY'], 1);
    for (const x of ptOrder) { S.pick(x); S.raw(['SIZE', 'NIP', ptLen[x], 'NUMEQUALVERIFY'], 1); }
    trn(S);
    outline(S, 'AIRF', [...S.st], (X) => { g.parseOOD(X); g.air(X); });
    if (thread) {
      const CAT = thread.category;
      const commit = (k) => { S.pick('G'); S.raw([TTAG, 'SWAP', 'CAT', Uint8Array.of(k), 'CAT', 'SHA256', Uint8Array.of(k), 'SWAP', 'CAT'], 1, ['TD']); };
      if (kind === 0) {
        // input 0 spends the minting baton; output 0 returns it to the same locking; outputs 1..T-1 are immutable thread
        // NFTs (same locking) with commitments k ‖ SHA256(tag ‖ G ‖ k); no other output carries a token
        S.raw([0, 'UTXOTOKENCATEGORY', Buffer.concat([CAT, Uint8Array.of(2)]), 'EQUALVERIFY'], 0);
        S.raw([0, 'OUTPUTTOKENCATEGORY', Buffer.concat([CAT, Uint8Array.of(2)]), 'EQUALVERIFY', 0, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY'], 0);
        for (let k = 1; k < T; k++) {
          S.raw([k, 'OUTPUTTOKENCATEGORY', CAT, 'EQUALVERIFY', k, 'OUTPUTBYTECODE', 'INPUTINDEX', 'UTXOBYTECODE', 'EQUALVERIFY'], 0);
          commit(k); S.raw([k, 'OUTPUTTOKENCOMMITMENT', 'EQUALVERIFY'], 1);
        }
        S.raw(['TXOUTPUTCOUNT', T, 'GREATERTHAN', 'IF', 'TXOUTPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', T, 'LESSTHAN', 'UNTIL', 'DROP', 'ENDIF'], 0);
      } else {
        // input 0 holds the immutable thread NFT k for this G; no other input and no output carries a token
        S.raw([0, 'UTXOTOKENCATEGORY', CAT, 'EQUALVERIFY'], 0);
        commit(kind); S.raw([0, 'UTXOTOKENCOMMITMENT', 'EQUALVERIFY'], 1);
        S.raw(['TXINPUTCOUNT', '1SUB', 'BEGIN', 'DUP', 'UTXOTOKENCATEGORY', 0, 'EQUALVERIFY', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
        S.raw(['TXOUTPUTCOUNT', 'BEGIN', '1SUB', 'DUP', 'OUTPUTTOKENCATEGORY', 0, 'EQUALVERIFY', 'DUP', 'NOT', 'UNTIL', 'DROP'], 0);
      }
    }
    cleanup(S);
    return S.bytes();
  };

  // ---- QRY: own pushes [L_lo, PTH_lo, ..., L_hi-1, PTH_hi-1, PAD]; the role stub pushes lo hi ----
  const qrole = () => {
    const S = new Stk(['PAD', 'lo', 'hi']);
    S.pick('hi'); S.pick('lo'); S.raw(['SUB', 2, 'MUL', 4, 'ADD', 'DEPTH', 'NUMEQUALVERIFY'], 2);
    S.roll('PAD'); S.raw(['SIZE', 0, 'SWAP', 'NUM2BIN', 'EQUALVERIFY'], 1);
    // PT from HEAD's unlocking: push header checked before each item
    S.raw([0, 'INPUTBYTECODE'], 0, ['HU']);
    for (const x of ptOrder) { const hd = hdrOf(ptLen[x]); S.raw([hd.length, 'SPLIT', 'SWAP', hd, 'EQUALVERIFY', ptLen[x], 'SPLIT'], 1, [x, 'HU']); }
    S.drop('HU');   // the rest is HEAD's pad and R (HEAD pins its own layout)
    trn(S);
    if (thread) S.drop('G');
    outline(S, 'CNS', S.st.slice(S.st.indexOf('hi') + 1), (X) => { g.parseOOD(X); for (let k = 0; k < D; k++) X.drop('al' + k); g.consts(X); g.unpack(X); });
    S.roll('hi'); S.roll('lo'); S.rename('lo', 'q');
    const QA = S.clone();
    { QA.pick('q'); const d = QA.depth('idx' + (Q - 1)) - 1 + Q - 1; QA.raw([d, 'SWAP', 'SUB', 'PICK'], 1, ['idx']); }
    QA.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', vk.qBytes, 'NUMEQUALVERIFY'], 0, ['L']);
    QA.raw(['DEPTH', '1SUB', 'ROLL', 'SIZE', pathBytes, 'NUMEQUALVERIFY'], 0, ['PTH']);
    g.emitQuery(QA, {toAlt: false});
    // full paths: per tree, k = 2^depth + (idx >> shift), cur = the leaf digest from kb, then depth fresh levels
    vk.trees.forEach((tr, ti) => {
      QA.pick('kb'); QA.raw([4, 'SPLIT', 4 + ti * h - 4, 'SPLIT', 'NIP', h, 'SPLIT', 'DROP', 'SWAP', 'BIN2NUM', ...(tr.shift ? [tr.shift, 'RSHIFTNUM'] : []), 1 << tr.depth, 'ADD', 'SWAP'], 1, ['k', 'cur']);
      QA.roll('PTH');
      let d = tr.depth; const runs = [];
      for (const [len, id] of [[16, OPS.F16], [8, OPS.F8], [4, OPS.F4], [2, OPS.F2], [1, OPS.F1]]) while (d >= len) { runs.push(id); d -= len; }
      QA.raw(runs.flatMap((id) => [id, 'INVOKE', 'DROP']), 3, ['k', 'cur', 'PTH']);
      const [src, off] = rootSrc[ti];
      QA.roll('cur'); QA.pick(src, 'rt'); QA.raw([...(off ? [off, 'SPLIT', 'NIP'] : []), h, 'SPLIT', 'DROP', 'EQUALVERIFY'], 2);
      QA.roll('k'); QA.raw([1, 'NUMEQUALVERIFY'], 1);
    });
    QA.roll('PTH'); QA.raw([0, 'EQUALVERIFY'], 1);
    QA.drop('kb');
    if (QA.st.length !== S.st.length || !QA.st.every((x) => S.st.includes(x))) throw new Error('QRY query function changes the shape: ' + QA.st.filter((x) => !S.st.includes(x)));
    QA.arrange(S.st);
    const idQ = defFn('QA', QA.bytes());
    S.raw(['BEGIN', idQ, 'INVOKE', '1ADD', '2DUP', 'NUMEQUAL', 'UNTIL'], 0);
    cleanup(S);
    return S.bytes();
  };
  const idQROLE = defFn('QROLE', qrole());

  // ---- roles per transaction kind ----
  plan.txs.forEach((tx, kind) => {
    const roleFn = (index, body) => fns.set(`ROLE${kind}_${index}`, {id: ROLE_BASE + 100 * kind + index, body: Uint8Array.from(body)});
    roleFn(0, headFor(kind));
    for (let i = 1; i <= nc; i++) roleFn(i, asm('DEPTH', 1, 'NUMEQUALVERIFY', 'DROP', 1));
    tx.qry.forEach(([lo, hi], j) => roleFn(nc + 1 + j, asm(lo, hi, idQROLE, 'INVOKE')));
  });
  // ---- code blobs: function definitions packed greedily; the last blob also pins the graph and dispatches ----
  const kindCode = T === 1 ? asm(0)
    : asm(0, 'UTXOTOKENCATEGORY', 'SIZE', 'NIP', 33, 'NUMEQUAL', 'IF', 0, 'ELSE', 0, 'UTXOTOKENCOMMITMENT', 1, 'SPLIT', 'DROP', 'BIN2NUM', 'ENDIF');
  const inCount = plan.txs.map((tx) => 1 + nc + tx.qry.length);
  const dispatch = asm(
    {raw: kindCode},                                                                       // [kind]
    ...(T === 1 ? [inCount[0]] : [...[...inCount].reverse(), T, 'PICK', 'PICK', 'TOALTSTACK', ...Array(T).fill('DROP'), 'FROMALTSTACK']),
    'TXINPUTCOUNT', 'NUMEQUALVERIFY',
    'INPUTINDEX', 'UTXOBYTECODE', 'TXINPUTCOUNT', '1SUB',
    'BEGIN', 'DUP', 'UTXOBYTECODE', 2, 'PICK', 'EQUALVERIFY', '1SUB', 'DUP', 0, 'LESSTHAN', 'UNTIL', '2DROP',
    100, 'MUL', 'INPUTINDEX', 'ADD', ROLE_BASE, 'ADD', 'INVOKE');
  const defs = [...fns.values()].map((f) => asm(f.body, f.id, 'DEFINE'));
  const LIM = 10_000 - 3 - (60 * nc + 3) - 8;   // the CODE input's unlocking holds the blob push and R
  // balanced: every CODE input runs R, which hashes all blobs, so a tiny blob's input would lack the hash-iteration
  // allowance (0.5 per byte); fill each blob up to the mean size (at most LIM)
  const total = defs.reduce((a, d) => a + d.length, 0) + dispatch.length;
  const target = Math.min(LIM, Math.ceil(total / nc) + 400);
  const blobs = Array.from({length: nc}, () => []);
  let bi = 0, used = 0;
  for (const d of defs) {
    if (used + d.length > (bi === nc - 1 ? LIM - dispatch.length : target)) { bi++; used = 0; if (bi >= nc) throw new Error(`code does not fit ${nc} blob(s) of ${LIM} B`); }
    blobs[bi].push(d); used += d.length;
  }
  blobs[nc - 1].push(dispatch);
  const code = blobs.map((b) => Uint8Array.from(b.flatMap((x) => [...x])));
  if (code.some((c) => c.length > LIM || c.length === 0)) throw new Error('code does not fit: blob sizes ' + code.map((c) => c.length));
  const redeem = asm(
    code.map((c, i) => { const hd = hdrOf(c.length); return [i + 1, 'INPUTBYTECODE', hd.length, 'SPLIT', 'SWAP', hd, 'EQUALVERIFY', c.length, 'SPLIT', 'DROP', 'DUP', 'SHA256', sha(c), 'EQUALVERIFY', ID_CODE + i + 1, 'DEFINE']; }),
    code.map((_, i) => [ID_CODE + i + 1, 'INVOKE']));
  return {code, redeem, ptOrder, pathBytes, fns, g, nc};
}
