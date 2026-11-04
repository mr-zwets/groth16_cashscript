// Layout a' (Track 8 S7): plans, witnesses and transactions for gena.mjs (today's standard rules).
//   plan  {txs: [{qry: [[lo, hi], ...]}], nc, parts, thread?}: transaction t holds HEAD, nc CODE inputs, FIN and its
//         QRY inputs; T > 1 transactions are linked by the NFT thread (kind 0 mints, kind k > 0 burns)
//   CTX   is the final transaction's outputs (the statement outputs); the other transactions carry the thread
import {encodeTransaction, hash256} from '@bitauth/libauth';
import {buildA, threadCommit, stateCommit} from './gena.mjs';
import {encodeA, partsOf, sha} from './modela.mjs';
import {pushes, VMS, evaluate} from './vm.mjs';

export const CATEGORY = Buffer.from(hash256(Uint8Array.from(Buffer.from('pq-stark-batch/thread category (test genesis outpoint)'))));
const M64 = (1n << 64n) - 1n;
// a P2PKH output (test key hash) for the middle transactions of plans with T > 2
const MIDDLE_OUT = Uint8Array.from([0x76, 0xa9, 0x14, ...hash256(Uint8Array.from(Buffer.from('pq-wrap g2 middle'))).subarray(0, 20), 0x88, 0xac]);
const u64s = (xs) => Buffer.concat(xs.map((x) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(((x % (1n << 64n)) + (1n << 64n)) & M64); return b; }));

// counts: per transaction, the number of queries of each QRY input, e.g. [[3, 3, 3, 3, 3, 3, 3], [3]]
// opt: gena.mjs plan.opt (layout-review optimizations; {} or absent = baseline)
export function makePlanA(vk, counts, {nc = 2, ctx, pad, opt} = {}) {
  let q = 0;
  const txs = counts.map((cs) => ({qry: cs.map((n) => { const r = [q, q + n]; q += n; return r; })}));
  if (q !== vk.Q) throw new Error(`plan covers ${q} of ${vk.Q} queries`);
  return {txs, nc, parts: partsOf(vk, nc), ...(txs.length > 1 ? {thread: {category: CATEGORY}} : {}), ...(ctx ? {ctx} : {}), ...(pad ? {pad} : {}), ...(opt && Object.keys(opt).length ? {opt} : {})};
}
// CLI helper: '--opt sib,lad' -> {sib: true, lad: true}
export const parseOpt = (s) => Object.fromEntries((s ?? '').split(',').filter(Boolean).map((k) => { const [a, b] = k.split('='); return [a, b === undefined ? true : +b]; }));
const sibs = (b) => Array.from({length: b.length / 32}, (_, i) => b.subarray(32 * i, 32 * i + 32));
// opt.cap = c: the path of every tree without its top c siblings (they sit under LAYER)
const trimPath = (vk, pth, c) => { const out = []; let o = 0; for (const tr of vk.trees) { const n = tr.depth - tr.capH; out.push(...sibs(pth.subarray(o, o + 32 * (n - c)))); o += 32 * n; } return out; };
// opt.cap = c: LAYER = the 2^c nodes at level c of every tree, from the honest climbs of all queries (paths and their
// siblings; parents filled from known children); a node no query reaches cannot be derived from the proof
const layerCache = new WeakMap();
export function layerA(vk, enc, c) {
  if (layerCache.has(enc)) return layerCache.get(enc);
  const maps = vk.trees.map(() => new Map());
  for (let q = 0; q < vk.Q; q++) {
    if (!enc.dig[q]) continue;
    let o = 0;
    vk.trees.forEach((tr, ti) => {
      let k = (1 << tr.depth) + (enc.idx[q] >>> tr.shift), cur = enc.dig[q][ti]; const m = maps[ti];
      for (let l = 0; l < tr.depth - tr.capH; l++) { const s = enc.PTH[q].subarray(o, o + 32); o += 32; m.set(k, cur); m.set(k ^ 1, s); cur = k & 1 ? sha(s, cur) : sha(cur, s); k >>>= 1; }
    });
  }
  const out = Buffer.concat(vk.trees.map((tr, ti) => Buffer.concat(Array.from({length: 1 << c}, (_, j) => maps[ti].get((1 << c) + j) ?? Buffer.alloc(32)))));
  layerCache.set(enc, out);
  return out;
}

const cache = new Map();
export function programA(vk, pis, plan, opts = {}) {
  const key = JSON.stringify([vk.SO.batch.toString('hex'), vk.Q, vk.qpow, vk.capHeight, pis.slice(0, 4).map(String), plan.txs, plan.nc, plan.parts, plan.ctx ?? 'tx', plan.pad ?? null, plan.opt ?? null, opts]);
  if (!cache.has(key)) cache.set(key, buildA(vk, pis, plan, opts));
  return cache.get(key);
}

// opt.state: the STATE items (gena sItems order) of one proof
export function stateValsA(pg, enc, pis) {
  const v = {ROOTS: enc.PT.ROOTS, FROOTS: enc.PT.FROOTS, FIN: enc.PT.FIN, TBL: enc.TBL, LAD: enc.LAD, NF: u64s(pis.slice(4, 8)), CTXW: u64s(pis.slice(8, 12)), G: enc.G};
  return pg.sItems.map(([k]) => v[k]);
}
// opt.state: the state values as tx0's witness carries them (an item that is missing falls back to the honest value)
export function stateValsOfWit(pg, w0, enc, pis) {
  const honest = stateValsA(pg, enc, pis), names = pg.sItems.map(([k]) => k);
  const head = Object.fromEntries(pg.hItems.map(([k], i) => [k, w0[0]?.[i]]));
  const fin = Object.fromEntries(pg.fItems.map(([k], i) => [k, w0[pg.FIN_IN]?.[i]]));
  return names.map((k, i) => (k === 'G' ? honest[i] : (k === 'ROOTS' || k === 'FROOTS' || k === 'NF' || k === 'CTXW' ? head[k] : fin[k]) ?? honest[i]));
}
const capOf = (plan) => (plan.opt?.cap ? +plan.opt.cap : 0);
// witnesses: per transaction, per input, the pushed items (bottom first)
export function witnessesA(vk, plan, pg, enc, pis) {
  const nf = u64s(pis.slice(4, 8)), ctx = u64s(pis.slice(8, 12));
  const c = capOf(plan);
  const qryItems = (t, [lo, hi], j) => { const it = plan.pad ? [Buffer.alloc(plan.pad.qry[t][j])] : []; for (let q = lo; q < hi; q++) it.push(enc.L[q], ...(c ? trimPath(vk, enc.PTH[q], c) : plan.opt?.sib ? sibs(enc.PTH[q]) : [enc.PTH[q]])); return it; };
  // opt.state: transaction t >= 1 = STATE, R1's code blob(s), QRY inputs
  if (pg.R1) return plan.txs.map((tx, t) => (t === 0 ? null : [stateValsA(pg, enc, pis), ...pg.R1.code.map((b) => [b]), ...(c ? [[layerA(vk, enc, c)]] : []), ...tx.qry.map((r, j) => qryItems(t, r, j))]))
    .map((x, t) => x ?? witnessesA(vk, {...plan, txs: [plan.txs[0]]}, {...pg, R1: null}, enc, pis)[0]);
  return plan.txs.map((tx, t) => [
    pg.hItems.map(([k]) => (k === 'NF' ? nf : k === 'CTXW' ? ctx : k === 'LAYER' ? layerA(vk, enc, c) : enc.PT[k])),
    ...pg.code.map((c, j) => (t === 0 ? [c, enc.ACC[j]] : [c])),
    [...(plan.pad ? [Buffer.alloc(plan.pad.fin)] : []), enc.PT.FIN, enc.TBL, ...(plan.opt?.lad ? [enc.LAD] : [])],
    ...tx.qry.map((r, j) => qryItems(t, r, j)),
  ]);
}

// transactions: every input locked by R; values are test fixtures (the note of 1,000,000 sat sits in the final
// transaction; the fee is about 1 sat/B)
export function txsA(plan, pg, wit, G, outputs, {commitments} = {}) {
  const T = plan.txs.length, CAT = plan.thread?.category;
  // libauth's token.category is in user-facing (reversed) order; the VM pushes the internal order (= CAT)
  const tok = (capability, commitment = new Uint8Array(0)) => ({amount: 0n, category: Uint8Array.from(CAT).reverse(), nft: {capability, commitment: Uint8Array.from(commitment)}});
  return wit.map((inputs, t) => {
    const unl = inputs.map((items) => pushes(items));
    const final = t === T - 1;
    const sourceOutputs = unl.map((_, i) => {
      let value = 2_000n;
      if (final && i === (T > 1 ? 1 : 0)) value = 1_000_000n;
      // G2: tx0 also funds the T - 2 middle transactions (200,000 sat each on their NFT output)
      if (!final && i === 0) value = t === 0 ? 200_000n * BigInt(Math.max(1, T - 1)) : 200_000n;
      if (T > 1 && final && i === 0) value = 5_000n;
      const token = CAT && i === 0 ? (t === 0 ? tok('minting') : tok('none', commitments?.[t] ?? threadCommit(G, t))) : undefined;
      // opt.state: transactions t >= 1 spend R1 UTXOs
      return {lockingBytecode: t > 0 && pg.R1 ? pg.R1.redeem : pg.redeem, valueSatoshis: value, ...(token ? {token} : {})};
    });
    // G2: plans of T > 2 transactions: a middle transaction (0 < t < T - 1) burns its NFT and pays one plain output
    const outs = final ? outputs
      : t > 0 ? [{lockingBytecode: MIDDLE_OUT, valueSatoshis: 100_000n}]
      : [{lockingBytecode: pg.redeem, valueSatoshis: 5_000n, token: tok('minting')}, ...Array.from({length: T - 1}, (_, k) => ({lockingBytecode: pg.R1 ? pg.R1.redeem : pg.redeem, valueSatoshis: k + 1 < T - 1 ? 200_000n : 5_000n, token: tok('none', commitments?.[k + 1] ?? threadCommit(G, k + 1))}))];
    const transaction = {version: 2, locktime: 0, inputs: unl.map((u, i) => ({outpointTransactionHash: new Uint8Array(32).fill(0x70 + t), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: u})), outputs: outs};
    return {transaction, sourceOutputs, unl, txBytes: encodeTransaction(transaction).length};
  });
}

// one proof: encode, witnesses, transactions
export function spendA(vk, plan, proof, pis, outputs, opts = {}, mutate) {
  const pg = programA(vk, pis, plan, opts.gen ?? {});
  const enc = encodeA(vk, proof, pis, plan.parts);
  let wit = witnessesA(vk, plan, pg, enc, pis);
  if (mutate) wit = mutate(wit, enc, pg) ?? wit;
  // opt.state: tx0 mints NFT k over the honest state values (stateCommit), unless the caller gives commitments
  // the commitments tx0's HEAD would compute from tx0's own witness (HEAD's items, FIN's TBL / LAD; G is the honest
  // transcript digest): a tampered tx0 then mints over its tampered values, so HEAD's HS check passes and the input
  // that owns the value (FIN for TBL and LAD) is the one that must reject it (test-a2 owner checks)
  const o2 = pg.R1 && !opts.commitments ? {...opts, commitments: plan.txs.map((_, k) => (k ? stateCommit(stateValsOfWit(pg, wit[0], enc, pis), k) : null))} : opts;
  const txs = txsA(plan, pg, wit, opts.G ?? enc.G, outputs, o2);
  return {pg, enc, wit, txs};
}

// every input of a transaction on a VM; stopAtReject: stop at the first rejecting input
export function evaluateTxA(tx, vmName, {stopAtReject = false} = {}) {
  const out = [];
  for (let i = 0; i < tx.transaction.inputs.length; i++) {
    const u = tx.transaction.inputs[i].unlockingBytecode.length;
    const r = evaluate(vmName, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    out.push({...r, unlocking: u, budget: (41 + u) * 800});
    if (stopAtReject && !r.accepted) break;
  }
  return out;
}
export const verifyTxA = (tx, vmName) => VMS[vmName].verify({transaction: tx.transaction, sourceOutputs: tx.sourceOutputs});
