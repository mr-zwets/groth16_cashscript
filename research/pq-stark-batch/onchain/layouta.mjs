// Layout a' (Track 8 S7): plans, witnesses and transactions for gena.mjs (today's standard rules).
//   plan  {txs: [{qry: [[lo, hi], ...]}], nc, parts, thread?}: transaction t holds HEAD, nc CODE inputs, FIN and its
//         QRY inputs; T > 1 transactions are linked by the NFT thread (kind 0 mints, kind k > 0 burns)
//   CTX   is the final transaction's outputs (the statement outputs); the other transactions carry the thread
import {encodeTransaction, hash256} from '@bitauth/libauth';
import {buildA, threadCommit} from './gena.mjs';
import {encodeA, partsOf} from './modela.mjs';
import {pushes, VMS, evaluate} from './vm.mjs';

export const CATEGORY = Buffer.from(hash256(Uint8Array.from(Buffer.from('pq-stark-batch/thread category (test genesis outpoint)'))));
const M64 = (1n << 64n) - 1n;
const u64s = (xs) => Buffer.concat(xs.map((x) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(((x % (1n << 64n)) + (1n << 64n)) & M64); return b; }));

// counts: per transaction, the number of queries of each QRY input, e.g. [[3, 3, 3, 3, 3, 3, 3], [3]]
export function makePlanA(vk, counts, {nc = 2} = {}) {
  let q = 0;
  const txs = counts.map((cs) => ({qry: cs.map((n) => { const r = [q, q + n]; q += n; return r; })}));
  if (q !== vk.Q) throw new Error(`plan covers ${q} of ${vk.Q} queries`);
  return {txs, nc, parts: partsOf(vk, nc), ...(txs.length > 1 ? {thread: {category: CATEGORY}} : {})};
}

const cache = new Map();
export function programA(vk, pis, plan, opts = {}) {
  const key = JSON.stringify([vk.SO.batch.toString('hex'), vk.Q, vk.qpow, vk.capHeight, pis.slice(0, 4).map(String), plan.txs, plan.nc, plan.parts, opts]);
  if (!cache.has(key)) cache.set(key, buildA(vk, pis, plan, opts));
  return cache.get(key);
}

// witnesses: per transaction, per input, the pushed items (bottom first)
export function witnessesA(vk, plan, pg, enc, pis) {
  const nf = u64s(pis.slice(4, 8)), ctx = u64s(pis.slice(8, 12));
  return plan.txs.map((tx, t) => [
    pg.hItems.map(([k]) => (k === 'NF' ? nf : k === 'CTXW' ? ctx : enc.PT[k])),
    ...pg.code.map((c, j) => (t === 0 ? [c, enc.ACC[j]] : [c])),
    [enc.PT.FIN, enc.TBL],
    ...tx.qry.map(([lo, hi]) => { const it = []; for (let q = lo; q < hi; q++) it.push(enc.L[q], enc.PTH[q]); return it; }),
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
      if (!final && i === 0) value = 200_000n;
      if (T > 1 && final && i === 0) value = 5_000n;
      const token = CAT && i === 0 ? (t === 0 ? tok('minting') : tok('none', commitments?.[t] ?? threadCommit(G, t))) : undefined;
      return {lockingBytecode: pg.redeem, valueSatoshis: value, ...(token ? {token} : {})};
    });
    const outs = final ? outputs
      : [{lockingBytecode: pg.redeem, valueSatoshis: 5_000n, token: tok('minting')}, ...Array.from({length: T - 1}, (_, k) => ({lockingBytecode: pg.redeem, valueSatoshis: 5_000n, token: tok('none', commitments?.[k + 1] ?? threadCommit(G, k + 1))}))];
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
  const txs = txsA(plan, pg, wit, opts.G ?? enc.G, outputs, opts);
  return {pg, enc, wit, txs};
}

// every input of a transaction on a VM; stopAtReject: stop at the first rejecting input
export function evaluateTxA(tx, vmName, {stopAtReject = false} = {}) {
  const out = [];
  for (let i = 0; i < tx.unl.length; i++) {
    const r = evaluate(vmName, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    out.push({...r, unlocking: tx.unl[i].length, budget: (41 + tx.unl[i].length) * 800});
    if (stopAtReject && !r.accepted) break;
  }
  return out;
}
export const verifyTxA = (tx, vmName) => VMS[vmName].verify({transaction: tx.transaction, sourceOutputs: tx.sourceOutputs});
