// Layout (a): transactions of standard size (<= 100,000 B) whose inputs each hold <= 10,000 B of unlocking, built
// from gen-a.mjs. makePlan(): partition the queries into QRY inputs and transactions; witnessesA()/txsA(): the
// witnesses, the transaction(s) and their source outputs; evaluateTx(): every input on a given VM.
import {createTestAuthenticationProgramBch, encodeTransaction, hash256} from '@bitauth/libauth';
import {encodeA} from './model.mjs';
import {buildA, threadCommit} from './gen-a.mjs';
import {VMS, p2sh32, pushes, evaluate} from './vm.mjs';
export {loadVector} from './layout-b.mjs';

const pushLen = (n) => n + (n < 76 ? 1 : n < 256 ? 2 : 3);
const varint = (n) => (n < 253 ? 1 : n < 65536 ? 3 : 5);
// queries per QRY input (byte-bound: unlocking <= 10,000 B) and transactions (<= 100,000 B)
export function makePlan(vk, {redeemBytes = 400, codeBytes = [10_000], ptBytes = 0, pathBytes, per} = {}) {
  const qItem = pushLen(vk.qBytes) + pushLen(pathBytes);
  per ??= Math.floor((10_000 - pushLen(redeemBytes) - 1) / qItem);
  if (per < 1) throw new Error('one query does not fit a 10,000 B input');
  const inBytes = (unl) => 41 + varint(unl) + unl;
  const headIn = inBytes(ptBytes + 1 + pushLen(redeemBytes)), codeIn = codeBytes.reduce((a, c) => a + inBytes(pushLen(c) + pushLen(redeemBytes)), 0);
  const qryIn = (n) => inBytes(n * qItem + 1 + pushLen(redeemBytes));
  const fixed = 4 + 4 + 3 + 3 + 3 * 45 + headIn + codeIn;     // version, locktime, counts, outputs (token outputs ~ 45-90 B)
  // queries per transaction: as many whole QRY inputs as fit next to HEAD and CODE
  const perTxInputs = Math.floor((100_000 - fixed - 200) / qryIn(per));
  if (perTxInputs < 1) throw new Error('no QRY input fits a transaction');
  const nIn = Math.ceil(vk.Q / per), nTx = Math.ceil(nIn / perTxInputs);
  // balanced: spread the inputs over the transactions, the queries over the inputs
  const txs = []; let q0 = 0;
  const inPerTx = Array.from({length: nTx}, (_, t) => Math.floor(nIn / nTx) + (t < nIn % nTx ? 1 : 0));
  const qPerIn = Array.from({length: nIn}, (_, j) => Math.floor(vk.Q / nIn) + (j < vk.Q % nIn ? 1 : 0));
  let j = 0;
  for (let t = 0; t < nTx; t++) {
    const qry = [];
    for (let k = 0; k < inPerTx[t]; k++) { qry.push([q0, q0 + qPerIn[j]]); q0 += qPerIn[j]; j++; }
    txs.push({qry});
  }
  return {txs, per, ...(nTx > 1 ? {thread: {category: hash256(Uint8Array.from(Buffer.from('pq-stark/thread category (test genesis outpoint)')))}} : {})};
}

const cache = new Map();
export function programA(vk, pis, plan, opts = {}) {
  const key = JSON.stringify([vk.air, vk.logN, vk.Q, vk.logBlowup, vk.logArities, vk.L, vk.h, vk.zk, vk.D, vk.bpow, vk.cpow, vk.qpow, vk.rc, vk.salt, pis.map(String), opts,
    plan.txs, plan.thread ? Buffer.from(plan.thread.category).toString('hex') : null]);
  if (!cache.has(key)) { const b = buildA(vk, pis, plan, opts); cache.set(key, {...b, locking: p2sh32(b.redeem)}); }
  return cache.get(key);
}

// witnesses per tx: [HEAD items, CODE items.., QRY items..] (without R); pads per input (bytes)
export function witnessesA(vk, plan, pg, enc, pads = {}) {
  const PT = enc.PT;
  return plan.txs.map((tx, t) => {
    const head = [...pg.ptOrder.map((x) => PT[x]), Buffer.alloc(pads[`${t}:0`] ?? 0)];
    const code = pg.code.map((c) => [c]);
    const qry = tx.qry.map(([lo, hi], j) => {
      const items = [];
      for (let q = lo; q < hi; q++) items.push(enc.L[q], enc.paths[q]);
      items.push(Buffer.alloc(pads[`${t}:${1 + pg.nc + j}`] ?? 0));
      return items;
    });
    return [head, ...code, ...qry];
  });
}

export function txsA(vk, plan, pg, wit, G) {
  const lock = pg.locking, R = pg.redeem;
  const CAT = plan.thread?.category;
  const T = plan.txs.length;
  // libauth's token.category is in user-facing (reversed) byte order; the VM pushes the internal order (= plan's bytes)
  const tok = (cap, commitment = new Uint8Array(0)) => ({amount: 0n, category: Uint8Array.from(CAT).reverse(), nft: {capability: cap, commitment}});
  return wit.map((inputs, t) => {
    const unl = inputs.map((items) => pushes([...items, R]));
    const sourceOutputs = unl.map((_, i) => ({lockingBytecode: lock, valueSatoshis: 10_000n, ...(CAT && i === 0 ? {token: t === 0 ? tok('minting') : tok('none', plan.thread.commitments?.[t] ?? threadCommit(G, t))} : {})}));
    const outputs = CAT && t === 0
      ? [{lockingBytecode: lock, valueSatoshis: 1000n, token: tok('minting')}, ...Array.from({length: T - 1}, (_, k) => ({lockingBytecode: lock, valueSatoshis: 1000n, token: tok('none', threadCommit(G, k + 1))}))]
      : [{lockingBytecode: Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]), valueSatoshis: 1000n}];
    const transaction = {version: 2, locktime: 0, inputs: unl.map((u, i) => ({outpointTransactionHash: new Uint8Array(32).fill(t + 1), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: u})), outputs};
    const txBytes = encodeTransaction(transaction).length;
    return {transaction, sourceOutputs, unl, txBytes};
  });
}

export function evaluateTx(tx, vmName) {
  return tx.unl.map((u, i) => {
    const r = evaluate(vmName, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    return {...r, unlocking: u.length, budget: (41 + u.length) * 800};
  });
}
// full-transaction verification (libauth vm.verify: every input plus the transaction-level rules)
export function verifyTx(tx, vmName) {
  return VMS[vmName].verify({transaction: tx.transaction, sourceOutputs: tx.sourceOutputs});
}
export {encodeA};
void createTestAuthenticationProgramBch;
