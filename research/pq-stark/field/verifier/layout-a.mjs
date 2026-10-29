// Layout (a): transactions of standard size (<= 100,000 B) whose inputs are each <= 10,000 B of unlocking, built from
// gen-a.mjs. plan(): partition the queries into QRY inputs; txs(): witnesses, the transaction(s) and their source
// outputs; evaluateTx(): every input on a given VM with per-input metrics (op-cost, budget, hash iterations).
import {readFileSync} from 'node:fs';
import {createTestAuthenticationProgramBch, encodeTransaction, hash256} from '@bitauth/libauth';
import {makeParams} from './params.mjs';
import {encodeA} from './model.mjs';
import {buildA} from './gen-a.mjs';
import {VMS, p2sh32, pushes, evaluate} from './vm.mjs';

export function loadVector(path) {
  const v = JSON.parse(readFileSync(path, 'utf8'));
  return {v, prm: makeParams(v.params), proof: Buffer.from(v.proof, 'hex')};
}
// split [0, s) into transactions and QRY inputs of at most `per` queries; a tx holds at most `perTx` queries
export function makePlan(prm, {per = 3, perTx = prm.s, thread} = {}) {
  const txs = [];
  for (let t0 = 0; t0 < prm.s; t0 += perTx) {
    const t1 = Math.min(prm.s, t0 + perTx), n = t1 - t0, k = Math.ceil(n / per), qry = [];
    // balanced split of n queries over k inputs
    let lo = t0;
    for (let j = 0; j < k; j++) { const m = Math.floor(n / k) + (j < n % k ? 1 : 0); qry.push([lo, lo + m]); lo += m; }
    txs.push({qry});
  }
  return {txs, ...(txs.length > 1 ? {thread: thread ?? {category: hash256(Uint8Array.from(Buffer.from('pq-hash/thread category (test genesis outpoint)')))}} : {})};
}

const cache = new Map();
export function programA(prm, statement, plan, opts = {}) {
  const key = prm.name + Buffer.from(statement).toString('hex') + JSON.stringify(plan, (k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v)) + JSON.stringify(opts);
  if (!cache.has(key)) { const b = buildA(prm, statement, plan, opts); cache.set(key, {...b, locking: p2sh32(b.redeem)}); }
  return cache.get(key);
}

// witnesses per tx: [HEAD items, CODE items, QRY items...] (without R); pads per input (bytes)
export function witnessesA(prm, plan, pg, enc, pads = {}) {
  const pt = {FIN: enc.pt[6 + prm.r - 3] ?? null};
  // enc.pt order: st rT rC OOD rF.. FIN NONCE
  const [, rT, rC, OOD, ...rest] = enc.pt; const rFs = rest.slice(0, prm.r - 1); const FIN = rest[prm.r - 1], NONCE = rest[prm.r];
  void pt;
  const byName = {FIN, rT, rC, OOD, NONCE}; rFs.forEach((x, i) => { byName['rF' + (i + 1)] = x; });
  return plan.txs.map((tx, t) => {
    const head = [...pg.ptOrder.map((x) => byName[x]), new Uint8Array(pads[`${t}:0`] ?? 0)];
    const code = [pg.code];
    const qry = tx.qry.map(([lo, hi], j) => {
      const items = [];
      for (let q = lo; q < hi; q++) items.push(enc.leafBlobs[q], enc.paths[q]);
      items.push(new Uint8Array(pads[`${t}:${2 + j}`] ?? 0));
      return items;
    });
    return [head, code, ...qry];
  });
}

export function txsA(prm, plan, pg, wit) {
  const lock = pg.locking, R = pg.redeem;
  const CAT = plan.thread?.category;
  // libauth's token.category is in user-facing (reversed) byte order; the VM pushes the internal order (= plan's bytes)
  const tok = (cap, commitment = new Uint8Array(0)) => ({amount: 0n, category: Uint8Array.from(CAT).reverse(), nft: {capability: cap, commitment}});
  return wit.map((inputs, t) => {
    const unl = inputs.map((items) => pushes([...items, R]));
    const sourceOutputs = unl.map((_, i) => ({lockingBytecode: lock, valueSatoshis: 10_000n, ...(CAT && i === 0 ? {token: t === 0 ? tok('minting') : tok('none', plan.thread.commitment)} : {})}));
    const outputs = CAT && t === 0
      ? [{lockingBytecode: lock, valueSatoshis: 1000n, token: tok('minting')}, {lockingBytecode: lock, valueSatoshis: 1000n, token: tok('none', plan.thread.commitment)}]
      : [{lockingBytecode: Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]), valueSatoshis: 1000n}];
    const transaction = {version: 2, locktime: 0, inputs: unl.map((u, i) => ({outpointTransactionHash: new Uint8Array(32).fill(t + 1), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: u})), outputs};
    const txBytes = encodeTransaction(transaction).length;   // encoded size (token prefixes included)
    return {transaction, sourceOutputs, unl, txBytes};
  });
}

export function evaluateTx(tx, vmName) {
  return tx.unl.map((u, i) => {
    const r = evaluate(vmName, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    return {...r, unlocking: u.length, budget: (41 + u.length) * 800};
  });
}
// full-transaction verification (libauth vm.verify: every input plus the transaction-level rules: token accounting,
// sizes, standardness of outputs); returns true or the error string
export function verifyTx(tx, vmName) {
  return VMS[vmName].verify({transaction: tx.transaction, sourceOutputs: tx.sourceOutputs});
}
void createTestAuthenticationProgramBch;
