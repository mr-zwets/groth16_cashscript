// Track 9 S1: W-state transactions for the tests (libauth objects). Values are regtest fixtures:
// D = 1,000,000 sat; the R carrier (input 0) holds 2,000 sat; the payout is D - 3,000 (fee 5,000 sat).
import {encodeTransaction, hash256} from '@bitauth/libauth';
import {buildW, stubR, D_DEFAULT} from './wcov.mjs';
import {numBytes} from '../p2/lib/asm.mjs';
import {pushes, p2sh32, VMS, evaluate} from '../p2/vm.mjs';
import {sha256, encodeW, nfBytes, keyOf, ringPath} from './smt.mjs';

export const CATEGORY = Buffer.from(hash256(Uint8Array.from(Buffer.from('pq-pool/W category (test genesis outpoint)'))));
export const tokenOf = (cat, commitment, capability = 'mutable') => ({amount: 0n, category: Uint8Array.from(cat).reverse(), nft: {capability, commitment: Uint8Array.from(commitment)}});
export const PAYOUT = Uint8Array.from([0x76, 0xa9, 0x14, ...sha256(Buffer.from('t9s1 recipient')).subarray(0, 20), 0x88, 0xac]);

export function makePool({R = stubR(), CAT = CATEGORY, D = D_DEFAULT, nIn = 2, wIdx = 1} = {}) {
  const HR = sha256(R);
  const redeem = buildW({HR, CAT, D, nIn, wIdx});
  return {R, CAT, D, nIn, wIdx, HR, redeem, locking: p2sh32(redeem)};
}

// one withdrawal from W state {nfRoot, histRoot, epoch} (value wValue) with:
//   head: {ROOT (32 B), NF (32 B), CTXW (32 B)}  the HEAD tail (stub R checks only sizes)
//   wit:  {S, B, L, HS, slot}                    W's unlocking items
//   newNfRoot                                    the output commitment's nfRoot
// t: optional tamper hooks {outputs(o), inputs(i), wPushes(items), headPushes(items), commitment(c)}
export function withdrawTx(pool, {state, wValue, head, wit, newNfRoot, t = {}}) {
  let headItems = [head.ROOT, head.NF, head.CTXW];
  if (t.headPushes) headItems = t.headPushes(headItems);
  let wItems = [wit.S, wit.B, numBytes(wit.L), wit.HS, numBytes(wit.slot), pool.redeem];
  if (t.wPushes) wItems = t.wPushes(wItems);
  let commitment = encodeW({...state, nfRoot: newNfRoot});
  if (t.commitment) commitment = t.commitment(commitment);
  const inCommit = encodeW(state);
  let sourceOutputs = [
    {lockingBytecode: pool.R, valueSatoshis: 2_000n},
    {lockingBytecode: pool.locking, valueSatoshis: wValue, token: tokenOf(pool.CAT, inCommit)},
  ];
  let inputs = [
    {outpointTransactionHash: new Uint8Array(32).fill(0x91), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: pushes(headItems)},
    {outpointTransactionHash: new Uint8Array(32).fill(0x92), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: pushes(wItems)},
  ];
  let outputs = [
    {lockingBytecode: pool.locking, valueSatoshis: wValue - pool.D, token: tokenOf(pool.CAT, commitment)},
    {lockingBytecode: PAYOUT, valueSatoshis: pool.D - 3_000n},
  ];
  if (t.tx) ({sourceOutputs, inputs, outputs} = t.tx({sourceOutputs, inputs, outputs}));
  if (t.outputs) outputs = t.outputs(outputs);
  const transaction = {version: 2, locktime: 0, inputs, outputs};
  return {transaction, sourceOutputs, bytes: encodeTransaction(transaction).length};
}

// evaluate every input (and the whole tx) on a VM
export function runTx(tx, vm = 'bchStd') {
  const ins = tx.transaction.inputs.map((inp, i) => {
    const r = evaluate(vm, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    const u = inp.unlockingBytecode.length;
    return {accepted: r.accepted, error: r.error ? String(r.error) : undefined, opCost: r.opCost, unlocking: u, budget: (41 + u) * 800, iters: r.iters};
  });
  const v = VMS[vm].verify({sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
  return {ins, tx: v === true ? true : String(v), bytes: tx.bytes};
}

// the honest witness for a withdrawal of NF (lanes) against ring slot `slot` and SMT `smt` (reference), and the
// expected new nfRoot (null if the key is present: then the witness is the key's membership path)
export function honest(smt, slots, slot, nfLanes) {
  const NF = nfBytes(nfLanes), K = keyOf(NF);
  const p = smt.path(K);
  return {NF, K, present: smt.has(K), wit: {S: p.sibs, B: p.bitmap, L: p.L, HS: ringPath(slots, slot), slot}, ROOT: slots[slot]};
}
