// Track 9 S2: the pool side of a withdrawal's final transaction (tx1 of the 2-transaction a' plan): the W-state input
// (S1's covenant, ../w/wcov.mjs) and output 0 (the next W state), from a W state held in JS.
//
//   state  {keys: [K...] (spent NF keys), slots (16 ring slots), histRoot, epoch, value (sat), outpoint, index}
//   W      makePool({R: the a' locking R, nIn: tx1's input count, wIdx: tx1's last index}) (S1 wtx.mjs)
//
// Values (regtest fixtures, DESIGN-T9 maintainer decision 7): D = 1,000,000 sat; the payout of statement k is
// D - PHI (PHI = 50,000 sat covers the miner fee of tx1 with the R carriers' 13,000 sat).
import {encodeTransaction, hash256} from '@bitauth/libauth';
import {makePool, tokenOf} from '../w/wtx.mjs';
import {D_DEFAULT} from '../w/wcov.mjs';
import {SMT, encodeW, nfBytes, keyOf, ringPath, walk, sha256} from '../w/smt.mjs';
import {genesis} from '../w/genesis.mjs';
import {numBytes} from '../p2/lib/asm.mjs';

export const D = D_DEFAULT, PHI = 50_000n;
export const G = genesis();
export const payoutLocking = (k) => Uint8Array.from([0x76, 0xa9, 0x14, ...sha256(Buffer.from(`t9s2 recipient ${k}`)).subarray(0, 20), 0x88, 0xac]);
export const payoutsFor = (k) => [{lockingBytecode: payoutLocking(k), valueSatoshis: D - PHI}];

export function poolOf(pg) {
  if (pg.wIdx === null || pg.wIdx === undefined) throw new Error('plan without the W slot');
  return makePool({R: pg.redeem, nIn: pg.inCount[pg.inCount.length - 1], wIdx: pg.wIdx});
}
export function genesisState(value = 100n * D) {
  return {keys: [], slots: G.slots, histRoot: G.histRoot, epoch: G.state.epoch, value, outpoint: Buffer.alloc(32, 0x57), index: 0};
}
export const smtOf = (keys) => { const t = new SMT(); for (const k of keys) t.insert(k); return t; };
export const nfRootOf = (st) => smtOf(st.keys).root();
export const commitmentOf = (st) => encodeW({nfRoot: nfRootOf(st), histRoot: st.histRoot, epoch: st.epoch});

// the W input ({locking, items, value, token, outpoint, outpointIndex}) and output 0 for a withdrawal of NF (lanes)
// against ROOT (lanes) from state st. A ROOT that is not in the ring gets slot 0's path (W rejects it); a present NF
// gets its membership path (W rejects it). t: {slot, wItems(items), out0(output)} tamper hooks.
export function wSpend(pool, st, rootLanes, nfLanes, t = {}) {
  const NF = nfBytes(nfLanes), K = keyOf(NF), ROOT = nfBytes(rootLanes);
  let slot = st.slots.findIndex((x) => Buffer.from(x).equals(ROOT));
  if (t.slot !== undefined) slot = t.slot; else if (slot < 0) slot = 0;
  const smt = smtOf(st.keys), p = smt.path(K);
  const wk = walk(K, p.bitmap, p.sibs);
  const present = smt.has(K);
  const newRoot = present ? smt.root() : wk.new;
  let items = [p.sibs, p.bitmap, numBytes(p.L), ringPath(st.slots, slot), numBytes(slot), pool.redeem];
  if (t.wItems) items = t.wItems(items);
  let out0 = {lockingBytecode: pool.locking, valueSatoshis: st.value - pool.D, token: tokenOf(pool.CAT, encodeW({nfRoot: newRoot, histRoot: st.histRoot, epoch: st.epoch}))};
  if (t.out0) out0 = t.out0(out0);
  return {
    w: {locking: pool.locking, items, value: st.value, token: tokenOf(pool.CAT, commitmentOf(st)), outpoint: st.outpoint, outpointIndex: st.index},
    out0, K, present, slot,
  };
}
// the next state after a confirmed tx1 (its output 0)
export function nextState(st, K, tx1) {
  const txid = Buffer.from(hash256(encodeTransaction(tx1.transaction))).reverse();
  return {...st, keys: [...st.keys, K], value: st.value - D, outpoint: Buffer.from(txid).reverse(), index: 0};
}
