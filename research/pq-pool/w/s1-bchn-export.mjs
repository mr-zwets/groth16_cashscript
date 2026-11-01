// Track 9 S1: W-state withdrawals as node-check workloads (bench research/node-check nc.ts, json: format), for a
// default-policy BCHN v29.1.0 regtest node (POLICY=1). W is built for the node-check faucet category (`nc.ts category`,
// internal byte order), so the funder can mint W's mutable NFT with any commitment; input 0 is the stand-in R (S1).
//   w-genesis   withdrawal from the genesis state (empty nullifier set, loop A only)
//   w-1000      withdrawal after 1,000 random spends
//   w-worst     constructed state: one key, the leaf neighbour of K (L = 0, loop B over 64 levels, 90.6% of budget)
//   w-64sib     constructed state: every sibling present (64 siblings, the largest W input)
// Usage: node s1-bchn-export.mjs CATEGORY_INTERNAL_HEX OUT.json
import fs from 'node:fs';
import {SMT, keyOf, nfBytes, sha256} from './smt.mjs';
import {genesis} from './genesis.mjs';
import {makePool, withdrawTx, runTx, honest} from './wtx.mjs';
import {P} from '../p2/p2gl8.mjs';

const [catHex, out] = process.argv.slice(2);
const CAT = Buffer.from(catHex, 'hex');
if (CAT.length !== 32) throw new Error('category: 32 B hex');
const g = genesis(), pool = makePool({CAT});
const hex = (b) => Buffer.from(b).toString('hex');
let ctr = 0;
const lane = () => { for (;;) { const v = sha256(Buffer.from(`t9s1-bchn/${ctr++}`)).readBigUInt64LE(0); if (v < P) return v; } };
const nfNew = () => [lane(), lane(), lane(), lane()];
const CTXW = sha256(Buffer.from('t9s1 ctx'));
const W0 = 100_000_000n;

const tokJ = (t) => (t ? {categoryHex: hex(t.category), amount: t.amount.toString(), nft: {capability: t.nft.capability, commitmentHex: hex(t.nft.commitment)}} : undefined);
function workload(id, description, smt, nf, slot) {
  const state = {...g.state, nfRoot: smt.root()};
  const h = honest(smt, g.slots, slot, nf);
  const after = new SMT(); after.nodes = new Map(smt.nodes); after.keys = new Set(smt.keys); after.insert(h.K);
  const tx = withdrawTx(pool, {state, wValue: W0, head: {ROOT: h.ROOT, NF: h.NF, CTXW}, wit: h.wit, newNfRoot: after.root()});
  const r = runTx(tx);
  if (r.tx !== true) throw new Error(`${id}: libauth rejects: ${r.tx}`);
  const w = r.ins[pool.wIdx];
  return {id, group: 't9-s1', kind: 'valid', expect: 'accept', expectLibauth: 'accept', defBytes: 0,
    description: `${description}; W input op ${w.opCost} / budget ${w.budget} (${(100 * w.opCost / w.budget).toFixed(1)}%), ${r.bytes} B`,
    libauth: {ins: r.ins, bytes: r.bytes},
    txs: [{label: id, version: 2, locktime: 0,
      inputs: tx.transaction.inputs.map((inp, i) => ({source: {lockingHex: hex(tx.sourceOutputs[i].lockingBytecode), valueSatoshis: tx.sourceOutputs[i].valueSatoshis.toString(), ...(tx.sourceOutputs[i].token ? {token: tokJ(tx.sourceOutputs[i].token)} : {})}, unlockingHex: hex(inp.unlockingBytecode), sequenceNumber: 0})),
      outputs: tx.transaction.outputs.map((o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: o.valueSatoshis.toString(), ...(o.token ? {token: tokJ(o.token)} : {})}))}]};
}

const W = [];
W.push(workload('w-genesis', 'withdrawal from the genesis state (empty set)', new SMT(), g.notes[0].nf, 0));
{ const s = new SMT(); for (let i = 0; i < 1000; i++) s.insert(keyOf(nfBytes(nfNew()))); W.push(workload('w-1000', 'withdrawal after 1,000 spends', s, nfNew(), 1)); }
{ const nf = nfNew(), K = keyOf(nfBytes(nf)); const s = new SMT(); s.insert(K ^ 1n); W.push(workload('w-worst', 'constructed: one key K xor 1 (L = 0, 1 sibling)', s, nf, 0)); }
{ const nf = nfNew(), K = keyOf(nfBytes(nf)); const s = new SMT(); for (let l = 0; l < 64; l++) s.insert(K ^ (1n << BigInt(l))); W.push(workload('w-64sib', 'constructed: 64 siblings', s, nf, 1)); }
fs.writeFileSync(out, JSON.stringify({workloads: W}, null, 1));
console.log(W.map((w) => `${w.id}: ${w.description}`).join('\n'));
