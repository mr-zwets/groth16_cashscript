// Track 9 S4: JS reference of the D state and the flush, and the transaction builders (libauth objects) for the
// genesis, deposit and flush transactions. The reference is independent of the script: it keeps the leaves and the
// frontier as values and computes the flush with S0's permRef; the offline tree (w/genesis.mjs tree()) is the check.
//
// Pool (makePool4): one category CAT; D (dcov.mjs buildD) and W (w/wcov.mjs buildW with the flush branch), both
// P2SH32; the worker locking and the flush blob are pool independent (codeSet).
// Regtest fixtures: D = 1,000,000 sat, f = 10,000 sat, worker UTXOs 2,000 sat, funding/change outputs P2SH32(OP_1)
// (spendable with a push of 0x51, standard), deposit fee 2,000 sat.
import {encodeTransaction, hash256} from '@bitauth/libauth';
import {permRef} from '../p2/p2gl8.mjs';
import {numBytes} from '../p2/lib/asm.mjs';
import {pushes, p2sh32, VMS, evaluate} from '../p2/vm.mjs';
import {ZH, TREE_DEPTH, TAG_NF} from '../w/genesis.mjs';
import {sha256, Z, nfBytes, ringRoot, ringPath, encodeW, SMT, keyOf} from '../w/smt.mjs';
import {buildW, stubR} from '../w/wcov.mjs';
import {tokenOf} from '../w/wtx.mjs';
import {buildD, codeSet, Q0, ZHB, BATCH, K_LOG, NLEVEL, PATH_LO, CUTS, OP_L, OP_C, OP_S, OP_E, W1_TEMPLATE, W2_TEMPLATE, D_DEFAULT, FEE_DEFAULT, MAX_COUNT} from './dcov.mjs';

export const compress = (a, b) => permRef([...a, ...b]).slice(0, 4);
export const lanesOf = (b) => [0, 1, 2, 3].map((i) => Buffer.from(b).readBigUInt64LE(8 * i));
export const OP1_REDEEM = Uint8Array.of(0x51);
export const FUND_LOCKING = p2sh32(OP1_REDEEM);
export const FUND_UNLOCK = pushes([OP1_REDEEM]);
export const WORKER_VALUE = 2_000n;
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

// ---------------------------------------------------------------- notes
// a note from (nk, r) lanes: NF = T(P(nk || 0,0,0,TAG_NF)), leaf = T(P(NF || r)) (stmt.rs, as in w/genesis.mjs)
export function noteOf(nk, r) { const nf = compress(nk, [0n, 0n, 0n, TAG_NF]); return {nk, r, nf, leaf: compress(nf, r)}; }
export function noteLanes(tag, i, P = 2n ** 64n - 2n ** 32n + 1n) {
  const out = [];
  for (let j = 0; out.length < 4; j++) { const v = sha256(Buffer.from(`${tag}/${i}/${j}`)).readBigUInt64LE(0); if (v < P) out.push(v); }
  return out;
}

// ---------------------------------------------------------------- D state
export class DState {
  constructor() { this.len = 0; this.chain = Z; this.count = 0; this.F = Array(NLEVEL).fill(Z); this.pending = []; this.leaves = []; }
  clone() { const c = new DState(); Object.assign(c, this, {F: [...this.F], pending: [...this.pending], leaves: [...this.leaves]}); return c; }
  queue() { return sha256(Uint8Array.of(this.len), this.chain); }
  FR() { return Buffer.concat(this.F); }
  depHash() { return sha256(u32(this.count), this.FR()); }
  commitment() { return Buffer.concat([Buffer.of(0x44), this.queue(), this.depHash()]); }
  deposit(C) {   // C: 32 B (no checks here: the script checks)
    const n = this.clone();
    n.chain = sha256(this.chain, C); n.len = this.len + 1; n.pending.push(Buffer.from(C));
    return n;
  }
}
export const D0_COMMITMENT = new DState().commitment();
if (!new DState().queue().equals(Q0)) throw new Error('Q0');

// ---------------------------------------------------------------- W state (S4: built by flushes)
export class WState {
  constructor() { this.keys = []; this.slots = Array(16).fill(Z); this.epoch = 0; }
  clone() { const c = new WState(); c.keys = [...this.keys]; c.slots = [...this.slots]; c.epoch = this.epoch; return c; }
  smt() { const t = new SMT(); for (const k of this.keys) t.insert(k); return t; }
  histRoot() { return ringRoot(this.slots); }
  commitment() { return encodeW({nfRoot: this.smt().root(), histRoot: this.histRoot(), epoch: this.epoch}); }
}

// ---------------------------------------------------------------- the flush (reference + witnesses)
// IO of one path level l (bit = bit l of count; l0: the lowest zero bit at or above 4)
const levelIO = (l, bit, isl0, X, Fl) => Buffer.concat([
  isl0 ? Buffer.concat([Buffer.of(OP_E), X, Buffer.of(OP_L), X]) : Buffer.alloc(0),
  bit ? Buffer.concat([Buffer.of(OP_L), Fl, Buffer.of(OP_S, OP_C)]) : Buffer.concat([Buffer.of(OP_L), ZHB[l], Buffer.of(OP_C)]),
]);
const tmplIO = (tokens, leaves, mid) => Buffer.concat(tokens.map((t) => {
  if (t === 'C') return Buffer.of(OP_C);
  if (t.startsWith('E:') || t.startsWith('L:')) return Buffer.concat([Buffer.of(t[0] === 'E' ? OP_E : OP_L), mid[t.slice(2)]]);
  return Buffer.concat([Buffer.of(OP_L), leaves[+t.slice(1)]]);
}));

// d: DState with 16 pending leaves, w: WState -> {ROOT, IO[4], wit (D's unlocking items), d2, w2, ...}
export function flushPlan(d, w) {
  if (d.pending.length !== BATCH) throw new Error(`flush needs ${BATCH} queued leaves, have ${d.pending.length}`);
  const c = d.pending.map(lanesOf);
  const T = (xs) => (xs.length === 1 ? xs[0] : compress(T(xs.slice(0, xs.length / 2)), T(xs.slice(xs.length / 2))));
  const A8 = T(c.slice(0, 8)), B4 = T(c.slice(8, 12)), C4 = T(c.slice(12, 16));
  const S16 = compress(A8, compress(B4, C4));
  if (S16.some((x, i) => x !== T(c)[i])) throw new Error('subtree');
  const Fn = [...d.F]; let node = S16, X = Z, found = false; const H = {};
  const io = {2: [], 3: [], 4: []};
  let wk = 2;
  for (let l = PATH_LO; l < TREE_DEPTH; l++) {
    if (l === CUTS[0]) { H.H11 = node; wk = 3; }
    if (l === CUTS[1]) { H.H23 = node; wk = 4; }
    const bit = (d.count >> l) & 1, isl0 = !found && !bit;
    const nb = nfBytes(node);
    if (isl0) { X = nb; Fn[l - PATH_LO] = nb; found = true; } else if (!found && bit) Fn[l - PATH_LO] = Z;
    io[wk].push(levelIO(l, bit, isl0, X, d.F[l - PATH_LO]));
    node = bit ? compress(lanesOf(d.F[l - PATH_LO]), node) : compress(node, ZH[l]);
  }
  const ROOT = node;
  const mid = {A8: nfBytes(A8), B4: nfBytes(B4), H11: nfBytes(H.H11), H23: nfBytes(H.H23), ROOT: nfBytes(ROOT), X};
  const IO = [
    tmplIO(W1_TEMPLATE, d.pending, mid),
    Buffer.concat([tmplIO(W2_TEMPLATE, d.pending, mid), ...io[2], Buffer.of(OP_E), mid.H11]),
    Buffer.concat([Buffer.of(OP_L), mid.H11, ...io[3], Buffer.of(OP_E), mid.H23]),
    Buffer.concat([Buffer.of(OP_L), mid.H23, ...io[4], Buffer.of(OP_E), mid.ROOT]),
  ];
  const slot = w.epoch % 16;
  const RING = Buffer.concat([w.slots[slot], ringPath(w.slots, slot)]);
  const MID = Buffer.concat([mid.A8, mid.B4, mid.H11, mid.H23, mid.ROOT, mid.X]);
  const d2 = new DState(); d2.count = d.count + BATCH; d2.F = Fn; d2.leaves = [...d.leaves, ...d.pending];
  const w2 = w.clone(); w2.slots[slot] = mid.ROOT; w2.epoch = w.epoch + 1;
  return {ROOT, rootBytes: mid.ROOT, mid, IO, slot, d2, w2, wit: {LV: Buffer.concat(d.pending), FR: d.FR(), count: d.count, MID, RING}};
}

// ---------------------------------------------------------------- pool
export function makePool4({CAT, R = stubR(), nIn = 2, wIdx = 1, D = D_DEFAULT, FEE = FEE_DEFAULT} = {}) {
  const cs = codeSet({D, FEE});
  const Dredeem = buildD({CAT, D, FEE, HF: cs.HF});
  const HR = sha256(R);
  const Wredeem = buildW({HR, CAT, D, nIn, wIdx, FEE});
  return {...cs, CAT: Buffer.from(CAT), R, HR, nIn, wIdx, Dredeem, Dlocking: p2sh32(Dredeem), Wredeem, Wlocking: p2sh32(Wredeem),
    // the S1 helpers (w/wtx.mjs withdrawTx) read these names
    redeem: Wredeem, locking: p2sh32(Wredeem)};
}

// worker unlocking: IO, a pad, the worker blob; exactly `size` bytes (0: the smallest, an empty pad). Sizes per
// worker (10, 12, 12 and 7 compressions): worker 1 8,600 B, workers 2 and 3 10,000 B, worker 4 the smallest.
export const WORKER_SIZES = [8_600, 10_000, 10_000, 0];
export function workerUnlocking(pool, io, size = 10_000) {
  if (!size) return pushes([io, new Uint8Array(0), pool.wblob]);
  let pad = Math.max(1, size - io.length - pool.wblob.length - 8), u;
  for (let i = 0; i < 8; i++) { u = pushes([io, new Uint8Array(pad).fill(0x55), pool.wblob]); if (u.length === size) break; pad += size - u.length; }
  if (u.length !== size) throw new Error('worker unlocking size');
  return u;
}

// UTXO references: {txid (32 B, as libauth's outpointTransactionHash: display order), vout, value}
const inp = (o, unlockingBytecode) => ({outpointTransactionHash: Uint8Array.from(o.txid), outpointIndex: o.vout, sequenceNumber: 0, unlockingBytecode});
const opOf = (tag) => ({txid: Buffer.from(hash256(Buffer.from(tag))), vout: 0});

// genesis outputs: D (output 0) and W (output 1), mutable NFTs of CAT
export function genesisOutputs(pool, {dValue = 100_000n, wValue = 100_000n, d = new DState(), w = new WState()} = {}) {
  return [
    {lockingBytecode: pool.Dlocking, valueSatoshis: dValue, token: tokenOf(pool.CAT, d.commitment())},
    {lockingBytecode: pool.Wlocking, valueSatoshis: wValue, token: tokenOf(pool.CAT, w.commitment())},
  ];
}

// deposit: D (input 0) + a funding input; outputs D' and change. t: tamper hooks {items(items), out0(o), tx(tx)}
export function depositTx(pool, {d, dUtxo, fund = {...opOf('fund'), value: 2_000_000n}, C, fee = 2_000n, t = {}}) {
  let items = [C, numBytes(d.len), d.chain, pool.Dredeem];
  if (t.items) items = t.items(items);
  const d2 = d.deposit(C);
  let out0 = {lockingBytecode: pool.Dlocking, valueSatoshis: dUtxo.value + pool.D + pool.FEE, token: tokenOf(pool.CAT, d2.commitment())};
  if (t.out0) out0 = t.out0(out0);
  const sourceOutputs = [
    {lockingBytecode: pool.Dlocking, valueSatoshis: dUtxo.value, token: tokenOf(pool.CAT, d.commitment())},
    {lockingBytecode: FUND_LOCKING, valueSatoshis: fund.value},
  ];
  const outputs = [out0, {lockingBytecode: FUND_LOCKING, valueSatoshis: fund.value - pool.D - pool.FEE - fee}];
  let tx = {transaction: {version: 2, locktime: 0, inputs: [inp(dUtxo, pushes(items)), inp(fund, FUND_UNLOCK)], outputs}, sourceOutputs};
  if (t.tx) tx = t.tx(tx) ?? tx;
  return {...tx, d2, bytes: encodeTransaction(tx.transaction).length};
}

// flush: D (0), W (1), workers (2..5); outputs D', W', keeper. t: {wit(wit), io(IO), dItems(items), outputs(o), tx(tx)}
export function flushTx(pool, {d, w, dUtxo, wUtxo, workers, plan = flushPlan(d, w), keeperFee = 50_000n, t = {}}) {
  let wit = {...plan.wit};
  if (t.wit) wit = t.wit(wit) ?? wit;
  let IO = [...plan.IO];
  if (t.io) IO = t.io(IO) ?? IO;
  let dItems = [wit.LV, wit.FR, numBytes(wit.count), wit.MID, wit.RING, pool.fblob, pool.Dredeem];
  if (t.dItems) dItems = t.dItems(dItems);
  const wk = workers ?? [0, 1, 2, 3].map((i) => ({...opOf('worker' + i), value: WORKER_VALUE}));
  const sourceOutputs = [
    {lockingBytecode: pool.Dlocking, valueSatoshis: dUtxo.value, token: tokenOf(pool.CAT, d.commitment())},
    {lockingBytecode: pool.Wlocking, valueSatoshis: wUtxo.value, token: tokenOf(pool.CAT, w.commitment())},
    ...wk.map((x) => ({lockingBytecode: pool.WORKER, valueSatoshis: x.value})),
  ];
  const inputs = [inp(dUtxo, pushes(dItems)), inp(wUtxo, pushes([pool.Wredeem])), ...wk.map((x, i) => inp(x, workerUnlocking(pool, IO[i], (t.sizes ?? WORKER_SIZES)[i])))];
  const moved = BigInt(BATCH) * pool.D, fees = BigInt(BATCH) * pool.FEE;
  let outputs = [
    {lockingBytecode: pool.Dlocking, valueSatoshis: dUtxo.value - moved - fees, token: tokenOf(pool.CAT, plan.d2.commitment())},
    {lockingBytecode: pool.Wlocking, valueSatoshis: wUtxo.value + moved, token: tokenOf(pool.CAT, plan.w2.commitment())},
    {lockingBytecode: FUND_LOCKING, valueSatoshis: fees + wk.reduce((a, x) => a + x.value, 0n) - keeperFee},
  ];
  if (t.outputs) outputs = t.outputs(outputs) ?? outputs;
  let tx = {transaction: {version: 2, locktime: 0, inputs, outputs}, sourceOutputs};
  if (t.tx) tx = t.tx(tx) ?? tx;
  return {...tx, plan, bytes: encodeTransaction(tx.transaction).length};
}

// every input on a VM (+ whole-tx verification); op-cost BCHN-adjusted by the OP_DEFINE bodies of each input
export function defineBytesOf(pool, role) {
  if (role === 'D-flush') return pool.fblob.length + pool.fblobLevelFn;
  if (role === 'worker') return pool.wblob.length + pool.compressLen;
  return 0;
}
export function runTx(tx, vm = 'bchStd', {roles = [], pool} = {}) {
  const ins = tx.transaction.inputs.map((x, i) => {
    const r = evaluate(vm, null, null, {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
    const u = x.unlockingBytecode.length, def = pool && roles[i] ? defineBytesOf(pool, roles[i]) : 0;
    return {role: roles[i], accepted: r.accepted, error: r.error ? String(r.error) : undefined, opCost: r.opCost, opBchnAdj: r.opCost + def, unlocking: u, budget: (41 + u) * 800,
      pct: +(100 * (r.opCost + def) / ((41 + u) * 800)).toFixed(2)};
  });
  const v = VMS[vm].verify({sourceOutputs: tx.sourceOutputs, transaction: tx.transaction});
  return {ins, tx: v === true ? true : String(v), bytes: encodeTransaction(tx.transaction).length, ok: v === true && ins.every((x) => x.accepted && x.opBchnAdj <= x.budget)};
}
export const txidOf = (tx) => Buffer.from(hash256(encodeTransaction(tx.transaction)));   // internal order
export {MAX_COUNT, K_LOG};
