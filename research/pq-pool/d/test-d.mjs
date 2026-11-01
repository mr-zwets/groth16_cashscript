#!/usr/bin/env node
// Track 9 S4 acceptance (DESIGN-T9 sec. 6 S4), libauth BCH 2026 (3.1.0-next.8, unpatched), today's rules:
//   seq    64 sequential deposits, 4 flushes: after each flush the new root equals the offline Poseidon2 tree
//          (w/genesis.mjs tree(), a separate computation from the frontier reference) over all leaves so far, and
//          W's histRoot equals the ring of those roots; one note of each flush is withdrawn against its root
//   wrap   flushes 5..17 (272 deposits in all): a note of flush 0 is withdrawn against root 0 just before the flush
//          at epoch 16 (accepted), and another note of flush 0 against root 0 just after it (rejected by W: slot 0
//          now holds root 16); that note is then withdrawn against the current root (accepted)
//   reject plain rejections: deposit (leaf lane >= p, full queue, witness, output 0), flush (premature, wrong
//          frontier, count, MID/IO, ring, W and D outputs, workers, a fake D or W), each naming the input that must
//          reject; a rejection counts only if the input also rejects on the loose VM (no resource limit), as in S1/S2
//   edge   synthetic D states (the script cannot tell them from real ones): l0 = 29, count = 2^30 - 16 (no l0: the
//          tree becomes full), count = 2^30 (rejected), a queued leaf with a lane = p (worker 1 rejects)
// Withdrawals here use S1's stand-in R (stubR: three 32 B pushes, no proof): they test W's ring and nullifier rules
// on a flushed history; the real R with a real proof is the BCHN end-to-end run (../node/s4.ts).
// Every valid transaction must pass bchStd and bchCons on every input, libauth's whole-transaction verification, and
// the BCHN-adjusted op-cost (libauth + OP_DEFINE body bytes) must stay within each input's budget.
// usage: node test-d.mjs [--flushes 17] [--out results/s4-d.json]
import {writeFileSync} from 'node:fs';
import {makePool4, DState, WState, depositTx, flushTx, flushPlan, runTx, noteOf, noteLanes, lanesOf, WORKER_VALUE, FUND_LOCKING} from './dpool.mjs';
import {BATCH, MAX_COUNT, OP_E} from './dcov.mjs';
import {P} from '../p2/p2gl8.mjs';
import {nfBytes, keyOf, ringPath, ringRoot, Z, sha256} from '../w/smt.mjs';
import {tree, treeRoot, TREE_DEPTH} from '../w/genesis.mjs';
import {withdrawTx, tokenOf} from '../w/wtx.mjs';
import {evaluate, pushes} from '../p2/vm.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const NFLUSH = +opt('--flushes', 17), OUT = opt('--out', new URL('./results/s4-d.json', import.meta.url).pathname);
const CAT = sha256(Buffer.from('pq-pool/S4 pool category (test genesis outpoint)'));
const pool = makePool4({CAT});
const ROLES = ['D', 'W', 'worker1', 'worker2', 'worker3', 'worker4'];
const roleDef = (r) => (r === 'D' ? 'D-flush' : r?.startsWith('worker') ? 'worker' : null);
const res = {stage: 'Track 9 S4', what: 'D-state covenant, flush, ring (libauth)', sizes: {Dredeem: pool.Dredeem.length, Wredeem: pool.Wredeem.length,
  flushBlob: pool.fblob.length, workerBlob: pool.wblob.length, workerLocking: pool.WORKER.length, compress: pool.compressLen, levelFn: pool.fblobLevelFn},
seq: [], wrap: {}, families: {}, cases: [], fail: [], costs: {deposit: [], flush: []}};
const log = (s) => console.log(s);
let uid = 0;
const nextOp = (value) => ({txid: sha256(Buffer.from(`op ${uid++}`)), vout: 0, value});

// ---------------------------------------------------------------- verdicts
function verdicts(tx) {
  return tx.transaction.inputs.map((_, i) => {
    const prog = {inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction};
    const s = evaluate('bchStd', null, null, prog);
    if (s.accepted) return 'accept';
    return evaluate('looseStd', null, null, prog).accepted ? 'limit' : 'reject';
  });
}
// a valid transaction: every input on bchStd and bchCons, whole tx, BCHN-adjusted op-cost within budget
function valid(tx, roles) {
  const a = runTx(tx, 'bchStd', {pool, roles}), b = runTx(tx, 'bchCons', {pool, roles});
  return {ok: a.ok && b.ok, std: a, cons: b, bytes: a.bytes, maxPct: Math.max(...a.ins.map((x) => x.pct)),
    err: a.ok && b.ok ? undefined : JSON.stringify([a.tx, ...a.ins.filter((x) => !x.accepted || x.opBchnAdj > x.budget).map((x) => [x.role, x.error, x.pct])]).slice(0, 300)};
}
// a rejection case: `rejecter` (input index, or a list: any of them) must reject on a failed check; others: 'accept'
// (every other input accepts) or undefined (not checked)
function rej(family, name, tx, {rejecter, others}) {
  const v = verdicts(tx);
  const rs = Array.isArray(rejecter) ? rejecter : [rejecter];
  const hit = rs.some((i) => v[i] === 'reject');
  const othersOk = others !== 'accept' || v.every((x, i) => rs.includes(i) || x === 'accept');
  const ok = hit && othersOk && !v.includes('limit');
  const F = (res.families[family] ??= {cases: 0, ok: 0});
  F.cases++; if (ok) F.ok++;
  const c = {family, name, ok, rejecter: rs.map((i) => ROLES[i] ?? i), verdicts: v.join(' ')};
  res.cases.push(c); if (!ok) res.fail.push(c);
  log(`${ok ? 'ok  ' : 'FAIL'} [${family}] ${name}: ${v.map((x, i) => `${ROLES[i] ?? i}:${x}`).join(' ')}`);
  return ok;
}
function acc(family, name, tx, roles) {
  const r = valid(tx, roles);
  const F = (res.families[family] ??= {cases: 0, ok: 0});
  F.cases++; if (r.ok) F.ok++;
  const c = {family, name, ok: r.ok, expect: 'accept', err: r.err};
  res.cases.push(c); if (!r.ok) res.fail.push(c);
  log(`${r.ok ? 'ok  ' : 'FAIL'} [${family}] ${name}: ${r.ok ? 'accepted' : r.err}`);
  return r.ok;
}

// ---------------------------------------------------------------- the pool simulation
const S = {d: new DState(), w: new WState(), dUtxo: nextOp(100_000n), wUtxo: nextOp(100_000n), notes: [], roots: [], flushes: 0};
const noteN = (i) => noteOf(noteLanes('t9s4 nk', i), noteLanes('t9s4 r', i));
function deposit(note) {
  const tx = depositTx(pool, {d: S.d, dUtxo: S.dUtxo, C: nfBytes(note.leaf), fund: nextOp(2_000_000n)});
  const r = valid(tx, ['D-deposit', null]);
  if (!r.ok) throw new Error('deposit rejected: ' + r.err);
  res.costs.deposit.push({bytes: r.bytes, opD: r.std.ins[0].opCost, budgetD: r.std.ins[0].budget});
  S.d = tx.d2; S.dUtxo = nextOp(tx.transaction.outputs[0].valueSatoshis); S.notes.push({...note, index: S.notes.length});
}
function flush() {
  const tx = flushTx(pool, {d: S.d, w: S.w, dUtxo: S.dUtxo, wUtxo: S.wUtxo});
  const r = valid(tx, ['D-flush', null, 'worker', 'worker', 'worker', 'worker']);
  if (!r.ok) throw new Error('flush rejected: ' + r.err);
  res.costs.flush.push({bytes: r.bytes, per: r.std.ins.map((x, i) => ({role: ROLES[i], unlocking: x.unlocking, op: x.opBchnAdj, pct: x.pct}))});
  const p = tx.plan;
  S.d = p.d2; S.w = p.w2; S.dUtxo = nextOp(tx.transaction.outputs[0].valueSatoshis); S.wUtxo = nextOp(tx.transaction.outputs[1].valueSatoshis);
  S.roots.push(p.rootBytes); S.flushes++;
  return {tx, r, p};
}
// withdrawal with the stand-in R (W at input 1): note against rootBytes (slot: where it is, else `slot`)
function withdrawal(note, rootBytes, {slot} = {}) {
  const NF = nfBytes(note.nf), K = keyOf(NF);
  let sl = S.w.slots.findIndex((x) => x.equals(rootBytes));
  if (sl < 0) sl = slot ?? 0;
  const smt = S.w.smt(), p = smt.path(K);
  const smt2 = S.w.smt(); smt2.insert(K);
  const tx = withdrawTx(pool, {state: {nfRoot: smt.root(), histRoot: S.w.histRoot(), epoch: S.w.epoch}, wValue: S.wUtxo.value,
    head: {ROOT: rootBytes, NF, CTXW: Buffer.alloc(32, 7)}, wit: {S: p.sibs, B: p.bitmap, L: p.L, HS: ringPath(S.w.slots, sl), slot: sl}, newNfRoot: smt2.root()});
  return {tx, K};
}
function applyWithdrawal({tx, K}) { S.w = S.w.clone(); S.w.keys.push(K); S.wUtxo = nextOp(tx.transaction.outputs[0].valueSatoshis); }

// ================================================================ seq: 64 deposits, 4 flushes
const t0 = Date.now();
for (let f = 0; f < 4; f++) {
  for (let j = 0; j < BATCH; j++) deposit(noteN(S.notes.length));
  const {r, p} = flush();
  const off = treeRoot(tree(S.notes.map((x) => x.leaf)));
  const offB = nfBytes(off);
  const ringOk = S.w.histRoot().equals(ringRoot(Array.from({length: 16}, (_, i) => S.roots[i] ?? Z)));
  const eq = offB.equals(p.rootBytes);
  // withdraw one note of this flush against its root
  const wd = withdrawal(S.notes[16 * f + 3], p.rootBytes);
  const wOk = acc('seq', `flush ${f}: note ${16 * f + 3} withdrawn against root ${f} (stand-in R)`, wd.tx, [null, null]);
  if (wOk) applyWithdrawal(wd);
  res.seq.push({flush: f, leaves: S.notes.length, root: p.rootBytes.toString('hex'), offline: offB.toString('hex'), rootEqualsOffline: eq, histRootEqualsRing: ringOk,
    count: S.d.count, epoch: S.w.epoch, bytes: r.bytes, maxPct: r.maxPct, withdrawal: wOk});
  const F = (res.families.seq ??= {cases: 0, ok: 0}); F.cases++; if (eq && ringOk) F.ok++;   // (the flush itself was accepted: flush() throws otherwise)
  if (!(eq && ringOk)) res.fail.push({family: 'seq', name: `flush ${f} root/ring`});
  log(`flush ${f}: ${S.notes.length} leaves, root ${eq ? '= offline tree' : 'DIFFERS from the offline tree'}, histRoot ${ringOk ? '= ring' : 'differs'}, ${r.bytes} B, max ${r.maxPct}%`);
}
res.seqAll = res.seq.every((x) => x.rootEqualsOffline && x.histRootEqualsRing && x.withdrawal);

// ================================================================ reject families (on the state after flush 3)
const C0 = nfBytes(noteN(100000).leaf);
const lane = (b, k, v) => { const c = Buffer.from(b); c.writeBigUInt64LE(v, 8 * k); return c; };
const dep = (o) => depositTx(pool, {d: S.d, dUtxo: S.dUtxo, C: C0, fund: nextOp(2_000_000n), ...o});
// controls: a valid deposit; lanes = p - 1
acc('deposit', 'control: an honest deposit', dep({}), ['D-deposit', null]);
acc('deposit', 'control: every leaf lane = p - 1 (the largest allowed)', dep({C: Buffer.concat([0, 1, 2, 3].map(() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(P - 1n); return b; }))}), ['D-deposit', null]);
rej('lane', 'leaf lane 0 = p', dep({C: lane(C0, 0, P)}), {rejecter: 0, others: 'accept'});
rej('lane', 'leaf lane 3 = p', dep({C: lane(C0, 3, P)}), {rejecter: 0, others: 'accept'});
rej('lane', 'leaf lane 1 = 2^64 - 1', dep({C: lane(C0, 1, 2n ** 64n - 1n)}), {rejecter: 0, others: 'accept'});
rej('lane', 'leaf lane 2 = p + 5', dep({C: lane(C0, 2, P + 5n)}), {rejecter: 0, others: 'accept'});
rej('deposit', 'leaf of 31 B', dep({C: C0.subarray(1)}), {rejecter: 0, others: 'accept'});
rej('deposit', 'leaf of 33 B', dep({C: Buffer.concat([C0, Buffer.of(0)])}), {rejecter: 0, others: 'accept'});
rej('deposit', 'witness len + 1', dep({t: {items: (it) => [it[0], Uint8Array.of(S.d.len + 1), it[2], it[3]]}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'witness chain byte flipped', dep({t: {items: (it) => { const c = Buffer.from(it[2]); c[0] ^= 1; return [it[0], it[1], c, it[3]]; }}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 value: in + D + f - 1', dep({t: {out0: (o) => ({...o, valueSatoshis: o.valueSatoshis - 1n})}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 value: in + D (no fee)', dep({t: {out0: (o) => ({...o, valueSatoshis: o.valueSatoshis - pool.FEE})}}), {rejecter: 0, others: 'accept'});
const recom = (f) => (o) => ({...o, token: {...o.token, nft: {...o.token.nft, commitment: f(Buffer.from(o.token.nft.commitment))}}});
rej('deposit', 'output 0 commitment: queue unchanged', dep({t: {out0: recom((c) => Buffer.concat([c.subarray(0, 1), S.d.queue(), c.subarray(33)]))}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 commitment: depHash byte flipped', dep({t: {out0: recom((c) => { c[40] ^= 1; return c; })}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 commitment: prefix 0x57', dep({t: {out0: recom((c) => { c[0] = 0x57; return c; })}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 locking: W\'s locking', dep({t: {out0: (o) => ({...o, lockingBytecode: pool.Wlocking})}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'output 0 NFT immutable', dep({t: {out0: (o) => ({...o, token: {...o.token, nft: {...o.token.nft, capability: 'none'}}})}}), {rejecter: 0, others: 'accept'});
rej('deposit', 'D at input 1 (inputs swapped)', dep({t: {tx: (t) => { const i = t.transaction.inputs, so = t.sourceOutputs; [i[0], i[1]] = [i[1], i[0]]; [so[0], so[1]] = [so[1], so[0]]; return t; }}}), {rejecter: 1});
rej('deposit', 'D token moved to output 1, output 0 plain', dep({t: {tx: (t) => { const o = t.transaction.outputs; const tok = o[0].token; o[0] = {...o[0], token: undefined}; o[1] = {...o[1], token: tok}; return t; }}}), {rejecter: 0});
{ // full queue: 16 pending leaves (after 16 more deposits), a 17th is rejected
  const save = {...S, d: S.d.clone()};
  for (let j = 0; j < BATCH; j++) deposit(noteN(S.notes.length));
  rej('deposit', 'a 17th deposit on a full queue (len = 16)', depositTx(pool, {d: S.d, dUtxo: S.dUtxo, C: C0, fund: nextOp(2_000_000n)}), {rejecter: 0, others: 'accept'});
  // ---- flush families on this state (16 queued, count 64, epoch 4)
  const fx = (t = {}, extra = {}) => flushTx(pool, {d: S.d, w: S.w, dUtxo: S.dUtxo, wUtxo: S.wUtxo, t, ...extra});
  const plan = flushPlan(S.d, S.w);
  acc('flush', 'control: an honest flush (count 64, epoch 4)', fx(), ['D-flush', null, 'worker', 'worker', 'worker', 'worker']);
  const wset = (k, v) => (w) => ({...w, [k]: v});
  rej('frontier', 'FR byte 0 flipped', fx({wit: (w) => wset('FR', (() => { const b = Buffer.from(w.FR); b[0] ^= 1; return b; })())(w)}), {rejecter: 0});
  rej('frontier', 'FR entry of level 6 (the set bit of 64) replaced by Z', fx({wit: (w) => wset('FR', (() => { const b = Buffer.from(w.FR); Z.copy(b, 32 * 2); return b; })())(w)}), {rejecter: 0});
  rej('frontier', 'FR entries of levels 6 and 7 swapped', fx({wit: (w) => { const b = Buffer.from(w.FR); const a = Buffer.from(b.subarray(64, 96)); b.copy(b, 64, 96, 128); a.copy(b, 96); return {...w, FR: b}; }}), {rejecter: 0});
  rej('frontier', 'FR of 25 entries', fx({wit: (w) => wset('FR', w.FR.subarray(32))(w)}), {rejecter: 0});
  rej('frontier', 'count + 16 (FR unchanged)', fx({wit: (w) => wset('count', w.count + 16)(w)}), {rejecter: 0});
  rej('frontier', 'count - 16 (FR unchanged)', fx({wit: (w) => wset('count', w.count - 16)(w)}), {rejecter: 0});
  // a consistent but wrong frontier needs a SHA-256 collision; the reference's frontier for another count
  { const d2 = S.d.clone(); d2.count = 48; d2.F = [...S.d.F]; d2.F[0] = plan.mid.A8; const p2 = flushPlan(d2, S.w);
    rej('frontier', 'the IO and witness of another frontier (count 48), against this depHash', fx({wit: () => p2.wit, io: () => p2.IO}), {rejecter: 0}); }
  rej('ring', 'RING: old slot value flipped', fx({wit: (w) => { const b = Buffer.from(w.RING); b[0] ^= 1; return {...w, RING: b}; }}), {rejecter: 0});
  rej('ring', 'RING: a sibling flipped', fx({wit: (w) => { const b = Buffer.from(w.RING); b[100] ^= 1; return {...w, RING: b}; }}), {rejecter: 0});
  // (slot 5's path equals slot 4's while slots 4..7 are all Z: not a tamper; slot 0 holds root 0)
  { const r0 = Buffer.concat([S.w.slots[0], ringPath(S.w.slots, 0)]); if (r0.equals(plan.wit.RING)) throw new Error('no-op ring tamper');
    rej('ring', 'RING: slot 0\'s value and path (epoch mod 16 = 4)', fx({wit: (w) => ({...w, RING: r0})}), {rejecter: 0}); }
  rej('ring', 'RING of 128 B (no old value)', fx({wit: (w) => ({...w, RING: w.RING.subarray(32)})}), {rejecter: 0});
  const midSet = (k, v) => (w) => { const m = Buffer.from(w.MID); const off = {A8: 0, B4: 32, H11: 64, H23: 96, ROOT: 128, X: 160}[k]; v.copy(m, off); return {...w, MID: m}; };
  const flipB = (b) => { const c = Buffer.from(b); c[3] ^= 1; return c; };
  rej('mid', 'MID: ROOT flipped (workers keep the honest IO)', fx({wit: midSet('ROOT', flipB(plan.mid.ROOT))}), {rejecter: 0});
  rej('mid', 'MID: A8 flipped (workers keep the honest IO)', fx({wit: midSet('A8', flipB(plan.mid.A8))}), {rejecter: 0});
  rej('mid', 'MID: X flipped (workers keep the honest IO)', fx({wit: midSet('X', flipB(plan.mid.X))}), {rejecter: 0});
  // consistent wrong claims: D's IO, the worker IO and D's outputs agree; the worker that computes the node rejects
  const outW = (root) => (o) => { const w2 = S.w.clone(); w2.slots[S.w.epoch % 16] = root; w2.epoch++; o[1] = {...o[1], token: tokenOf(pool.CAT, w2.commitment())}; return o; };
  const swapNode = (io, a, b) => Buffer.from(io.toString('hex').split(a.toString('hex')).join(b.toString('hex')), 'hex');
  { const bad = flipB(plan.mid.ROOT);
    rej('mid', 'a wrong ROOT claimed consistently (MID, worker 4 IO, W\'s histRoot\'): worker 4 rejects', fx({wit: midSet('ROOT', bad), io: (IO) => [IO[0], IO[1], IO[2], swapNode(IO[3], plan.mid.ROOT, bad)], outputs: outW(bad)}), {rejecter: 5, others: 'accept'}); }
  { const bad = flipB(plan.mid.H11);
    rej('mid', 'a wrong H11 claimed consistently (MID, workers 2 and 3 IO): worker 2 rejects (worker 3, starting from it, misses H23)', fx({wit: midSet('H11', bad), io: (IO) => [IO[0], swapNode(IO[1], plan.mid.H11, bad), swapNode(IO[2], plan.mid.H11, bad), IO[3]]}), {rejecter: 3}); }
  { const bad = flipB(plan.mid.A8);
    rej('mid', 'a wrong A8 claimed consistently (MID, workers 1 and 2 IO): worker 1 rejects (worker 2, starting from it, misses H11)', fx({wit: midSet('A8', bad), io: (IO) => [swapNode(IO[0], plan.mid.A8, bad), swapNode(IO[1], plan.mid.A8, bad), IO[2], IO[3]]}), {rejecter: 2}); }
  { // X: count 64 -> l0 = 4 (bit 4 is 0): X = the subtree root, exported by worker 2 and written to F'[4]
    const bad = flipB(plan.mid.X);
    const d2 = plan.d2.clone(); d2.F = [...plan.d2.F]; d2.F[0] = bad;
    rej('mid', 'a wrong X (the new frontier node) claimed consistently (MID, worker 2 IO, D\'s F\'): worker 2 rejects', fx({wit: midSet('X', bad), io: (IO) => [IO[0], swapNode(IO[1], Buffer.concat([Buffer.of(OP_E), plan.mid.X, Buffer.of(1), plan.mid.X]), Buffer.concat([Buffer.of(OP_E), bad, Buffer.of(1), bad])), IO[2], IO[3]],
      outputs: (o) => { o[0] = {...o[0], token: tokenOf(pool.CAT, d2.commitment())}; return o; }}), {rejecter: 3, others: 'accept'}); }
  rej('io', 'worker 1 IO: a leaf byte flipped', fx({io: (IO) => [flipB(IO[0]), IO[1], IO[2], IO[3]]}), {rejecter: 0});
  rej('io', 'worker 4 IO: last byte flipped (its E literal)', fx({io: (IO) => { const b = Buffer.from(IO[3]); b[b.length - 1] ^= 1; return [IO[0], IO[1], IO[2], b]; }}), {rejecter: [0, 5]});
  rej('io', 'workers 2 and 3 swapped', fx({tx: (t) => { const i = t.transaction.inputs, so = t.sourceOutputs; [i[3], i[4]] = [i[4], i[3]]; [so[3], so[4]] = [so[4], so[3]]; return t; }}), {rejecter: 0});
  rej('io', 'worker 4 missing (5 inputs)', fx({tx: (t) => { t.transaction.inputs.pop(); t.sourceOutputs.pop(); return t; }}), {rejecter: 0});
  rej('io', 'worker 3 locking: a P2S OP_1 (its unlocking unchanged)', fx({tx: (t) => { t.sourceOutputs[4] = {...t.sourceOutputs[4], lockingBytecode: Uint8Array.of(0x51)}; return t; }}), {rejecter: 0});
  rej('io', 'worker 1 unlocking: an extra push before IO', fx({tx: (t) => { const u = t.transaction.inputs[2].unlockingBytecode; t.transaction.inputs[2] = {...t.transaction.inputs[2], unlockingBytecode: Uint8Array.from([0x51, ...u])}; return t; }}), {rejecter: [0, 2]});
  rej('wout', 'W output: histRoot\' with ROOT in slot 5 (not epoch mod 16)', fx({outputs: (o) => { const w2 = S.w.clone(); w2.slots[5] = plan.rootBytes; w2.epoch++; o[1] = {...o[1], token: tokenOf(pool.CAT, w2.commitment())}; return o; }}), {rejecter: 0, others: 'accept'});
  rej('wout', 'W output: epoch not incremented', fx({outputs: (o) => { const w2 = plan.w2.clone(); w2.epoch--; o[1] = {...o[1], token: tokenOf(pool.CAT, w2.commitment())}; return o; }}), {rejecter: 0, others: 'accept'});
  rej('wout', 'W output: nfRoot changed', fx({outputs: (o) => { const w2 = plan.w2.clone(); w2.keys = [...w2.keys, 12345n]; o[1] = {...o[1], token: tokenOf(pool.CAT, w2.commitment())}; return o; }}), {rejecter: [0, 1]});
  rej('wout', 'W output value: + 16 D - 1', fx({outputs: (o) => { o[1] = {...o[1], valueSatoshis: o[1].valueSatoshis - 1n}; o[2] = {...o[2], valueSatoshis: o[2].valueSatoshis + 1n}; return o; }}), {rejecter: [0, 1]});
  rej('wout', 'W output locking: D\'s locking', fx({outputs: (o) => { o[1] = {...o[1], lockingBytecode: pool.Dlocking}; return o; }}), {rejecter: [0, 1]});
  rej('dout', 'D output value: - 16 (D + f) - 1 (keeper takes 1 sat more)', fx({outputs: (o) => { o[0] = {...o[0], valueSatoshis: o[0].valueSatoshis - 1n}; o[2] = {...o[2], valueSatoshis: o[2].valueSatoshis + 1n}; return o; }}), {rejecter: [0, 1]});
  rej('dout', 'D output commitment: queue not reset', fx({outputs: (o) => { const c = Buffer.from(o[0].token.nft.commitment); S.d.queue().copy(c, 1); o[0] = {...o[0], token: tokenOf(pool.CAT, c)}; return o; }}), {rejecter: 0, others: 'accept'});
  rej('dout', 'D output commitment: depHash of count + 16 with the old frontier', fx({outputs: (o) => { const d2 = plan.d2.clone(); d2.F = [...S.d.F]; o[0] = {...o[0], token: tokenOf(pool.CAT, d2.commitment())}; return o; }}), {rejecter: 0, others: 'accept'});
  // W's flush branch needs D's flush: D runs its deposit branch in the same transaction
  { // (S.d has a full queue: use the state before the 16 deposits, len 0, so that D's own deposit branch accepts)
    const dd = save.d.clone(); const t2 = depositTx(pool, {d: dd, dUtxo: S.dUtxo, C: C0, fund: nextOp(2_000_000n)});
    t2.transaction.inputs.splice(1, 0, {outpointTransactionHash: S.wUtxo.txid, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: pushes([pool.Wredeem])});
    t2.sourceOutputs.splice(1, 0, {lockingBytecode: pool.Wlocking, valueSatoshis: S.wUtxo.value, token: tokenOf(pool.CAT, S.w.commitment())});
    t2.transaction.outputs.splice(1, 0, {lockingBytecode: pool.Wlocking, valueSatoshis: S.wUtxo.value + 16n * pool.D, token: tokenOf(pool.CAT, S.w.commitment())});
    t2.transaction.outputs[2] = {...t2.transaction.outputs[2], valueSatoshis: t2.transaction.outputs[2].valueSatoshis - 16n * pool.D};
    t2.sourceOutputs[2] = {...t2.sourceOutputs[2], valueSatoshis: t2.sourceOutputs[2].valueSatoshis + 16n * pool.D};
    rej('wbranch', 'W\'s flush branch with D running its deposit branch (D at 0, W at 1): W rejects', t2, {rejecter: 1, others: 'accept'}); }
  // a fake D (another category, prefix 0x44, a P2S OP_1 locking) at input 0 with W's flush branch
  { const FAKE = sha256(Buffer.from('another category'));
    const t = fx();
    t.sourceOutputs[0] = {lockingBytecode: Uint8Array.of(0x51), valueSatoshis: S.dUtxo.value, token: tokenOf(FAKE, S.d.commitment())};
    t.transaction.inputs[0] = {...t.transaction.inputs[0], unlockingBytecode: Uint8Array.of()};
    t.transaction.outputs[0] = {...t.transaction.outputs[0], token: tokenOf(FAKE, plan.d2.commitment())};
    rej('wbranch', 'a fake D (another category, prefix 0x44, OP_1 locking) at input 0: W rejects', t, {rejecter: 1});
    const t3 = fx();
    t3.sourceOutputs[1] = {lockingBytecode: Uint8Array.of(0x51), valueSatoshis: S.wUtxo.value, token: tokenOf(FAKE, S.w.commitment())};
    t3.transaction.inputs[1] = {...t3.transaction.inputs[1], unlockingBytecode: Uint8Array.of()};
    t3.transaction.outputs[1] = {...t3.transaction.outputs[1], token: tokenOf(FAKE, plan.w2.commitment())};
    rej('wbranch', 'a fake W (another category, prefix 0x57, OP_1 locking) at input 1: D rejects', t3, {rejecter: 0}); }
  // S.d keeps its 16 queued deposits: the wrap phase flushes them first
}

// premature flush: 15 queued leaves
{
  const d15 = S.d.clone();
  // S.d holds 16 queued; drop the last one by rebuilding from its pending leaves
  const base = new DState(); base.count = S.d.count; base.F = [...S.d.F]; base.leaves = [...S.d.leaves];
  let dd = base; for (const c of S.d.pending.slice(0, 15)) dd = dd.deposit(c);
  const extra = nfBytes(noteN(200000).leaf);
  const dPlus = dd.clone(); dPlus.pending = [...dd.pending, extra];   // a 16th leaf that was never deposited
  const p = flushPlan(dPlus, S.w);
  const t = flushTx(pool, {d: dd, w: S.w, dUtxo: S.dUtxo, wUtxo: S.wUtxo, plan: p});
  rej('premature', 'flush with 15 queued deposits plus a 16th leaf never deposited', t, {rejecter: 0});
  const t2 = flushTx(pool, {d: dd, w: S.w, dUtxo: S.dUtxo, wUtxo: S.wUtxo, plan: p, t: {wit: (w) => ({...w, LV: w.LV.subarray(0, 15 * 32)})}});
  rej('premature', 'flush with the 15 queued leaves only (LV of 480 B)', t2, {rejecter: 0});
  void d15;
}

// ================================================================ wrap: flushes up to NFLUSH; root 0 expires at epoch 16
{
  const flushedAt = {};
  flushedAt[0] = S.roots[0];
  const aNote = S.notes[5], bNote = S.notes[9], cNote = S.notes[11];   // flush 0 notes, not yet withdrawn
  // S.d already holds 16 queued deposits (from the full-queue case); flush them
  flush();
  while (S.flushes < NFLUSH) {
    if (S.w.epoch === 16) {
      // just before the flush at epoch 16: root 0 is still in slot 0
      const wa = withdrawal(aNote, S.roots[0]);
      const okA = acc('wrap', `epoch ${S.w.epoch}: a flush-0 note against root 0 (slot 0, written at epoch 0) accepted`, wa.tx, [null, null]);
      if (okA) applyWithdrawal(wa);
      res.wrap.before = {epoch: S.w.epoch, accepted: okA};
    }
    for (let j = 0; j < BATCH; j++) deposit(noteN(S.notes.length));
    flush();
    if (S.w.epoch === 17) {
      const wb = withdrawal(bNote, S.roots[0], {slot: 0});
      const okB = rej('wrap', `epoch ${S.w.epoch}: another flush-0 note against root 0 after the flush at epoch 16 overwrote slot 0`, wb.tx, {rejecter: 1, others: 'accept'});
      const wb2 = withdrawal(bNote, S.roots[0], {slot: 1});
      rej('wrap', `epoch ${S.w.epoch}: the same, with slot 1's path`, wb2.tx, {rejecter: 1, others: 'accept'});
      const cur = S.roots[S.roots.length - 1];
      const wc = withdrawal(bNote, cur);
      const okC = acc('wrap', `epoch ${S.w.epoch}: that note against the newest root (root 16, slot 0) accepted`, wc.tx, [null, null]);
      if (okC) applyWithdrawal(wc);
      const wd = withdrawal(cNote, S.roots[1]);
      const okD = acc('wrap', `epoch ${S.w.epoch}: a flush-0 note against root 1 (slot 1, written at epoch 1, still in the ring) accepted`, wd.tx, [null, null]);
      if (okD) applyWithdrawal(wd);
      res.wrap.after = {epoch: S.w.epoch, staleRejected: okB, newestAccepted: okC, root1Accepted: okD, slot0IsRoot16: S.w.slots[0].equals(cur)};
    }
  }
  // the offline tree over every leaf, against the last root
  const off = nfBytes(treeRoot(tree(S.notes.map((x) => x.leaf))));
  res.wrap.flushes = S.flushes; res.wrap.deposits = S.notes.length; res.wrap.lastRootEqualsOffline = off.equals(S.roots[S.roots.length - 1]);
  res.wrap.allRootsEqualOffline = S.roots.every((r, f) => nfBytes(treeRoot(tree(S.notes.slice(0, 16 * (f + 1)).map((x) => x.leaf)))).equals(r));
  log(`wrap: ${S.flushes} flushes, ${S.notes.length} deposits; every root = offline tree: ${res.wrap.allRootsEqualOffline}`);
  if (!res.wrap.allRootsEqualOffline) res.fail.push({family: 'wrap', name: 'roots vs offline tree'});
}

// ================================================================ edge: synthetic D states
{
  const leaves = Array.from({length: 16}, (_, i) => nfBytes(noteN(300000 + i).leaf));
  const fr = (n) => Array.from({length: 26}, (_, i) => (((n >> (i + 4)) & 1) ? nfBytes(noteN(400000 + i).leaf) : Z));
  const dU = {...S.dUtxo, value: 100_000n + 16n * (pool.D + pool.FEE)};
  const synth = (count) => { let d = new DState(); d.count = count; d.F = fr(count); for (const c of leaves) d = d.deposit(c); return d; };
  const run = (name, count, expect) => {
    const d = synth(count);
    if (expect === 'accept') {
      const t = flushTx(pool, {d, w: S.w, dUtxo: dU, wUtxo: S.wUtxo});
      // reference: the root from the frontier equals the root of the path computed directly
      const ok = acc('edge', `${name} (count ${count})`, t, ['D-flush', null, 'worker', 'worker', 'worker', 'worker']);
      res.costs.edge = [...(res.costs.edge ?? []), {count, ok, per: runTx(t, 'bchStd', {pool, roles: ['D-flush', null, 'worker', 'worker', 'worker', 'worker']}).ins.map((x) => x.pct)}];
      return t;
    }
    // count = 2^30: flushPlan still computes, the script refuses the count
    const d2 = synth(count - 16); const p = flushPlan(d2, S.w);
    const t = flushTx(pool, {d, w: S.w, dUtxo: dU, wUtxo: S.wUtxo, plan: p, t: {wit: (w) => ({...w, count, FR: d.FR()})}});
    return rej('edge', `${name} (count ${count})`, t, {rejecter: 0});
  };
  run('l0 = 29: bits 4..28 of count set', 2 ** 29 - 16, 'accept');
  run('count = 2^30 - 16: no zero bit, the tree becomes full (F\' all Z)', MAX_COUNT, 'accept');
  run('count = 2^30: the tree is full', 2 ** 30, 'reject');
  run('count = 0 (an empty tree)', 0, 'accept');
  // a queued leaf with a lane = p (only possible if a deposit had skipped the check): worker 1 rejects
  { let d = new DState(); d.count = 0; const bad = Buffer.from(leaves[3]); bad.writeBigUInt64LE(P, 0);
    for (const [i, c] of leaves.entries()) d = d.deposit(i === 3 ? bad : c);
    const p = flushPlan(d, S.w);
    rej('edge', 'a queued leaf with lane 0 = p (synthetic queue): worker 1 rejects (literal lane < p)', flushTx(pool, {d, w: S.w, dUtxo: dU, wUtxo: S.wUtxo, plan: p}), {rejecter: 2, others: 'accept'}); }
}

// ================================================================ summary
const fl = res.costs.flush, dp = res.costs.deposit;
res.summary = {
  seq: res.seqAll, wrap: res.wrap, failures: res.fail.length, cases: res.cases.length,
  deposit: {n: dp.length, bytes: [Math.min(...dp.map((x) => x.bytes)), Math.max(...dp.map((x) => x.bytes))], opD: [Math.min(...dp.map((x) => x.opD)), Math.max(...dp.map((x) => x.opD))], budgetD: dp[0].budgetD},
  flush: {n: fl.length, bytes: [Math.min(...fl.map((x) => x.bytes)), Math.max(...fl.map((x) => x.bytes))],
    perRole: ROLES.map((r, i) => ({role: r, unlocking: fl[0].per[i].unlocking, op: [Math.min(...fl.map((x) => x.per[i].op)), Math.max(...fl.map((x) => x.per[i].op))], pctMax: Math.max(...fl.map((x) => x.per[i].pct))}))},
  seconds: Math.round((Date.now() - t0) / 1000),
};
delete res.costs.deposit; res.costs.flushSample = fl.slice(0, 2);
writeFileSync(OUT, JSON.stringify(res, (_, v) => (typeof v === 'bigint' ? String(v) : v), 1) + '\n');
log(`test-d: ${res.fail.length ? 'FAIL' : 'PASS'}: ${res.cases.length} cases, ${res.fail.length} unexpected; seq ${res.seqAll}; wrap before ${res.wrap.before?.accepted} after ${JSON.stringify(res.wrap.after)}; ${res.summary.seconds} s`);
for (const [k, v] of Object.entries(res.families)) log(`  ${k}: ${v.ok}/${v.cases}`);
process.exitCode = res.fail.length ? 1 : 0;

void lanesOf; void WORKER_VALUE; void FUND_LOCKING; void TREE_DEPTH;
