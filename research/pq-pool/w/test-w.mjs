// Track 9 S1 acceptance (DESIGN-T9 sec. 6 S1):
//   1. SMT library vs the JS reference SMT (smt.mjs, an explicit node store): 10,000 random insert and
//      non-membership cases, keys drawn to cover long shared prefixes, neighbours, extremes and deep trees.
//      The script must accept exactly when the reference says the key is absent, and then its old and new roots
//      must equal the reference's roots before and after the insert (the harness checks both).
//   2. W covenant vs the reference on whole transactions (libauth BCH 2026 standard VM, every input plus the
//      transaction): random withdrawals from the genesis state, including NFs already spent (must be rejected).
//   3. Plain rejection families on W: NF + 1, a present key, wrong bitmap / L / sibling, ring, commitment carry-over,
//      output token/locking, value out, input graph. Each must be rejected by W's input while the stand-in R input
//      (input 0) still accepts, unless the family changes input 0 itself.
//   4. Costs: W input op-cost vs its budget (41 + unlocking) * 800, by tree size, plus constructed worst cases.
// usage: node test-w.mjs [--lib 10000] [--w 10000] [--seed 1]
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {SMT, Z, keyOf, nfBytes, encodeW, sha256, ringPath, lowBit, u64le} from './smt.mjs';
import {smtHarness, stubR} from './wcov.mjs';
import {genesis} from './genesis.mjs';
import {makePool, withdrawTx, runTx, honest, tokenOf, CATEGORY} from './wtx.mjs';
import {evaluate, pushes, p2sh32} from '../p2/vm.mjs';
import {encodeTransaction} from '@bitauth/libauth';
import {numBytes, asm} from '../p2/lib/asm.mjs';
import {P} from '../p2/p2gl8.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? +args[i + 1] : d; };
const NLIB = opt('--lib', 10_000), NW = opt('--w', 10_000), SEED = opt('--seed', 1);
const HERE = new URL('.', import.meta.url).pathname;

// deterministic PRNG (SHA-256 counter)
let ctr = 0;
const rnd64 = () => sha256(Buffer.from(`t9s1/${SEED}/${ctr++}`)).readBigUInt64LE(0);
const rndInt = (n) => Number(rnd64() % BigInt(n));
const rndLane = () => { for (;;) { const v = rnd64(); if (v < P) return v; } };
const rndNF = () => [rndLane(), rndLane(), rndLane(), rndLane()];
const M64 = (1n << 64n) - 1n;
const t0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s]`, ...a);

// ============================================================ 1. library agreement
function libCase(smt, K, kind) {
  const p = smt.path(K), present = smt.has(K), old = smt.root();
  let newRoot = old;
  if (!present) { smt.insert(K); newRoot = smt.root(); }
  const u = pushes([old, newRoot, p.sibs, p.bitmap, numBytes(p.L), u64le(K)]);
  const r = evaluate('looseCons', smtHarness(), u);
  return {present, accepted: r.accepted, agree: r.accepted === !present, opCost: r.opCost, count: p.count, L: p.L};
}
function libraryAgreement() {
  const out = {cases: 0, inserts: 0, present: 0, disagreements: [], byKind: {}, opCost: {min: Infinity, max: 0}, maxCount: 0, Ls: new Set()};
  const H = smtHarness();
  void H;
  const plan = [  // [tree preseed size, cases]
    [0, 1500], [0, 1500], [16, 1000], [256, 1000], [1024, 1000], [4096, 1500], [0, 1000], [64, 1500],
  ];
  const scale = NLIB / plan.reduce((a, [, c]) => a + c, 0);
  for (const [pre, c0] of plan) {
    const smt = new SMT();
    for (let i = 0; i < pre; i++) { const K = rnd64(); if (!smt.has(K)) smt.insert(K); }
    const keys = () => [...smt.keys];
    const n = Math.round(c0 * scale);
    for (let i = 0; i < n; i++) {
      const ks = keys();
      const pick = () => ks[rndInt(ks.length)];
      let kind = ['random', 'random', 'prefix', 'prefix', 'neighbour', 'flipbit', 'present', 'present', 'extreme'][rndInt(9)];
      if (!ks.length && kind !== 'random' && kind !== 'extreme') kind = 'random';
      let K;
      if (kind === 'random') K = rnd64();
      else if (kind === 'prefix') { const t = 1 + rndInt(63); const mask = (M64 >> BigInt(64 - t)) << BigInt(64 - t); K = (pick() & mask) | (rnd64() & ~mask & M64); }
      else if (kind === 'neighbour') K = pick() ^ 1n;
      else if (kind === 'flipbit') K = pick() ^ (1n << BigInt(rndInt(64)));
      else if (kind === 'present') K = pick();
      else K = [0n, M64, 1n, M64 - 1n, 1n << 63n][rndInt(5)];
      const r = libCase(smt, K, kind);
      out.cases++; r.present ? out.present++ : out.inserts++;
      const b = (out.byKind[kind] ??= {cases: 0, present: 0, agree: 0});
      b.cases++; if (r.present) b.present++; if (r.agree) b.agree++;
      if (!r.agree) out.disagreements.push({kind, K: K.toString(), present: r.present, accepted: r.accepted});
      if (r.accepted) { out.opCost.min = Math.min(out.opCost.min, r.opCost); out.opCost.max = Math.max(out.opCost.max, r.opCost); out.maxCount = Math.max(out.maxCount, r.count); out.Ls.add(r.L); }
    }
    log(`library: tree preseed ${pre}: ${out.cases} cases so far, ${out.disagreements.length} disagreements`);
  }
  out.Ls = [...out.Ls].sort((a, b) => a - b);
  out.distinctL = out.Ls.length; out.Lmin = out.Ls[0]; out.Lmax = out.Ls.at(-1); delete out.Ls;
  return out;
}

// ============================================================ shared W helpers
const g = genesis();
const pool = makePool();
const CTXW = sha256(Buffer.from('t9s1 ctx'));
const W0 = 100_000_000n;   // genesis funding: 100 D

function baseCase(smt, state, wValue, nf, slot) {
  const h = honest(smt, g.slots, slot, nf);
  const newSmt = h.present ? null : (() => { const c = cloneSMT(smt); c.insert(h.K); return c; })();
  return {h, args: {state, wValue, head: {ROOT: h.ROOT, NF: h.NF, CTXW}, wit: h.wit, newNfRoot: newSmt ? newSmt.root() : smt.root()}, newSmt};
}
function cloneSMT(s) { const c = new SMT(); c.nodes = new Map(s.nodes); c.keys = new Set(s.keys); return c; }

// ============================================================ 2. W agreement on whole transactions
function wAgreement() {
  const smt = new SMT(); let state = {...g.state}, wValue = W0 + BigInt(NW) * pool.D;
  const spent = [];
  const out = {cases: 0, withdrawals: 0, presentAttempts: 0, disagreements: [], opCost: {min: Infinity, max: 0}, worstPct: 0, maxBytes: 0, samples: []};
  for (let i = 0; i < NW; i++) {
    const present = spent.length > 0 && rndInt(4) === 0;
    const nf = present ? spent[rndInt(spent.length)] : rndNF();
    const slot = rndInt(2);   // the two genesis epochs
    const c = baseCase(smt, state, wValue, nf, slot);
    const r = runTx(withdrawTx(pool, c.args));
    const ok = r.tx === true && r.ins.every((x) => x.accepted);
    const expect = !c.h.present;
    out.cases++; present ? out.presentAttempts++ : out.withdrawals++;
    if (ok !== expect || (c.h.present !== present)) out.disagreements.push({i, present, accepted: ok, error: r.tx === true ? undefined : r.tx.slice(0, 200)});
    if (ok) {
      const w = r.ins[pool.wIdx];
      out.opCost.min = Math.min(out.opCost.min, w.opCost); out.opCost.max = Math.max(out.opCost.max, w.opCost);
      out.worstPct = Math.max(out.worstPct, +(100 * w.opCost / w.budget).toFixed(2)); out.maxBytes = Math.max(out.maxBytes, r.bytes);
      smt.insert(c.h.K); spent.push(nf); state = {...state, nfRoot: smt.root()}; wValue -= pool.D;
      if ([1, 2, 10, 100, 1000, 5000].includes(smt.size) || smt.size === NW) out.samples.push({spent: smt.size, siblings: c.h.wit.S.length / 32, L: c.h.wit.L, wUnlocking: w.unlocking, opCost: w.opCost, budget: w.budget, pct: +(100 * w.opCost / w.budget).toFixed(2), txBytes: r.bytes});
    }
    if ((i + 1) % 1000 === 0) log(`W: ${i + 1} cases, ${smt.size} spent, ${out.disagreements.length} disagreements`);
  }
  out.finalSpent = smt.size; out.finalValue = wValue.toString();
  return {out, smt, state, wValue, spent};
}

// ============================================================ 3. rejection families
function rejections(states) {
  const fams = [];
  const skipped = [];
  const txKey = (tx) => Buffer.from(encodeTransaction(tx.transaction)).toString('hex') + JSON.stringify(tx.sourceOutputs, (k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v));
  const add = (family, name, ctx, tamper, {expectIn0 = true, mkCase} = {}) => {
    const c = mkCase ? mkCase() : ctx.base();
    const t = tamper(c);
    if (t === null) { skipped.push({family, name, state: ctx.name, why: 'not applicable in this state'}); return; }
    const tx = withdrawTx(pool, {...c.args, ...(t.args ?? {}), t: t.t ?? {}});
    const noop = !mkCase && txKey(tx) === txKey(withdrawTx(pool, c.args));
    const r = runTx(tx);
    const wi = tx.sourceOutputs.findIndex((o) => Buffer.from(o.lockingBytecode).equals(Buffer.from(pool.locking)));
    const v = {tx: r.tx === true, in0: r.ins[0]?.accepted, w: r.ins[wi]?.accepted};
    const rejected = !v.tx && v.w === false;
    const ok = !noop && rejected && (!expectIn0 || v.in0 === true);
    fams.push({family, name, state: ctx.name, rejected, wIndex: wi, wRejected: v.w === false, in0Accepted: v.in0, noop, pass: ok, wError: r.ins[wi]?.error});
  };
  for (const ctx of states) {
    // control
    { const c = ctx.base(); const r = runTx(withdrawTx(pool, c.args)); fams.push({family: 'control', name: 'honest withdrawal', state: ctx.name, rejected: r.tx !== true, pass: r.tx === true}); }
    const flipByte = (b, i) => { const x = Buffer.from(b); x[i] ^= 0x01; return x; };
    const lanePlus = (nf32, lane) => { const x = Buffer.from(nf32); const v = (x.readBigUInt64LE(8 * lane) + 1n) % P; x.writeBigUInt64LE(v, 8 * lane); return x; };
    // NF
    add('nf', 'NF + 1 (lane 0) in HEAD, W witness and output for NF', ctx, (c) => ({args: {head: {...c.args.head, NF: lanePlus(c.h.NF, 0)}}}));
    add('nf', 'NF + 1 (lane 3) in HEAD, W witness and output for NF', ctx, (c) => ({args: {head: {...c.args.head, NF: lanePlus(c.h.NF, 3)}}}));
    add('nf', 'NF + 1 in HEAD with its own honest witness, output for NF', ctx, (c) => {
      const nf1 = [...ctx.nf]; nf1[0] = (nf1[0] + 1n) % P; const h1 = honest(ctx.smt, g.slots, ctx.slot, nf1);
      return {args: {head: {...c.args.head, NF: h1.NF}, wit: h1.wit}};
    });
    // present key
    if (ctx.spentNf) {
      add('present', 'NF already spent (its membership path)', ctx, () => ({}), {mkCase: () => baseCase(ctx.smt, ctx.state, ctx.wValue, ctx.spentNf, ctx.slot)});
      add('present', 'NF already spent, witness from before it was spent (stale state replay)', ctx, (c) => ({args: {wit: ctx.staleWit, newNfRoot: ctx.staleNew}}), {mkCase: () => baseCase(ctx.smt, ctx.state, ctx.wValue, ctx.spentNf, ctx.slot)});
    }
    // bitmap / L
    const setBits = (c) => { const bm = c.h.wit.B.readBigUInt64LE(0); return [...Array(64).keys()].filter((l) => (bm >> BigInt(l)) & 1n); };
    const withBm = (c, f) => { const b = Buffer.from(c.h.wit.B); b.writeBigUInt64LE(f(b.readBigUInt64LE(0)) & M64); return b; };
    add('bitmap', 'clear the highest set bit (siblings unchanged)', ctx, (c) => { const s = setBits(c); return s.length ? {args: {wit: {...c.h.wit, B: withBm(c, (x) => x ^ (1n << BigInt(s.at(-1)))), L: lowBit(withBm(c, (x) => x ^ (1n << BigInt(s.at(-1)))).readBigUInt64LE(0))}}} : {args: {wit: {...c.h.wit, B: withBm(c, (x) => x | 1n), L: 0}}}; });
    add('bitmap', 'set an unset bit above L (siblings unchanged)', ctx, (c) => { const bm = c.h.wit.B.readBigUInt64LE(0); const free = [...Array(64).keys()].filter((l) => l > c.h.wit.L && !((bm >> BigInt(l)) & 1n)); if (!free.length) return null; const l = free[free.length >> 1]; return {args: {wit: {...c.h.wit, B: withBm(c, (x) => x | (1n << BigInt(l)))}}}; });
    add('bitmap', 'set an unset bit below L, L unchanged (siblings unchanged)', ctx, (c) => (c.h.wit.L > 0 ? {args: {wit: {...c.h.wit, B: withBm(c, (x) => x | (1n << BigInt(c.h.wit.L - 1)))}}} : null));
    add('bitmap', 'set an unset bit below L, L moved to it (siblings unchanged)', ctx, (c) => (c.h.wit.L > 0 ? {args: {wit: {...c.h.wit, B: withBm(c, (x) => x | 1n), L: 0}}} : {args: {wit: {...c.h.wit, B: withBm(c, (x) => x | (1n << 63n))}}}));
    add('bitmap', 'set an unset bit and send Z as its sibling (non-canonical; L moved down if needed)', ctx, (c) => {
      const bm = c.h.wit.B.readBigUInt64LE(0); const free = [...Array(64).keys()].filter((k) => !((bm >> BigInt(k)) & 1n));
      if (!free.length) return null;
      const l = free.find((k) => k > c.h.wit.L) ?? free.at(-1);
      const before = [...Array(l).keys()].filter((k) => (bm >> BigInt(k)) & 1n).length;
      const S = Buffer.concat([c.h.wit.S.subarray(0, 32 * before), Z, c.h.wit.S.subarray(32 * before)]);
      return {args: {wit: {...c.h.wit, S, B: withBm(c, (x) => x | (1n << BigInt(l))), L: Math.min(l, c.h.wit.L)}}};
    });
    add('bitmap', 'L + 1', ctx, (c) => ({args: {wit: {...c.h.wit, L: c.h.wit.L + 1}}}));
    add('bitmap', 'L - 1 (or 63 when L = 0)', ctx, (c) => ({args: {wit: {...c.h.wit, L: c.h.wit.L ? c.h.wit.L - 1 : 63}}}));
    add('bitmap', 'L = 64 with the bitmap unchanged', ctx, (c) => (c.h.wit.L === 64 ? {args: {wit: {...c.h.wit, L: 65}}} : {args: {wit: {...c.h.wit, L: 64}}}));
    add('bitmap', 'bitmap 9 bytes', ctx, (c) => ({args: {wit: {...c.h.wit, B: Buffer.concat([c.h.wit.B, Buffer.alloc(1)])}}}));
    add('bitmap', 'bitmap 7 bytes', ctx, (c) => ({args: {wit: {...c.h.wit, B: c.h.wit.B.subarray(0, 7)}}}));
    // siblings
    add('sibling', 'flip one bit of the last sibling (or add one if none)', ctx, (c) => (c.h.wit.S.length ? {args: {wit: {...c.h.wit, S: flipByte(c.h.wit.S, c.h.wit.S.length - 5)}}} : {args: {wit: {...c.h.wit, S: sha256(Buffer.from('x'))}}}));
    add('sibling', 'flip one bit of the first sibling', ctx, (c) => (c.h.wit.S.length ? {args: {wit: {...c.h.wit, S: flipByte(c.h.wit.S, 3)}}} : {args: {wit: {...c.h.wit, S: Buffer.alloc(32, 1)}}}));
    add('sibling', 'swap the first two siblings', ctx, (c) => { const S = c.h.wit.S; return S.length >= 64 ? {args: {wit: {...c.h.wit, S: Buffer.concat([S.subarray(32, 64), S.subarray(0, 32), S.subarray(64)])}}} : null; });
    add('sibling', 'drop the last sibling', ctx, (c) => (c.h.wit.S.length ? {args: {wit: {...c.h.wit, S: c.h.wit.S.subarray(0, c.h.wit.S.length - 32)}}} : null));
    add('sibling', 'extra 32 B sibling at the end', ctx, (c) => ({args: {wit: {...c.h.wit, S: Buffer.concat([c.h.wit.S, sha256(Buffer.from('extra'))])}}}));
    add('sibling', 'extra 1 byte at the end', ctx, (c) => ({args: {wit: {...c.h.wit, S: Buffer.concat([c.h.wit.S, Buffer.from([7])])}}}));
    add('sibling', 'compressed path of another absent key', ctx, (c) => {
      for (let k = 0; k < 64; k++) { const K2 = c.h.K ^ (1n << BigInt(63 - k)); if (ctx.smt.has(K2)) continue; const o = ctx.smt.path(K2); if (!o.sibs.equals(c.h.wit.S) || !o.bitmap.equals(c.h.wit.B)) return {args: {wit: {...c.h.wit, S: o.sibs, B: o.bitmap, L: o.L}}}; }
      return null;   // every other key has the same path (empty set)
    });
    // ring
    add('ring', 'ROOT not in the ring (random lanes)', ctx, (c) => ({args: {head: {...c.args.head, ROOT: nfBytes(rndNF())}}}));
    add('ring', 'ROOT of the other epoch, path of this slot', ctx, (c) => ({args: {head: {...c.args.head, ROOT: g.slots[ctx.slot ^ 1]}}}));
    add('ring', 'wrong slot index (slot xor 1)', ctx, (c) => ({args: {wit: {...c.h.wit, slot: ctx.slot ^ 1}}}));
    add('ring', 'slot 16 (path of slot 0)', ctx, (c) => ({args: {wit: {...c.h.wit, slot: 16}}}));
    add('ring', 'slot -1', ctx, (c) => ({args: {wit: {...c.h.wit, slot: -1}}}));
    add('ring', 'flip one bit of a ring sibling', ctx, (c) => ({args: {wit: {...c.h.wit, HS: flipByte(c.h.wit.HS, 70)}}}));
    add('ring', 'ring siblings 96 B', ctx, (c) => ({args: {wit: {...c.h.wit, HS: c.h.wit.HS.subarray(0, 96)}}}));
    add('ring', 'ROOT = Z with the path of an empty slot (5)', ctx, (c) => ({args: {head: {...c.args.head, ROOT: Z}, wit: {...c.h.wit, slot: 5, HS: ringPath(g.slots, 5)}}}));
    // commitment carry-over (output 0)
    const com = (f) => ({t: {commitment: f}});
    add('carry', 'output nfRoot unchanged (old root)', ctx, () => ({args: {newNfRoot: ctx.state.nfRoot}}));
    add('carry', 'output nfRoot = root after inserting another key', ctx, (c) => { const x = cloneSMT(ctx.smt); x.insert(c.h.K ^ 2n); return {args: {newNfRoot: x.root()}}; });
    add('carry', 'histRoot changed (one bit)', ctx, () => com((x) => flipByte(x, 40)));
    add('carry', 'histRoot replaced by a ring with an extra root', ctx, () => com((x) => { const s = [...g.slots]; s[2] = nfBytes(rndNF()); const y = Buffer.from(x); Buffer.from(sha256(Buffer.alloc(0))).copy(y, 33); const r = Buffer.concat([y.subarray(0, 33), (() => { let lv = s.map((q) => Buffer.from(q)); while (lv.length > 1) lv = Array.from({length: lv.length / 2}, (_, i) => sha256(lv[2 * i], lv[2 * i + 1])); return lv[0]; })(), y.subarray(65)]); return r; }));
    add('carry', 'epoch + 1', ctx, () => com((x) => { const y = Buffer.from(x); y.writeUInt32LE(y.readUInt32LE(65) + 1, 65); return y; }));
    add('carry', 'prefix 0x44', ctx, () => com((x) => { const y = Buffer.from(x); y[0] = 0x44; return y; }));
    add('carry', 'one extra byte', ctx, () => com((x) => Buffer.concat([x, Buffer.from([0])])));
    add('carry', 'last byte dropped', ctx, () => com((x) => x.subarray(0, 68)));
    add('output', 'output 0 NFT immutable (capability none)', ctx, () => ({t: {outputs: (o) => [{...o[0], token: {...o[0].token, nft: {...o[0].token.nft, capability: 'none'}}}, ...o.slice(1)]}}));
    add('output', 'output 0 without the token (burned)', ctx, () => ({t: {outputs: (o) => [{lockingBytecode: o[0].lockingBytecode, valueSatoshis: o[0].valueSatoshis}, ...o.slice(1)]}}));
    add('output', 'token moved to output 1, output 0 plain', ctx, () => ({t: {outputs: (o) => [{lockingBytecode: o[0].lockingBytecode, valueSatoshis: o[0].valueSatoshis}, {...o[1], token: o[0].token}]}}));
    add('output', 'output 0 locking = another P2SH32', ctx, () => ({t: {outputs: (o) => [{...o[0], lockingBytecode: p2sh32(Uint8Array.of(0x51))}, ...o.slice(1)]}}));
    add('output', 'output 0 and 1 swapped', ctx, () => ({t: {outputs: (o) => [o[1], o[0]]}}));
    // value
    add('value', 'output 0 value = in - D + 1', ctx, () => ({t: {outputs: (o) => [{...o[0], valueSatoshis: o[0].valueSatoshis + 1n}, ...o.slice(1)]}}));
    add('value', 'output 0 value = in - D - 1', ctx, () => ({t: {outputs: (o) => [{...o[0], valueSatoshis: o[0].valueSatoshis - 1n}, ...o.slice(1)]}}));
    add('value', 'output 0 value = in', ctx, () => ({t: {outputs: (o) => [{...o[0], valueSatoshis: o[0].valueSatoshis + pool.D}, ...o.slice(1)]}}));
    add('value', 'output 0 value = in - 2D, payout 2D - fee', ctx, () => ({t: {outputs: (o) => [{...o[0], valueSatoshis: o[0].valueSatoshis - pool.D}, {...o[1], valueSatoshis: o[1].valueSatoshis + pool.D}]}}));
    // graph
    const otherR = asm({raw: stubR()}, 'NOP');
    add('graph', 'input 0 locked by another script (not R)', ctx, () => ({t: {tx: (x) => ({...x, sourceOutputs: [{...x.sourceOutputs[0], lockingBytecode: otherR}, x.sourceOutputs[1]]})}}), {expectIn0: false});
    add('graph', 'W at input 0, HEAD at input 1 (swapped)', ctx, () => ({t: {tx: (x) => ({...x, sourceOutputs: [x.sourceOutputs[1], x.sourceOutputs[0]], inputs: [x.inputs[1], x.inputs[0]]})}}), {expectIn0: false});
    add('graph', 'a third input (another R carrier)', ctx, () => ({t: {tx: (x) => ({...x, sourceOutputs: [...x.sourceOutputs, x.sourceOutputs[0]], inputs: [...x.inputs, {...x.inputs[0], outpointIndex: 7}]})}}));
    add('graph', 'W only (no HEAD input)', ctx, () => ({t: {tx: (x) => ({...x, sourceOutputs: [x.sourceOutputs[1]], inputs: [x.inputs[1]]})}}), {expectIn0: false});
    add('head', 'HEAD tail: an extra 1-byte push after CTXW (stand-in R also rejects)', ctx, () => ({t: {headPushes: (it) => [...it, Uint8Array.of(0x20)]}}), {expectIn0: false});
  }
  return {fams, skipped};
}

// ============================================================ 4. constructed cost cases
function costCases() {
  // W-level worst cases: the SMT state is just nfRoot, so the reference can hold arbitrary keys
  const nf = rndNF(), K = keyOf(nfBytes(nf));
  const mk = (name, keys) => {
    const smt = new SMT(); for (const k of keys) if (!smt.has(k) && k !== K) smt.insert(k);
    const state = {...g.state, nfRoot: smt.root()};
    const c = baseCase(smt, state, W0, nf, 0);
    const r = runTx(withdrawTx(pool, c.args)); const w = r.ins[pool.wIdx];
    return {name, keys: smt.size, siblings: c.h.wit.S.length / 32, L: c.h.wit.L, accepted: r.tx === true, wUnlocking: w.unlocking, opCost: w.opCost, budget: w.budget, pct: +(100 * w.opCost / w.budget).toFixed(2), txBytes: r.bytes};
  };
  return [
    mk('empty set (L = 64: loop A only)', []),
    mk('one key, the leaf neighbour K xor 1 (L = 0, 1 sibling: loop B over all 64 levels with the fewest bytes)', [K ^ 1n]),
    mk('one key K xor 2^63 (L = 63, 1 sibling)', [K ^ (1n << 63n)]),
    mk('64 keys K xor 2^l (every sibling present: 64 siblings)', [...Array(64).keys()].map((l) => K ^ (1n << BigInt(l)))),
    mk('2^12 random keys', Array.from({length: 4096}, () => rnd64())),
    mk('2^16 random keys', Array.from({length: 65536}, () => rnd64())),
  ];
}

// ============================================================ main
const res = {stage: 'Track 9 S1', what: 'SHA-256 SMT library + W-state covenant (static genesis history): agreement, rejections, costs',
  vm: 'libauth 3.1.0-next.8 BCH 2026 (standard for W transactions; looseCons for the bare library harness)', seed: SEED,
  redeemBytes: pool.redeem.length, smtHarnessBytes: smtHarness().length, D: pool.D.toString(), genesis: {histRoot: g.histRoot.toString('hex'), commitment: g.commitment.toString('hex')}};
res.library = libraryAgreement(); log('library done', res.library.disagreements.length, 'disagreements');
const wa = wAgreement(); res.w = wa.out; log('W agreement done', res.w.disagreements.length, 'disagreements');

// rejection contexts: genesis (empty set), after 1 spend, after the W agreement run (many spends)
const ctxOf = (name, smt, state, wValue, spentNf, slot) => {
  const nf = rndNF();
  const ctx = {name, smt, state, wValue, nf, slot, spentNf};
  ctx.base = () => baseCase(smt, state, wValue, nf, slot);
  if (spentNf) {   // stale witness: the spent NF's absence path from a state without it
    const before = new SMT(); for (const k of smt.keys) if (k !== keyOf(nfBytes(spentNf))) before.insert(k);
    const p = before.path(keyOf(nfBytes(spentNf))); const after = cloneSMT(before); after.insert(keyOf(nfBytes(spentNf)));
    ctx.staleWit = {S: p.sibs, B: p.bitmap, L: p.L, HS: ringPath(g.slots, slot), slot}; ctx.staleNew = after.root();
  }
  return ctx;
};
const s1 = new SMT(); const nf1 = rndNF(); s1.insert(keyOf(nfBytes(nf1)));
const small = new SMT(); const smallNfs = Array.from({length: 40}, () => rndNF()); for (const x of smallNfs) small.insert(keyOf(nfBytes(x)));
const ctxs = [
  ctxOf('genesis (empty set), slot 0', new SMT(), {...g.state}, W0, null, 0),
  ctxOf('1 spent, slot 1', s1, {...g.state, nfRoot: s1.root()}, W0 - pool.D, nf1, 1),
  ctxOf('40 spent, slot 0', small, {...g.state, nfRoot: small.root()}, W0 - 40n * pool.D, smallNfs[17], 0),
  ctxOf(`${wa.smt.size} spent (after the W run), slot 1`, wa.smt, wa.state, wa.wValue, wa.spent[3], 1),
];
const {fams, skipped} = rejections(ctxs);
const famSummary = {};
for (const f of fams) { const s = (famSummary[f.family] ??= {cases: 0, pass: 0}); s.cases++; if (f.pass) s.pass++; }
res.rejections = {summary: famSummary, failures: fams.filter((f) => !f.pass), skipped, cases: fams};
log('rejections', JSON.stringify(famSummary));

// double spend in sequence: withdraw NF, then the same NF again from the new state
{
  const smt = new SMT(); const nf = rndNF();
  const c1 = baseCase(smt, {...g.state}, W0, nf, 0); const r1 = runTx(withdrawTx(pool, c1.args));
  const state2 = {...g.state, nfRoot: c1.newSmt.root()};
  const c2 = baseCase(c1.newSmt, state2, W0 - pool.D, nf, 1); const r2 = runTx(withdrawTx(pool, c2.args));
  // and the first transaction's W witness replayed against the new state
  const r3 = runTx(withdrawTx(pool, {...c1.args, state: state2, wValue: W0 - pool.D}));
  res.sequenceDoubleSpend = {first: r1.tx === true, second: r2.tx === true, replayFirstWitness: r3.tx === true, pass: r1.tx === true && r2.tx !== true && r3.tx !== true};
}
res.costs = costCases(); log('costs', JSON.stringify(res.costs.map((c) => [c.siblings, c.L, c.opCost, c.pct])));
res.pass = res.library.disagreements.length === 0 && res.w.disagreements.length === 0 && res.rejections.failures.length === 0 && res.sequenceDoubleSpend.pass && res.costs.every((c) => c.accepted);
res.seconds = Math.round((Date.now() - t0) / 1000);
fs.mkdirSync(HERE + 'results', {recursive: true});
fs.writeFileSync(HERE + 'results/s1-w.json', JSON.stringify(res, (k, v) => (typeof v === 'bigint' ? v.toString() : v === Infinity ? null : v), 1) + '\n');
log('PASS', res.pass);
void createHash; void encodeW; void tokenOf; void CATEGORY;
