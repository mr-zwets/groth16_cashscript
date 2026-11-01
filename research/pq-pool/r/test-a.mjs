#!/usr/bin/env node
// Track 9 S2 (copy of Track 8 onchain/test-a.mjs, adapted to the pool R): production runs use the 2-transaction a'
// plan with the W-state input as tx1's last input (wIdx = 5) and output 0 = the next W state; CTX is computed over
// outputs [1..] (the statement's payouts); ROOT is a HEAD push. Every Track 8 S7 family is kept (the tx and thread
// families now change the payouts, output 1.., where Track 8 changed output 0); the root family tampers the HEAD
// push. --pool adds the DESIGN-T9 S2 families (poolCases below): ring, nf (same NF twice: in sequence and in
// conflicting transactions), windex (W at the wrong index or missing), commit (output-0 commitment), out0 (output 0
// changes do not touch CTX; outputs >= 1 do), wonly (W without R), and 'documented' (a non-W input at the W slot:
// R alone accepts; no pool funds move). Pool cases name the input that must reject (W, HEAD or any) and check that
// every other input of tx1 accepts under today's standard rules.
// --harness runs the 1-transaction plan without W (CTX a witness item) on S3's generic cap-5 case files.
// Track 8 header follows.
// test-a.mjs: layout a' (today's standard rules, Track 8 S7) accept/reject sweep over case files in the S3
// gen-cases.mjs format, plus the a' layout and thread families on each valid proof. Every case gets three verdicts
// that must all equal the expected one:
//   chain  the generated transaction(s) on libauth BCH 2026 (valid: every input standard and consensus, and libauth's
//          whole-transaction verification, today's rules; reject cases: the loose VM, so that a reject is a failed
//          check and not a resource limit; a plan is accepted only if every input of every transaction is)
//   model  modela.mjs (the on-chain algorithm in JS)
//   ref    ../verifier/verify-batch.mjs (S3 reference)
// Families added here (DESIGN-T8 §7 S7, §8 layout): constants (tampered HEAD/FIN/CODE constants: TBL, ACC, CTXW),
// input (witness manipulations of one input), graph (input order, count, locking, code), mix (inputs from another
// proof: cross-input and cross-transaction mixing), thread (2-transaction plan: NFT commitment, category,
// capability, replays), tx (outputs changed, so CTX differs), root (another script ROOT).
// usage: node test-a.mjs [--plan 1tx|2tx] [--harness] [--layout] [--out FILE] CASEFILE...
//   --harness  CTX is a witness item (S3's generic cap-5 case files, whose statements are not transaction-bound)
import {writeFileSync, existsSync} from 'node:fs';
import {readVector} from '../../pq-stark-batch/onchain/layoutn.mjs';
import {vkxA, verifyModelA, encodeA, P, sha} from '../../pq-stark-batch/onchain/modela.mjs';
import {applyTamper} from '../../pq-stark-batch/onchain/modeln.mjs';
import {makePlanA, spendA, evaluateTxA, verifyTxA, CATEGORY, programA} from './layouta.mjs';
import {poolOf, genesisState, wSpend, nextState, G as GEN} from './pool.mjs';
import {keyOf, nfBytes} from '../w/smt.mjs';
import {threadCommit} from './gena.mjs';
import {runCase, vkFromVector, parse as strictParse} from '../../pq-stark-batch/verifier/verify-batch.mjs';
import {ctxOf} from './ctx.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const HARNESS = args.includes('--harness'), LAYOUT = args.includes('--layout'), PLAN = opt('--plan', HARNESS ? '1tx' : '2tx');
const POOL = args.includes('--pool'), T8DIR = opt('--t8', null);   // T8DIR: Track 8 S7 vectors (valid proofs, ROOT not in the ring)
const WITH_W = !HARNESS;
const outFile = opt('--out', null);
const files = args.filter((a, i) => !a.startsWith('--') && !['--out', '--plan', '--t8'].includes(args[i - 1]));
const M64 = 1n << 64n;
// the statement's outputs [1..] (payouts); output 0 is built from the W state per run
const outputsOf = (v) => (v.t9_payouts ?? v.s4_outputs ?? [{lockingBytecode: '76a914' + '00'.repeat(20) + '88ac', valueSatoshis: '900000'}]).map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));   // payout list
const altTx1 = (outs) => outs.map((o, i) => (i === 1 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));       // full tx1 outputs
const countsOf = (vk, which) => { const per = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i)); return which === '1tx' ? [per] : [per.slice(0, -1), per.slice(-1)]; };
const planOf = (vk) => makePlanA(vk, countsOf(vk, PLAN), HARNESS ? {ctx: 'witness'} : {w: true});

const stats = {plan: PLAN, harness: HARNESS, files: 0, cases: 0, unexpected: 0, na: 0, refused: 0, encoderOnly: 0, malformed: 0, families: {}, list: [], skippedFiles: []};
const fam = (f) => (stats.families[f] ??= {cases: 0, chainReject: 0, accept: 0, unexpected: 0});
// kind: undefined (the chain ran), 'notRun' (the statement layer or the generator short-circuits: no script runs, the
// case is counted apart, not as a chain rejection), 'encoderOnly' (malformed p3b-v1 that the encoder refuses; the
// script sees the valid proof's witness and accepts; expect relabelled to true; counted apart from the totals)
function record(file, family, name, expect, chain, model, ref, extra = '', kind) {
  const F = fam(family); F.cases++; stats.cases++;
  const ok = chain === expect && (model === null || model === expect) && (ref === null || ref === expect);
  if (kind === 'notRun') { F.notRunOnChain = (F.notRunOnChain ?? 0) + 1; stats.notRunOnChain = (stats.notRunOnChain ?? 0) + 1; }
  else if (kind === 'encoderOnly') { F.encoderOnlyRelabel = (F.encoderOnlyRelabel ?? 0) + 1; stats.encoderOnlyRelabel = (stats.encoderOnlyRelabel ?? 0) + 1; }
  else if (chain) F.accept++; else F.chainReject++;
  if (!ok) { F.unexpected++; stats.unexpected++; stats.list.push({file, family, name, expect, chain, model, ref, extra, kind}); }
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${file} [${family}] ${name}: chain ${kind === 'notRun' ? 'NOT RUN (reject)' : chain ? 'ACCEPT' : 'reject'}${model === null ? '' : ` model ${model ? 'ACCEPT' : 'reject'}`}${ref === null ? '' : ` ref ${ref ? 'ACCEPT' : 'reject'}`} ${extra}`);
}
// the chain verdict of a plan: valid -> bchStd + bchCons on every input and whole-tx verify; reject -> loose VM
// pool: tx1 = [out0 (from the W state), ...payouts]; W spends ROOT/NF of pis from o.state (default: genesis)
const POOLS = new Map();
const poolFor = (vk, plan, pis) => { const pg = programA(vk, pis, plan); if (!POOLS.has(pg)) POOLS.set(pg, poolOf(pg)); return POOLS.get(pg); };
function withW(vk, plan, pis, outs, o) {
  if (!WITH_W) return {outs, o};
  const ws = wSpend(poolFor(vk, plan, pis), o.state ?? genesisState(), pis.slice(0, 4), pis.slice(4, 8), o.wT ?? {});
  return {outs: [ws.out0, ...outs], o: {...o, w: o.noW ? undefined : ws.w}, ws};
}
function chainRun(vk, plan, buf, pis, outs0, expectValid, {mutate, txMutate, ...o0} = {}) {
  const {outs, o, ws} = withW(vk, plan, pis, outs0, o0);
  const sp = spendA(vk, plan, buf, pis, outs, o, mutate);
  sp.ws = ws;
  let txs = sp.txs;
  if (txMutate) txs = txMutate(txs.map((tx) => ({...tx, transaction: {...tx.transaction, inputs: [...tx.transaction.inputs], outputs: [...tx.transaction.outputs]}, sourceOutputs: [...tx.sourceOutputs]})), sp) ?? txs;
  let acc = true, err = null;
  for (const [t, tx] of txs.entries()) {
    if (expectValid) {
      for (const vm of ['bchStd', 'bchCons']) { const r = evaluateTxA(tx, vm); const bad = r.findIndex((x) => !x.accepted); if (bad >= 0) { acc = false; err ??= `tx${t} in${bad} ${vm}: ${r[bad].error}`; } }
      if (acc) { const w = verifyTxA(tx, 'bchStd'); if (w !== true) { acc = false; err = `tx${t} whole-tx: ${w}`; } }
    } else {
      const r = evaluateTxA(tx, 'looseStd', {stopAtReject: true}); const bad = r.findIndex((x) => !x.accepted);
      if (bad >= 0) { acc = false; err = `tx${t} in${bad}: ${r[bad].error}`; break; }
    }
  }
  return {acc, err, sp, txs};
}
const same = (wa, wb) => wa.length === wb.length && wa.every((tx, t) => tx.length === wb[t].length && tx.every((it, i) => it.length === wb[t][i].length && it.every((x, k) => Buffer.compare(Buffer.from(x), Buffer.from(wb[t][i][k])) === 0)));
const flip = (b, at) => { const c = Buffer.from(b); c[at < 0 ? c.length + at : at] ^= 1; return c; };
const cloneWit = (w) => w.map((tx) => tx.map((it) => it.map((x) => Buffer.from(x))));

// ---------------- the a' layout families on one valid proof ----------------
function layoutCases(vk, plan, v, file, dir, base, outs) {
  const C = []; const add = (family, nm, o) => C.push({family, nm, ...o});
  const nc = plan.nc, FIN = nc + 1, Q0 = nc + 2, T = plan.txs.length;
  const hItems = programA(vk, base, plan).hItems;
  const hIdx = (k) => hItems.findIndex(([x]) => x === k);
  const m = (f) => (w) => { const x = cloneWit(w); f(x); return x; };
  // constants: TBL fields (FIN checks its own push), ACC (each CODE input checks its own), CTXW (final HEAD)
  let o = 0;
  for (const [nm, n, w] of vk.tblLayout) {
    const at = o; o += n * w;
    add('constants', `FIN: TBL field ${nm} byte 0 flipped`, {mutate: m((x) => { x[0][FIN][1] = flip(x[0][FIN][1], at); })});
    if (nm === 'idx') add('constants', 'FIN: TBL idx_0 replaced by idx_1 (another valid index)', {mutate: m((x) => { const b = Buffer.from(x[0][FIN][1]); b.copy(b, 0, w, 2 * w); x[0][FIN][1] = b; })});
  }
  add('constants', 'FIN: TBL truncated by one byte', {mutate: m((x) => { x[0][FIN][1] = x[0][FIN][1].subarray(0, -1); })});
  add('constants', 'FIN: TBL extended by one byte', {mutate: m((x) => { x[0][FIN][1] = Buffer.concat([x[0][FIN][1], Buffer.alloc(1)]); })});
  for (let j = 1; j <= nc; j++) add('constants', `CODE ${j}: ACC byte 3 flipped`, {mutate: m((x) => { x[0][j][1] = flip(x[0][j][1], 3); })});
  add('constants', 'CODE 1 and CODE 2: ACC values swapped', {mutate: m((x) => { [x[0][1][1], x[0][2][1]] = [x[0][2][1], x[0][1][1]]; })});
  // ACC_1 + delta and ACC_2 - alpha^(C - hi_1) delta: HEAD's sum still holds; each CODE input checks its own push
  add('constants', 'CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged)', {mutate: (w, enc) => {
    const F = vk.F, t = enc.t; const x = cloneWit(w);
    const rd = (b) => [0, 1, 2].map((k) => b.readBigUInt64LE(8 * k));
    const wr = (a) => Buffer.concat(a.map((y) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(y); return b; }));
    const a1 = rd(x[0][1][1]), a2 = rd(x[0][2][1]);
    const e = BigInt(vk.C - plan.parts[0][1]);
    const d = F.lift(1n);
    x[0][1][1] = wr(F.add(a1, d)); x[0][2][1] = wr(F.sub(a2, F.mul(d, F.pow(t.alpha, e))));
    return x;
  }});
  add('constants', 'CODE 1: ACC push missing', {mutate: m((x) => { x[0][1] = [x[0][1][0]]; })});
  add('constants', 'HEAD: CTXW lane 0 byte 0 flipped', {mutate: m((x) => { for (const tx of x) tx[0][hIdx('CTXW')] = flip(tx[0][hIdx('CTXW')], 0); })});
  add('constants', 'HEAD: NF lane 0 byte 0 flipped', {mutate: m((x) => { for (const tx of x) tx[0][hIdx('NF')] = flip(tx[0][hIdx('NF')], 0); })});
  add('constants', 'HEAD: ROOT lane 0 byte 0 flipped (Track 9: ROOT is a HEAD push)', {mutate: m((x) => { for (const tx of x) tx[0][hIdx('ROOT')] = flip(tx[0][hIdx('ROOT')], 0); })});
  add('constants', 'HEAD: ROOT lane 3 byte 7 flipped in tx1 only', {mutate: m((x) => { const t = x.length - 1; x[t][0][hIdx('ROOT')] = flip(x[t][0][hIdx('ROOT')], 31); })});
  add('input', 'HEAD: ROOT push missing (NF, CTXW shift down)', {mutate: m((x) => { x[0][0].splice(hIdx('ROOT'), 1); })});
  // HEAD and FIN proof data
  for (const [k, at] of [['ROOTS', 5], ['ROOTS', vk.capOff.quotient + 32 * 17 + 2], ['ROOTS', vk.capOff.random + 9], ['OOD', 100], ['BPOW', 0], ['FROOTS', 32 * 31], ['CPOW', 0], ['QPOW', 0]]) add('input', `HEAD: ${k} byte ${at} flipped`, {mutate: m((x) => { x[0][0][hIdx(k)] = flip(x[0][0][hIdx(k)], at); })});
  add('input', 'FIN: final polynomial byte flipped', {mutate: m((x) => { x[0][FIN][0] = flip(x[0][FIN][0], 1000); })});
  add('input', 'HEAD: extra empty item', {mutate: m((x) => { x[0][0].push(Buffer.alloc(0)); })});
  add('input', 'HEAD: CTXW missing', {mutate: m((x) => { x[0][0].pop(); })});
  // QRY inputs
  const hintOff = vk.blob.total - 8;
  add('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][0]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q0][0] = b; })});
  add('input', 'QRY: hint T of another query', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][0]); x[0][Q0][2].copy(b, hintOff, hintOff, hintOff + 8); x[0][Q0][0] = b; })});
  add('input', 'QRY: L byte (trace row) flipped', {mutate: m((x) => { x[0][Q0][0] = flip(x[0][Q0][0], 3); })});
  add('input', 'QRY: L byte (FRI sibling value) flipped', {mutate: m((x) => { x[0][Q0][0] = flip(x[0][Q0][0], vk.blob.total - 8 - 40); })});
  add('input', 'QRY: path byte (input tree) flipped', {mutate: m((x) => { x[0][Q0][1] = flip(x[0][Q0][1], 100); })});
  add('input', 'QRY: path byte (FRI tree, last level below the cap) flipped', {mutate: m((x) => { x[0][Q0][1] = flip(x[0][Q0][1], -5); })});
  add('input', 'QRY: two queries swapped inside an input', {mutate: m((x) => { const a = x[0][Q0]; [a[0], a[2]] = [a[2], a[0]]; [a[1], a[3]] = [a[3], a[1]]; })});
  add('input', 'QRY: L and path swapped', {mutate: m((x) => { const a = x[0][Q0]; [a[0], a[1]] = [a[1], a[0]]; })});
  add('input', 'QRY: last query (L, path) missing', {mutate: m((x) => { x[0][Q0] = x[0][Q0].slice(0, -2); })});
  add('input', 'QRY: extra empty push', {mutate: m((x) => { x[0][Q0].push(Buffer.alloc(0)); })});
  add('input', 'QRY: paths of two queries swapped', {mutate: m((x) => { const a = x[0][Q0]; [a[1], a[3]] = [a[3], a[1]]; })});
  add('input', 'QRY: two QRY inputs swapped (witnesses)', {mutate: m((x) => { [x[0][Q0], x[0][Q0 + 1]] = [x[0][Q0 + 1], x[0][Q0]]; })});
  // the input graph and the code
  add('graph', 'CODE 1: code blob byte flipped', {mutate: m((x) => { x[0][1][0] = flip(x[0][1][0], 500); })});
  add('graph', 'CODE 2: code blob truncated by one byte', {mutate: m((x) => { x[0][2][0] = x[0][2][0].subarray(0, -1); })});
  const swapIn = (a, b) => (txs) => { const tx = txs[0]; const i = tx.transaction.inputs; [i[a], i[b]] = [i[b], i[a]]; [tx.sourceOutputs[a], tx.sourceOutputs[b]] = [tx.sourceOutputs[b], tx.sourceOutputs[a]]; return txs; };
  add('graph', 'inputs HEAD and FIN swapped (order)', {txMutate: swapIn(0, FIN)});
  add('graph', 'inputs CODE 1 and CODE 2 swapped (order)', {txMutate: swapIn(1, 2)});
  add('graph', 'two QRY inputs swapped (order)', {txMutate: swapIn(Q0, Q0 + 1)});
  add('graph', 'one input with another locking (R + one byte)', {txMutate: (txs) => { const so = txs[0].sourceOutputs; so[Q0] = {...so[Q0], lockingBytecode: Uint8Array.from([...so[Q0].lockingBytecode, 0x61])}; return txs; }});
  add('graph', 'extra input (a copy of a QRY input)', {txMutate: (txs) => { const tx = txs[0]; tx.transaction.inputs.push({...tx.transaction.inputs[Q0], outpointIndex: 99}); tx.sourceOutputs.push(tx.sourceOutputs[Q0]); return txs; }});
  add('graph', 'last QRY input missing', {txMutate: (txs) => { const tx = txs[0]; tx.transaction.inputs.pop(); tx.sourceOutputs.pop(); return txs; }});
  // mixing: inputs from another proof
  const others = [];
  const seed2 = `${dir}/${file.replace(/\.json$/, '-seed2.json')}`;
  if (existsSync(seed2)) others.push(['another proof of the same statement (other ZK seed)', seed2]);
  const nb = file.replace(/-(\d+)-Z128_cap5\.json$/, (_, i) => `-${(+i + 1) % 24}-Z128_cap5.json`);
  if (nb !== file && existsSync(`${dir}/${nb}`)) others.push(['another statement', `${dir}/${nb}`]);
  for (const [label, path] of others) {
    const ov = readVector(path), op = ov.public_values.flat().map(BigInt);
    const ow = () => spendA(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outs).wit;
    add('mix', `HEAD from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][0] = y[0][0]; return x; }});
    add('mix', `FIN from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][FIN] = y[0][FIN]; return x; }});
    add('mix', `HEAD and FIN from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][0] = y[0][0]; x[0][FIN] = y[0][FIN]; return x; }});
    add('mix', `ACC of CODE 1 from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][1][1] = y[0][1][1]; return x; }});
    add('mix', `one QRY input from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][Q0 + 1] = y[0][Q0 + 1]; return x; }});
    if (T > 1) add('mix', `transaction 1 (all inputs) from ${label}, the NFT of this proof (replay)`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[1] = y[1]; return x; }});
    if (label.startsWith('another proof')) {
      add('control', `control: ${label} verifies on its own (same VK)`, {other: [ov, op], expect: true});
    }
  }
  // thread (2-transaction plans): the NFT links tx0 to tx k
  if (T > 1) {
    const tok = (cap, commit, cat = CATEGORY) => ({amount: 0n, category: Uint8Array.from(cat).reverse(), nft: {capability: cap, commitment: Uint8Array.from(commit)}});
    const setIn0 = (t, f) => (txs, sp) => { const so = txs[t].sourceOutputs; so[0] = {...so[0], token: f(so[0].token, sp)}; if (f.null) delete so[0].token; return txs; };
    const G = () => null;
    void G;
    add('thread', 'tx1: spends an NFT minted for another proof (commitment of another G)', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('none', threadCommit(sha(Buffer.from('another proof')), 1))}; return txs; }});
    add('thread', 'tx1: NFT commitment index byte 2 (k = 2)', {txMutate: (txs, sp) => { const so = txs[1].sourceOutputs; const c = Buffer.from(so[0].token.nft.commitment); c[0] = 2; so[0] = {...so[0], token: tok('none', c)}; return txs; }});
    add('thread', 'tx1: NFT of another category', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('none', so[0].token.nft.commitment, flip(CATEGORY, 0))}; return txs; }});
    add('thread', 'tx1: input 0 NFT is mutable', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('mutable', so[0].token.nft.commitment)}; return txs; }});
    add('thread', 'tx1: input 0 without the NFT', {txMutate: (txs) => { const so = txs[1].sourceOutputs; const {token, ...rest} = so[0]; void token; so[0] = rest; return txs; }});
    add('thread', 'tx1: the NFT passed on to an extra output', {txMutate: (txs) => { const tx = txs[1]; tx.transaction.outputs.push({lockingBytecode: tx.sourceOutputs[0].lockingBytecode, valueSatoshis: 5000n, token: tx.sourceOutputs[0].token}); return txs; }});
    add('thread', 'tx1: another input carries a token of the category', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[1] = {...so[1], token: {amount: 1n, category: Uint8Array.from(CATEGORY).reverse()}}; return txs; }});
    add('thread', 'tx1: outputs changed (payout value - 1, so CTX differs)', {txMutate: (txs) => { const tx = txs[1]; tx.transaction.outputs = altTx1(tx.transaction.outputs); return txs; }});
    if (WITH_W) add('thread', 'tx1: the thread NFT moved to output 0 (in place of the W-state output)', {txMutate: (txs) => { const tx = txs[1]; tx.transaction.outputs[0] = {lockingBytecode: tx.sourceOutputs[0].lockingBytecode, valueSatoshis: 5000n, token: tx.sourceOutputs[0].token}; return txs; }});
    add('thread', 'tx1: a QRY input of tx0 (queries 0-2) instead of its own', {mutate: m((x) => { x[1][Q0] = x[0][Q0]; })});
    add('thread', 'tx0: baton returned to another locking', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o[0] = {...o[0], lockingBytecode: Uint8Array.from([0x6a])}; return txs; }});
    add('thread', 'tx0: baton not returned (output 0 is the NFT only)', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o.shift(); return txs; }});
    add('thread', 'tx0: thread NFT with another commitment', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o[1] = {...o[1], token: tok('none', flip(o[1].token.nft.commitment, 5))}; return txs; }});
    add('thread', 'tx0: thread NFT minted mutable', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o[1] = {...o[1], token: tok('mutable', o[1].token.nft.commitment)}; return txs; }});
    add('thread', 'tx0: an extra NFT minted (extra token output)', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o.push({...o[1]}); return txs; }});
    add('thread', 'tx0: input 0 without the minting baton', {txMutate: (txs) => { const so = txs[0].sourceOutputs; const {token, ...rest} = so[0]; void token; so[0] = rest; return txs; }});
    void setIn0;
  }
  return C;
}


// ---------------- DESIGN-T9 S2 pool families (production, 2-transaction plan with W) ----------------
// tx1's inputs on today's standard rules: accept = bchStd accepts; reject = looseStd rejects too (a failed check, not a
// resource limit); 'limit' (bchStd rejects, loose accepts) never passes an expectation.
function verdicts(tx) {
  const std = evaluateTxA(tx, 'bchStd');
  return std.map((r, i) => {
    if (r.accepted) return 'accept';
    const l = evaluateTxA({...tx}, 'looseStd').at(i);
    return l.accepted ? 'limit' : 'reject';
  });
}
// build tx0 + tx1 (W from `state`), apply tx1 hooks, return {txs, v1 (tx1 verdicts), whole1, wIdx}
function poolTxs(vk, plan, buf, pis, payouts, {state, wT, tx1, outs1, noW} = {}) {
  const {outs, o} = withW(vk, plan, pis, payouts, {state, wT, noW});
  const sp = spendA(vk, plan, buf, pis, outs1 ? outs1(outs) : outs, o);
  let t1 = {...sp.txs[1], transaction: {...sp.txs[1].transaction, inputs: [...sp.txs[1].transaction.inputs], outputs: [...sp.txs[1].transaction.outputs]}, sourceOutputs: [...sp.txs[1].sourceOutputs]};
  if (tx1) t1 = tx1(t1) ?? t1;
  return {txs: [sp.txs[0], t1], sp};
}
// expect: {accept: true} (every input of both transactions on bchStd and bchCons, whole-tx verify) or
// {rejecter: 'W' | 'HEAD' | 'any', others: 'accept' | null}: tx1's input `rejecter` rejects; with others = 'accept'
// every other tx1 input accepts (shows which script enforces the rule)
function poolCheck(file, family, name, built, expect) {
  const [tx0, tx1] = built.txs;
  if (expect.accept) {
    let ok = true, err = '';
    for (const [t, tx] of [tx0, tx1].entries()) for (const vm of ['bchStd', 'bchCons']) { const r = evaluateTxA(tx, vm); const b = r.findIndex((x) => !x.accepted); if (b >= 0 && ok) { ok = false; err = `tx${t} in${b} ${vm}: ${r[b].error}`; } }
    if (ok) for (const [t, tx] of [tx0, tx1].entries()) { const w = verifyTxA(tx, 'bchStd'); if (w !== true && ok) { ok = false; err = `tx${t} whole: ${w}`; } }
    record(file, family, name, true, ok, null, null, ok ? `(tx1 ${tx1.txBytes} B)` : err.slice(0, 100));
    return ok;
  }
  const v = verdicts(tx1);
  const n = tx1.transaction.inputs.length;
  const wAt = tx1.sourceOutputs.findIndex((so) => so.token && Buffer.from(so.token.category).reverse().equals(Buffer.from(POOL_CAT)));
  const idx = expect.rejecter === 'W' ? wAt : expect.rejecter === 'HEAD' ? 0 : -1;
  let ok;
  if (expect.rejecter === 'any') ok = v.some((x) => x === 'reject') && !v.includes('limit');
  else ok = idx >= 0 && v[idx] === 'reject' && (expect.others !== 'accept' || v.every((x, i) => i === idx || x === 'accept'));
  record(file, family, name, false, ok ? false : true, null, null, `tx1 inputs: ${v.map((x, i) => `${i === wAt ? 'W' : i}:${x[0]}`).join(' ')}${ok ? '' : ` (expected ${expect.rejecter} rejects${expect.others ? ', others accept' : ''})`}`);
  return ok;
}
let POOL_CAT = null;
function poolCases(vk, plan, v, file, dir, base, payouts) {
  const buf = Buffer.from(v.proof_hex, 'hex');
  const pool = poolFor(vk, plan, base); POOL_CAT = pool.CAT;
  const G0 = genesisState();
  const K = keyOf(nfBytes(base.slice(4, 8)));
  const note = GEN.notes[v.t9_note];
  const run = (family, name, opts, expect) => poolCheck(file, family, name, poolTxs(vk, plan, buf, base, payouts, opts), expect);
  // valid from genesis, then the state after it
  const first = poolTxs(vk, plan, buf, base, payouts, {state: G0});
  if (!poolCheck(file, 'nf', 'first withdrawal from the genesis state (accepted)', first, {accept: true})) return;
  const S1 = nextState(G0, K, first.txs[1]);
  // ring
  run('ring', 'W: ring path of the other epoch slot (ROOT is in the ring, wrong slot)', {state: G0, wT: {slot: 1 - note.slot}}, {rejecter: 'W', others: 'accept'});
  run('ring', 'W: ring slot 2 (an empty slot, Z)', {state: G0, wT: {slot: 2}}, {rejecter: 'W', others: 'accept'});
  if (T8DIR) {
    const k = +file.match(/-(\d+)-Z128_cap5\.json$/)[1];
    const t8 = `${T8DIR}/m1-s7-${k}-Z128_cap5.json`;
    if (existsSync(t8)) {
      const ov = readVector(t8), op = ov.public_values.flat().map(BigInt);
      const opay = ov.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
      const b = poolTxs(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, opay, {state: G0});
      poolCheck(file, 'ring', `a valid proof whose ROOT is not in the ring (Track 8 S7 statement ${k}, same VK; CTX = its payout as output 1)`, b, {rejecter: 'W', others: 'accept'});
    }
  }
  // same NF twice, in sequence
  run('nf', 'same proof again after the first withdrawal (state S1: NF present)', {state: S1}, {rejecter: 'W', others: 'accept'});
  run('nf', 'same proof again, stale W witness (absence path from the genesis state) on S1', {state: S1, wT: {wItems: () => wSpend(pool, G0, base.slice(0, 4), base.slice(4, 8)).w.items}}, {rejecter: 'W', others: 'accept'});
  const seed2 = `${dir}/${file.replace(/\.json$/, '-seed2.json')}`;
  if (existsSync(seed2)) {
    const ov = readVector(seed2), op = ov.public_values.flat().map(BigInt), ob = Buffer.from(ov.proof_hex, 'hex');
    poolCheck(file, 'nf', 'another proof of the same note (other ZK seed) after the first withdrawal (S1)', poolTxs(vk, plan, ob, op, payouts, {state: S1}), {rejecter: 'W', others: 'accept'});
    // conflicting: both tx1 spend the same W outpoint from G0; each is valid alone; the loser fails on the winner's state
    const a = first, b = poolTxs(vk, plan, ob, op, payouts, {state: G0});
    const okB = poolCheck(file, 'nf', 'conflicting: the other-seed proof\'s tx1 on the same genesis W outpoint is valid alone', b, {accept: true});
    const sameOut = (x, y) => Buffer.from(x.transaction.inputs.at(-1).outpointTransactionHash).equals(Buffer.from(y.transaction.inputs.at(-1).outpointTransactionHash)) && x.transaction.inputs.at(-1).outpointIndex === y.transaction.inputs.at(-1).outpointIndex;
    record(file, 'nf', 'conflicting: both tx1 spend the same W outpoint (at most one confirms)', true, okB && sameOut(a.txs[1], b.txs[1]), null, null);
    const Sb = nextState(G0, K, b.txs[1]);
    run('nf', 'conflicting: after the other-seed tx1 confirms, this proof rebuilt on its state (NF present)', {state: Sb}, {rejecter: 'W', others: 'accept'});
  }
  // W at the wrong index or missing (tx1)
  const swapIn = (a, b) => (t) => { const i = t.transaction.inputs, so = t.sourceOutputs; [i[a], i[b]] = [i[b], i[a]]; [so[a], so[b]] = [so[b], so[a]]; return t; };
  const wIdx = plan.txs[1].qry.length + plan.nc + 2;
  run('windex', 'W swapped with the QRY input (W at index 4)', {state: G0, tx1: swapIn(wIdx - 1, wIdx)}, {rejecter: 'any'});
  run('windex', 'W swapped with HEAD (W at index 0)', {state: G0, tx1: swapIn(0, wIdx)}, {rejecter: 'any'});
  run('windex', 'W missing (tx1 without its last input; output 0 kept)', {state: G0, tx1: (t) => { t.transaction.inputs.pop(); t.sourceOutputs.pop(); return t; }}, {rejecter: 'any'});
  run('windex', 'an extra R input after W (a copy of the QRY input)', {state: G0, tx1: (t) => { t.transaction.inputs.push({...t.transaction.inputs[wIdx - 1], outpointIndex: 77}); t.sourceOutputs.push(t.sourceOutputs[wIdx - 1]); return t; }}, {rejecter: 'any'});
  run('windex', 'an R input (a copy of the QRY input) in the W slot', {state: G0, tx1: (t) => { t.transaction.inputs[wIdx] = {...t.transaction.inputs[wIdx - 1], outpointIndex: 77}; t.sourceOutputs[wIdx] = t.sourceOutputs[wIdx - 1]; return t; }}, {rejecter: 'any'});
  // output 0: commitment, and changes CTX does not see
  const tok0 = (t, f) => { const o = t.transaction.outputs; o[0] = {...o[0], token: {...o[0].token, nft: {...o[0].token.nft, commitment: f(Buffer.from(o[0].token.nft.commitment))}}}; return t; };
  run('commit', 'output 0: nfRoot unchanged (NF not inserted)', {state: G0, tx1: (t) => tok0(t, (c) => { G0.keys.length || Buffer.alloc(32).copy(c, 1); return c; })}, {rejecter: 'W', others: 'accept'});
  run('commit', 'output 0: nfRoot after inserting another key', {state: G0, tx1: (t) => tok0(t, (c) => { wSpend(pool, G0, base.slice(0, 4), GEN.notes[(v.t9_note + 1) % 32].nf).out0.token.nft.commitment.slice(1, 33).forEach((x, i) => { c[1 + i] = x; }); return c; })}, {rejecter: 'W', others: 'accept'});
  run('commit', 'output 0: histRoot byte flipped', {state: G0, tx1: (t) => tok0(t, (c) => { c[40] ^= 1; return c; })}, {rejecter: 'W', others: 'accept'});
  run('commit', 'output 0: epoch + 1', {state: G0, tx1: (t) => tok0(t, (c) => { c[65] += 1; return c; })}, {rejecter: 'W', others: 'accept'});
  run('out0', 'output 0 value - 1 (W pays D + 1): R accepts (CTX excludes output 0), W rejects', {state: G0, tx1: (t) => { const o = t.transaction.outputs; o[0] = {...o[0], valueSatoshis: o[0].valueSatoshis - 1n}; return t; }}, {rejecter: 'W', others: 'accept'});
  run('out0', 'output 0 locking changed: R accepts, W rejects', {state: G0, tx1: (t) => { const o = t.transaction.outputs; o[0] = {...o[0], lockingBytecode: Uint8Array.from([...o[0].lockingBytecode.slice(0, -1), 0x88])}; return t; }}, {rejecter: 'W', others: 'accept'});
  // race: another withdrawal confirmed first; tx1 rebuilt on the new state (same proof, same tx0): accepted
  {
    const other = GEN.notes[(v.t9_note + 24) % 32];
    const fx = {...G0, keys: [keyOf(nfBytes(other.nf))], value: G0.value - 1_000_000n, outpoint: Buffer.alloc(32, 0x58)};
    run('out0', `race: tx1 rebuilt on a later W state (note ${other.index} withdrawn first; output 0 and the W witness change, the proof does not)`, {state: fx}, {accept: true});
  }
  run('out0', 'output 1 (payout) value - 1: HEAD rejects (CTX), W accepts', {state: G0, outs1: altTx1}, {rejecter: 'HEAD', others: 'accept'});
  run('out0', 'output 1 (payout) locking changed: HEAD rejects, W accepts', {state: G0, outs1: (o) => o.map((x, i) => (i === 1 ? {...x, lockingBytecode: Uint8Array.from(x.lockingBytecode.map((b, k) => (k === 5 ? b ^ 1 : b)))} : x))}, {rejecter: 'HEAD', others: 'accept'});
  run('out0', 'an extra output 2 (OP_RETURN): HEAD rejects, W accepts', {state: G0, outs1: (o) => [...o, {lockingBytecode: Uint8Array.of(0x6a, 1, 7), valueSatoshis: 0n}]}, {rejecter: 'HEAD', others: 'accept'});
  run('out0', 'payout removed (output 0 only): HEAD rejects, W accepts', {state: G0, outs1: (o) => o.slice(0, 1)}, {rejecter: 'HEAD', others: 'accept'});
  run('out0', 'outputs 0 and 1 swapped', {state: G0, outs1: (o) => [o[1], o[0]]}, {rejecter: 'any'});
  // W without R at input 0
  {
    const b = poolTxs(vk, plan, buf, base, payouts, {state: G0});
    const t1 = b.txs[1]; const k = t1.transaction.inputs.length - 1;
    t1.transaction = {...t1.transaction, inputs: [t1.transaction.inputs[k]]}; t1.sourceOutputs = [t1.sourceOutputs[k]];
    poolCheck(file, 'wonly', 'a withdrawal with W alone (no R inputs)', b, {rejecter: 'W'});
    const c = poolTxs(vk, plan, buf, base, payouts, {state: G0});
    const t2 = c.txs[1];
    t2.transaction = {...t2.transaction, inputs: [t2.transaction.inputs[k], t2.transaction.inputs[k]].map((x, i) => (i ? x : {...x, outpointIndex: 9}))}; t2.sourceOutputs = [{lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 2000n}, t2.sourceOutputs[k]];
    t2.transaction.inputs[0] = {...t2.transaction.inputs[0], unlockingBytecode: Uint8Array.of()};
    const v2 = verdicts(t2);
    record(file, 'wonly', 'W at its index after a non-R input 0 (OP_1 locking): W rejects (HR)', false, v2[1] !== 'reject', null, null, `inputs: ${v2.join(' ')}`);
  }
  // documented: a non-W input at the W slot. R does not pin W (no cycle); R's inputs accept; the transaction moves no
  // pool funds (its outputs are paid by that input), so this is not a pool spend
  {
    const b = poolTxs(vk, plan, buf, base, payouts, {state: G0, tx1: (t) => { t.sourceOutputs[wIdx] = {lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1_000_000n}; t.transaction.inputs[wIdx] = {...t.transaction.inputs[wIdx], unlockingBytecode: Uint8Array.of()}; t.transaction.outputs = t.transaction.outputs.slice(1); return t; }, outs1: (o) => o});
    // without the W output, CTX over outputs [1..] no longer covers the payout: put a plain output 0 back
    const t1 = b.txs[1]; t1.transaction.outputs = [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}, ...t1.transaction.outputs];
    const v1 = verdicts(t1);
    const rOk = v1.slice(0, wIdx).every((x) => x === 'accept');
    F_DOC.push({file, name: 'a non-W input (OP_1, 1,000,000 sat) at the W slot, output 0 = OP_RETURN', rInputs: v1.slice(0, wIdx), slotInput: v1[wIdx]});
    console.log(`doc  ${file} [documented] non-W input at the W slot: R inputs ${rOk ? 'all accept' : v1.slice(0, wIdx).join(',')}; slot input ${v1[wIdx]} (expected: R does not pin W; no pool funds move)`);
  }
}
const F_DOC = [];

for (const f of files) {
  const v = readVector(f), file = f.split('/').pop(), dir = f.split('/').slice(0, -1).join('/');
  let vk;
  try { vk = vkxA(v); if (vk.capHeight !== 5) throw new Error('cap height ' + vk.capHeight + " (layout a' is the cap-5 deployment)"); } catch (e) {
    const expect = v.s3_valid_expect ?? !v.s3_vk_variant;
    stats.skippedFiles.push(`${file}: ${e.message}`);
    if (v.s3_vk_variant) record(file, 'vk_variant', `VK refused by the generator: ${e.message}`, expect, false, null, runCase(vkFromVector(v), v, null).accept, '', 'notRun');
    else console.log(`skip ${file}: ${e.message}`);
    continue;
  }
  stats.files++;
  const plan = planOf(vk);
  const ref0 = vkFromVector(v);
  const outs = outputsOf(v), base = v.public_values.flat().map(BigInt);
  const valid0 = spendA(vk, plan, Buffer.from(v.proof_hex, 'hex'), base, outs), validWit = valid0.wit;
  const cases = [null, ...(v.tampered ?? [])];
  for (const t of cases) {
    const family = t ? (t.family ?? 'tampered') : (v.s3_vk_variant ? 'vk_variant' : 'valid');
    const name = t ? t.name : (v.s3_vk_variant ? `stored proof under VK ${v.s3_vk_variant}` : 'valid');
    const expect = t ? (t.expect ?? false) : (v.s3_valid_expect ?? true);
    const buf = t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex');
    const pvs = t?.public_values ?? v.public_values;
    const pv = pvs.flat().map(BigInt);
    // Track 9: a tamper that changes neither the proof nor the public values is a no-op (the pool's statements share
    // epoch roots: 16 notes per root, so S3's 'ROOT of another tree' taken from a same-epoch vector is the same ROOT).
    // Counted apart (stats.noop), not as a verdict.
    if (t && buf.equals(Buffer.from(v.proof_hex, 'hex')) && pv.length === base.length && pv.every((x, k) => x === base[k])) {
      stats.noop = (stats.noop ?? 0) + 1; (stats.noopList ??= []).push(`${file}: ${name}`);
      console.log(`noop ${file} [${family}] ${name}: the tamper changes neither the proof nor the public values (skipped)`); continue;
    }
    const ref = runCase(ref0, v, t).accept;
    if (pvs.length !== 1 || pvs[0].length !== 12) { stats.refused++; record(file, family, name, expect, false, null, ref, '(public values in another per-instance layout: refused by the statement layer)', 'notRun'); continue; }
    if (pv.some((x) => x < 0n || x >= M64)) { stats.na++; console.log(`n/a  ${file} [${family}] ${name}: a public value >= 2^64 has no 8-byte encoding`); continue; }
    if (pv.slice(0, 4).some((x) => x >= P)) { stats.refused++; record(file, family, name, expect, false, null, ref, '(non-canonical ROOT: the generator refuses this statement)', 'notRun'); continue; }
    let useOuts = outs;
    if (!HARNESS) { if (pv.slice(8, 12).some((x, k) => x !== base[8 + k])) useOuts = altOutputs(outs); }
    else if (pv.slice(8, 12).some((x) => x >= 1n << 56n)) { record(file, family, name, expect, false, null, ref, '(CTX lane >= 2^56: not producible by the statement layer)', 'notRun'); continue; }
    const pvModel = HARNESS ? pv : [...pv.slice(0, 8), ...ctxOf(useOuts).lanes];
    // malformed-by-length handling applies to tampered copies of a proof that is valid under this VK (not to the
    // stored proof of a VK-variant file, which is itself the reject case)
    const validFile = !(v.s3_vk_variant || v.s3_valid_expect === false);
    let malformed = null; if (t && validFile) try { strictParse(buf, ref0); } catch (e) { if (/truncated|trailing/.test(e.message)) malformed = e.message; }
    // leftover multiproof siblings count as malformed only under the valid transcript (a tamper that changes the
    // transcript changes the queried leaves, so the multiproof no longer fits: an ordinary reject)
    if (!malformed && t && validFile) { const e = encodeA(vk, buf, pv, plan.parts); if (e.malformed && e.G.equals(valid0.enc.G)) malformed = e.malformed; }
    if (malformed) {
      stats.malformed++;
      const w = chainRun(vk, plan, buf, pv, useOuts, false);
      if (same(w.sp.wit, validWit) && pv.every((x, k) => x === base[k])) {
        stats.encoderOnly++;
        record(file, family, name, true, w.acc, null, null, `(malformed p3b-v1: ${malformed}; the encoder refuses it; the full-path witness is the valid proof's, so the script accepts it)`, 'encoderOnly');
        continue;
      }
      record(file, family, name, expect, w.acc, verifyModelA(vk, buf, pvModel, plan.parts).ok, ref, `(malformed: ${malformed}; encoder refuses; lenient witness rejected)`);
      continue;
    }
    const c = chainRun(vk, plan, buf, pv, useOuts, expect);
    const model = pvModel.every((x) => x >= 0n && x < P) ? verifyModelA(vk, buf, pvModel, plan.parts).ok : false;
    record(file, family, name, expect, c.acc, model, ref, c.acc === expect ? '' : String(c.err ?? '').slice(0, 100));
  }
  if (v.s3_vk_variant || v.s3_valid_expect === false) continue;
  const buf = Buffer.from(v.proof_hex, 'hex');
  if (!HARNESS) {
    const txc = [
      ['output value - 1 sat', (o) => altOutputs(o)],
      ['recipient changed (one byte of the locking bytecode)', (o) => o.map((x, i) => (i ? x : {...x, lockingBytecode: Uint8Array.from(x.lockingBytecode.map((b, k) => (k === 5 ? b ^ 1 : b)))}))],
      ['extra OP_RETURN output', (o) => [...o, {lockingBytecode: Uint8Array.of(0x6a, 1, 7), valueSatoshis: 0n}]],
      ['token added to the output', (o) => o.map((x, i) => (i ? x : {...x, token: {category: Uint8Array.from(Array(32).fill(9)), amount: 1n}}))],
    ];
    for (const [nm, fn] of txc) { const c = chainRun(vk, plan, buf, base, fn(outs), false); record(file, 'tx', nm, false, c.acc, null, null, c.acc ? '' : String(c.err).slice(0, 60)); }
    { const r = [...base]; r[3] = (r[3] + 1n) % P; const c = chainRun(vk, plan, buf, r, outs, false); record(file, 'root', 'HEAD ROOT[3] + 1 (and W spends it)', false, c.acc, null, null); }
    { const r = [...base]; r[0] = (r[0] + 1n) % P; const c = chainRun(vk, plan, buf, r, outs, false, {wT: {slot: GEN.notes[v.t9_note ?? 0]?.slot}}); record(file, 'root', 'HEAD ROOT[0] + 1, W with the proof ROOT\'s slot path', false, c.acc, null, null); }
    if (v.t9_note !== undefined) {
      const other = GEN.epochs[1 - GEN.notes[v.t9_note].epoch].root;
      const r = [...other, ...base.slice(4)]; const c = chainRun(vk, plan, buf, r, outs, false);
      record(file, 'root', 'HEAD ROOT = the other genesis epoch\'s root (in the ring; not this proof\'s)', false, c.acc, null, null, c.acc ? '' : String(c.err).slice(0, 60));
    }
    if (base[0] + P < M64) { const r = [...base]; r[0] += P; const c = chainRun(vk, plan, buf, r, outs, false); record(file, 'root', 'HEAD ROOT[0] + p (non-canonical lane)', false, c.acc, null, null, c.acc ? '' : String(c.err).slice(0, 60)); }
  }
  if (POOL && WITH_W && !HARNESS && v.t9_note !== undefined) poolCases(vk, plan, v, file, dir, base, outs);
  if (LAYOUT) for (const lc of layoutCases(vk, plan, v, file, dir, base, outs)) {
    if (lc.other) {
      const [ov, op] = lc.other; const c = chainRun(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outs, true);
      record(file, lc.family, lc.nm, true, c.acc, null, null, c.acc ? '' : String(c.err).slice(0, 80));
      continue;
    }
    const c = chainRun(vk, plan, buf, base, outs, false, {mutate: lc.mutate, txMutate: lc.txMutate, commitments: lc.commitments});
    record(file, lc.family, lc.nm, false, c.acc, null, null, c.acc ? '' : String(c.err ?? '').slice(0, 70));
  }
}
console.log(`no-op tampers skipped: ${stats.noop ?? 0}`);
console.log(`test-a (plan ${PLAN}${HARNESS ? ', harness: CTX a witness item' : ', production: CTX from the final transaction'}): ${stats.files} files, ${stats.cases} cases, ${stats.unexpected} unexpected, ${stats.na} n/a, ${stats.refused} refused by the statement layer/generator, ${stats.malformed} malformed (${stats.encoderOnly} encoder-only), ${stats.skippedFiles.length} files skipped`);
const notRunNote = () => `; ${stats.notRunOnChain ?? 0} not run on chain (short-circuit, counted as rejects: ${JSON.stringify(Object.fromEntries(Object.entries(stats.families).filter(([, x]) => x.notRunOnChain).map(([k, x]) => [k, x.notRunOnChain])))}); ${stats.encoderOnlyRelabel ?? 0} encoder-only relabels (reference rejects; script accepts the valid witness; inside the ok count)`;
console.log(notRunNote().slice(2));
console.log(JSON.stringify(stats.families));
stats.documented = F_DOC;
if (outFile) writeFileSync(outFile, JSON.stringify(stats, null, 1) + '\n');
process.exit(stats.unexpected ? 1 : 0);
