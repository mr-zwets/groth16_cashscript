#!/usr/bin/env node
// test-a2.mjs (Track 10 G2 copy of Track 8's test-a.mjs): the plan is grade-a2.mjs planFor (pads, T transactions,
// 1..3 queries per QRY input); FIN/QRY witness indices shift by the pad push; pad families added; the cap is any.
// Track 8's header:
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
// usage: node test-a.mjs [--plan 1tx|2tx] [--harness] [--layout] [--opt a,b] [--out FILE] CASEFILE...
//   --opt  layout-review optimizations (gena.mjs plan.opt; absent = baseline); opt.sib adds the 'sib' family
//   --harness  CTX is a witness item (S3's generic cap-5 case files, whose statements are not transaction-bound)
import {writeFileSync, existsSync} from 'node:fs';
import {readVector} from './layoutn.mjs';
import {vkxA, verifyModelA, encodeA, P, sha} from './modela.mjs';
import {applyTamper} from './modeln.mjs';
import {makePlanA, spendA, evaluateTxA, verifyTxA, CATEGORY, parseOpt} from './layouta.mjs';
import {threadCommit} from './gena.mjs';
import {planFor} from './grade-a2.mjs';
import {runCase, vkFromVector, parse as strictParse} from '../verifier/verify-batch.mjs';
import {ctxOf} from './ctx.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const HARNESS = args.includes('--harness'), LAYOUT = args.includes('--layout'), PLAN = opt('--plan', '1tx');
const outFile = opt('--out', null);
const files = args.filter((a, i) => !a.startsWith('--') && !['--out', '--plan', '--nc', '--opt'].includes(args[i - 1]));
const M64 = 1n << 64n;
const outputsOf = (v) => (v.s4_outputs ?? [{lockingBytecode: '76a914' + '00'.repeat(20) + '88ac', valueSatoshis: '900000'}]).map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));
const countsOf = (vk, which) => { const per = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i)); return which === '1tx' ? [per] : [per.slice(0, -1), per.slice(-1)]; };
void countsOf; void makePlanA;
const planOf = (vk, v, outs) => { const p = planFor(vk, Buffer.from(v.proof_hex, 'hex'), v.public_values.flat().map(BigInt), outs, {nc: +opt('--nc', 3), opt: parseOpt(opt('--opt'))}); if (!p.plan) throw new Error('no plan: ' + JSON.stringify(p.tried)); return HARNESS ? {...p.plan, ctx: 'witness'} : p.plan; };

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
function chainRun(vk, plan, buf, pis, outs, expectValid, {mutate, txMutate, ...o} = {}) {
  const sp = spendA(vk, plan, buf, pis, outs, o, mutate);
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
  const fo = plan.pad ? 1 : 0, qo = plan.pad ? 1 : 0, per0 = plan.txs[0].qry[0][1] - plan.txs[0].qry[0][0];
  // QRY items per query: L PTH, or (opt.sib) L and nS siblings of 32 B
  const SIB = !!plan.opt?.sib, nS = vk.pathB / 32, pq = SIB ? 1 + nS : 2, np = pq - 1;
  const pathAt = (a, k, off) => { if (!SIB) return [k + 1, off]; const o = off < 0 ? vk.pathB + off : off; return [k + 1 + Math.floor(o / 32), o % 32]; };
  const flipPath = (a, k, off) => { const [i, b] = pathAt(a, k, off); a[i] = flip(a[i], b); };
  const swapPaths = (a, k, a2, k2) => { for (let j = 1; j <= np; j++) [a[k + j], a2[k2 + j]] = [a2[k2 + j], a[k + j]]; };
  const hIdx = (k) => ['ROOTS', 'OOD', 'BPOW', 'FROOTS', 'CPOW', 'QPOW', 'NF', 'CTXW'].indexOf(k);
  const m = (f) => (w) => { const x = cloneWit(w); f(x); return x; };
  // constants: TBL fields (FIN checks its own push), ACC (each CODE input checks its own), CTXW (final HEAD)
  let o = 0;
  for (const [nm, n, w] of vk.tblLayout) {
    const at = o; o += n * w;
    add('constants', `FIN: TBL field ${nm} byte 0 flipped`, {mutate: m((x) => { x[0][FIN][1 + fo] = flip(x[0][FIN][1 + fo], at); })});
    if (nm === 'idx') add('constants', 'FIN: TBL idx_0 replaced by idx_1 (another valid index)', {mutate: m((x) => { const b = Buffer.from(x[0][FIN][1 + fo]); b.copy(b, 0, w, 2 * w); x[0][FIN][1 + fo] = b; })});
  }
  add('constants', 'FIN: TBL truncated by one byte', {mutate: m((x) => { x[0][FIN][1 + fo] = x[0][FIN][1 + fo].subarray(0, -1); })});
  add('constants', 'FIN: TBL extended by one byte', {mutate: m((x) => { x[0][FIN][1 + fo] = Buffer.concat([x[0][FIN][1 + fo], Buffer.alloc(1)]); })});
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
  // HEAD and FIN proof data
  // G2: offsets inside the item for any cap (Track 8's were for cap 5: 32 digests per cap)
  const capD = vk.capB.quotient / 32, fD = (vk.friB[vk.friB.length - 1] ?? 32) / 32;
  for (const [k, at] of [['ROOTS', 5], ['ROOTS', vk.capOff.quotient + 32 * Math.min(17, capD - 1) + 2], ['ROOTS', vk.capOff.random + 9], ['OOD', 100], ['BPOW', 0], ['FROOTS', vk.friOff[vk.friOff.length - 1] + 32 * (fD - 1)], ['CPOW', 0], ['QPOW', 0]]) add('input', `HEAD: ${k} byte ${at} flipped`, {mutate: m((x) => { if (at >= x[0][0][hIdx(k)].length) throw new Error('offset outside the item'); x[0][0][hIdx(k)] = flip(x[0][0][hIdx(k)], at); })});
  if (plan.opt?.lad) {
    // opt.lad: FIN's LAD push (alpha'^0 .. alpha'^(maxLadder - 1), 24 B each), checked by FIN, read by QRY
    const LI = fo + 2, E = 24, last = T - 1;
    const setLad = (t, f) => m((x) => { x[t][FIN][LI] = f(Buffer.from(x[t][FIN][LI])); });
    add('lad', 'FIN: wrong ladder value (LAD element 0 = alpha\'^0, byte 0 flipped)', {mutate: setLad(0, (b) => flip(b, 0))});
    add('lad', 'FIN: wrong ladder value (LAD element 50, limb 1 byte 3 flipped)', {mutate: setLad(0, (b) => flip(b, 50 * E + 8 + 3))});
    add('lad', 'FIN: wrong ladder value (last LAD element, last byte flipped)', {mutate: setLad(0, (b) => flip(b, -1))});
    add('lad', `FIN of tx${last} (final): wrong ladder value (LAD element 7 flipped)`, {mutate: setLad(last, (b) => flip(b, 7 * E + 2))});
    add('lad', 'FIN: LAD element 1 non-canonical (limb 0 + p, same value mod p, if < 2^64)', {mutate: setLad(0, (b) => { const v = b.readBigUInt64LE(E); if (v + P < M64) b.writeBigUInt64LE(v + P, E); else b.writeBigUInt64LE(v - 1n, E); return b; })});
    add('lad', 'FIN: LAD shifted by one element (alpha\'^1 .. alpha\'^n)', {mutate: setLad(0, (b) => Buffer.concat([b.subarray(E), b.subarray(-E)]))});
    add('lad', 'FIN: LAD elements 3 and 4 swapped', {mutate: setLad(0, (b) => { const c = Buffer.from(b); b.copy(c, 3 * E, 4 * E, 5 * E); b.copy(c, 4 * E, 3 * E, 4 * E); return c; })});
    add('lad', 'FIN: LAD truncated by one element', {mutate: setLad(0, (b) => b.subarray(0, -E))});
    add('lad', 'FIN: LAD extended by one byte', {mutate: setLad(0, (b) => Buffer.concat([b, Buffer.alloc(1)]))});
    add('lad', 'FIN: LAD missing', {mutate: m((x) => { x[0][FIN] = x[0][FIN].slice(0, LI); })});
    add('lad', 'FIN: LAD all zero', {mutate: setLad(0, (b) => Buffer.alloc(b.length))});
    add('lad', 'FIN: LAD of alpha\'+1 (the ladder of another alpha\')', {mutate: setLad(0, (b) => { const F = vk.F; const enc = encodeA(vk, Buffer.from(v.proof_hex, 'hex'), base, plan.parts); const a = F.add(enc.t.alphaP, F.one()); let z = F.one(); const out = []; for (let i = 0; i < b.length / E; i++) { out.push(...z.map((y) => { const q = Buffer.alloc(8); q.writeBigUInt64LE(y % P); return q; })); z = F.mul(z, a); } return Buffer.concat(out); })});
  }
  add('input', 'FIN: final polynomial byte flipped', {mutate: m((x) => { x[0][FIN][fo] = flip(x[0][FIN][fo], 1000); })});
  add('input', 'HEAD: extra empty item', {mutate: m((x) => { x[0][0].push(Buffer.alloc(0)); })});
  add('input', 'HEAD: CTXW missing', {mutate: m((x) => { x[0][0].pop(); })});
  // QRY inputs
  const hintOff = vk.blob.total - 8;
  // the second query's items: inside the same QRY input (per0 >= 2) or the next QRY input's first query
  const q2 = (x) => (per0 >= 2 ? [x[0][Q0], qo + pq] : [x[0][Q0 + 1], qo]);
  add('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][qo]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q0][qo] = b; })});
  add('input', 'QRY: hint T of another query', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][qo]); const [a2, k2] = q2(x); a2[k2].copy(b, hintOff, hintOff, hintOff + 8); x[0][Q0][qo] = b; })});
  add('input', 'QRY: L byte (trace row) flipped', {mutate: m((x) => { x[0][Q0][qo] = flip(x[0][Q0][qo], 3); })});
  add('input', 'QRY: L byte (FRI sibling value) flipped', {mutate: m((x) => { x[0][Q0][qo] = flip(x[0][Q0][qo], vk.blob.total - 8 - 40); })});
  add('input', 'QRY: path byte (input tree) flipped', {mutate: m((x) => { flipPath(x[0][Q0], qo, 100); })});
  add('input', 'QRY: path byte (FRI tree, last level below the cap) flipped', {mutate: m((x) => { flipPath(x[0][Q0], qo, -5); })});
  add('input', 'QRY: queries of two QRY positions swapped (L and path)', {mutate: m((x) => { const [a2, k2] = q2(x); const a = x[0][Q0]; [a[qo], a2[k2]] = [a2[k2], a[qo]]; swapPaths(a, qo, a2, k2); })});
  add('input', 'QRY: L and path swapped', {mutate: m((x) => { const a = x[0][Q0]; [a[qo], a[qo + 1]] = [a[qo + 1], a[qo]]; })});
  add('input', 'QRY: last query (L, path) missing', {mutate: m((x) => { x[0][Q0] = x[0][Q0].slice(0, -pq); })});
  add('input', 'QRY: extra empty push', {mutate: m((x) => { x[0][Q0].push(Buffer.alloc(0)); })});
  add('input', 'QRY: paths of two queries swapped', {mutate: m((x) => { const [a2, k2] = q2(x); swapPaths(x[0][Q0], qo, a2, k2); })});
  if (SIB) {
    // opt.sib: one witness item per Merkle sibling (count fixed by the DEPTH check, each SIZE 32)
    const s0 = qo + 1, sL = qo + nS;   // first and last sibling of the input's first query
    add('sib', 'QRY: wrong sibling (sibling 0 replaced by sibling 1)', {mutate: m((x) => { const a = x[0][Q0]; a[s0] = Buffer.from(a[s0 + 1]); })});
    add('sib', 'QRY: wrong sibling (last FRI sibling replaced by zeros)', {mutate: m((x) => { x[0][Q0][sL] = Buffer.alloc(32); })});
    add('sib', 'QRY: wrong sibling (sibling 7 from the next query)', {mutate: m((x) => { const [a2, k2] = q2(x); x[0][Q0][s0 + 7] = Buffer.from(a2[k2 + 1 + 7]); })});
    add('sib', 'QRY: two adjacent siblings swapped (levels 2 and 3)', {mutate: m((x) => { const a = x[0][Q0]; [a[s0 + 2], a[s0 + 3]] = [a[s0 + 3], a[s0 + 2]]; })});
    add('sib', 'QRY: missing sibling (sibling 5 removed)', {mutate: m((x) => { x[0][Q0].splice(s0 + 5, 1); })});
    add('sib', 'QRY: missing sibling (last removed), extra 32-byte push at the end (count kept)', {mutate: m((x) => { const a = x[0][Q0]; a.splice(sL, 1); a.push(Buffer.alloc(32)); })});
    add('sib', 'QRY: missing sibling, an empty push in its place (count kept)', {mutate: m((x) => { x[0][Q0][s0 + 5] = Buffer.alloc(0); })});
    add('sib', 'QRY: extra sibling (sibling 0 duplicated)', {mutate: m((x) => { const a = x[0][Q0]; a.splice(s0, 0, Buffer.from(a[s0])); })});
    add('sib', 'QRY: sibling extended by one byte', {mutate: m((x) => { const a = x[0][Q0]; a[s0 + 9] = Buffer.concat([a[s0 + 9], Buffer.alloc(1)]); })});
    add('sib', 'QRY: sibling truncated by one byte', {mutate: m((x) => { const a = x[0][Q0]; a[s0 + 9] = a[s0 + 9].subarray(0, 31); })});
    add('sib', 'QRY: siblings 4 and 5 merged into one 64-byte push, an empty push at the end (count kept)', {mutate: m((x) => { const a = x[0][Q0]; a.splice(s0 + 4, 2, Buffer.concat([a[s0 + 4], a[s0 + 5]])); a.push(Buffer.alloc(0)); })});
    add('sib', 'QRY: siblings of the first query moved after L of the second query (per-query order)', {mutate: m((x) => { if (per0 < 2) { const [a2, k2] = q2(x); const a = x[0][Q0]; [a[s0], a2[k2 + 1]] = [a2[k2 + 1], a[s0]]; return; } const a = x[0][Q0]; const L2 = a.splice(qo + pq, 1)[0]; a.splice(qo + 1, 0, L2); })});
  }
  if (plan.pad) {
    // an empty pad (pad length 0: the input is byte-bound) has no byte to flip or remove: those cases become 'the
    // empty pad replaced by one byte 0x01'
    const pq0 = plan.pad.qry[0][0], pf0 = plan.pad.fin;
    if (pq0) {
      add('pad', 'QRY: pad byte 0 set to 1', {mutate: m((x) => { x[0][Q0][0] = flip(x[0][Q0][0], 0); })});
      add('pad', 'QRY: pad one byte shorter', {mutate: m((x) => { x[0][Q0][0] = x[0][Q0][0].subarray(1); })});
    } else add('pad', 'QRY: empty pad replaced by one byte 0x01', {mutate: m((x) => { x[0][Q0][0] = Buffer.from([1]); })});
    add('pad', 'QRY: pad one byte longer', {mutate: m((x) => { x[0][Q0][0] = Buffer.concat([x[0][Q0][0], Buffer.alloc(1)]); })});
    add('pad', 'QRY: pad missing', {mutate: m((x) => { x[0][Q0] = x[0][Q0].slice(1); })});
    if (pf0) {
      add('pad', 'FIN: pad last byte set to 1', {mutate: m((x) => { x[0][FIN][0] = flip(x[0][FIN][0], -1); })});
      add('pad', 'FIN: pad one byte shorter', {mutate: m((x) => { x[0][FIN][0] = x[0][FIN][0].subarray(1); })});
    } else add('pad', 'FIN: empty pad replaced by one byte 0x01', {mutate: m((x) => { x[0][FIN][0] = Buffer.from([1]); })});
  }
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
  const nb = file.replace(/-(\d+)-(Z128[^/]*)\.json$/, (_, i, s) => `-${(+i + 1) % 2}-${s}.json`);
  if (nb !== file && existsSync(`${dir}/${nb}`)) others.push(['another statement', `${dir}/${nb}`]);
  for (const [label, path] of others) {
    const ov = readVector(path), op = ov.public_values.flat().map(BigInt);
    const ow = () => spendA(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outs).wit;
    add('mix', `HEAD from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][0] = y[0][0]; return x; }});
    add('mix', `FIN from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][FIN] = y[0][FIN]; return x; }});
    if (plan.opt?.lad) add('mix', `LAD (FIN's ladder) from ${label}`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][FIN][(plan.pad ? 1 : 0) + 2] = y[0][FIN][(plan.pad ? 1 : 0) + 2]; return x; }});
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
    // G2: the statement outputs (CTX) are the final transaction's; with T > 2, tx1 is a middle transaction whose one
    // plain output is not bound (as tx0's extra plain outputs in Track 8): the case targets the final transaction
    add('thread', `tx${T - 1} (final): outputs changed (value - 1, so CTX differs)`, {txMutate: (txs) => { const tx = txs[T - 1]; tx.transaction.outputs = altOutputs(tx.transaction.outputs); return txs; }});
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

for (const f of files) {
  const v = readVector(f), file = f.split('/').pop(), dir = f.split('/').slice(0, -1).join('/');
  let vk;
  try { vk = vkxA(v); } catch (e) {
    const expect = v.s3_valid_expect ?? !v.s3_vk_variant;
    stats.skippedFiles.push(`${file}: ${e.message}`);
    if (v.s3_vk_variant) record(file, 'vk_variant', `VK refused by the generator: ${e.message}`, expect, false, null, runCase(vkFromVector(v), v, null).accept, '', 'notRun');
    else console.log(`skip ${file}: ${e.message}`);
    continue;
  }
  stats.files++;
  const plan = planOf(vk, v, outputsOf(v));
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
    const ref = runCase(ref0, v, t).accept;
    if (pvs[0].length !== 12 || pvs.slice(1).some((p) => p.length)) { stats.refused++; record(file, family, name, expect, false, null, ref, '(public values in another per-instance layout: refused by the statement layer)', 'notRun'); continue; }
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
    { const r = [...base]; r[3] = (r[3] + 1n) % P; const c = chainRun(vk, plan, buf, r, outs, false); record(file, 'root', 'script ROOT[3] + 1', false, c.acc, null, null); }
  }
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
console.log(`test-a (plan ${PLAN}${HARNESS ? ', harness: CTX a witness item' : ', production: CTX from the final transaction'}): ${stats.files} files, ${stats.cases} cases, ${stats.unexpected} unexpected, ${stats.na} n/a, ${stats.refused} refused by the statement layer/generator, ${stats.malformed} malformed (${stats.encoderOnly} encoder-only), ${stats.skippedFiles.length} files skipped`);
const notRunNote = () => `; ${stats.notRunOnChain ?? 0} not run on chain (short-circuit, counted as rejects: ${JSON.stringify(Object.fromEntries(Object.entries(stats.families).filter(([, x]) => x.notRunOnChain).map(([k, x]) => [k, x.notRunOnChain])))}); ${stats.encoderOnlyRelabel ?? 0} encoder-only relabels (reference rejects; script accepts the valid witness; inside the ok count)`;
console.log(notRunNote().slice(2));
console.log(JSON.stringify(stats.families));
if (outFile) writeFileSync(outFile, JSON.stringify(stats, null, 1) + '\n');
process.exit(stats.unexpected ? 1 : 0);
