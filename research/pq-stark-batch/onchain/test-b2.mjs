#!/usr/bin/env node
// test-b2.mjs: layout b2 (two inputs, DESIGN-T8 §5) accept/reject sweep over case files in the S3 gen-cases.mjs format,
// plus the layout family on each valid proof (S6). Every case gets three verdicts that must all equal the expected one:
//   chain  the generated b2 transaction on libauth (valid: both inputs under r100, standard and consensus; reject
//          cases: the loose VM, so that a reject is a failed check and not a resource limit; the transaction is
//          accepted only if both inputs are)
//   model  modeln.mjs with the same query split (the on-chain algorithm in JS)
//   ref    ../verifier/verify-batch.mjs (S3 reference)
// Vectors with Q < 4 (Plonky3's PT/PTZ test shapes) run in layout b (one input), since input 1 of b2 would hold
// too few bytes for its density budget.
// Statement: M1/M2 files (pool statement): ROOT a script constant, NF a witness item, CTX a witness item (harness;
// --prod: CTX from the spending transaction's outputs, for transaction-bound statements with `s4_outputs`). Plonky3
// AIRs: every public value a witness item (each < p). A case whose public values have another per-instance layout
// is refused by the statement layer (reject); a lane >= 2^64 has no encoding (n/a).
// usage: node test-b2.mjs [--prod] [--layout] [--out FILE] CASEFILE...
import {writeFileSync, existsSync} from 'node:fs';
import {readVector, vkxN, stmtFor, spendB2, spendBN} from './layoutn.mjs';
import {verifyModelN, P, applyTamper} from './modeln.mjs';
import {runCase, vkFromVector, parse as strictParse} from '../verifier/verify-batch.mjs';
import {evaluate} from './vm.mjs';
import {verifyTxN} from './vmn.mjs';
import {ctxOf} from './ctx.mjs';

const args = process.argv.slice(2);
const PROD = args.includes('--prod'), LAYOUT = args.includes('--layout');
const oi = args.indexOf('--out'); const outFile = oi >= 0 ? args[oi + 1] : null;
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out');
const M64 = 1n << 64n;
const qaOf = (vk) => (vk.Q < 4 ? null : vk.inst.length === 2 && vk.inst.some((I) => I.numLookups) && vk.heights.length > 1 ? 9 : 12);
const outputsOf = (v) => (v.s4_outputs ?? [{lockingBytecode: '6a', valueSatoshis: '0'}]).map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));

const stats = {files: 0, cases: 0, unexpected: 0, na: 0, refused: 0, encoderRefused: 0, families: {}, list: [], skippedFiles: [], layoutB: 0};
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
// one chain verdict: b2 (or b for tiny Q); valid runs use r100 std+cons, rejects the loose VM
function chainRun(vk, stmt, buf, pis, outs, expectValid, mutate, txMutate) {
  const QA = qaOf(vk);
  if (QA === null) {
    const sp = spendBN(vk, stmt, buf, pis, outs, {}, mutate ? (it) => mutate(it, [])[0] : undefined);
    const vms = expectValid ? ['r100Std', 'r100Cons'] : ['looseStd'];
    const r = vms.map((m) => evaluate(m, sp.locking, sp.unlocking, sp.prog));
    return {acc: r.every((x) => x.accepted), err: r.find((x) => !x.accepted)?.error, sp, layout: 'b'};
  }
  const sp = spendB2(vk, stmt, QA, buf, pis, outs, {}, mutate, txMutate);
  const vms = expectValid ? ['r100Std', 'r100Cons'] : ['looseStd'];
  let acc = true, err = null; const per = [];
  for (const i of [0, 1]) for (const m of vms) {
    const r = evaluate(m, null, null, sp.progs[i]); per.push(r.accepted);
    if (!r.accepted) { acc = false; err ??= `input ${i}: ${r.error}`; }
    if (!acc && !expectValid) break;
  }
  if (acc && expectValid) {
    const big = sp.unlocking0.length + sp.unlocking1.length > 99_000;
    const t = verifyTxN(big ? 'r100tStd' : 'r100Std', sp.sourceOutputs, sp.tx);
    if (t !== true) { acc = false; err = 'whole-tx: ' + t; }
  }
  return {acc, err, sp, per, layout: 'b2'};
}

function layoutCases(vk, fileDir, name, v) {
  const C = []; const mut = (nm, f, tx, other) => C.push({nm, f, tx, other});
  const flip = (b, at) => { const c = Buffer.from(b); c[at] ^= 1; return c; };
  const QA = qaOf(vk), Q1 = vk.Q - QA, nT = vk.trees.length, nR0 = Math.ceil(QA / 2), nR1 = Math.ceil(Q1 / 2);
  const iL1 = (j) => Q1 - 1 - j, iL0 = (j) => 1 + QA - 1 - j;        // items0[0] is lib
  const iG0 = (t, g) => 1 + QA + t * nR0 + g, iG1 = (t, g) => Q1 + t * nR1 + g;
  // blob offsets
  const inT = vk.trees.filter((t) => t.kind === 'in');
  const bt = vk.blob.trees; let o = 0; const off = inT.map((tr, ti) => { const g = []; for (const n of bt[ti].groups) { g.push(o); o += n; } const s = o; o += bt[ti].sibs; return {groups: g, sibs: s}; });
  const hintOff = vk.blob.total - vk.blob.hints;
  mut('lib (code library) one byte flipped', (a, b) => { a[0] = flip(a[0], 100); return [a, b]; });
  mut('lib truncated by one byte', (a, b) => { a[0] = a[0].subarray(0, a[0].length - 1); return [a, b]; });
  mut('query blobs swapped across the inputs (L_0 of each)', (a, b) => { [a[iL0(0)], b[iL1(0)]] = [b[iL1(0)], a[iL0(0)]]; return [a, b]; });
  mut('records swapped across the inputs (tree 0, push 0)', (a, b) => { [a[iG0(0, 0)], b[iG1(0, 0)]] = [b[iG1(0, 0)], a[iG0(0, 0)]]; return [a, b]; });
  mut('input 1: one query blob duplicated over another', (a, b) => { b[iL1(1)] = Buffer.from(b[iL1(0)]); return [a, b]; });
  mut('input 1: a record push duplicated over another', (a, b) => { b[iG1(0, 1)] = Buffer.from(b[iG1(0, 0)]); return [a, b]; });
  mut('input 1: one item missing', (a, b) => [a, b.slice(1)]);
  mut('input 1: extra empty item', (a, b) => [a, [Buffer.alloc(0), ...b]]);
  mut('input 0: extra empty item on top', (a, b) => [[...a, Buffer.alloc(0)], b]);
  mut('input 0: PT item flipped (FIN)', (a, b) => { const i = 1 + QA + nT * nR0 + vk.ptItems.findIndex(([k]) => k === 'FIN'); a[i] = flip(a[i], 3); return [a, b]; });
  mut('input 1: hint T_top + 1', (a, b) => { const x = Buffer.from(b[iL1(0)]); x.writeBigUInt64LE((x.readBigUInt64LE(hintOff) + 1n) % P, hintOff); b[iL1(0)] = x; return [a, b]; });
  if (vk.heights.length > 1) {
    const ho = hintOff + 8;
    mut('input 0: hint T_h (lower height) + 1', (a, b) => { const x = Buffer.from(a[iL0(0)]); x.writeBigUInt64LE((x.readBigUInt64LE(ho) + 1n) % P, ho); a[iL0(0)] = x; return [a, b]; });
    mut('input 0: hint T_h + p (or flipped)', (a, b) => { const x = Buffer.from(a[iL0(0)]); const T = x.readBigUInt64LE(ho); if (T + P < M64) x.writeBigUInt64LE(T + P, ho); else x[ho] ^= 1; a[iL0(0)] = x; return [a, b]; });
    mut('input 1: hint T_h of another query', (a, b) => { const x = Buffer.from(b[iL1(0)]); b[iL1(1)].copy(x, ho, ho, ho + 8); b[iL1(0)] = x; return [a, b]; });
    inT.forEach((tr, ti) => {
      if (!tr.B) return;
      mut(`input 0: injection path (${tr.name}): bottom sibling byte flipped`, (a, b) => { a[iL0(0)] = flip(a[iL0(0)], off[ti].sibs + 5); return [a, b]; });
      mut(`input 1: injection path (${tr.name}): bottom siblings of two queries swapped`, (a, b) => { const x = Buffer.from(b[iL1(0)]), y = Buffer.from(b[iL1(1)]); const n = tr.B * 32; const s = off[ti].sibs; const t = Buffer.from(x.subarray(s, s + n)); y.copy(x, s, s, s + n); t.copy(y, s); b[iL1(0)] = x; b[iL1(1)] = y; return [a, b]; });
      mut(`input 0: injected (short) rows of ${tr.name}: one byte flipped`, (a, b) => { a[iL0(1)] = flip(a[iL0(1)], off[ti].groups[1] + 2); return [a, b]; });
      mut(`input 1: injected rows of ${tr.name} moved to another query`, (a, b) => { const x = Buffer.from(b[iL1(0)]); const s = off[ti].groups[1], n = bt[ti].groups[1]; b[iL1(1)].copy(x, s, s, s + n); b[iL1(0)] = x; return [a, b]; });
    });
  }
  mut('third input added', null, (tx, so) => [{...tx, inputs: [...tx.inputs, {outpointTransactionHash: Uint8Array.from(Buffer.alloc(32, 7)), outpointIndex: 1, sequenceNumber: 0, unlockingBytecode: Uint8Array.of(0x51)}]}, [...so, {lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n}]]);
  mut('inputs swapped (order)', null, (tx, so) => [{...tx, inputs: [tx.inputs[1], tx.inputs[0]]}, [so[1], so[0]]]);
  mut('input 1 locking: loader with one extra byte (another locking)', null, (tx, so) => [tx, [so[0], {...so[1], lockingBytecode: Uint8Array.from([...so[1].lockingBytecode, 0x61])}]]);
  mut('input 0 locking: one extra byte (another locking)', null, (tx, so) => [tx, [{...so[0], lockingBytecode: Uint8Array.from([...so[0].lockingBytecode, 0x61])}, so[1]]]);
  mut('input 1 is a copy of input 0 (same outpoint data, input 0 locking)', null, (tx, so) => [{...tx, inputs: [tx.inputs[0], {...tx.inputs[1], unlockingBytecode: tx.inputs[0].unlockingBytecode}]}, [so[0], so[0]]]);
  // input 1 data from another proof of the same statement and VK (second ZK seed): mismatched proofs across inputs
  for (const alt of [name.replace(/\.json$/, '-seed2.json')]) {
    const p = `${fileDir}/${alt}`;
    if (existsSync(p)) C.push({nm: `input 1 data from another proof of the same statement, other ZK seed (${alt})`, other: p});
  }
  void v;
  return C;
}

for (const f of files) {
  const v = readVector(f), file = f.split('/').pop(), dir = f.split('/').slice(0, -1).join('/');
  let vk; try { vk = vkxN(v, {stmt: PROD ? 'pool' : 'auto'}); } catch (e) { stats.skippedFiles.push(`${file}: ${e.message}`); record(file, v.s3_vk_variant ? 'vk_variant' : 'valid', `VK refused by the generator: ${e.message}`, v.s3_valid_expect ?? !v.s3_vk_variant, false, null, runCase(vkFromVector(v), v, null).accept, '', 'notRun'); continue; }
  stats.files++;
  if (qaOf(vk) === null) stats.layoutB++;
  const ref0 = vkFromVector(v);
  const outs = outputsOf(v), base = v.public_values.flat().map(BigInt);
  const pool = vk.stmt === 'pool';
  const mkStmt = (pv, ctxMode) => stmtFor(vk, pv, {mode: vk.stmt, ctx: ctxMode});
  const cases = [null, ...(v.tampered ?? [])];
  for (const t of cases) {
    const family = t ? (t.family ?? 'tampered') : (v.s3_vk_variant ? 'vk_variant' : 'valid');
    const name = t ? t.name : (v.s3_vk_variant ? `stored proof under VK ${v.s3_vk_variant}` : 'valid');
    const expect = t ? (t.expect ?? false) : (v.s3_valid_expect ?? true);
    const buf = t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex');
    const pvs = t?.public_values ?? v.public_values;
    const pv = pvs.flat().map(BigInt);
    const ref = runCase(ref0, v, t).accept;
    if (pvs.length !== vk.inst.length || pvs.some((p, i) => p.length !== vk.inst[i].numPublic)) { stats.refused++; record(file, family, name, expect, false, null, ref, '(public values in another per-instance layout: refused by the statement layer)', 'notRun'); continue; }
    if (pv.some((x) => x < 0n || x >= M64)) { stats.na++; console.log(`n/a  ${file} [${family}] ${name}: a public value >= 2^64 has no 8-byte encoding`); continue; }
    let useOuts = outs, ctxMode = 'witness';
    if (pool) {
      if (pv.slice(0, 4).some((x) => x >= P)) { stats.refused++; record(file, family, name, expect, false, null, ref, '(non-canonical ROOT: the generator refuses this statement)', 'notRun'); continue; }
      if (PROD) { ctxMode = 'tx'; if (pv.slice(8, 12).some((x, k) => x !== base[8 + k])) useOuts = altOutputs(outs); }
      else if (pv.slice(8, 12).some((x) => x >= 1n << 56n)) { record(file, family, name, expect, false, null, ref, '(CTX lane >= 2^56: not producible by the statement layer)', 'notRun'); continue; }
    }
    const stmt = mkStmt(pv, ctxMode);
    const pvModel = pool && PROD ? [...pv.slice(0, 8), ...ctxOf(useOuts).lanes] : pv;
    let malformed = null; try { strictParse(buf, ref0); } catch (e) { if (/truncated|trailing/.test(e.message)) malformed = e.message; }
    const QA = qaOf(vk);
    const parts = QA === null ? undefined : [Array.from({length: QA}, (_, q) => q), Array.from({length: vk.Q - QA}, (_, q) => QA + q)];
    if (malformed) {
      stats.encoderRefused++;
      const w = chainRun(vk, stmt, buf, pv, useOuts, false), w0 = chainRun(vk, mkStmt(base, ctxMode), Buffer.from(v.proof_hex, 'hex'), base, outs, false);
      const items = (x) => (x.layout === 'b' ? x.sp.items : [...x.sp.items0, ...x.sp.items1]);
      const a = items(w), b = items(w0);
      if (a.length === b.length && a.every((x, i) => Buffer.compare(x, b[i]) === 0) && pv.every((x, k) => x === base[k])) {
        record(file, family, name, true, w.acc, null, null, `(malformed p3b-v1: ${malformed}; the encoder refuses it; its lenient witness is the valid proof's, so the script accepts it)`, 'encoderOnly');
        continue;
      }
      const model = verifyModelN(vk, buf, pvModel, parts).ok;
      record(file, family, name, expect, w.acc, model, ref, '(malformed by length: encoder refuses; lenient witness rejected)');
      continue;
    }
    const c = chainRun(vk, stmt, buf, pv, useOuts, expect);
    const model = pvModel.every((x) => x >= 0n && x < P) ? verifyModelN(vk, buf, pvModel, parts).ok : false;
    record(file, family, name, expect, c.acc, model, ref, c.acc === expect ? '' : String(c.err ?? '').slice(0, 100));
  }
  if (v.s3_vk_variant || v.s3_valid_expect === false) continue;
  const buf = Buffer.from(v.proof_hex, 'hex');
  const stmt0 = mkStmt(base, PROD && pool ? 'tx' : 'witness');
  if (PROD && pool) {
    const txc = [
      ['output value - 1 sat', (o) => altOutputs(o)],
      ['recipient changed (one byte of the locking bytecode)', (o) => o.map((x, i) => (i ? x : {...x, lockingBytecode: Uint8Array.from(x.lockingBytecode.map((b, k) => (k === 5 ? b ^ 1 : b)))}))],
      ['extra OP_RETURN output', (o) => [...o, {lockingBytecode: Uint8Array.of(0x6a, 1, 7), valueSatoshis: 0n}]],
      ['token added to the output', (o) => o.map((x, i) => (i ? x : {...x, token: {category: Uint8Array.from(Array(32).fill(9)), amount: 1n}}))],
    ];
    for (const [nm, fn] of txc) { const c = chainRun(vk, stmt0, buf, base, fn(outs), false); record(file, 'tx', nm, false, c.acc, null, null); }
    { const r = base.slice(0, 4); r[3] = (r[3] + 1n) % P; const c = chainRun(vk, {...stmt0, root: r}, buf, base, outs, false); record(file, 'root', 'script ROOT[3] + 1', false, c.acc, null, null); }
  }
  if (LAYOUT && qaOf(vk) !== null) for (const lc of layoutCases(vk, dir, file, v)) {
    let c;
    if (lc.other) {
      const o = readVector(lc.other);
      const QA = qaOf(vk);
      const other = spendB2(vk, stmt0, QA, Buffer.from(o.proof_hex, 'hex'), o.public_values.flat().map(BigInt), outs);
      c = chainRun(vk, stmt0, buf, base, outs, false, (a) => [a, other.items1.map((x) => Buffer.from(x))]);
      // and the other proof alone is valid (control) under its own VK: the Plonky3 test AIRs salt their preprocessed
      // commitment with the prover's RNG (no published setup seed), so their second-seed proof has another VK
      const sameVk = JSON.stringify(o.preprocessed_commitment ?? null) === JSON.stringify(v.preprocessed_commitment ?? null);
      const vko = sameVk ? vk : vkxN(o, {stmt: 'auto'});
      const ctl = chainRun(vko, sameVk ? stmt0 : stmtFor(vko, o.public_values.flat().map(BigInt), {mode: vko.stmt, ctx: stmt0.ctx}), Buffer.from(o.proof_hex, 'hex'), o.public_values.flat().map(BigInt), outs, true);
      record(file, 'layout', `control: ${lc.nm.replace('input 1 data from ', '')} verifies on its own${sameVk ? ' (same VK)' : ' (under its own VK: other preprocessed commitment)'}`, true, ctl.acc, null, null, ctl.acc ? '' : String(ctl.err).slice(0, 80));
    } else c = chainRun(vk, stmt0, buf, base, outs, false, lc.f ? (a, b) => lc.f(a.map((x) => Buffer.from(x)), b.map((x) => Buffer.from(x))) : undefined, lc.tx);
    record(file, 'layout', lc.nm, false, c.acc, null, null, c.acc ? '' : String(c.err ?? '').slice(0, 70));
  }
}
console.log(`test-b2${PROD ? ' (production: CTX from the transaction)' : ''}: ${stats.files} files (${stats.layoutB} in layout b), ${stats.cases} cases, ${stats.unexpected} unexpected, ${stats.na} n/a, ${stats.refused} refused by the statement layer/generator, ${stats.encoderRefused} malformed by length, ${stats.skippedFiles.length} VKs refused by the generator`);
const notRunNote = () => `; ${stats.notRunOnChain ?? 0} not run on chain (short-circuit, counted as rejects: ${JSON.stringify(Object.fromEntries(Object.entries(stats.families).filter(([, x]) => x.notRunOnChain).map(([k, x]) => [k, x.notRunOnChain])))}); ${stats.encoderOnlyRelabel ?? 0} encoder-only relabels (reference rejects; script accepts the valid witness; inside the ok count)`;
console.log(notRunNote().slice(2));
console.log(JSON.stringify(stats.families));
if (outFile) writeFileSync(outFile, JSON.stringify(stats, null, 1) + '\n');
process.exit(stats.unexpected ? 1 : 0);
