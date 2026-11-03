#!/usr/bin/env node
// test-b.mjs: layout (b) accept/reject sweep (DESIGN-T8 §8) for case files in the S3 gen-cases.mjs format (a vector
// whose `tampered` list holds the cases; each case may carry `public_values`, `replace`, `expect`).
//
// Every case gets three verdicts that must all equal the expected one:
//   chain  the generated script on libauth (valid: BCH 2026 with raised per-input limits (r100), standard and
//          consensus; reject cases: the loose VM, so that a reject is a failed check and not a resource limit)
//   model  model.mjs (the on-chain algorithm in JS)
//   ref    ../verifier/verify-batch.mjs (S3 reference; agrees with Plonky3's verify_batch on all S3 cases)
// Statement mapping onto the chain: ROOT is a constant of the script (the generator refuses a non-canonical ROOT:
// counted as rejected-by-generator), NF is a witness item (4 x u64 LE; a lane value >= 2^64 has no encoding: such
// cases are listed as "n/a"), CTX comes from the spending transaction (production) or from a witness item
// (--harness, used for S3's own case files, whose CTX values were drawn at random). In production, a case whose CTX
// differs from the transaction's is run with the transaction's outputs: the proof's CTX then differs from the
// script's, which is the "changed outputs" situation.
//
// Families added here (production files): tx (changed outputs), nf (non-canonical NF lanes, permuted lanes, NF item
// size), witness (manipulations of the valid spend's witness, Track 5 test-b list adapted).
// usage: node test-b.mjs [--harness] [--wit] [--out FILE] CASEFILE...
import {readFileSync, writeFileSync} from 'node:fs';
import {readVector, spendB, applyTamper} from './layout-b.mjs';
import {vkxFromVector, verifyModel, P, le8} from './model.mjs';
import {runCase, vkFromVector, parse as strictParse} from '../verifier/verify-batch.mjs';
import {evaluate} from './vm.mjs';
import {ctxOf} from './ctx.mjs';

const args = process.argv.slice(2);
const HARNESS = args.includes('--harness'), WIT = args.includes('--wit');
const oi = args.indexOf('--out'); const outFile = oi >= 0 ? args[oi + 1] : null;
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out');
const opts = HARNESS ? {ctx: 'witness'} : {};
const M64 = 1n << 64n;
const outputsOf = (v) => (v.s4_outputs ?? [{lockingBytecode: '6a', valueSatoshis: '0'}]).map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));

const stats = {files: 0, cases: 0, unexpected: 0, na: 0, refusedByGenerator: 0, families: {}, list: [], skippedFiles: []};
const fam = (f) => (stats.families[f] ??= {cases: 0, chainReject: 0, accept: 0, unexpected: 0, na: 0, refused: 0});
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
const canon = (xs) => xs.every((x) => x >= 0n && x < P);
function chainRun(vk, root, buf, pvEnc, outs, expectValid, mutate) {
  const sp = spendB(vk, root, buf, pvEnc, outs, opts, mutate);
  if (expectValid) {
    const a = evaluate('r100Std', sp.locking, sp.unlocking, sp.prog), b = evaluate('r100Cons', sp.locking, sp.unlocking, sp.prog);
    return {acc: a.accepted && b.accepted, err: a.error ?? b.error, sp};
  }
  const r = evaluate('looseStd', sp.locking, sp.unlocking, sp.prog);
  return {acc: r.accepted, err: r.error, sp};
}

function witnessCases(vk) {
  const Q = vk.Q, nRec = Math.ceil(Q / 2), nT = vk.trees.length;
  const iG = (t, g) => Q + t * nRec + g;
  const pt0 = Q + nT * nRec;   // ROOTS
  const iOOD = pt0 + 1, iFIN = pt0 + 2 + (vk.bpow ? 1 : 0) + 1 + (vk.cpow ? 1 : 0), iQPOW = iFIN + 1, iNF = iFIN + 1 + (vk.qpow ? 1 : 0);
  const flip = (b, at) => { const c = Buffer.from(b); c[at] ^= 1; return c; };
  const C = []; const mut = (name, f) => C.push({name, f});
  const batch = vk.batchBytes.reduce((a, x) => a + x, 0);
  mut('swap the L blobs of two queries', (it) => { [it[0], it[1]] = [it[1], it[0]]; return it; });
  mut('flip a row byte (random round)', (it) => { it[0] = flip(it[0], 0); return it; });
  mut('flip a row byte (trace round)', (it) => { it[0] = flip(it[0], vk.batchBytes[0] + 3); return it; });
  mut('flip a row byte (quotient round, last matrix)', (it) => { it[1] = flip(it[1], batch - 20); return it; });
  mut('flip a salt byte (trace round)', (it) => { it[0] = flip(it[0], vk.batchBytes[0] + 8 * vk.claims[1][0].width); return it; });
  mut('flip a FRI sibling byte', (it) => { it[2] = flip(it[2], batch + 5); return it; });
  mut('flip a FRI salt byte', (it) => { it[3] = flip(it[3], batch + vk.friBytes[0] - 2); return it; });
  mut('hint T + p (or flipped when T + p does not fit 8 bytes)', (it) => { const b = Buffer.from(it[0]); const T = b.readBigUInt64LE(b.length - 8); if (T + P < M64) b.writeBigUInt64LE(T + P, b.length - 8); else b[b.length - 8] ^= 1; it[0] = b; return it; });
  mut('hint T = 0', (it) => { const b = Buffer.from(it[0]); b.writeBigUInt64LE(0n, b.length - 8); it[0] = b; return it; });
  mut('hint T of another query', (it) => { const a = Buffer.from(it[0]), b = it[1]; b.copy(a, a.length - 8, b.length - 8); it[0] = a; return it; });
  mut('query blob one byte short', (it) => { it[0] = it[0].subarray(0, it[0].length - 1); return it; });
  mut('query blob one byte long', (it) => { it[0] = Buffer.concat([it[0], Buffer.alloc(1)]); return it; });
  mut('records: move a record between the first two pushes of tree 0 (repack, same bytes)', (it) => { const g0 = it[iG(0, 0)], g1 = it[iG(0, 1)]; const cut = recCut(vk, g0); it[iG(0, 0)] = g0.subarray(0, cut); it[iG(0, 1)] = Buffer.concat([g0.subarray(cut), g1]); return it; });
  mut('records: swap the first two pushes of tree 0', (it) => { [it[iG(0, 0)], it[iG(0, 1)]] = [it[iG(0, 1)], it[iG(0, 0)]]; return it; });
  mut('records: swap push 0 of tree 0 and tree 1', (it) => { [it[iG(0, 0)], it[iG(1, 0)]] = [it[iG(1, 0)], it[iG(0, 0)]]; return it; });
  mut('records: swap push 0 of the trace tree and the FRI tree', (it) => { [it[iG(1, 0)], it[iG(nT - 1, 0)]] = [it[iG(nT - 1, 0)], it[iG(1, 0)]]; return it; });
  mut('records: change sigma of the first record', (it) => { const g = Buffer.from(it[iG(0, 0)]); g[0] = (g[0] + 1) % Q; it[iG(0, 0)] = g; return it; });
  mut('records: sigma >= Q', (it) => { const g = Buffer.from(it[iG(0, 0)]); g[0] = Q; it[iG(0, 0)] = g; return it; });
  mut('records: op byte 10 (outside the record ops)', (it) => { const g = Buffer.from(it[iG(2, 0)]); g[1] = 10; it[iG(2, 0)] = g; return it; });
  mut('records: flip a sibling byte', (it) => { it[iG(1, 0)] = flip(it[iG(1, 0)], 6); return it; });
  mut('records: replace push 1 of tree 0 by a copy of push 0', (it) => { it[iG(0, 1)] = Buffer.from(it[iG(0, 0)]); return it; });
  mut('records: one trailing byte on the last push', (it) => { const i = iG(nT - 1, nRec - 1); it[i] = Buffer.concat([it[i], Uint8Array.of(9)]); return it; });
  mut('records: last push of tree 0 empty, its bytes appended to the one before', (it) => { const i = iG(0, nRec - 1); it[i - 1] = Buffer.concat([it[i - 1], it[i]]); it[i] = Buffer.alloc(0); return it; });
  mut('extra empty item at the bottom', (it) => [Buffer.alloc(0), ...it]);
  mut('extra empty item on top (below the redeem)', (it) => [...it, Buffer.alloc(0)]);
  mut('one item missing (first query blob)', (it) => it.slice(1));
  mut('swap OOD and FIN', (it) => { [it[iOOD], it[iFIN]] = [it[iFIN], it[iOOD]]; return it; });
  mut('flip a ROOTS byte (trace cap)', (it) => { it[pt0] = flip(it[pt0], 1); return it; });
  mut('flip a ROOTS byte (random cap)', (it) => { it[pt0] = flip(it[pt0], 64 + 1); return it; });
  mut('ROOTS: trace and quotient caps swapped', (it) => { const r = it[pt0]; it[pt0] = Buffer.concat([r.subarray(32, 64), r.subarray(0, 32), r.subarray(64)]); return it; });
  mut('flip an OOD byte (trace value)', (it) => { it[iOOD] = flip(it[iOOD], 6 * 24 + 3); return it; });
  mut('flip a FIN byte (last coefficient)', (it) => { it[iFIN] = flip(it[iFIN], it[iFIN].length - 20); return it; });
  if (vk.qpow) mut('query PoW witness + 1', (it) => { const b = Buffer.from(it[iQPOW]); b.writeBigUInt64LE((b.readBigUInt64LE(0) + 1n) % M64); it[iQPOW] = b; return it; });
  mut('NF item 31 bytes', (it) => { it[iNF] = it[iNF].subarray(0, 31); return it; });
  mut('NF item 33 bytes', (it) => { it[iNF] = Buffer.concat([it[iNF], Uint8Array.of(0)]); return it; });
  mut('NF lanes 0 and 1 swapped', (it) => { const b = it[iNF]; it[iNF] = Buffer.concat([b.subarray(8, 16), b.subarray(0, 8), b.subarray(16)]); return it; });
  mut('NF lane 0 = p (non-canonical)', (it) => { const b = Buffer.from(it[iNF]); b.writeBigUInt64LE(P, 0); it[iNF] = b; return it; });
  mut('NF lane 3 = 2^64 - 1 (non-canonical)', (it) => { const b = Buffer.from(it[iNF]); b.writeBigUInt64LE(M64 - 1n, 24); it[iNF] = b; return it; });
  mut('NF lane 0 + p when that fits 8 bytes, else lane 0 + 1', (it) => { const b = Buffer.from(it[iNF]); const x = b.readBigUInt64LE(0); b.writeBigUInt64LE(x + P < M64 ? x + P : (x + 1n) % P, 0); it[iNF] = b; return it; });
  return C;
}
function recCut(vk, g) { let o = 1; for (;;) { const op = g[o++]; const fresh = {1: 1, 2: 2, 3: 4, 4: 8, 5: 16}[op]; if (fresh) o += fresh * vk.h; else if (op === 8 || op === 9) return o; } }

for (const f of files) {
  const v = readVector(f), file = f.split('/').pop();
  let vk; try { vk = vkxFromVector(v); } catch (e) { stats.skippedFiles.push(`${file}: ${e.message}`); console.log(`skip ${file}: ${e.message}`); continue; }
  stats.files++;
  const ref0 = vk.base;
  const outs = outputsOf(v), base = v.public_values.flat().map(BigInt);
  const cases = [null, ...(v.tampered ?? [])];
  for (const t of cases) {
    const family = t ? (t.family ?? 'tampered') : (v.s3_vk_variant ? 'vk_variant' : 'valid');
    const name = t ? t.name : (v.s3_vk_variant ? `stored proof under VK ${v.s3_vk_variant}` : 'valid');
    const expect = t ? (t.expect ?? false) : (v.s3_valid_expect ?? true);
    const buf = t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex');
    const pv = t?.public_values ? t.public_values.flat().map(BigInt) : base;
    const ref = runCase(ref0, v, t).accept;
    if (pv.length !== 12) { record(file, family, name, expect, false, null, ref, '(public values for another instance layout: refused by the statement layer)', 'notRun'); continue; }
    const root = pv.slice(0, 4), nf = pv.slice(4, 8);
    if (!canon(root)) { fam(family).refused++; stats.refusedByGenerator++; record(file, family, name, expect, false, null, ref, '(non-canonical ROOT: the generator refuses this VK/statement)', 'notRun'); continue; }
    if (nf.some((x) => x < 0n || x >= M64)) { fam(family).na++; stats.na++; console.log(`n/a  ${file} [${family}] ${name}: NF lane >= 2^64 has no 8-byte encoding (see the nf family for encodable non-canonical lanes)`); continue; }
    // the chain's statement: CTX of the transaction (production) or the case's CTX (harness)
    let useOuts = outs;
    if (!HARNESS && pv.slice(8, 12).some((x, k) => x !== base[8 + k])) useOuts = altOutputs(outs);
    const ctxChain = HARNESS ? pv.slice(8, 12) : ctxOf(useOuts).lanes;
    if (HARNESS && pv.slice(8, 12).some((x) => x >= 1n << 56n)) { record(file, family, name, expect, false, null, ref, '(CTX lane >= 2^56: not producible by the statement layer)', 'notRun'); continue; }
    // a byte string that is not well-formed p3b-v1 by length (truncated, trailing bytes): the production encoder
    // refuses it. The lenient encoding still goes to the chain; when it reproduces the valid proof's witness exactly
    // (a truncated zero byte), the script is right to accept it, and the case is counted as encoder-refused.
    let malformed = null; try { strictParse(buf, ref0); } catch (e) { if (/truncated|trailing/.test(e.message)) malformed = e.message; }
    if (malformed) {
      fam(family).encoderRefused = (fam(family).encoderRefused ?? 0) + 1; stats.encoderRefused = (stats.encoderRefused ?? 0) + 1;
      const w = spendB(vk, root, buf, pv, useOuts, opts).items, w0 = spendB(vk, root, Buffer.from(v.proof_hex, 'hex'), base, outs, opts).items;
      const same = w.length === w0.length && w.every((x, i) => Buffer.compare(x, w0[i]) === 0) && pv.every((x, k) => x === base[k]);
      if (same) {
        const c0 = chainRun(vk, root, buf, pv, useOuts, false);
        record(file, family, name, true, c0.acc, null, null, `(malformed p3b-v1: ${malformed}; encoder refuses; its lenient witness is the valid proof's witness, so the script accepts it)`, 'encoderOnly');
        continue;
      }
    }
    const c = chainRun(vk, root, buf, pv, useOuts, expect);
    // model on the chain's statement (CTX from the transaction: a changed-output case has CTX != proof's)
    const pvModel = [...pv.slice(0, 8), ...ctxChain];
    const model = canon(pvModel) ? verifyModel(vk, buf, pvModel).ok : false;
    record(file, family, name, expect, c.acc, model, ref, c.acc === expect ? '' : String(c.err ?? '').slice(0, 80));
  }
  if (v.s3_vk_variant || v.s3_valid_expect === false) continue;
  // ---- transaction-level and witness families on the valid proof
  const buf = Buffer.from(v.proof_hex, 'hex');
  if (!HARNESS) {
    const txc = [
      ['output value - 1 sat', (o) => altOutputs(o)],
      ['output value + 1 sat', (o) => o.map((x, i) => (i ? x : {...x, valueSatoshis: x.valueSatoshis + 1n}))],
      ['recipient changed (one byte of the locking bytecode)', (o) => o.map((x, i) => (i ? x : {...x, lockingBytecode: Uint8Array.from(x.lockingBytecode.map((b, k) => (k === 5 ? b ^ 1 : b)))}))],
      ['extra OP_RETURN output', (o) => [...o, {lockingBytecode: Uint8Array.of(0x6a, 1, 7), valueSatoshis: 0n}]],
      ['output split in two', (o) => [{...o[0], valueSatoshis: o[0].valueSatoshis - 1000n}, {...o[0], valueSatoshis: 1000n}, ...o.slice(1)]],
      ['token added to the output', (o) => o.map((x, i) => (i ? x : {...x, token: {category: Uint8Array.from(Array(32).fill(9)), amount: 1n}}))],
      ['outputs of another statement', () => outputsOf({s4_outputs: [{lockingBytecode: '76a914' + 'ab'.repeat(20) + '88ac', valueSatoshis: '900000'}]})],
    ];
    for (const [name, fn] of txc) { const c = chainRun(vk, base.slice(0, 4), buf, base, fn(outs), false); record(file, 'tx', name, false, c.acc, null, null, c.acc ? '' : String(c.err ?? '').slice(0, 60)); }
    // foreign / stale ROOT: the script of another statement (another tree) with this proof
    // (the first other file whose ROOT differs: another tree, or the same tree's earlier root)
    let ovRoot = null, ovName = null;
    for (const x of files) { if (x === f) continue; const o = readVector(x); const r = o.public_values.flat().map(BigInt).slice(0, 4); if (r.length === 4 && r.some((y, k) => y !== base[k])) { ovRoot = r; ovName = x.split('/').pop(); break; } }
    if (ovRoot) { const c = chainRun(vk, ovRoot, buf, base, outs, false); record(file, 'root', `the script of ${ovName} (foreign/stale ROOT)`, false, c.acc, null, null); }
    { const r = base.slice(0, 4); r[3] = (r[3] + 1n) % P; const c = chainRun(vk, r, buf, base, outs, false); record(file, 'root', 'script ROOT[3] + 1', false, c.acc, null, null); }
  }
  if (WIT) for (const w of witnessCases(vk)) {
    const c = chainRun(vk, base.slice(0, 4), buf, base, outs, false, (items) => w.f(items.map((x) => Buffer.from(x))));
    record(file, 'witness', w.name, false, c.acc, null, null, c.acc ? '' : String(c.err ?? '').slice(0, 60));
  }
}
console.log(`test-b${HARNESS ? ' (harness: CTX as a witness item)' : ''}: ${stats.files} files, ${stats.cases} cases, ${stats.unexpected} unexpected, ${stats.na} n/a, ${stats.refusedByGenerator} refused by the generator, ${stats.encoderRefused ?? 0} malformed by length (encoder refuses), ${stats.skippedFiles.length} files skipped`);
const notRunNote = () => `; ${stats.notRunOnChain ?? 0} not run on chain (short-circuit, counted as rejects: ${JSON.stringify(Object.fromEntries(Object.entries(stats.families).filter(([, x]) => x.notRunOnChain).map(([k, x]) => [k, x.notRunOnChain])))}); ${stats.encoderOnlyRelabel ?? 0} encoder-only relabels (reference rejects; script accepts the valid witness; inside the ok count)`;
console.log(notRunNote().slice(2));
console.log(JSON.stringify(stats.families));
if (outFile) writeFileSync(outFile, JSON.stringify(stats, null, 1) + '\n');
process.exit(stats.unexpected ? 1 : 0);
void le8; void vkFromVector; void readFileSync;
