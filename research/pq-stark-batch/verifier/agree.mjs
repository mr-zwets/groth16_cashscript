#!/usr/bin/env node
// agree.mjs: S3 agreement suite. Runs the JS verifier over every case file written by gen-cases.mjs (the
// valid proof, with its transcript compared to Rust's byte for byte, then every case) and compares each
// verdict with Rust's `check --verdicts` output for the same files.
//
// Usage: node agree.mjs --rust RUST-VERDICTS.json --out REPORT.json CASEFILE.json...
// Exit 1 on any JS/Rust disagreement, any verdict against the case's expectation, or any transcript difference.
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { vkFromVector, runCase } from './verify-batch.mjs';

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const files = args.filter((a, i) => !a.startsWith('--') && !['--rust', '--out'].includes(args[i - 1]));
const rust = new Map(JSON.parse(readFileSync(opt('--rust'), 'utf8')).map((r) => [`${basename(r.file)}\u0000${r.name}`, r]));

const fam = {}; const vectors = []; const variants = []; const disagree = []; const unexpected = []; let transcriptBad = 0; let n = 0;
const bump = (f, k) => { fam[f] ??= { cases: 0, js_accept: 0, rust_accept: 0, agree: 0, as_expected: 0 }; fam[f][k]++; };
for (const f of files) {
  const v = JSON.parse(readFileSync(f, 'utf8')); const vk = vkFromVector(v); const name = basename(f);
  const validExpect = v.s3_valid_expect ?? true; // false: a VK-variant file (the proof under another VK)
  const all = [{ name: 'valid', family: validExpect ? 'valid' : 'vk_variant', expect: validExpect, t: null }, ...v.tampered.map((t) => ({ name: t.name, family: t.family, expect: !!t.expect, t }))];
  let vms = 0;
  for (const c of all) {
    const log = c.t ? null : [];
    const t0 = performance.now(); const r = runCase(vk, v, c.t, log); const ms = performance.now() - t0;
    const rr = rust.get(`${name}\u0000${c.name}`);
    if (!rr) throw new Error(`no Rust verdict for ${name} / ${c.name}`);
    n++; bump(c.family, 'cases');
    if (r.accept) bump(c.family, 'js_accept');
    if (rr.accept) bump(c.family, 'rust_accept');
    if (r.accept === rr.accept) bump(c.family, 'agree'); else disagree.push({ file: name, case: c.name, js: r, rust: rr });
    if (r.accept === c.expect) bump(c.family, 'as_expected'); else unexpected.push({ file: name, case: c.name, js: r, expect: c.expect });
    if (!c.t) {
      vms = ms;
      const rt = v.transcript_hash_inputs; const same = rt.length === log.length && rt.every((h, i) => h === log[i]);
      if (!validExpect) { variants.push({ file: name, variant: v.s3_vk_variant, js: r, rust: rr }); continue; }
      if (!same) transcriptBad++;
      vectors.push({ file: name, source: v.s3_source, case: v.case, set: v.set.name, seed: v.seed, bytes: v.proof_hex.length / 2,
        accept: r.accept, transcript_identical: same, transcript_hashes: log.length, js_verify_ms: Math.round(ms), cases: all.length - 1 });
    }
  }
  const d = disagree.filter((x) => x.file === name).length; const u = unexpected.filter((x) => x.file === name).length;
  console.log(`${d || u ? 'FAIL' : 'ok  '} ${name}: ${all.length} cases (valid ${Math.round(vms)} ms), ${d} disagree, ${u} unexpected`);
}
// two proofs of the same statement under the same VK must differ (ZK salts and random codewords)
const groups = {};
for (const f of files) {
  const v = JSON.parse(readFileSync(f, 'utf8'));
  if (!v.set.zk) continue;
  const k = `${v.case}|${v.set.name}|${v.shift}`; (groups[k] ??= []).push({ seed: v.seed, hex: v.proof_hex });
}
const reseed = Object.entries(groups).filter(([, g]) => g.length > 1).map(([k, g]) => ({ group: k, proofs: g.length, seeds: g.map((x) => x.seed), all_distinct: new Set(g.map((x) => x.hex)).size === g.length }));

const report = {
  what: 'Track 8 S3: JS verify-batch.mjs vs Plonky3 verify_batch (Rust check --verdicts) on the same cases',
  valid_vectors: vectors.length, valid_accepted: vectors.filter((x) => x.accept).length, transcripts_identical: vectors.filter((x) => x.transcript_identical).length,
  vk_variants: variants, cases: n, disagreements: disagree.length, unexpected: unexpected.length, families: fam, reseed_distinct: reseed,
  js_verify_ms: { min: Math.min(...vectors.map((x) => x.js_verify_ms)), max: Math.max(...vectors.map((x) => x.js_verify_ms)) },
  disagree, unexpected_list: unexpected, vectors,
};
writeFileSync(opt('--out'), JSON.stringify(report, null, 1));
console.log(`agree: ${vectors.length} valid vectors (${report.valid_accepted} accepted, ${report.transcripts_identical} transcripts identical), ${n} cases, ${disagree.length} JS/Rust disagreements, ${unexpected.length} unexpected`);
console.log(`reseed: ${reseed.length} groups, ${reseed.filter((x) => x.all_distinct).length} with all proofs distinct`);
for (const [k, x] of Object.entries(fam)) console.log(`  ${k.padEnd(10)} ${String(x.cases).padStart(5)} cases  js accept ${x.js_accept}  rust accept ${x.rust_accept}  agree ${x.agree}  as expected ${x.as_expected}`);
process.exit(disagree.length || unexpected.length || transcriptBad ? 1 : 0);
