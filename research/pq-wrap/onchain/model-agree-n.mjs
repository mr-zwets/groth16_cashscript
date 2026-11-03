#!/usr/bin/env node
// model-agree-n.mjs: the generalized on-chain algorithm (modeln.mjs) against the S3 reference verifier
// (../verifier/verify-batch.mjs) on every case of the given case files (S3 gen-cases.mjs format). Valid proofs: verdicts
// equal and every SHA-256 transcript input equal to the reference's recording. Each case is run with the queries
// split as layout b2 splits them (--split QA, default 12) and, with --both, also unsplit (layout b).
// usage: node model-agree-n.mjs [--split QA] [--both] CASEFILE.json...   (exit 1 on any disagreement)
import {readFileSync} from 'node:fs';
import {vkxN, verifyModelN, applyTamper} from './modeln.mjs';
import {runCase, vkFromVector} from '../verifier/verify-batch.mjs';

const args = process.argv.slice(2);
const si = args.indexOf('--split'); const QA = si >= 0 ? +args[si + 1] : 12; const BOTH = args.includes('--both');
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--split');
const exact = (k, x, ctx) => (typeof x === 'number' && !Number.isSafeInteger(x) ? JSON.rawJSON(ctx.source) : x);
let total = 0, dis = 0, skipped = 0;
const fam = {};
for (const f of files) {
  const v = JSON.parse(readFileSync(f, 'utf8'), exact);
  let vk; try { vk = vkxN(v, {stmt: 'witness'}); } catch (e) { skipped++; console.log(`skip ${f.split('/').pop()}: ${e.message}`); continue; }
  const ref = vkFromVector(v);
  const qa = Math.min(QA, vk.Q - 1);
  const splits = [[Array.from({length: qa}, (_, q) => q), Array.from({length: vk.Q - qa}, (_, q) => qa + q)]];
  if (BOTH) splits.push([Array.from({length: vk.Q}, (_, q) => q)]);
  const pv = (t) => (t?.public_values ?? v.public_values).flat().map(BigInt);
  const cases = [null, ...(v.tampered ?? [])];
  const t0 = Date.now();
  for (const t of cases) {
    const buf = t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex');
    const log = [];
    const r = runCase(ref, v, t, t ? null : log);
    const pis = pv(t);
    const k = t?.family ?? 'valid'; fam[k] ??= [0, 0];
    // the statement layer fixes each instance's public-value count (VK data): another layout is refused
    const layoutOk = (t?.public_values ?? v.public_values).every((p, i) => p.length === vk.inst[i]?.numPublic) && (t?.public_values ?? v.public_values).length === vk.inst.length;
    if (!layoutOk) { total++; fam[k][0]++; if (r.accept) { dis++; fam[k][1]++; console.log(`DIS ${f} ${t?.name}: layout refused but ref accepts`); } continue; }
    for (const parts of splits) {
      const m = verifyModelN(vk, buf, pis, parts);
      total++; fam[k][0]++;
      let same = m.ok === r.accept;
      if (!t && same && m.ok) {
        const mh = m.enc.t.hashes;
        if (mh.length !== log.length || mh.some((x, i) => x !== log[i])) { same = false; console.log(`DIS ${f}: transcript differs (${mh.length} vs ${log.length})`); }
      }
      if (!same) { dis++; fam[k][1]++; console.log(`DIS ${f.split('/').pop()} ${t?.name ?? 'valid'} [${parts.length} part(s)]: model ${m.ok ? 'ACCEPT' : 'reject (' + m.reason + ')'} / ref ${r.accept ? 'ACCEPT' : 'reject (' + r.why + ')'}`); }
    }
  }
  console.log(`ok   ${f.split('/').pop()}: ${cases.length} cases x ${splits.length} (${Date.now() - t0} ms)`);
}
console.log(`model-agree-n: ${total} case runs, ${dis} disagreements, ${skipped} files skipped (unsupported VK)`);
console.log('families', JSON.stringify(fam));
process.exit(dis ? 1 : 0);
