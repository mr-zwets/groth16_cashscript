#!/usr/bin/env node
// model-agree.mjs: the on-chain algorithm (model.mjs) against the S3 reference verifier (../verifier/verify-batch.mjs)
// on every case of the given case files (S3 gen-cases.mjs format: a vector whose `tampered` list holds the cases).
// Valid proofs: verdicts equal and every SHA-256 transcript input equal to the reference's recording (the model's
// digest chain hashes exactly the challenger's inputs). Cases whose VK differs from what this generator supports
// (other cap, M2, ...) are run through the model only when the vector itself is supported; a case that replaces the
// proof by another VK's proof stays in (the model must reject it).
// usage: node model-agree.mjs CASEFILE.json...   (exit 1 on any disagreement)
import {readFileSync} from 'node:fs';
import {vkxFromVector, verifyModel, applyTamper} from './model.mjs';
import {runCase, vkFromVector} from '../verifier/verify-batch.mjs';

const exact = (k, x, ctx) => (typeof x === 'number' && !Number.isSafeInteger(x) ? JSON.rawJSON(ctx.source) : x);
let total = 0, dis = 0, skipped = 0;
const fam = {};
for (const f of process.argv.slice(2)) {
  const v = JSON.parse(readFileSync(f, 'utf8'), exact);
  let vk; try { vk = vkxFromVector(v); } catch (e) { skipped++; console.log(`skip ${f.split('/').pop()}: ${e.message}`); continue; }
  const ref = vkFromVector(v);
  const pv = (t) => (t?.public_values ?? v.public_values).flat().map(BigInt);
  const cases = [null, ...(v.tampered ?? [])];
  for (const t of cases) {
    const buf = t ? applyTamper(v.proof_hex, t) : Buffer.from(v.proof_hex, 'hex');
    const log = [];
    const r = runCase(ref, v, t, t ? null : log);
    const pis = pv(t);
    if (pis.length !== vk.numPublic) { total++; if (r.accept) { dis++; console.log(`DIS ${f} ${t?.name}: public value count`); } continue; }
    const m = verifyModel(vk, buf, pis);
    total++;
    const k = t?.family ?? 'valid'; fam[k] ??= [0, 0]; fam[k][0]++;
    let same = m.ok === r.accept;
    if (!t && same && m.ok) {
      const mh = m.enc.t.hashes;
      // the model logs each digest-chain input; the reference logs each challenger flush (same strings)
      if (mh.length !== log.length || mh.some((x, i) => x !== log[i])) { same = false; console.log(`DIS ${f}: transcript differs (${mh.length} vs ${log.length})`); }
    }
    if (!same) { dis++; fam[k][1]++; console.log(`DIS ${f.split('/').pop()} ${t?.name ?? 'valid'}: model ${m.ok ? 'ACCEPT' : 'reject (' + m.reason + ')'} / ref ${r.accept ? 'ACCEPT' : 'reject (' + r.why + ')'}`); }
  }
  console.log(`ok   ${f.split('/').pop()}: ${cases.length} cases`);
}
console.log(`model-agree: ${total} cases, ${dis} disagreements, ${skipped} files skipped (unsupported VK)`);
console.log('families', JSON.stringify(fam));
process.exit(dis ? 1 : 0);
