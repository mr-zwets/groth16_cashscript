// Intratx vk_x replan: regenerate the GLV vk_x windows for an explicit boundary set, so the
// real build (build_vectors_residue.mjs) can measure the resulting chunk count / bytes / op
// under the HASH-FREE intratx cost model (vs the covenant-planned manifest_vkxglv.json, which
// sizes windows against measureCovenant's hashing overhead and thus over-splits for intratx).
//
//   node replan_vkx_candidate.mjs 0,34,68,101,128   -> 4 vk_x chunks (windows [0,34)…[101,128))
// The last window is `final` (fuses the finalize/assert), the first is `first` (genesis binding).
import { writeFileSync, rmSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { genCash } from '../pairing/gen_vkx_glv.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');

const bounds = (process.argv[2] ?? '').split(',').map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n));
if (bounds.length < 2 || bounds[0] !== 0 || bounds[bounds.length - 1] !== 128) {
  console.error('usage: node replan_vkx_candidate.mjs 0,<...>,128   (must start at 0, end at 128)');
  process.exit(1);
}
const N = bounds.length - 1;

// remove any stale vkxglv_*.cash beyond the new count so the file set matches the manifest
for (let i = 0; i < 32; i++) {
  const f = join(GEN, `vkxglv_${String(i).padStart(2, '0')}.cash`);
  if (existsSync(f)) rmSync(f);
}

const chunks = [];
for (let i = 0; i < N; i++) {
  const lo = bounds[i], hi = bounds[i + 1];
  const first = i === 0, final = i === N - 1;
  const src = genCash(lo, hi, first, final);
  writeFileSync(join(GEN, `vkxglv_${String(i).padStart(2, '0')}.cash`), src);
  chunks.push({ idx: i, lo, hi, first, final });
}
writeFileSync(join(GEN, 'manifest_vkxglv.json'), JSON.stringify({ numChunks: N, iters: 128, glv: true, chunks }, null, 2));
console.error(`regenerated ${N} vk_x chunk(s): ${chunks.map((c) => `[${c.lo},${c.hi})${c.final ? 'F' : ''}`).join(' ')}`);
