// Intratx/grouped Shamir vk_x replan (plain, non-residue BN254). Same idea as
// replan_vkx_candidate.mjs but for the 254-iter 2-scalar Shamir vk_x (manifest_vkx.json,
// gen_vkx.mjs). Regenerates the windows for an explicit boundary set so the real builds
// (intratx/build_vectors.mjs, grouped/build_vectors.mjs) can measure the hash-free deployment.
//
//   node replan_vkx_shamir_candidate.mjs 0,43,85,127,169,211,254   -> 6 vk_x chunks
// Shamir genCash(lo,hi,final,incoming,outgoing): incoming/outgoing are vestigial (the body
// forward-checks via variable-name covIn/covOut); the build's transform + specsVkx recompute
// all state, so only lo/hi/final matter. iters = 254; the last window is `final`.
import { writeFileSync, rmSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { genCash } from '../pairing/gen_vkx.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const ITERS = 254;

const bounds = (process.argv[2] ?? '').split(',').map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n));
if (bounds.length < 2 || bounds[0] !== 0 || bounds[bounds.length - 1] !== ITERS) {
  console.error(`usage: node replan_vkx_shamir_candidate.mjs 0,<...>,${ITERS}   (must start at 0, end at ${ITERS})`);
  process.exit(1);
}
const N = bounds.length - 1;

for (let i = 0; i < 32; i++) {
  const f = join(GEN, `vkx_${String(i).padStart(2, '0')}.cash`);
  if (existsSync(f)) rmSync(f);
}

const chunks = [];
for (let i = 0; i < N; i++) {
  const lo = bounds[i], hi = bounds[i + 1];
  const final = i === N - 1;
  writeFileSync(join(GEN, `vkx_${String(i).padStart(2, '0')}.cash`), genCash(lo, hi, final, '00', '00'));
  chunks.push({ idx: i, lo, hi, final, incoming: null, incomingState: null, zInv: null });
}
writeFileSync(join(GEN, 'manifest_vkx.json'), JSON.stringify({ numChunks: N, worstCaseSized: true, iters: ITERS, chunks }, null, 2));
console.error(`regenerated ${N} Shamir vk_x chunk(s): ${chunks.map((c) => `[${c.lo},${c.hi})${c.final ? 'F' : ''}`).join(' ')}`);
