// Bake the validated SAFE vk_x window floors into the hash-free (intratx/grouped) builders.
//
// Why this exists: the vk_x generators (gen_vkx_glv.mjs, gen_vkx.mjs) size windows against
// the COVENANT cost model (measureCovenant hashes the carried state every chunk), producing
// 5 GLV / 8 Shamir windows. But the intratx and grouped deployments forward-check with NO
// hashing (or hash only at group seams, never on a vk_x within-chunk), so those windows
// under-fill. Re-planning against the hash-free cost drops the chunk count. The intratx/
// grouped builders call the helpers below at startup so re-running a builder reproduces the
// replanned count instead of inheriting the covenant-planned manifest.
//
// SAFE FLOORS — grouped GLV revalidated 2026-07-15 with named full-valid density
// and asymmetric-resource fixtures plus an exhaustive equal-point event certificate;
// Shamir validated 2026-07-09. These floors are not based merely on a convenient
// proof vector: GLV's raw inputs decompose into four independently bounded witnesses.
//   GLV (128-iter, 4-scalar Straus): 3 windows [0,43)[43,86)[86,128)F — revalidated
//     after specializing fixed-table additions for affine second operands in
//     gen_vkx_glv.mjs. Builder max-density peak: 7,659,296 of 8,032,800.
//   GLV grouped 3x43 (up to three fixed-table additions per position): 2 windows
//     [0,21)[21,43)F. The concrete full-valid resource fixture peaks at 6,338,518
//     op-cost. prove_vkx_glv_resource_bound.mjs proves at most 4/6 equal-point
//     events per input and 9 total; prove_resource_ceiling.mjs combines both
//     maximal allocations with the Miller ceilings and constructs a 97,021-byte
//     proof-independent relayable transaction encoding.
//   Shamir (254-iter, 2-scalar): 6 windows [0,43)[43,86)[86,129)[129,172)[172,215)[215,254)F
//     — 95.4% of budget; the worst-case proof (in0,in1 popcount 253/254) already saturates
//     the binding windows, verified worst case. (5 windows > budget.)
// These bounds are specific to this VK/curve; re-validate with a max-density check
// (chunked/intratx/check_worstcase_vkx.mjs + a WC_IN override) if the circuit changes.
//
// The Shamir helper writes a PRIVATE manifest/.cash namespace (manifest_vkxplain.json,
// vkxplain_NN.cash) so the covenant build (chunked/pairing/build_vectors.mjs), which SHARES
// manifest_vkx and genuinely needs the 7-window hashing-sized layout, is left untouched.
import { writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { genCash as glvGenCash } from './pairing/gen_vkx_glv.mjs';
import { genCash as shamirGenCash } from './pairing/gen_vkx.mjs';

export const GLV_SAFE_BOUNDS = [0, 43, 86, 128];
export const GLV_GROUPED_BOUNDS = [0, 21, 43];
export const SHAMIR_SAFE_BOUNDS = [0, 43, 86, 129, 172, 215, 254];

const clearPrefix = (GEN, prefix) => {
  for (let i = 0; i < 32; i++) {
    const f = join(GEN, `${prefix}_${String(i).padStart(2, '0')}.cash`);
    if (existsSync(f)) rmSync(f);
  }
};

/** Regenerate the GLV vk_x windows (manifest_vkxglv.json + vkxglv_NN.cash) at the safe floor.
 * Shared by intratx-residue and grouped-residue (the only consumers of manifest_vkxglv). */
export function regenGlvSafe(
  GEN,
  bounds = GLV_SAFE_BOUNDS,
  stageBound = false,
  sharedTable = null,
  grouped = false,
  projectiveOutput = false,
) {
  clearPrefix(GEN, 'vkxglv');
  const chunks = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const lo = bounds[i], hi = bounds[i + 1];
    const first = i === 0, final = i === bounds.length - 2;
    writeFileSync(join(GEN, `vkxglv_${String(i).padStart(2, '0')}.cash`),
      glvGenCash(lo, hi, first, final, stageBound, sharedTable, false, grouped, projectiveOutput));
    chunks.push({ idx: i, lo, hi, first, final });
  }
  writeFileSync(join(GEN, 'manifest_vkxglv.json'), JSON.stringify({ numChunks: chunks.length,
    iters: grouped ? bounds.at(-1) : 128, glv: true, ...(grouped ? { grouped: true } : {}),
    safeFloor: true, stageBound, sharedTable: sharedTable !== null,
    ...(projectiveOutput ? { projectiveOutput: true } : {}), chunks }, null, 2));
  return chunks.length;
}

/** Regenerate the Shamir vk_x windows at the safe floor into a PRIVATE namespace
 * (manifest_${prefix}.json + ${prefix}_NN.cash), so the covenant build keeps manifest_vkx. */
export function regenShamirSafe(GEN, prefix = 'vkxplain', bounds = SHAMIR_SAFE_BOUNDS) {
  clearPrefix(GEN, prefix);
  const chunks = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const lo = bounds[i], hi = bounds[i + 1];
    const final = i === bounds.length - 2;
    writeFileSync(join(GEN, `${prefix}_${String(i).padStart(2, '0')}.cash`), shamirGenCash(lo, hi, final, '00', '00', true));
    chunks.push({ idx: i, lo, hi, first: i === 0, final, incoming: null, incomingState: null, zInv: null });
  }
  writeFileSync(join(GEN, `manifest_${prefix}.json`), JSON.stringify({ numChunks: chunks.length, worstCaseSized: true, stageBound: true, iters: 254, safeFloor: true, chunks }, null, 2));
  return chunks.length;
}
