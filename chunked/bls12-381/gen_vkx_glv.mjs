// GLV vk_x generator (BLS12-381): vk_x = IC0 + in0*IC1 + in1*IC2 via the G1 endomorphism.
// BLS port of chunked/pairing/gen_vkx_glv.mjs, using the SAME validated GLV constants as the
// op-optimized singleton (singleton/bls12-381/gen_singleton_minop.mjs): lambda = -x^2 mod r,
// basis {(1,-(x^2-1)),(x^2,1)}, beta the Fp cube root. Each public input k is decomposed (GLV)
// into NON-NEGATIVE k1 + k2*lambda (mod r) with k1,k2 < 2^128, turning the 2-scalar 255-bit MSM
// into a 4-scalar 128-bit Straus over the FIXED points {IC1, phi(IC1), IC2, phi(IC2)}
// (phi(x,y)=(beta*x,y)). A baked 16-entry subset-sum table folds all 4 scalars into ONE add per
// iteration -> ~half the doublings (vkx 12 -> 5 shared-table chunks). Each GLV witness is gated at
// genesis (k < 2^128 and the decomposition congruence holds); phi(IC*) and the table are baked.
//   node gen_vkx_glv.mjs    plan + emit vkxglv_NN.cash + manifest_vkxglv.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { P, OP_BUDGET, covIn, covOut, measureCovenant, planChunk, vk, bls12_381 } from './_vkxmath.mjs';
import {
  FIXED_VK_COLLAPSED_PROOF_OFFSET,
  FIXED_VK_COLLAPSED_PUBLIC_BASE,
  FIXED_VK_SPECIALIZATION,
} from './_pairingmath.mjs';
import { proof } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const G1 = bls12_381.G1.Point;
const Pstr = P.toString();
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const X = 0xd201000000010000n; // |x|
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const STAGE_BOUND = process.env.STAGE_BOUND_LAYOUT === '1';
const UNIT_G1 = process.env.BLS_UNIT_G1 === '1';
const FIXED_VK_COLLAPSE = process.env.BLS_FIXED_VK_COLLAPSE === '1';
const FIXED_COMB_WIDTH = Number(process.env.BLS_FIXED_COMB_WIDTH ?? 0);
if (FIXED_VK_COLLAPSE && !UNIT_G1) throw new Error('fixed-VK GLV collapse requires unit G1 coordinates');
if (FIXED_COMB_WIDTH !== 0 && (!FIXED_VK_COLLAPSE || ![4, 5, 6, 7, 8].includes(FIXED_COMB_WIDTH))) {
  throw new Error('fixed-base comb width must be between 4 and 8 in fixed-VK collapse mode');
}
const FIXED_COMB = FIXED_COMB_WIDTH !== 0;
const SCALAR_BITS = 128; // every GLV sub-scalar is below 2^128
// The collapsed fixed VK combines both public-input bases before decomposition. Fixed-comb mode
// consumes one canonical 255-bit scalar across width-spaced bases; the GLV mode consumes two bits
// from each of two components with a radix-4 joint table.
const ITERS = FIXED_COMB
  ? Math.ceil(255 / FIXED_COMB_WIDTH)
  : FIXED_VK_COLLAPSE ? SCALAR_BITS / 2 : SCALAR_BITS;

// ---- GLV constants (same as the singleton minop; proof-independent) ----
export const GLV_BETA = 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350n;
export const GLV_LAMBDA = r - ((X * X) % r); // -x^2 mod r
export const GLV_R = r;
export { ITERS as VKXGLV_ITERS };
// Deterministic all-position stress pair reproduced by find_glv_all_positions.mjs. Its four
// GLV sub-scalars execute an add at every Straus position. It produced the largest total op-cost
// among 32 full valid verifier proofs and a heavier maximum step than the previous fixture. A
// separate 256-pair audit of the exact shared-table lockings observed at most 7,646,311 of the
// 8,032,800 input budget. These are empirical stress results, not a formal global maximum.
export const GLV_HIGH_COST_INPUTS = [
  40792793307691160132937706698213704133054528069427933762012433436987942497952n,
  20976222017425405296340351928930328963278634447870202382235661951061637561134n,
];
export const GLV_COLLAPSED_HIGH_COST_INPUTS = [
  17929930412781756779500091620588165311269371813046065190763582548194664864854n,
  0n,
];
export const GLV_SHARED_AUDITED_BOUNDS = FIXED_VK_COLLAPSE
  ? FIXED_COMB_WIDTH === 8
    ? [0, 32]
    : FIXED_COMB_WIDTH === 7
      ? [0, 19, 37]
      : FIXED_COMB_WIDTH === 6
        ? [0, 43]
        : FIXED_COMB_WIDTH === 5
          ? [0, 26, 51]
          : [0, 16, 32, 48, 64]
  : [0, 25, 51, 77, 103, 128];

const modP = (v) => ((v % P) + P) % P;
const phiPt = (Pt) => { const a = Pt.toAffine(); return G1.fromAffine({ x: (a.x * GLV_BETA) % P, y: a.y }); };
const collapsedPublicBase = FIXED_VK_COLLAPSED_PUBLIC_BASE;
const collapsedProofOffset = FIXED_VK_COLLAPSED_PROOF_OFFSET;
const collapsedInputScalars = FIXED_VK_SPECIALIZATION.collapsedInputScalars;
if (collapsedInputScalars.length !== 2) throw new Error('fixed-key collapse requires two public-input scalars');
export const glvCollapsedScalar = (in0, in1) => (
  (collapsedInputScalars[0] * BigInt(in0) + collapsedInputScalars[1] * BigInt(in1)) % r + r
) % r;
export const glvCollapsedProofPoint = (cPoint) => cPoint
  .multiply(FIXED_VK_SPECIALIZATION.deltaG2Scalar)
  .add(collapsedProofOffset);
const fixedOffsetPoint = FIXED_VK_COLLAPSE ? G1.ZERO : vk.ic[0];
const _ic0 = fixedOffsetPoint.toAffine();
const IC0 = [_ic0.x, _ic0.y];
const BP = FIXED_COMB
  ? Array.from({ length: FIXED_COMB_WIDTH }, (_, j) => collapsedPublicBase.multiply(1n << BigInt(j * ITERS)))
  : FIXED_VK_COLLAPSE
    ? [collapsedPublicBase, phiPt(collapsedPublicBase)]
  : [vk.ic[1], phiPt(vk.ic[1]), vk.ic[2], phiPt(vk.ic[2])];
const TABLE = [];
for (let idx = 1; idx < (1 << (FIXED_COMB ? FIXED_COMB_WIDTH : 4)); idx++) {
  let acc = G1.ZERO;
  if (FIXED_COMB) {
    for (let j = 0; j < FIXED_COMB_WIDTH; j++) if (idx & (1 << j)) acc = acc.add(BP[j]);
  } else if (FIXED_VK_COLLAPSE) {
    const k1 = BigInt(idx % 4), k2 = BigInt(Math.floor(idx / 4));
    if (k1 !== 0n) acc = acc.add(BP[0].multiply(k1));
    if (k2 !== 0n) acc = acc.add(BP[1].multiply(k2));
  } else {
    for (let i = 0; i < 4; i++) if (idx & (1 << i)) acc = acc.add(BP[i]);
  }
  const a = acc.toAffine(); TABLE[idx] = [a.x, a.y];
}
if (TABLE.slice(1).some(([x]) => x === 0n)) throw new Error('x=0 is reserved for the GLV no-add sentinel');
// Table blob: entry (idx-1) = x(LE48) || y(LE48); split() reads an entry in O(1).
// 48-byte LE is sign-safe: p < 2^382 -> top byte <= 0x1a -> int() recovers positive.
const le48hex = (v) => { v = modP(v); let s = ''; for (let b = 0; b < 48; b++) s += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0'); return s; };
export const GLV_TABLE_HEX = '0x' + Array.from(
  { length: (1 << (FIXED_COMB ? FIXED_COMB_WIDTH : 4)) - 1 },
  (_, k) => le48hex(TABLE[k + 1][0]) + le48hex(TABLE[k + 1][1]),
).join('');
const tableBytes = Buffer.from(GLV_TABLE_HEX.slice(2), 'hex');
// Width seven is kept as two stack items because the complete table is larger than the
// current per-item byte limit. The two fixed digests still pin every table byte exactly.
export const GLV_TABLE_SEGMENT_LENGTHS = FIXED_COMB_WIDTH === 8
  ? [85 * 96, 85 * 96, 85 * 96]
  : FIXED_COMB_WIDTH === 7
    ? [84 * 96, 43 * 96]
    : [tableBytes.length];
const tableSegments = (() => {
  let offset = 0;
  return GLV_TABLE_SEGMENT_LENGTHS.map((length) => {
    const segment = tableBytes.subarray(offset, offset + length);
    offset += length;
    return segment;
  });
})();
if (tableSegments.reduce((sum, segment) => sum + segment.length, 0) !== tableBytes.length) {
  throw new Error('fixed-comb table segments do not cover the complete table');
}
// CashScript hash256 is double SHA-256. The carrier check uses these digests, so every
// sibling reading the same transaction inputs uses the fixed VK-derived table.
const TABLE_HASH_HEXES = tableSegments.map((segment) =>
  '0x' + createHash('sha256').update(createHash('sha256').update(segment).digest()).digest('hex'));

// ---- GLV decomposition (shared with the vector builder) ----
// basis {(1, -(x^2-1)), (x^2, 1)}: 1 - (x^2-1)*lambda == r == 0 and x^2 + lambda == 0 (mod r).
const A1 = 1n, B1 = -(X * X - 1n), A2 = X * X, B2 = 1n;
const rnd = (num, den) => { const q = num / den, rem = num - q * den, t = 2n * (rem < 0n ? -rem : rem); let res = q; if (t > den) res += ((num < 0n) !== (den < 0n)) ? -1n : 1n; return res; };
/** GLV decomposition of k into NON-NEGATIVE (k1,k2), k = k1 + k2*lambda (mod r), < 2^128. */
export function glvDecompose(k) {
  const c1 = rnd(B2 * k, r), c2 = rnd(-B1 * k, r);
  let k1 = k - c1 * A1 - c2 * A2, k2 = -c1 * B1 - c2 * B2;
  let best = null;
  for (let i = -2n; i <= 2n; i++) for (let j = -2n; j <= 2n; j++) { const x = k1 + i * A1 + j * A2, y = k2 + i * B1 + j * B2; if (x >= 0n && y >= 0n) { const sc = x > y ? x : y; if (best === null || sc < best.s) best = { x, y, s: sc }; } }
  return [best.x, best.y];
}

// ---- JS Jacobian MSM matching the contract (for planning + build) ----
const aF = (x, y) => modP(x + y), sF = (x, y) => modP(x - y), mF = (x, y) => modP(x * y), qF = (x) => modP(x * x);
function jacDouble(X0, Y0, Z0) { const a = qF(X0), b = qF(Y0), c = qF(b); const d = mF(2n, sF(sF(qF(aF(X0, b)), a), c)); const e = mF(3n, a), f = qF(e); const nx = sF(f, mF(2n, d)); return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y0, Z0))]; }
function jacAdd(aX, aY, aZ, bX, bY, bZ) { if (aZ === 0n) return [bX, bY, bZ]; const z1 = qF(aZ), z2 = qF(bZ); const u1 = mF(aX, z2), u2 = mF(bX, z1); const s1 = mF(mF(aY, bZ), z2), s2 = mF(mF(bY, aZ), z1); if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ); const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2); const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2); const nx = sF(sF(qF(rr), j), mF(2n, v)); return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1), z2), h)]; }
const affineIdentity = ([x, y]) => x === 0n && y === 0n;
function affineDouble(point) {
  const [x, y] = point;
  if (affineIdentity(point) || y === 0n) return { point: [0n, 0n], slope: 0n };
  const slope = mF(mF(3n, qF(x)), modinvP(mF(2n, y)));
  const nx = sF(qF(slope), mF(2n, x));
  return { point: [nx, sF(mF(slope, sF(x, nx)), y)], slope };
}
function affineAdd(point, addend) {
  if (affineIdentity(addend)) return { point, slope: 0n };
  if (affineIdentity(point)) return { point: addend, slope: 0n };
  const [x, y] = point, [qx, qy] = addend;
  if (x === qx) {
    if (y === qy) return affineDouble(point);
    if (aF(y, qy) !== 0n) throw new Error('invalid affine equal-x branch');
    return { point: [0n, 0n], slope: 0n };
  }
  const slope = mF(sF(y, qy), modinvP(sF(x, qx)));
  const nx = sF(sF(qF(slope), x), qx);
  return { point: [nx, sF(mF(slope, sF(x, nx)), y)], slope };
}
const TBL = TABLE.map((pt) => (pt ? [modP(pt[0]), modP(pt[1])] : null));
/** accumulator [X,Y,Z] after MSM windows [0,upto) for scalars (k10,k20,k11,k21). */
export function vkxGlvStateAt(k10, k20, k11, k21, upto, cPoint = null) {
  let Xa = 0n, Ya = 1n, Za = 0n;
  if (FIXED_VK_COLLAPSE) {
    if (k11 !== 0n || k21 !== 0n) throw new Error('collapsed GLV reserves the second scalar pair');
    if (FIXED_COMB && k20 !== 0n) throw new Error('fixed-base comb reserves the second GLV component');
    let point = [0n, 0n];
    if (upto > 0) {
      const idx = FIXED_COMB
        ? Array.from({ length: FIXED_COMB_WIDTH }, (_, j) => {
            const bit = ITERS - 1 + j * ITERS;
            return bit < 255 ? Number((k10 >> BigInt(bit)) & 1n) << j : 0;
          }).reduce((sum, digit) => sum + digit, 0)
        : Number(((k10 >> BigInt(2 * (ITERS - 1))) & 3n) + 4n * ((k20 >> BigInt(2 * (ITERS - 1))) & 3n));
      point = idx > 0 ? TBL[idx] : [0n, 0n];
    }
    for (let w = 1; w < upto; w++) {
      point = affineDouble(point).point;
      if (!FIXED_COMB) point = affineDouble(point).point;
      const idx = FIXED_COMB
        ? Array.from({ length: FIXED_COMB_WIDTH }, (_, j) =>
            Number((k10 >> BigInt(ITERS - 1 - w + j * ITERS)) & 1n) << j)
          .reduce((sum, digit) => sum + digit, 0)
        : Number(((k10 >> BigInt(2 * (ITERS - 1 - w))) & 3n) + 4n * ((k20 >> BigInt(2 * (ITERS - 1 - w))) & 3n));
      point = affineAdd(point, idx > 0 ? TBL[idx] : [0n, 0n]).point;
    }
    return point;
  }
  for (let w = 0; w < upto; w++) {
    const i = BigInt((ITERS - 1) - w);
    if (Za !== 0n) [Xa, Ya, Za] = jacDouble(Xa, Ya, Za);
    const idx = Number(((k10 >> i) & 1n) + 2n * ((k20 >> i) & 1n) + 4n * ((k11 >> i) & 1n) + 8n * ((k21 >> i) & 1n));
    if (idx > 0) { const t = TBL[idx]; [Xa, Ya, Za] = jacAdd(Xa, Ya, Za, t[0], t[1], 1n); }
  }
  return [Xa, Ya, Za];
}
const modinvP = (a) => { let R = 1n, b = modP(a), e = P - 2n; while (e > 0n) { if (e & 1n) R = (R * b) % P; b = (b * b) % P; e >>= 1n; } return R; };
export function glvUnitCoordinates(point) {
  if (point.is0()) return { u: 0n, v: 0n, vInv: 0n };
  const { x, y } = point.toAffine();
  const twoYInv = modinvP(mF(2n, y));
  const u = modP(0n - mF(x, twoYInv));
  const v = modP(0n - twoYInv);
  return { u, v, vInv: modinvP(v) };
}
const finishGlv = (acc, cPoint) => {
  if (!FIXED_VK_COLLAPSE) return jacAdd(acc[0], acc[1], acc[2], modP(IC0[0]), modP(IC0[1]), 1n);
  if (cPoint === null) throw new Error('collapsed GLV finalization requires the proof C point');
  const transformed = glvCollapsedProofPoint(cPoint);
  const transformedAffine = transformed.toAffine();
  const affine = transformed.is0() ? [0n, 0n] : [transformedAffine.x, transformedAffine.y];
  return affineAdd(acc, affine).point;
};
/** final zInv = (Z of (acc + IC0))^-1 mod p. */
export function vkxGlvZinv(k10, k20, k11, k21, cPoint = null) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, ITERS, cPoint);
  const [, , fz] = finishGlv(acc, cPoint);
  return fz === 0n ? 0n : modinvP(fz);
}
/** final yInv for the identity-complete unit G1 handoff. Jacobian Y remains
 * nonzero for both finite points and the canonical Z=0 infinity state. */
export function vkxGlvYinv(k10, k20, k11, k21, cPoint = null) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, ITERS, cPoint);
  const [, fy] = finishGlv(acc, cPoint);
  return fy === 0n ? 0n : modinvP(mF(2n, fy));
}
export function vkxGlvUnit(k10, k20, k11, k21, cPoint = null) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, ITERS, cPoint);
  if (FIXED_VK_COLLAPSE) {
    const [fx, fy] = finishGlv(acc, cPoint);
    if (fx === 0n && fy === 0n) return [0n, 0n];
    const yInv = modinvP(mF(2n, fy));
    return [modP(0n - mF(fx, yInv)), modP(0n - yInv)];
  }
  const [fx, fy, fz] = finishGlv(acc, cPoint);
  const yInv = modinvP(mF(2n, fy));
  const z2 = qF(fz), z3 = mF(z2, fz);
  return [modP(0n - mF(mF(fx, fz), yInv)), modP(0n - mF(z3, yInv))];
}
export function vkxGlvSlopeLimbs(k10, k20, k11, k21, lo, hi, cPoint = null) {
  if (!FIXED_VK_COLLAPSE) return [];
  if (k11 !== 0n || k21 !== 0n) throw new Error('collapsed GLV reserves the second scalar pair');
  if (FIXED_COMB && k20 !== 0n) throw new Error('fixed-base comb reserves the second GLV component');
  let point = vkxGlvStateAt(k10, k20, k11, k21, lo, cPoint);
  const slopes = [];
  for (let w = lo; w < hi; w++) {
    if (w === 0) {
      const idx = FIXED_COMB
        ? Array.from({ length: FIXED_COMB_WIDTH }, (_, j) => {
            const bit = ITERS - 1 + j * ITERS;
            return bit < 255 ? Number((k10 >> BigInt(bit)) & 1n) << j : 0;
          }).reduce((sum, digit) => sum + digit, 0)
        : Number(((k10 >> BigInt(2 * (ITERS - 1))) & 3n) + 4n * ((k20 >> BigInt(2 * (ITERS - 1))) & 3n));
      point = idx > 0 ? TBL[idx] : [0n, 0n];
      continue;
    }
    let step = affineDouble(point); slopes.push(step.slope); point = step.point;
    if (!FIXED_COMB) { step = affineDouble(point); slopes.push(step.slope); point = step.point; }
    const idx = FIXED_COMB
      ? Array.from({ length: FIXED_COMB_WIDTH }, (_, j) =>
          Number((k10 >> BigInt(ITERS - 1 - w + j * ITERS)) & 1n) << j)
        .reduce((sum, digit) => sum + digit, 0)
      : Number(((k10 >> BigInt(2 * (ITERS - 1 - w))) & 3n) + 4n * ((k20 >> BigInt(2 * (ITERS - 1 - w))) & 3n));
    step = affineAdd(point, idx > 0 ? TBL[idx] : [0n, 0n]); slopes.push(step.slope); point = step.point;
  }
  if (hi === ITERS) {
    const transformed = glvCollapsedProofPoint(cPoint);
    const transformedAffine = transformed.toAffine();
    const addend = transformed.is0() ? [0n, 0n] : [transformedAffine.x, transformedAffine.y];
    slopes.push(affineAdd(point, addend).slope);
  }
  return slopes;
}
export const GLV_IC0 = IC0;
export const GLV_FIXED_VK_COLLAPSE = FIXED_VK_COLLAPSE;
export const GLV_FIXED_COMB_WIDTH = FIXED_COMB_WIDTH;

// ---- contract template ----
const STATE = FIXED_VK_COLLAPSE
  ? FIXED_COMB
    ? ['rX', 'rY', 'in0', 'in1']
    : ['rX', 'rY', 'in0', 'in1', 'k10', 'k20']
  : ['rX', 'rY', 'rZ', 'in0', 'in1', 'k10', 'k20', 'k11', 'k21'];
const GENESIS_STATE = STATE.slice(FIXED_VK_COLLAPSE ? 2 : 3);
const PROOF_NAMES = UNIT_G1
  ? FIXED_VK_COLLAPSE
    ? ['Au', 'Av', 'Bxa', 'Bxb', 'Bya', 'Byb']
    : ['Au', 'Av', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cu', 'Cv']
  : ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy'];
const tableParamNames = FIXED_VK_COLLAPSE
  ? tableSegments.map((_, index) => `table${index}`)
  : ['table'];
const tableParams = (sharedTable) => sharedTable
  ? tableParamNames.map((name) => `bytes ${name}`).join(', ')
  : '';
const embeddedTables = () => FIXED_VK_COLLAPSE
  ? tableSegments
      .map((segment, index) => `bytes table${index} = 0x${segment.toString('hex')};`)
      .join('\n        ')
  : `bytes table = ${GLV_TABLE_HEX};`;
const tableEntrySelection = !FIXED_VK_COLLAPSE
  ? 'bytes ent = table.split((idx - 1) * 96)[1].split(96)[0];'
  : tableSegments.length === 1
    ? 'bytes ent = table0.split((idx - 1) * 96)[1].split(96)[0];'
  : (() => {
      let firstEntry = 1;
      const branches = GLV_TABLE_SEGMENT_LENGTHS.map((length, index) => {
        const lastEntry = firstEntry + length / 96 - 1;
        const prefix = index === 0
          ? `if (idx <= ${lastEntry})`
          : index === GLV_TABLE_SEGMENT_LENGTHS.length - 1
            ? 'else'
            : `else if (idx <= ${lastEntry})`;
        const offset = firstEntry === 1 ? 'idx - 1' : `idx - ${firstEntry}`;
        const branch = `${prefix} {
            ent = table${index}.split((${offset}) * 96)[1].split(96)[0];
        }`;
        firstEntry = lastEntry + 1;
        return branch;
      });
      return `bytes ent = table0.split(0)[0];
        ${branches.join(' ')}`;
    })();
// Every coordinate entering the emitted affine formulas is canonical. Positive p/2p biases keep
// unreduced differences nonnegative; field multiplication and final remainders preserve the same
// equations while canonicalizing each output once.
const prologue = (sharedTable) => `function addFp(int x, int y) returns (int) { return (x + y) % ${Pstr}; }
function subFp(int x, int y) returns (int) { return (x - y + ${Pstr}) % ${Pstr}; }
function mulFp(int x, int y) returns (int) { return (x * y) % ${Pstr}; }
function sqrFp(int x) returns (int) { return (x * x) % ${Pstr}; }
function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = sqrFp(x); int b = sqrFp(y); int c = sqrFp(b);
    int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
    int e = mulFp(3, a); int f = sqrFp(e);
    int nx = subFp(f, mulFp(2, d));
    int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
    int nz = mulFp(2, mulFp(y, z));
    return nx, ny, nz;
}
function jacAddAffine(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = 1;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ);
        int u2 = mulFp(bX, z1z1);
        int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (aX == u2 && aY == s2) {
            int da = sqrFp(aX); int db = sqrFp(aY); int dc = sqrFp(db);
            int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
            int de = mulFp(3, da); int df = sqrFp(de);
            int dnx = subFp(df, mulFp(2, dd));
            int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
            int dnz = mulFp(2, mulFp(aY, aZ));
            rx = dnx; ry = dny; rz = dnz;
        } else {
            int h = subFp(u2, aX); int i2 = sqrFp(mulFp(2, h)); int jj = mulFp(h, i2);
            int rr = mulFp(2, subFp(s2, aY)); int vv = mulFp(aX, i2);
            int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(aY, jj)));
            int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, 1)), z1z1), 1), h);
            rx = anx; ry = any; rz = anz;
        }
    }
    return rx, ry, rz;
}
function affineDouble(int x, int y, int slope) returns (int, int) {
    int rx = 0; int ry = 0;
    bool toIdentity = (x == 0 && y == 0) || y == 0;
    if (toIdentity) {
        require(slope == 0);
    } else {
        require(within(slope, 0, ${Pstr}));
        require(mulFp(y + y, slope) == mulFp(3, sqrFp(x)));
        rx = (sqrFp(slope) + ${2n * P} - x - x) % ${Pstr};
        ry = (mulFp(slope, x + ${Pstr} - rx) + ${Pstr} - y) % ${Pstr};
    }
    return rx, ry;
}
function affineAdd(int x, int y, int qx, int qy, int slope) returns (int, int) {
    int rx = x; int ry = y;
    bool pIdentity = x == 0 && y == 0;
    bool qIdentity = qx == 0 && qy == 0;
    if (qIdentity) {
        require(slope == 0);
    } else if (pIdentity) {
        require(slope == 0); rx = qx; ry = qy;
    } else if (x == qx) {
        if (y == qy) {
            (int dx, int dy) = affineDouble(x, y, slope); rx = dx; ry = dy;
        } else {
            require(y + qy == ${Pstr}); require(slope == 0); rx = 0; ry = 0;
        }
    } else {
        require(within(slope, 0, ${Pstr}));
        require(mulFp(slope, x + ${Pstr} - qx) == (y + ${Pstr} - qy) % ${Pstr});
        rx = (sqrFp(slope) + ${2n * P} - x - qx) % ${Pstr};
        ry = (mulFp(slope, x + ${Pstr} - rx) + ${Pstr} - y) % ${Pstr};
    }
    return rx, ry;
}
function select16(int idx${sharedTable ? `, ${tableParams(true)}` : ''}) returns (int, int) {
    // idx=0 keeps aX=0; every fixed affine table entry has nonzero x.
    int aX = 0; int aY = 0;
    if (idx != 0) {
        ${sharedTable ? '' : embeddedTables()}
        ${tableEntrySelection}
        aX = int(ent.split(48)[0]);
        aY = int(ent.split(48)[1]);
    }
    return aX, aY;
}`;

export function genCash(lo, hi, first, final, stageBound = false, sharedTable = null, fullStageBound = false) {
  const sharedParts = sharedTable === null
    ? []
    : sharedTable.parts ?? [{
        inputIndex: sharedTable.inputIndex,
        dataOffset: sharedTable.dataOffset,
        length: tableBytes.length,
      }];
  const sharedSlopeParts = sharedTable?.slopeParts ?? [];
  if (sharedTable !== null && (sharedParts.length === 0 ||
    sharedParts.some(({ inputIndex, dataOffset, length }) =>
      !Number.isSafeInteger(inputIndex) || inputIndex < 0 ||
      !Number.isSafeInteger(dataOffset) || dataOffset < 0 ||
      !Number.isSafeInteger(length) || length <= 0) ||
    sharedParts.reduce((sum, part) => sum + part.length, 0) !== tableBytes.length)) {
    throw new Error(`invalid shared GLV table source: ${JSON.stringify(sharedTable)}`);
  }
  if (sharedSlopeParts.some(({ windowStart, inputIndex, unlockingBytecodeOffset, length }) =>
    !Number.isSafeInteger(windowStart) || windowStart <= 0 || windowStart >= ITERS ||
    !Number.isSafeInteger(inputIndex) || inputIndex < 0 ||
    !Number.isSafeInteger(unlockingBytecodeOffset) || unlockingBytecodeOffset < 0 ||
    !Number.isSafeInteger(length) || length <= 0) ||
    sharedSlopeParts.some((part, index) => index > 0 && part.windowStart <= sharedSlopeParts[index - 1].windowStart)) {
    throw new Error(`invalid shared GLV slope source: ${JSON.stringify(sharedSlopeParts)}`);
  }
  if (sharedSlopeParts.length !== 0 &&
    (!FIXED_VK_COLLAPSE || !FIXED_COMB || !first || !final || lo !== 0 || hi !== ITERS)) {
    throw new Error('shared GLV slopes require one complete fixed-comb chunk');
  }
  const sharedSegmentParts = [];
  if (sharedTable !== null) {
    let partIndex = 0;
    for (const segmentLength of GLV_TABLE_SEGMENT_LENGTHS) {
      const segmentParts = [];
      let covered = 0;
      while (covered < segmentLength && partIndex < sharedParts.length) {
        const part = sharedParts[partIndex++];
        if (covered + part.length > segmentLength) {
          throw new Error('shared GLV table part crosses a segment boundary');
        }
        segmentParts.push(part);
        covered += part.length;
      }
      if (covered !== segmentLength) throw new Error('shared GLV table segment is incomplete');
      sharedSegmentParts.push(segmentParts);
    }
    if (partIndex !== sharedParts.length) throw new Error('shared GLV table has unused parts');
  }
  const count = hi - lo, hiBit = (ITERS - 1) - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`// BLS12-381 GLV vk_x chunk: 4-scalar Straus window [${lo},${hi}), first=${first} final=${final}.`);
  L.push(prologue(sharedTable !== null));
  L.push('contract VkxGlvBlsChunk() {');
  if (fullStageBound && !stageBound) throw new Error('full-stage GLV generation requires a stage-bound genesis');
  const extraParams = [
    FIXED_VK_COLLAPSE ? 'bytes glvSlopes' : null,
    ...(final && FIXED_VK_COLLAPSE ? ['int Cx', 'int Cy'] : []),
    final ? `int ${UNIT_G1 ? 'yInv' : 'zInv'}` : null,
    ...(final && fullStageBound ? PROOF_NAMES.map((name) => `int ${name}`) : []),
    sharedTable !== null && final && !FIXED_VK_COLLAPSE ? 'bytes glvTable' : null,
  ]
    .filter(Boolean);
  const stateParams = stageBound && first ? GENESIS_STATE : STATE;
  L.push(`    function spend(${[...stateParams.map((s) => `int ${s}`), ...extraParams, 'bytes unused zeroPadding'].join(', ')}) {`);
  L.push(covIn(stateParams));
  if (sharedTable !== null) {
    if (FIXED_VK_COLLAPSE) {
      sharedSegmentParts.forEach((parts, segmentIndex) => {
        const partExprs = parts.map(({ inputIndex, dataOffset, length }) =>
          `tx.inputs[${inputIndex}].unlockingBytecode.split(${dataOffset})[1].split(${length})[0]`);
        L.push(`        bytes glvTable${segmentIndex} = ${partExprs.join(' + ')};`);
        if (final) L.push(`        require(hash256(glvTable${segmentIndex}) == ${TABLE_HASH_HEXES[segmentIndex]});`);
      });
    } else if (final) {
      L.push(`        require(hash256(glvTable) == ${TABLE_HASH_HEXES[0]});`);
    } else {
      const part = sharedParts[0];
      L.push(`        bytes glvTable = tx.inputs[${part.inputIndex}].unlockingBytecode.split(${part.dataOffset})[1].split(${tableBytes.length})[0];`);
    }
  }
  const sharedTableArguments = sharedTable === null
    ? ''
    : FIXED_VK_COLLAPSE
      ? ', ' + tableSegments.map((_, index) => `glvTable${index}`).join(', ')
      : ', glvTable';
  if (first) {
    if (stageBound) {
      L.push(FIXED_VK_COLLAPSE
        ? '        int rX = 0; int rY = 0;'
        : '        int rX = 0; int rY = 1; int rZ = 0;');
      L.push(`        require(in0 >= 0 && in0 < ${r}); require(in1 >= 0 && in1 < ${r});`);
      if (!FIXED_COMB) L.push(FIXED_VK_COLLAPSE
        ? '        require(k10 >= 0); require(k20 >= 0);'
        : '        require(k10 >= 0); require(k20 >= 0); require(k11 >= 0); require(k21 >= 0);');
    }
    // Bind the GLV witnesses to the committed public inputs: k1 + k2*lambda == in (mod r),
    // AND bound their magnitude to < 2^128 so the 128-iteration MSM processes every bit (else a
    // prover could add r to a scalar -> same residue mod r but bits above 127 silently dropped).
    const BOUND = 1n << 128n;
    if (!FIXED_COMB) L.push(FIXED_VK_COLLAPSE
      ? `        require(k10 < ${BOUND}); require(k20 < ${BOUND});`
      : `        require(k10 < ${BOUND}); require(k20 < ${BOUND}); require(k11 < ${BOUND}); require(k21 < ${BOUND});`);
    if (FIXED_COMB) {
      // The fixed-base comb consumes the canonical public-input combination directly.
    } else if (FIXED_VK_COLLAPSE) {
      L.push(`        require((k10 + k20 * ${GLV_LAMBDA}) % ${r} == (${collapsedInputScalars[0]} * in0 + ${collapsedInputScalars[1]} * in1) % ${r});`);
    } else {
      L.push(`        require((k10 + k20 * ${GLV_LAMBDA}) % ${r} == in0);`);
      L.push(`        require((k11 + k21 * ${GLV_LAMBDA}) % ${r} == in1);`);
    }
  }
  if (final && FIXED_VK_COLLAPSE) {
    L.push(`        require(within(Cx, 0, ${P})); require(within(Cy, 0, ${P}));`);
    L.push('        bool cIdentity = Cx == 0 && Cy == 0;');
    L.push('        require(cIdentity || sqrFp(Cy) == addFp(mulFp(sqrFp(Cx), Cx), 4));');
  }
  if (FIXED_COMB) L.push(`        int combScalar = (${collapsedInputScalars[0]} * in0 + ${collapsedInputScalars[1]} * in1) % ${r};`);
  const directFirstWindow = FIXED_VK_COLLAPSE && first && lo === 0;
  if (FIXED_VK_COLLAPSE) {
    const slopesPerWindow = FIXED_COMB ? 2 : 3;
    const slopeCount = slopesPerWindow * (count - (directFirstWindow ? 1 : 0)) + (final ? 1 : 0);
    sharedSlopeParts.forEach((part, index) => {
      const end = sharedSlopeParts[index + 1]?.windowStart ?? count;
      const expectedLength = (slopesPerWindow * (end - part.windowStart) +
        (final && index === sharedSlopeParts.length - 1 ? 1 : 0)) * 48;
      if (part.length !== expectedLength) {
        throw new Error(`shared GLV slope part ${index} has length ${part.length}, expected ${expectedLength}`);
      }
    });
    const localSlopeCount = sharedSlopeParts.length === 0
      ? slopeCount
      : slopesPerWindow * (sharedSlopeParts[0].windowStart - (directFirstWindow ? 1 : 0));
    L.push(`        require(glvSlopes.length == ${localSlopeCount * 48});`);
    L.push('        bytes slopeTail = glvSlopes;');
  }
  if (directFirstWindow) {
    if (FIXED_COMB) {
      const terms = Array.from({ length: FIXED_COMB_WIDTH }, (_, j) => ({ bit: ITERS - 1 + j * ITERS, weight: 1 << j }))
        .filter(({ bit }) => bit < 255)
        .map(({ bit, weight }) => weight === 1
          ? `(combScalar >> ${bit}) % 2`
          : `${weight} * ((combScalar >> ${bit}) % 2)`);
      L.push(`        int firstIdx = ${terms.join(' + ')};`);
    } else {
      L.push(`        int firstIdx = (k10 >> ${2 * (ITERS - 1)}) % 4 + 4 * ((k20 >> ${2 * (ITERS - 1)}) % 4);`);
    }
    L.push(`        (int firstX, int firstY) = select16(firstIdx${sharedTableArguments});`);
    L.push('        rX = firstX; rY = firstY;');
  }
  const loopStarts = [directFirstWindow ? 1 : 0, ...sharedSlopeParts.map(({ windowStart }) => windowStart)];
  const loopEnds = [...sharedSlopeParts.map(({ windowStart }) => windowStart), count];
  loopStarts.forEach((loopStart, loopIndex) => {
    if (loopIndex > 0) {
      const { inputIndex, unlockingBytecodeOffset, length } = sharedSlopeParts[loopIndex - 1];
      L.push(`        slopeTail = tx.inputs[${inputIndex}].unlockingBytecode.split(${unlockingBytecodeOffset})[1].split(${length})[0];`);
    }
    L.push(`        for (int k = ${loopStart}; k < ${loopEnds[loopIndex]}; k = k + 1) {`);
    if (FIXED_VK_COLLAPSE) {
      L.push('            int d0m = int(slopeTail.split(48)[0]); slopeTail = slopeTail.split(48)[1];');
      if (!FIXED_COMB) L.push('            int d1m = int(slopeTail.split(48)[0]); slopeTail = slopeTail.split(48)[1];');
      L.push('            int am = int(slopeTail.split(48)[0]); slopeTail = slopeTail.split(48)[1];');
      L.push('            (int d0x, int d0y) = affineDouble(rX, rY, d0m); rX = d0x; rY = d0y;');
      if (FIXED_COMB) {
        const terms = Array.from({ length: FIXED_COMB_WIDTH }, (_, j) => j === 0
          ? `(combScalar >> (${ITERS - 1 - lo} - k)) % 2`
          : `${1 << j} * ((combScalar >> (${ITERS - 1 - lo} - k + ${j * ITERS})) % 2)`);
        L.push(`            int idx = ${terms.join(' + ')};`);
      } else {
        L.push('            (int d1x, int d1y) = affineDouble(rX, rY, d1m); rX = d1x; rY = d1y;');
        L.push(`            int i = 2 * (${ITERS - 1 - lo} - k);`);
        L.push('            int idx = (k10 >> i) % 4 + 4 * ((k20 >> i) % 4);');
      }
    } else {
      L.push(`            int i = ${hiBit} - k;`);
      L.push('            if (rZ != 0) { (int dx, int dy, int dz) = jacDouble(rX, rY, rZ); rX = dx; rY = dy; rZ = dz; }');
      L.push('            int idx = (k10 >> i) % 2 + 2 * ((k20 >> i) % 2) + 4 * ((k11 >> i) % 2) + 8 * ((k21 >> i) % 2);');
    }
    L.push(`            (int aX, int aY) = select16(idx${sharedTableArguments});`);
    L.push(FIXED_VK_COLLAPSE
      ? '            (int ax, int ay) = affineAdd(rX, rY, aX, aY, am); rX = ax; rY = ay;'
      : '            if (aX != 0) { (int ax, int ay, int az) = jacAddAffine(rX, rY, rZ, aX, aY); rX = ax; rY = ay; rZ = az; }');
    L.push('        }');
  });
  if (final) {
    if (FIXED_VK_COLLAPSE) {
      L.push('        int cm = int(slopeTail.split(48)[0]);');
      L.push('        (int cx, int cy) = affineAdd(rX, rY, Cx, Cy, cm); rX = cx; rY = cy;');
    } else {
      L.push(`        (int icx, int icy, int icz) = jacAddAffine(rX, rY, rZ, ${modP(IC0[0])}, ${modP(IC0[1])});`);
      L.push('        rX = icx; rY = icy; rZ = icz;');
    }
    if (UNIT_G1) {
      if (FIXED_VK_COLLAPSE) {
        L.push('        bool dIdentity = rX == 0 && rY == 0;');
        L.push('        int vkxU = 0; int vkxV = 0;');
        L.push('        if (dIdentity) { require(yInv == 0); }');
        L.push('        else {');
        L.push('            require(mulFp(addFp(rY, rY), yInv) == 1);');
        L.push('            vkxU = subFp(0, mulFp(rX, yInv));');
        L.push('            vkxV = subFp(0, yInv);');
        L.push('        }');
      } else {
        L.push('        require(mulFp(addFp(rY, rY), yInv) == 1);');
        L.push('        int vkxU = subFp(0, mulFp(mulFp(rX, rZ), yInv));');
        L.push('        int z3 = mulFp(sqrFp(rZ), rZ);');
        L.push('        int vkxV = subFp(0, mulFp(z3, yInv));');
      }
    } else {
      L.push('        require(mulFp(rZ, zInv) == 1);');
      L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
      L.push('        int vkxX = mulFp(rX, zInv2);');
      L.push('        int vkxY = mulFp(rY, zInv3);');
    }
    // Preserve the proof tuple exactly for the downstream range gate. mulFp makes vk_x canonical.
    const pointOutputs = UNIT_G1 ? ['vkxU', 'vkxV'] : ['vkxX', 'vkxY'];
    const outputs = fullStageBound ? [...PROOF_NAMES, ...pointOutputs] : pointOutputs;
    L.push(covOut(outputs, outputs));
  } else {
    // A stage-bound genesis derives the accumulator and bounds every scalar. Otherwise only the
    // first caller-supplied accumulator needs normalization; every later state is predecessor-bound.
    L.push(covOut(STATE, stageBound ? STATE : first ? [] : STATE));
  }
  L.push('    }');
  L.push('}');
  return (L.join('\n') + '\n');
}

// Legacy non-stage-bound genesis accepts a caller-supplied accumulator, so its first handoff must
// normalize every limb. Stage-bound genesis derives the accumulator and bounds all scalars.
{
  const legacyFirst = genCash(0, 1, true, false, false);
  if (!STATE.every((name) => legacyFirst.includes(`toPaddedBytes(${name} % Pmod, 48)`))) {
    throw new Error('legacy GLV genesis emitted an exact caller-supplied state');
  }
  const stageBoundFirst = genCash(0, 1, true, false, true);
  if (stageBoundFirst.includes('int Pmod =') || !STATE.every((name) => stageBoundFirst.includes(`toPaddedBytes(${name}, 48)`))) {
    throw new Error('stage-bound GLV genesis did not emit its proven-exact state');
  }
}

/** Emit the audited chunk plan selected by the active mode. Linked callers provide one
 * shared-table carrier; a covenant caller passes null and embeds the same fixed table in each
 * locking. */
export function regenGlvSharedAudited(GEN_DIR, sharedTable, stageBound = false, fullStageBound = false) {
  const prefix = fullStageBound ? 'vkxglvfull' : 'vkxglv';
  const chunks = GLV_SHARED_AUDITED_BOUNDS.slice(0, -1).map((lo, idx) => ({
    idx,
    lo,
    hi: GLV_SHARED_AUDITED_BOUNDS[idx + 1],
    first: idx === 0,
    final: idx === GLV_SHARED_AUDITED_BOUNDS.length - 2,
  }));
  for (const ch of chunks) {
    writeFileSync(join(GEN_DIR, `${prefix}_${String(ch.idx).padStart(2, '0')}.cash`), genCash(ch.lo, ch.hi, ch.first, ch.final, stageBound, sharedTable, fullStageBound));
  }
  writeFileSync(join(GEN_DIR, `manifest_${prefix}.json`), JSON.stringify({
    curve: 'BLS12-381', numChunks: chunks.length, iters: ITERS, glv: true, chunks,
    sharedTable: sharedTable !== null, stageBound, fullStageBound,
    slopeCarriers: sharedTable?.slopeParts ?? [],
  }, null, 2));
  return chunks.length;
}

// ---- plan + emit (valid inputs with add coverage at all 128 loop positions) ----
if (process.argv[1] && process.argv[1].endsWith('gen_vkx_glv.mjs')) {
  const [wk10, wk20] = glvDecompose(GLV_HIGH_COST_INPUTS[0]), [wk11, wk21] = glvDecompose(GLV_HIGH_COST_INPUTS[1]);
  if ((wk10 | wk20 | wk11 | wk21) !== (1n << 128n) - 1n) throw new Error('GLV all-positions vector does not cover every loop position');
  const win0 = ((wk10 + wk20 * GLV_LAMBDA) % r + r) % r, win1 = ((wk11 + wk21 * GLV_LAMBDA) % r + r) % r;
  const SER_state = (Xj, Yj, Zj) => [Xj, Yj, Zj, win0, win1, wk10, wk20, wk11, wk21];
  console.error(`planning BLS12-381 GLV vk_x chunks (${ITERS}-bit 4-scalar Straus)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
  const chunks = []; let lo = 0; const planState = { perUnit: null };
  while (lo < ITERS) {
    const planningC = FIXED_VK_COLLAPSE ? proof.c : null;
    const [X0, Y0, Z0] = vkxGlvStateAt(wk10, wk20, wk11, wk21, lo, planningC);
    const inSt = SER_state(X0, Y0, Z0);
    const tryHi = (hi) => {
      const final = hi === ITERS, first = lo === 0;
      const committedIn = STAGE_BOUND && first ? inSt.slice(3) : inSt;
      let outLimbs, args;
      if (final) {
        if (UNIT_G1) {
          const yInv = vkxGlvYinv(wk10, wk20, wk11, wk21, planningC);
          outLimbs = vkxGlvUnit(wk10, wk20, wk11, wk21, planningC);
          if (FIXED_VK_COLLAPSE) {
            const ca = glvUnitCoordinates(proof.c);
            args = [...committedIn, ca.u, ca.v, ca.vInv, yInv];
          } else args = [...committedIn, yInv];
        } else {
          const zinv = vkxGlvZinv(wk10, wk20, wk11, wk21, planningC);
          const acc = vkxGlvStateAt(wk10, wk20, wk11, wk21, ITERS, planningC);
          const [fx, fy] = jacAdd(acc[0], acc[1], acc[2], modP(IC0[0]), modP(IC0[1]), 1n);
          const z2 = qF(zinv), z3 = mF(z2, zinv);
          outLimbs = [mF(fx, z2), mF(fy, z3)]; args = [...committedIn, zinv];
        }
      } else { outLimbs = SER_state(...vkxGlvStateAt(wk10, wk20, wk11, wk21, hi, planningC)); args = committedIn; }
      const src = genCash(lo, hi, first, final, STAGE_BOUND);
      const m = measureCovenant(src, args.map(BigInt), committedIn.map(BigInt), outLimbs.map(BigInt));
      return { hi, final, src, m, operationCost: m.operationCost, lockingBytes: m.lockingBytes, fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET };
    };
    const best = planChunk(lo, ITERS, OP_TARGET, tryHi, planState);
    if (!best) throw new Error(`no fitting GLV window at lo=${lo}`);
    const idx = chunks.length;
    writeFileSync(join(GEN, `vkxglv_${String(idx).padStart(2, '0')}.cash`), best.src);
    chunks.push({ idx, lo, hi: best.hi, first: lo === 0, final: best.final, operationCost: best.m.operationCost, lockingBytes: best.m.lockingBytes });
    console.error(`  vkxglv chunk ${idx}: [${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} accepted=${best.m.accepted} final=${best.final}`);
    lo = best.hi;
  }
  writeFileSync(join(GEN, 'manifest_vkxglv.json'), JSON.stringify({ curve: 'BLS12-381', numChunks: chunks.length, iters: ITERS, glv: true, stageBound: STAGE_BOUND, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, final: c.final })) }, null, 2));
  console.error(`GLV vk_x: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}
