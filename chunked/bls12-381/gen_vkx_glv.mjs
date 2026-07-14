// GLV vk_x generator (BLS12-381): vk_x = IC0 + in0*IC1 + in1*IC2 via the G1 endomorphism.
// BLS port of chunked/pairing/gen_vkx_glv.mjs, using the SAME validated GLV constants as the
// op-optimized singleton (singleton/bls12-381/gen_singleton_minop.mjs): lambda = -x^2 mod r,
// basis {(1,-(x^2-1)),(x^2,1)}, beta the Fp cube root. Each public input k is decomposed (GLV)
// into NON-NEGATIVE k1 + k2*lambda (mod r) with k1,k2 < 2^128, turning the 2-scalar 255-bit MSM
// into a 4-scalar 128-bit Straus over the FIXED points {IC1, phi(IC1), IC2, phi(IC2)}
// (phi(x,y)=(beta*x,y)). A baked 16-entry subset-sum table folds all 4 scalars into ONE add per
// iteration -> ~half the doublings (vkx 12 -> 5 shared-table chunks). Witnesses k10,k20,k11,k21 are gated at
// genesis (k < 2^128, k1 + k2*lambda == in mod r); phi(IC*) and the table are baked.
// State (committed, 9 limbs): rX,rY,rZ, in0,in1, k10,k20,k11,k21.
//   node gen_vkx_glv.mjs    plan + emit vkxglv_NN.cash + manifest_vkxglv.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { P, OP_BUDGET, covIn, covOut, measureCovenant, planChunk, vk, bls12_381 } from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const G1 = bls12_381.G1.Point;
const Pstr = P.toString();
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const X = 0xd201000000010000n; // |x|
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const ITERS = 128; // GLV sub-scalars are < 2^128; 128 MSB-first positions

// ---- GLV constants (same as the singleton minop; proof-independent) ----
export const GLV_BETA = 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350n;
export const GLV_LAMBDA = r - ((X * X) % r); // -x^2 mod r
export const GLV_R = r;
export { ITERS as VKXGLV_ITERS };
// Deterministically searched valid inputs whose four GLV sub-scalars have a nonzero bit
// at every one of the 128 Straus positions. This is the density case the loop actually
// executes; near-r inputs are not sufficient because decomposition randomizes the bits.
export const GLV_MAX_DENSITY_INPUTS = [
  34858469356782761897909152752726474392223647467802337015319438976734096243172n,
  7481747670021426200056538375384252329781435103268576271399310381963838742462n,
];
export const GLV_SHARED_SAFE_BOUNDS = [0, 25, 51, 77, 103, 128];

const modP = (v) => ((v % P) + P) % P;
const phiPt = (Pt) => { const a = Pt.toAffine(); return G1.fromAffine({ x: (a.x * GLV_BETA) % P, y: a.y }); };
const _ic0 = vk.ic[0].toAffine();
const IC0 = [_ic0.x, _ic0.y];
const BP = [vk.ic[1], phiPt(vk.ic[1]), vk.ic[2], phiPt(vk.ic[2])]; // P1..P4
const TABLE = [];
for (let idx = 1; idx < 16; idx++) {
  let acc = G1.ZERO;
  for (let i = 0; i < 4; i++) if (idx & (1 << i)) acc = acc.add(BP[i]);
  const a = acc.toAffine(); TABLE[idx] = [a.x, a.y];
}
// 15-entry blob: entry (idx-1) = x(LE48) || y(LE48); split() reads an entry in O(1).
// 48-byte LE is sign-safe: p < 2^382 -> top byte <= 0x1a -> int() recovers positive.
const le48hex = (v) => { v = modP(v); let s = ''; for (let b = 0; b < 48; b++) s += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0'); return s; };
export const GLV_TABLE_HEX = '0x' + Array.from({ length: 15 }, (_, k) => le48hex(TABLE[k + 1][0]) + le48hex(TABLE[k + 1][1])).join('');
const tableBytes = Buffer.from(GLV_TABLE_HEX.slice(2), 'hex');
// CashScript hash256 is double SHA-256. The carrier chunk checks this digest, so every
// sibling reading the same transaction input uses the fixed VK-derived table.
const TABLE_HASH_HEX = '0x' + createHash('sha256').update(createHash('sha256').update(tableBytes).digest()).digest('hex');

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
const TBL = TABLE.map((pt) => (pt ? [modP(pt[0]), modP(pt[1])] : null));
/** accumulator [X,Y,Z] after MSM windows [0,upto) for scalars (k10,k20,k11,k21). */
export function vkxGlvStateAt(k10, k20, k11, k21, upto) {
  let Xa = 0n, Ya = 1n, Za = 0n;
  for (let w = 0; w < upto; w++) {
    const i = BigInt((ITERS - 1) - w);
    if (Za !== 0n) [Xa, Ya, Za] = jacDouble(Xa, Ya, Za);
    const idx = Number(((k10 >> i) & 1n) + 2n * ((k20 >> i) & 1n) + 4n * ((k11 >> i) & 1n) + 8n * ((k21 >> i) & 1n));
    if (idx > 0) { const t = TBL[idx]; [Xa, Ya, Za] = jacAdd(Xa, Ya, Za, t[0], t[1], 1n); }
  }
  return [Xa, Ya, Za];
}
const modinvP = (a) => { let R = 1n, b = modP(a), e = P - 2n; while (e > 0n) { if (e & 1n) R = (R * b) % P; b = (b * b) % P; e >>= 1n; } return R; };
/** final zInv = (Z of (acc + IC0))^-1 mod p. */
export function vkxGlvZinv(k10, k20, k11, k21) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, ITERS);
  const [, , fz] = jacAdd(acc[0], acc[1], acc[2], modP(IC0[0]), modP(IC0[1]), 1n);
  return fz === 0n ? 0n : modinvP(fz);
}
export const GLV_IC0 = IC0;

// ---- contract template ----
const STATE = ['rX', 'rY', 'rZ', 'in0', 'in1', 'k10', 'k20', 'k11', 'k21'];
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
function jacAdd(int aX, int aY, int aZ, int bX, int bY, int bZ) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = bZ;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ); int z2z2 = sqrFp(bZ);
        int u1 = mulFp(aX, z2z2); int u2 = mulFp(bX, z1z1);
        int s1 = mulFp(mulFp(aY, bZ), z2z2); int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (u1 == u2 && s1 == s2) {
            int da = sqrFp(aX); int db = sqrFp(aY); int dc = sqrFp(db);
            int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
            int de = mulFp(3, da); int df = sqrFp(de);
            int dnx = subFp(df, mulFp(2, dd));
            int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
            int dnz = mulFp(2, mulFp(aY, aZ));
            rx = dnx; ry = dny; rz = dnz;
        } else {
            int h = subFp(u2, u1); int i2 = sqrFp(mulFp(2, h)); int jj = mulFp(h, i2);
            int rr = mulFp(2, subFp(s2, s1)); int vv = mulFp(u1, i2);
            int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(s1, jj)));
            int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h);
            rx = anx; ry = any; rz = anz;
        }
    }
    return rx, ry, rz;
}
function select16(int idx${sharedTable ? ', bytes table' : ''}) returns (int, int, int) {
    int aX = 0; int aY = 0; int doAdd = 0;
    if (idx != 0) {
        ${sharedTable ? '' : `bytes table = ${GLV_TABLE_HEX};`}
        bytes ent = table.split((idx - 1) * 96)[1].split(96)[0];
        aX = int(ent.split(48)[0]);
        aY = int(ent.split(48)[1]);
        doAdd = 1;
    }
    return aX, aY, doAdd;
}`;

export function genCash(lo, hi, first, final, sharedTable = null) {
  if (sharedTable !== null && (!Number.isSafeInteger(sharedTable.inputIndex) || sharedTable.inputIndex < 0 ||
    !Number.isSafeInteger(sharedTable.dataOffset) || sharedTable.dataOffset < 0)) {
    throw new Error(`invalid shared GLV table source: ${JSON.stringify(sharedTable)}`);
  }
  const count = hi - lo, hiBit = (ITERS - 1) - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`// BLS12-381 GLV vk_x chunk: 4-scalar Straus window [${lo},${hi}), first=${first} final=${final}.`);
  L.push(prologue(sharedTable !== null));
  L.push('contract VkxGlvBlsChunk() {');
  const extraParams = [final ? 'int zInv' : null, sharedTable !== null && final ? 'bytes glvTable' : null]
    .filter(Boolean);
  L.push(`    function spend(${[...STATE.map((s) => `int ${s}`), ...extraParams, 'bytes unused zeroPadding'].join(', ')}) {`);
  L.push(covIn(STATE));
  if (sharedTable !== null) {
    if (final) L.push(`        require(hash256(glvTable) == ${TABLE_HASH_HEX});`);
    else L.push(`        bytes glvTable = tx.inputs[${sharedTable.inputIndex}].unlockingBytecode.split(${sharedTable.dataOffset})[1].split(${tableBytes.length})[0];`);
  }
  if (first) {
    // bind the GLV witnesses to the committed public inputs: k1 + k2*lambda == in (mod r),
    // AND bound their magnitude to < 2^128 so the 128-iteration MSM processes every bit (else a
    // prover could add r to a scalar -> same residue mod r but bits above 127 silently dropped).
    const BOUND = 1n << 128n;
    L.push(`        require(k10 < ${BOUND}); require(k20 < ${BOUND}); require(k11 < ${BOUND}); require(k21 < ${BOUND});`);
    L.push(`        require((k10 + k20 * ${GLV_LAMBDA}) % ${r} == in0);`);
    L.push(`        require((k11 + k21 * ${GLV_LAMBDA}) % ${r} == in1);`);
  }
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx, int dy, int dz) = jacDouble(rX, rY, rZ); rX = dx; rY = dy; rZ = dz; }');
  L.push('            int idx = (k10 >> i) % 2 + 2 * ((k20 >> i) % 2) + 4 * ((k11 >> i) % 2) + 8 * ((k21 >> i) % 2);');
  L.push(`            (int aX, int aY, int doAdd) = select16(idx${sharedTable !== null ? ', glvTable' : ''});`);
  L.push('            if (doAdd == 1) { (int ax, int ay, int az) = jacAdd(rX, rY, rZ, aX, aY, 1); rX = ax; rY = ay; rZ = az; }');
  L.push('        }');
  if (final) {
    L.push(`        (int icx, int icy, int icz) = jacAdd(rX, rY, rZ, ${modP(IC0[0])}, ${modP(IC0[1])}, 1);`);
    L.push('        rX = icx; rY = icy; rZ = icz;');
    L.push('        require(mulFp(rZ, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(rX, zInv2);');
    L.push('        int vkxY = mulFp(rY, zInv3);');
    L.push(covOut(['vkxX', 'vkxY']));
  } else {
    L.push(covOut(STATE));
  }
  L.push('    }');
  L.push('}');
  return (L.join('\n') + '\n');
}

/** Emit the density-validated five-window plan for hash-free, shared-table deployment. */
export function regenGlvSharedSafe(GEN_DIR, sharedTable) {
  const chunks = GLV_SHARED_SAFE_BOUNDS.slice(0, -1).map((lo, idx) => ({
    idx,
    lo,
    hi: GLV_SHARED_SAFE_BOUNDS[idx + 1],
    first: idx === 0,
    final: idx === GLV_SHARED_SAFE_BOUNDS.length - 2,
  }));
  for (const ch of chunks) {
    writeFileSync(join(GEN_DIR, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), genCash(ch.lo, ch.hi, ch.first, ch.final, sharedTable));
  }
  writeFileSync(join(GEN_DIR, 'manifest_vkxglv.json'), JSON.stringify({
    curve: 'BLS12-381', numChunks: chunks.length, iters: ITERS, glv: true, chunks,
    sharedTable: sharedTable !== null,
  }, null, 2));
  return chunks.length;
}

// ---- plan + emit (valid inputs with add coverage at all 128 loop positions) ----
if (process.argv[1] && process.argv[1].endsWith('gen_vkx_glv.mjs')) {
  const [wk10, wk20] = glvDecompose(GLV_MAX_DENSITY_INPUTS[0]), [wk11, wk21] = glvDecompose(GLV_MAX_DENSITY_INPUTS[1]);
  if ((wk10 | wk20 | wk11 | wk21) !== (1n << 128n) - 1n) throw new Error('GLV density vector does not cover every loop position');
  const win0 = ((wk10 + wk20 * GLV_LAMBDA) % r + r) % r, win1 = ((wk11 + wk21 * GLV_LAMBDA) % r + r) % r;
  const SER_state = (Xj, Yj, Zj) => [Xj, Yj, Zj, win0, win1, wk10, wk20, wk11, wk21];
  console.error(`planning BLS12-381 GLV vk_x chunks (${ITERS}-bit 4-scalar Straus)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
  const chunks = []; let lo = 0; const planState = { perUnit: null };
  while (lo < ITERS) {
    const [X0, Y0, Z0] = vkxGlvStateAt(wk10, wk20, wk11, wk21, lo);
    const inSt = SER_state(X0, Y0, Z0);
    const tryHi = (hi) => {
      const final = hi === ITERS, first = lo === 0;
      let outLimbs, args;
      if (final) {
        const zinv = vkxGlvZinv(wk10, wk20, wk11, wk21);
        const acc = vkxGlvStateAt(wk10, wk20, wk11, wk21, ITERS);
        const [fx, fy] = jacAdd(acc[0], acc[1], acc[2], modP(IC0[0]), modP(IC0[1]), 1n);
        const z2 = qF(zinv), z3 = mF(z2, zinv);
        outLimbs = [mF(fx, z2), mF(fy, z3)]; args = [...inSt, zinv];
      } else { outLimbs = SER_state(...vkxGlvStateAt(wk10, wk20, wk11, wk21, hi)); args = inSt; }
      const src = genCash(lo, hi, first, final);
      const m = measureCovenant(src, args.map(BigInt), inSt.map(BigInt), outLimbs.map(BigInt));
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
  writeFileSync(join(GEN, 'manifest_vkxglv.json'), JSON.stringify({ curve: 'BLS12-381', numChunks: chunks.length, iters: ITERS, glv: true, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, final: c.final })) }, null, 2));
  console.error(`GLV vk_x: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}
