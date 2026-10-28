// Generator for the OP-OPTIMIZED BLS12-381 Groth16 singleton: groth16_minop.cash.
// BLS analog of ../bn254/gen_singletons.mjs — stacks every op-lowering optimization:
//   - LAZY field tower for the Miller loop (lib/lazy/, deferred reductions);
//   - QUOTIENT-TORUS residue final exponentiation (ePrint 2024/640 in Fp12*/Fp6*, see
//     ../../chunked/bls12-381/_residuemath.mjs): the root is ONE gated 6-limb witness u
//     ([c]=[1+u*W], so [c^-1]=[1-u*W]); c-folds are 2-Fp6-product fp12MulTorus; the
//     terminal is the cross-multiplied quotient relation [fF]=[frob(c,1)] with the
//     vacuous [0:0] projective value rejected. lambda = p + |x|; the legacy Fp6
//     correction w vanishes in the quotient (no w witness, no c*cInv==1 gate);
//   - ONE batched c^-|x|-fused Miller (UNROLLED): only (-A,B) runs on-chain G2
//     arithmetic; e(alpha,beta) baked as a torus constant; (vk_x,gamma)/(C,delta) lines baked;
//   - G2 subgroup check psi(B) == [x]B = -[|x|]B (x < 0), FUSED into the Miller tail: the loop already
//     walks R_B to [|x|]B, so the membership test reuses it (no separate 64-step walk);
//   - NO G1 subgroup checks on A,C: redundant for soundness. A,C are only paired against
//     order-r G2 elements (B — checked — and the VK's delta), so any cofactor component
//     is annihilated by the pairing (e(A_cof,B)=1, gcd(ord(A_cof),r)=1); the equation
//     constrains only A_r/C_r, still a valid witness. On-curve checks remain. Matches the
//     deployed grouped/intra-tx residue verifiers;
//   - GLV vk_x: 4-scalar 128-bit Straus over a baked subset-sum table
//     (lambda = -x^2 mod r, basis {(1,-(x^2-1)),(x^2,1)}), gated witnesses.
// All field/curve arithmetic comes from the verified lazy lib (lib/lazy/Bls12381LazyG.cash).
//   node gen_singleton_minop.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { PUBLIC_INPUTS } from '../../../../singleton/bls12-381/bls_instance.mjs';

const C = await import('../../../../chunked/bls12-381/_pairingmath.mjs');
const R = await import('../../../../chunked/bls12-381/_residuemath.mjs');
const { bls12_381 } = await import('../../../../chunked/bls12-381/_vkxmath.mjs');

const here = dirname(fileURLToPath(import.meta.url));
const G1 = bls12_381.G1.Point;
const Fp = bls12_381.fields.Fp;

const P = Fp.ORDER;
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const X = 0xd201000000010000n; // |x|
export const GLV_BETA = 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350n;
export const GLV_LAMBDA = r - ((X * X) % r); // -x^2 mod r
export const GLV_R = r;
export const VKXGLV_ITERS = 128;

// ---- instance constants pulled from the verified JS (kept in sync, never hand-typed) ----
const { vk } = C;
const g1aff = (pt) => { const a = pt.toAffine(); return [a.x, a.y]; };
const IC0 = g1aff(vk.ic[0]);

const pairs = C.pairsFor(PUBLIC_INPUTS);
// baked UNCONJUGATED e(alpha,beta), as its finite quotient-torus coordinate (6 limbs):
// [fAB] = [1 + fAbU*W] with fAbU = fAB.c1 / fAB.c0 (VK-only; fails loudly if no finite chart).
const Fp6 = bls12_381.fields.Fp6;
const FAB12 = R.conj(C.singlePairMiller(pairs[1]).f);
if (Fp6.eql(FAB12.c0, Fp6.ZERO)) throw new Error('e(alpha,beta) has no finite torus coordinate');
const FABU = (() => {
  const t = Fp6.mul(FAB12.c1, Fp6.inv(FAB12.c0));
  return [t.c0.c0, t.c0.c1, t.c1.c0, t.c1.c1, t.c2.c0, t.c2.c1].map(String);
})();

const N = (n) => Array.from({ length: n }, (_, i) => i);
const list = (a) => a.join(',');
const decl12 = (p) => list(N(12).map((i) => `int ${p}${i}`));
const use12 = (p) => list(N(12).map((i) => `${p}${i}`));
const decl6 = (p) => list(N(6).map((i) => `int ${p}${i}`));
const use6 = (p) => list(N(6).map((i) => `${p}${i}`));
const lits = (arr) => list(arr);
const decl = (a) => a.map((n) => 'int ' + n).join(',');

// ---- GLV table (baked; proof-independent) ----
const phiPt = (Pt) => { const a = Pt.toAffine(); return G1.fromAffine({ x: (a.x * GLV_BETA) % P, y: a.y }); };
const BP = [vk.ic[1], phiPt(vk.ic[1]), vk.ic[2], phiPt(vk.ic[2])];
const TABLE = [];
for (let idx = 1; idx < 16; idx++) {
  let acc = G1.ZERO;
  for (let i = 0; i < 4; i++) if (idx & (1 << i)) acc = acc.add(BP[i]);
  const a = acc.toAffine(); TABLE[idx] = [a.x, a.y];
}
// 15-entry blob: entry (idx-1) = x(LE48) || y(LE48); split() reads an entry in O(1).
// 48-byte LE is sign-safe: p < 2^382 -> top byte <= 0x1a -> int() recovers positive.
const le48 = (v) => { v = ((v % P) + P) % P; let s = ''; for (let b = 0; b < 48; b++) s += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0'); return s; };
export const GLV_TABLE_HEX = '0x' + Array.from({ length: 15 }, (_, k) => le48(TABLE[k + 1][0]) + le48(TABLE[k + 1][1])).join('');

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
// JS Jacobian MSM replay (for the builder's zInv witness)
const modP = (v) => ((v % P) + P) % P;
const mF = (a, b) => modP(a * b), sF = (a, b) => modP(a - b), aFn = (a, b) => modP(a + b), qFn = (a) => modP(a * a);
function jacDouble(Xj, Yj, Zj) { const a = qFn(Xj), b = qFn(Yj), c = qFn(b); const d = mF(2n, sF(sF(qFn(aFn(Xj, b)), a), c)); const e = mF(3n, a), f = qFn(e); const nx = sF(f, mF(2n, d)); return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Yj, Zj))]; }
function jacAdd(aX, aY, aZ, bX, bY, bZ) { if (aZ === 0n) return [bX, bY, bZ]; const z1 = qFn(aZ), z2 = qFn(bZ); const u1 = mF(aX, z2), u2 = mF(bX, z1); const s1 = mF(mF(aY, bZ), z2), s2 = mF(mF(bY, aZ), z1); if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ); const h = sF(u2, u1), i2 = qFn(mF(2n, h)), j = mF(h, i2); const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2); const nx = sF(sF(qFn(rr), j), mF(2n, v)); return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qFn(aFn(aZ, bZ)), z1), z2), h)]; }
const TBL = TABLE.map((pt) => (pt ? [modP(pt[0]), modP(pt[1])] : null));
export function vkxGlvStateAt(k10, k20, k11, k21, upto) {
  let Xa = 0n, Ya = 1n, Za = 0n;
  for (let w = 0; w < upto; w++) {
    const i = BigInt((VKXGLV_ITERS - 1) - w);
    if (Za !== 0n) [Xa, Ya, Za] = jacDouble(Xa, Ya, Za);
    const idx = Number(((k10 >> i) & 1n) + 2n * ((k20 >> i) & 1n) + 4n * ((k11 >> i) & 1n) + 8n * ((k21 >> i) & 1n));
    if (idx > 0) { const t = TBL[idx]; [Xa, Ya, Za] = jacAdd(Xa, Ya, Za, t[0], t[1], 1n); }
  }
  return [Xa, Ya, Za];
}
const powmod = (b, e, m) => { let Rp = 1n; b = ((b % m) + m) % m; while (e > 0n) { if (e & 1n) Rp = (Rp * b) % m; b = (b * b) % m; e >>= 1n; } return Rp; };
export function vkxGlvZinv(k10, k20, k11, k21) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, VKXGLV_ITERS);
  const [, , fz] = jacAdd(acc[0], acc[1], acc[2], modP(IC0[0]), modP(IC0[1]), 1n);
  return fz === 0n ? 0n : powmod(fz, P - 2n, P);
}

// ---- emitted blocks ----
function emitInputValidationLazy() {
  return [
    '        // ---- validate spender-supplied proof points: on-curve (b=4, b\'=4+4u) ----',
    `        int fieldP = ${P};`,
    ...['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy']
      .map((name) => `        require(within(${name}, 0, fieldP));`),
    '        // torus root u must be canonical: the terminal Frobenius/cross-product compare',
    '        // and the [c^-1]=[1-u*W] derivation assume reduced coordinates.',
    ...N(6).map((i) => `        require(within(u${i}, 0, fieldP));`),
    '        require(mulFp(Ay, Ay) == mAdd(mulFp(mulFp(Ax, Ax), Ax), 4)); // A on E(Fp)',
    '        require(mulFp(Cy, Cy) == mAdd(mulFp(mulFp(Cx, Cx), Cx), 4)); // C on E(Fp)',
    '        (int bx2a,int bx2b) = r2Sqr(Bxa, Bxb);                       // B on E\'(Fp2)',
    '        (int bx3a,int bx3b) = r2Mul(bx2a, bx2b, Bxa, Bxb);',
    '        (int onrhsa,int onrhsb) = r2Add(bx3a, bx3b, 4, 4);',
    '        (int by2a,int by2b) = r2Sqr(Bya, Byb);',
    '        require(by2a == onrhsa); require(by2b == onrhsb);',
  ];
}
// GLV vk_x: 4-scalar 128-bit Straus over baked {IC1,phi(IC1),IC2,phi(IC2)} + baked 16-entry
// blob table. Witnesses k10,k20,k11,k21 (gated k<2^128, k1+k2*lambda==in mod r) + vkxZinv.
function emitGlvVkxLazy() {
  const BOUND = (1n << 128n).toString();
  const ic0 = IC0.map((v) => modP(v).toString());
  const L = [];
  L.push('        // ---- vk_x via GLV 4-scalar Straus (baked table) ----');
  L.push(`        require(within(k10, 0, ${BOUND})); require(within(k20, 0, ${BOUND})); require(within(k11, 0, ${BOUND})); require(within(k21, 0, ${BOUND}));`);
  L.push(`        require((k10 + k20 * ${GLV_LAMBDA}) % ${r} == in0);`);
  L.push(`        require((k11 + k21 * ${GLV_LAMBDA}) % ${r} == in1);`);
  L.push('        int gX = 0; int gY = 1; int gZ = 0;');
  L.push(`        bytes glvTable = ${GLV_TABLE_HEX};`);
  L.push(`        for (int gk = 0; gk < ${VKXGLV_ITERS}; gk = gk + 1) {`);
  L.push(`            int gidx = ${VKXGLV_ITERS - 1} - gk;`);
  L.push('            if (gZ != 0) { (int gdx, int gdy, int gdz) = jacDoubleG1(gX, gY, gZ); gX = gdx; gY = gdy; gZ = gdz; }');
  L.push('            int idx = (k10 >> gidx) % 2 + 2 * ((k20 >> gidx) % 2) + 4 * ((k11 >> gidx) % 2) + 8 * ((k21 >> gidx) % 2);');
  L.push('            if (idx != 0) {');
  L.push('                bytes ent = glvTable.split((idx - 1) * 96)[1].split(96)[0];');
  L.push('                int aX = int(ent.split(48)[0]); int aY = int(ent.split(48)[1]);');
  L.push('                (int gax, int gay, int gaz) = jacAddG1(gX, gY, gZ, aX, aY); gX = gax; gY = gay; gZ = gaz;');
  L.push('            }');
  L.push('        }');
  L.push(`        (int icx, int icy, int icz) = jacAddG1(gX, gY, gZ, ${ic0[0]}, ${ic0[1]});`);
  L.push('        require(mulFp(icz, vkxZinv) == 1);');
  L.push('        int vz2 = mSqr(vkxZinv); int vz3 = mulFp(vz2, vkxZinv);');
  L.push('        int vkxX = mulFp(icx, vz2);');
  L.push('        int vkxY = mulFp(icy, vz3);');
  return L;
}
// Batched c^-|x|-fused Miller (lazy, ROLLED). Research variant of the reviewed minop: the same op sequence
// (shared fp12Sqr, c^-|x| fold at each nonzero NAF digit, per pair a doubling line and, at a nonzero digit, an
// addition line), but
//   (1) one CashScript `for` loop over the 64 NAF digits of |x| (baked as a 64-byte digit string: 0, 1, 2 = -1)
//       instead of 471 unrolled SSA call sites, and
//   (2) the (vk_x,gamma)/(C,delta) line coefficients are no longer baked: gamma and delta are walked on-chain from
//       (x : y : 1) with the SAME pointDouble/pointAdd bodies used for B. The baked coefficients of the reviewed
//       minop were produced off-chain by exactly these formulas from the same start (C.millerBatchOps), so the
//       on-chain coefficients are congruent mod p to the baked ones and F is unchanged (differential test).
// Within one digit the line products are reordered (all doublings, then all additions); Fp12 multiplication is
// commutative, so F is unchanged mod p.
// Build-time check of the on-chain gamma/delta walks (deterministic, VK-only), against noble and against the reviewed
// minop's baked line coefficients: every step's coefficients equal the baked ones (C.millerBatchOps, pairs 2 and 3),
// Z != 0 and the y-slot coefficient c2 != 0 at every step, the homogeneous point equals noble's multiple, and the
// walk ends at [|x|]Q. Throws on any mismatch.
export function assertFixedWalks() {
  const Fp2 = bls12_381.fields.Fp2; const ops = C.millerBatchOps(pairs).ops; const NAF = C.ATE_NAF;
  for (const [j, Q] of [[2, vk.gamma], [3, vk.delta]]) {
    const a = Q.toAffine(); let R = { x: a.x, y: a.y, z: Fp2.ONE }; let mult = 1n; const baked = ops.filter((o) => o.t !== 'sqr' && o.j === j); let n = 0;
    const same = (R, m) => { const t = Q.multiply(m).toAffine(); const zi = Fp2.inv(R.z); return Fp2.eql(Fp2.mul(R.x, zi), t.x) && Fp2.eql(Fp2.mul(R.y, zi), t.y); };
    const chk = (st, kind) => { const b = baked[n++]; if (b.t !== kind) throw new Error('op order'); st.coeffs.forEach((c, i) => { if (!Fp2.eql(c, b.coeffs[i])) throw new Error(`pair ${j} step ${n}: coefficient ${i} differs from the baked one`); });
      if (Fp2.is0(st.R.z)) throw new Error(`pair ${j}: Z = 0`); if (Fp2.is0(st.coeffs[2])) throw new Error(`pair ${j}: c2 = 0`); };
    for (let k = 0; k < NAF.length; k++) {
      const d = C.pointDouble(R.x, R.y, R.z); chk(d, 'dl'); R = d.R; mult *= 2n; if (!same(R, mult)) throw new Error(`pair ${j}: walk != noble after doubling ${k}`);
      if (NAF[k]) { const s = C.pointAdd(R.x, R.y, R.z, a.x, NAF[k] === -1 ? Fp2.neg(a.y) : a.y); chk(s, 'al'); R = s.R; mult += BigInt(NAF[k]); if (!same(R, mult)) throw new Error(`pair ${j}: walk != noble after addition ${k}`); }
    }
    if (mult !== X || n !== baked.length) throw new Error(`pair ${j}: walk does not end at [|x|]Q`);
  }
  return true;
}
const HOIST = process.env.HOIST !== '0';
export const NAF_DIGITS = C.ATE_NAF.map((d) => (d === -1 ? 2 : d));
function emitMillerTailLazy() {
  const NAF = C.ATE_NAF;
  const L = [];
  const g2aff = (Q) => { const a = Q.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1].map((v) => modP(v).toString()); };
  const GM = g2aff(vk.gamma), DL = g2aff(vk.delta);
  const ngy = [modP(-BigInt(GM[2])).toString(), modP(-BigInt(GM[3])).toString()], ndy = [modP(-BigInt(DL[2])).toString(), modP(-BigInt(DL[3])).toString()];
  const digitHex = '0x' + NAF_DIGITS.map((d) => d.toString(16).padStart(2, '0')).join('');
  const S = (p, n) => N(n).map((i) => `${p}${i}`);
  const asg = (dst, src) => dst.map((d, i) => `${d} = ${src[i]};`).join(' ');
  L.push('        // ---- batched c^-|x|-fused Miller (ROLLED over the NAF of |x|): (-A,B), (vk_x,gamma), (C,delta) on-chain G2 walks ----');
  L.push('        int nAy = mSub(0, Ay);');
  L.push(`        (${decl6('nur')}) = fp6Neg(${use6('u')}, 1);`);
  L.push(`        ${N(6).map((i) => `int nu${i} = mulFp(nur${i}, 1);`).join(' ')}`);
  L.push('        (int nBya, int nByb) = fp2Neg(Bya, Byb, 1);');
  // genesis f = [c^-1] representative 1 + nu*W (folds the 2^63 c-term); genesis walks at (x : y : 1)
  L.push(`        int f0 = 1; int f1 = 0; int f2 = 0; int f3 = 0; int f4 = 0; int f5 = 0; ${N(6).map((i) => `int f${i + 6} = nu${i};`).join(' ')}`);
  L.push('        int rb0 = Bxa; int rb1 = Bxb; int rb2 = Bya; int rb3 = Byb; int rb4 = 1; int rb5 = 0;');
  // gamma, delta: baked affine coordinates, each pushed ONCE (HOIST=0 inlines the literals at every use instead)
  if (HOIST) {
    L.push(`        int gq0 = ${GM[0]}; int gq1 = ${GM[1]}; int gq2 = ${GM[2]}; int gq3 = ${GM[3]};`);
    L.push(`        int dq0 = ${DL[0]}; int dq1 = ${DL[1]}; int dq2 = ${DL[2]}; int dq3 = ${DL[3]};`);
  }
  const g = HOIST ? ['gq0', 'gq1', 'gq2', 'gq3'] : GM, dd = HOIST ? ['dq0', 'dq1', 'dq2', 'dq3'] : DL;
  const ng = HOIST ? ['mSub(0, gq2)', 'mSub(0, gq3)'] : ngy, nd = HOIST ? ['mSub(0, dq2)', 'mSub(0, dq3)'] : ndy;
  L.push(`        int rg0 = ${g[0]}; int rg1 = ${g[1]}; int rg2 = ${g[2]}; int rg3 = ${g[3]}; int rg4 = 1; int rg5 = 0;`);
  L.push(`        int rd0 = ${dd[0]}; int rd1 = ${dd[1]}; int rd2 = ${dd[2]}; int rd3 = ${dd[3]}; int rd4 = 1; int rd5 = 0;`);
  L.push(`        bytes nafDigits = ${digitHex};`);
  L.push(`        for (int nk = 0; nk < ${NAF.length}; nk = nk + 1) {`);
  L.push('            int dg = int(nafDigits.split(nk)[1].split(1)[0]);');
  L.push(`            (${decl(S('sq', 12))}) = fp12Sqr(${S('f', 12).join(',')});`);
  L.push(`            (${decl([...S('lb', 6), ...S('nb', 6)])}) = pointDouble(${S('rb', 6).join(',')});`);
  L.push(`            (${decl(S('fb', 12))}) = line(${S('sq', 12).join(',')}, ${S('lb', 6).join(',')}, Ax, nAy);`);
  L.push(`            (${decl([...S('lg', 6), ...S('ng', 6)])}) = pointDouble(${S('rg', 6).join(',')});`);
  L.push(`            (${decl(S('fg', 12))}) = line(${S('fb', 12).join(',')}, ${S('lg', 6).join(',')}, vkxX, vkxY);`);
  L.push(`            (${decl([...S('ld', 6), ...S('nd', 6)])}) = pointDouble(${S('rd', 6).join(',')});`);
  L.push(`            (${decl(S('fd', 12))}) = line(${S('fg', 12).join(',')}, ${S('ld', 6).join(',')}, Cx, Cy);`);
  L.push(`            ${asg(S('f', 12), S('fd', 12))}`);
  L.push(`            ${asg(S('rb', 6), S('nb', 6))} ${asg(S('rg', 6), S('ng', 6))} ${asg(S('rd', 6), S('nd', 6))}`);
  L.push('            if (dg != 0) {');
  // digit +1: fold [c^-1] = [1 - u W] (nu), add +Q; digit -1 (encoded 2): fold [c] = [1 + u W] (u), add -Q
  L.push(`                ${N(6).map((i) => `int tt${i} = nu${i};`).join(' ')} int qby0 = Bya; int qby1 = Byb; int qgy0 = ${g[2]}; int qgy1 = ${g[3]}; int qdy0 = ${dd[2]}; int qdy1 = ${dd[3]};`);
  L.push(`                if (dg == 2) { ${N(6).map((i) => `tt${i} = u${i};`).join(' ')} qby0 = nBya; qby1 = nByb; qgy0 = ${ng[0]}; qgy1 = ${ng[1]}; qdy0 = ${nd[0]}; qdy1 = ${nd[1]}; }`);
  L.push(`                (${decl(S('ft', 12))}) = fp12MulTorus(${S('f', 12).join(',')}, ${S('tt', 6).join(',')});`);
  L.push(`                (${decl([...S('ab', 6), ...S('mb', 6)])}) = pointAdd(${S('rb', 6).join(',')}, Bxa,Bxb,qby0,qby1);`);
  L.push(`                (${decl(S('gb', 12))}) = line(${S('ft', 12).join(',')}, ${S('ab', 6).join(',')}, Ax, nAy);`);
  L.push(`                (${decl([...S('ag', 6), ...S('mg', 6)])}) = pointAdd(${S('rg', 6).join(',')}, ${g[0]},${g[1]},qgy0,qgy1);`);
  L.push(`                (${decl(S('gg', 12))}) = line(${S('gb', 12).join(',')}, ${S('ag', 6).join(',')}, vkxX, vkxY);`);
  L.push(`                (${decl([...S('ad', 6), ...S('md', 6)])}) = pointAdd(${S('rd', 6).join(',')}, ${dd[0]},${dd[1]},qdy0,qdy1);`);
  L.push(`                (${decl(S('gd', 12))}) = line(${S('gg', 12).join(',')}, ${S('ad', 6).join(',')}, Cx, Cy);`);
  L.push(`                ${asg(S('f', 12), S('gd', 12))}`);
  L.push(`                ${asg(S('rb', 6), S('mb', 6))} ${asg(S('rg', 6), S('mg', 6))} ${asg(S('rd', 6), S('md', 6))}`);
  L.push('            }');
  L.push('        }');
  let f = S('f', 12); const rb = S('rb', 6);
  const emitF = (call) => { const g = N(12).map((i) => `fz${i}`); L.push(`        (${decl(g)}) = ${call};`); f = g; };
  // multiply in the baked e(alpha,beta) torus coordinate; f is now gF = g * c^-|x| (unconjugated)
  emitF(`fp12MulTorus(${f.join(',')}, ${lits(FABU)})`);
  // ---- G2 subgroup membership, FUSED into the Miller loop ----
  // The Miller loop above already walks R_B to [|x|]B (homogeneous projective; NAF excludes the
  // MSB, R_B starts at B), so psi(B) == -[|x|]B needs NO separate 64-step [|x|]B walk. Compare
  // affine(R_B)=(Rb/Rbz) to -psi(B): Rbx == psi(B).x*Rbz and Rby == -psi(B).y*Rbz.
  // GUARD (soundness): reject R_B = O. |x| has NAF prefix 13, and 13 | h2 (the G2 twist cofactor),
  // so an order-13 B (which passes the raw on-curve check) drives R_B through O; the homogeneous
  // pointDouble/pointAdd collapse it to (0:0:0), which VACUOUSLY satisfies the cross-multiplied
  // compare below (0 == psi.x*0). Requiring Rbz != 0 rejects that: gcd(prefix, r)=1 forces any
  // collapsing B to order exactly 13 -> Rbz=0, while every non-collapsing walk yields the true
  // [|x|]B where gcd(lambda, h2)=1 makes psi(B)==[x]B equivalent to B in G2. See psi-subgroup-degeneracy.md.
  L.push(`        require(redFp(${rb[4]}) != 0 || redFp(${rb[5]}) != 0);`);
  L.push('        (int psxa,int psxb,int psya,int psyb) = psi(Bxa, Bxb, Bya, Byb);');
  L.push('        (int npya,int npyb) = r2Neg(psya, psyb);');
  L.push(`        (int gcxa,int gcxb) = r2Mul(psxa, psxb, ${rb[4]}, ${rb[5]});`);
  L.push(`        require(redFp(${rb[0]}) == gcxa); require(redFp(${rb[1]}) == gcxb);`);
  L.push(`        (int gcya,int gcyb) = r2Mul(npya, npyb, ${rb[4]}, ${rb[5]});`);
  L.push(`        require(redFp(${rb[2]}) == gcya); require(redFp(${rb[3]}) == gcyb);`);
  // ---- quotient-torus terminal: [fF] == [frob(c,1)] in Q = Fp12*/Fp6* ----
  // fF = g*c^-|x|*fAB accumulated above; lambda = p+|x| makes acceptance equivalent to the full
  // pairing verdict (r-torsion result, gcd(r, p^6-1)=1). Canonicalize the lazy accumulator, reject
  // the vacuous projective value [0:0], then cross-multiply: [F_lo:F_hi] == [1:frob1(u)] iff
  // F_lo*frob1(u) == F_hi in Fp6.
  L.push(`        ${N(12).map((i) => `int tF${i} = mulFp(${f[i]}, 1);`).join(' ')}`);
  L.push(`        require(${N(12).map((i) => `tF${i}`).join(' + ')} != 0);`);
  L.push(`        (${N(6).map((i) => `int tu${i}`).join(',')}) = torusFrob1(${use6('u')});`);
  L.push(`        (${N(6).map((i) => `int tp${i}`).join(',')}) = fp6Mul(${N(6).map((i) => `tF${i}`).join(',')}, ${N(6).map((i) => `tu${i}`).join(',')});`);
  L.push('        ' + N(6).map((i) => `require(mulFp(tp${i} - tF${i + 6}, 1) == 0);`).join(' '));
  return L;
}
function emitMinOp() {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push('');
  L.push('// GENERATED by gen_singleton_minop.mjs — op-optimized BLS12-381 Groth16 singleton (lazy tower,');
  L.push('// quotient torus). ONE batched c^-|x|-fused Miller (UNROLLED, unconjugated boundary): only (-A,B)');
  L.push('// runs on-chain G2 arithmetic; e(alpha,beta) baked as its torus coordinate, (vk_x,gamma)/(C,delta)');
  L.push('// lines baked; QUOTIENT-TORUS residue final-exp (lambda=p+|x|): 6-limb root u ([c]=[1+u*W]),');
  L.push('// 2-Fp6-product c-folds, terminal [fF]=[frob(c,1)] cross-product with [0:0] rejected; G2 subgroup');
  L.push('// check psi(B)==[x]B=-[|x|]B FUSED into the Miller tail (reuses R_B=[|x|]B); no G1 subgroup checks');
  L.push('// (redundant given B in G2 — see header); GLV vk_x. Large by design — bytes are not this');
  L.push('// variant\'s axis; needs the cashc fork large-contract compile fix.');
  L.push('// Regenerate: node gen_singleton_minop.mjs.');
  L.push('import "../../../../singleton/bls12-381/lib/lazy/Bls12381LazyTorus.cash";');
  L.push('');
  L.push('contract Groth16VerifyMinOpRolled() {');
  const sig = ['int Ax', 'int Ay', 'int Bxa', 'int Bxb', 'int Bya', 'int Byb', 'int Cx', 'int Cy', 'int in0', 'int in1',
    decl6('u'), 'int k10', 'int k20', 'int k11', 'int k21', 'int vkxZinv'].join(', ');
  L.push(`    function spend(${sig}) {`);
  for (const ln of emitInputValidationLazy()) L.push(ln);
  // G1 subgroup checks on A,C are OMITTED (not just fused): they are redundant for Groth16
  // soundness. A and C are only ever paired against G2 elements that are in the order-r subgroup
  // (B — checked below — and the VK's delta), so any cofactor component of A/C is annihilated by
  // the pairing (e(A_cof,B)=1 since gcd(ord(A_cof),r)=1); the equation constrains only A_r/C_r,
  // which must still be a valid witness. On-curve checks (above) remain. This matches the deployed
  // grouped/intra-tx residue verifiers. The G2 subgroup check on B (which makes this valid) is
  // FUSED into the Miller tail, reusing R_B=[|x|]B — see emitMillerTailLazy.
  for (const ln of emitGlvVkxLazy()) L.push(ln);
  for (const ln of emitMillerTailLazy()) L.push(ln);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- write (only when run directly; the builder imports the GLV helpers above) ----
if (process.argv[1] && process.argv[1].endsWith('gen_minop_rolled.mjs')) {
  assertFixedWalks(); console.log('gamma/delta walks: 69 steps each, coefficients == baked minop lines, Z != 0, c2 != 0, endpoint [|x|]Q (noble)');
  writeFileSync(join(here, 'groth16_minop_rolled.cash'), emitMinOp());
  console.log('wrote groth16_minop_rolled.cash');
}
