// Generator for the OP-OPTIMIZED BLS12-381 Groth16 singleton: groth16_minop.cash.
// BLS analog of ../bn254/gen_singletons.mjs — stacks every op-lowering optimization:
//   - LAZY field tower for the Miller loop (lib/lazy/, deferred reductions);
//   - witnessed-residue final exponentiation (ePrint 2024/640 adapted to BLS12-381,
//     see ../../chunked/bls12-381/_residuemath.mjs): lambda = p + |x|, tail
//     fF*w == frob(c,1), witness subgroup check ((w^|x|)*w)^9 == 1 (w in mu_27A);
//   - ONE batched c^-|x|-fused Miller (UNROLLED): only (-A,B) runs on-chain G2
//     arithmetic; e(alpha,beta) baked; (vk_x,gamma)/(C,delta) lines baked;
//   - G2 subgroup check psi(B) == [-x]B, FUSED into the Miller tail: the loop already
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
import { PUBLIC_INPUTS } from './bls_instance.mjs';

const C = await import('../../chunked/bls12-381/_pairingmath.mjs');
const R = await import('../../chunked/bls12-381/_residuemath.mjs');
const { bls12_381 } = await import('../../chunked/bls12-381/_vkxmath.mjs');

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
const FAB = R.fp12limbsOf(R.conj(C.singlePairMiller(pairs[1]).f)).map(String); // baked UNCONJUGATED e(alpha,beta)

const N = (n) => Array.from({ length: n }, (_, i) => i);
const list = (a) => a.join(',');
const decl12 = (p) => list(N(12).map((i) => `int ${p}${i}`));
const use12 = (p) => list(N(12).map((i) => `${p}${i}`));
const lits = (arr) => list(arr);

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
  L.push(`        require(k10 < ${BOUND}); require(k20 < ${BOUND}); require(k11 < ${BOUND}); require(k21 < ${BOUND});`);
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
  L.push('                (int gax, int gay, int gaz) = jacAddG1(gX, gY, gZ, aX, aY, 1); gX = gax; gY = gay; gZ = gaz;');
  L.push('            }');
  L.push('        }');
  L.push(`        (int icx, int icy, int icz) = jacAddG1(gX, gY, gZ, ${ic0[0]}, ${ic0[1]}, 1);`);
  L.push('        require(mulFp(icz, vkxZinv) == 1);');
  L.push('        int vz2 = mSqr(vkxZinv); int vz3 = mulFp(vz2, vkxZinv);');
  L.push('        int vkxX = mulFp(icx, vz2);');
  L.push('        int vkxY = mulFp(icy, vz3);');
  return L;
}
// Batched c^-|x|-fused Miller (lazy, UNROLLED). Only the runtime pair (-A,B) runs on-chain
// G2 point arithmetic; the fixed-VK pairs (vk_x,gamma)/(C,delta) have proof-independent line
// coefficients (BAKED), e(alpha,beta) is the baked constant fAB. f is squared ONCE per step
// (shared) and c^-|x| is folded in-loop (genesis f = cInv folds the 2^63 MSB term). The
// witnessed-residue verdict replaces the final exponentiation. All on the UNCONJUGATED
// boundary (x<0's final conjugation is absorbed into the witness — see _residuemath.mjs).
function bakedLineLits(triple, Px, Py) {
  const lim = triple.flatMap((f) => [f.c0.toString(), f.c1.toString()]);
  return `        (${use12('F')}) = line(${use12('F')}, ${lim.join(', ')}, ${Px}, ${Py});`;
}
function emitMillerTailLazy() {
  const base = C.millerBatchOps(pairs, { skipPairs: new Set([1]) });
  const NAF = C.ATE_NAF;
  const Pof = { 0: ['Ax', 'nAy'], 2: ['vkxX', 'vkxY'], 3: ['Cx', 'Cy'] };
  const L = [];
  L.push('        // ---- batched c^-|x|-fused Miller (unrolled): (-A,B) runtime G2; (vk_x,gamma)/(C,delta) baked ----');
  L.push('        int nAy = mSub(0, Ay);');
  L.push(`        ${N(12).map((i) => `int F${i}=ci${i};`).join(' ')}`); // genesis f = cInv (folds the 2^63 c-term)
  L.push('        int Rbxa=Bxa; int Rbxb=Bxb; int Rbya=Bya; int Rbyb=Byb; int Rbza=1; int Rbzb=0;');
  let uid = 0, k = -1;
  for (const op of base.ops) {
    if (op.t === 'sqr') {
      k++;
      L.push(`        (${use12('F')}) = fp12Sqr(${use12('F')});`);
      if (NAF[k] !== undefined && NAF[k] !== 0) {
        // fold c^-|x|: digit +1 -> x cInv, digit -1 -> x c
        L.push(`        (${use12('F')}) = fp12Mul(${use12('F')}, ${NAF[k] === -1 ? use12('c') : use12('ci')});`);
      }
    } else if (op.t === 'dl') {
      const [px, py] = Pof[op.j];
      if (op.j === 0) {
        const d = N(6).map((i) => `d${uid}_${i}`), rr = N(6).map((i) => `dr${uid}_${i}`); uid++;
        L.push(`        (${d.map((n) => 'int ' + n).join(',')}, ${rr.map((n) => 'int ' + n).join(',')}) = pointDouble(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb);`);
        L.push(`        Rbxa=${rr[0]}; Rbxb=${rr[1]}; Rbya=${rr[2]}; Rbyb=${rr[3]}; Rbza=${rr[4]}; Rbzb=${rr[5]};`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${d.join(',')}, ${px}, ${py});`);
      } else {
        L.push(bakedLineLits(op.coeffs, px, py));
      }
    } else if (op.t === 'al') {
      const [px, py] = Pof[op.j];
      if (op.j === 0) {
        const a = N(6).map((i) => `a${uid}_${i}`), rr = N(6).map((i) => `ar${uid}_${i}`); const u = `uy${uid}`; uid++;
        L.push(`        int ${u}a = Bya; int ${u}b = Byb;`);
        if (op.neg) L.push(`        (${u}a,${u}b) = fp2Neg(Bya, Byb);`);
        L.push(`        (${a.map((n) => 'int ' + n).join(',')}, ${rr.map((n) => 'int ' + n).join(',')}) = pointAdd(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb, Bxa,Bxb,${u}a,${u}b);`);
        L.push(`        Rbxa=${rr[0]}; Rbxb=${rr[1]}; Rbya=${rr[2]}; Rbyb=${rr[3]}; Rbza=${rr[4]}; Rbzb=${rr[5]};`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${a.join(',')}, ${px}, ${py});`);
      } else {
        L.push(bakedLineLits(op.coeffs, px, py));
      }
    }
  }
  // multiply in the baked e(alpha,beta); F is now gF = g * c^-|x| (unconjugated)
  L.push(`        (${use12('F')}) = fp12Mul(${use12('F')}, ${lits(FAB)});`);
  // ---- G2 subgroup membership, FUSED into the Miller loop ----
  // The Miller loop above already walks R_B to [|x|]B (homogeneous projective; NAF excludes the
  // MSB, R_B starts at B), so psi(B) == -[|x|]B needs NO separate 64-step [|x|]B walk. Compare
  // affine(R_B)=(Rb/Rbz) to -psi(B): Rbx == psi(B).x*Rbz and Rby == -psi(B).y*Rbz.
  L.push('        (int psxa,int psxb,int psya,int psyb) = psi(Bxa, Bxb, Bya, Byb);');
  L.push('        (int npya,int npyb) = r2Neg(psya, psyb);');
  L.push('        (int gcxa,int gcxb) = r2Mul(psxa, psxb, Rbza, Rbzb);');
  L.push('        require(Rbxa == gcxa); require(Rbxb == gcxb);');
  L.push('        (int gcya,int gcyb) = r2Mul(npya, npyb, Rbza, Rbzb);');
  L.push('        require(Rbya == gcya); require(Rbyb == gcyb);');
  L.push(`        require(residueVerdict(${use12('F')}, ${use12('c')}, ${use12('ci')}, ${use12('w')}));`);
  return L;
}
function emitMinOp() {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push('');
  L.push('// GENERATED by gen_singleton_minop.mjs — op-optimized BLS12-381 Groth16 singleton (lazy tower).');
  L.push('// ONE batched c^-|x|-fused Miller (UNROLLED, unconjugated boundary): only (-A,B) runs on-chain');
  L.push('// G2 arithmetic; e(alpha,beta)=baked fAB, (vk_x,gamma)/(C,delta) lines baked; witnessed-residue');
  L.push('// final-exp (lambda=p+|x|, w in mu_27A); G2 subgroup check psi(B)==[-x]B FUSED into the Miller');
  L.push('// tail (reuses R_B=[|x|]B); no G1 subgroup checks (redundant given B in G2 — see header);');
  L.push('// GLV vk_x. Large by design — bytes are not this variant\'s axis; needs the cashc fork');
  L.push('// large-contract compile fix. Regenerate: node gen_singleton_minop.mjs.');
  L.push('import "./lib/lazy/Bls12381LazyG.cash";');
  L.push('');
  L.push('contract Groth16VerifyMinOp() {');
  const sig = ['int Ax', 'int Ay', 'int Bxa', 'int Bxb', 'int Bya', 'int Byb', 'int Cx', 'int Cy', 'int in0', 'int in1',
    decl12('c'), decl12('ci'), decl12('w'), 'int k10', 'int k20', 'int k11', 'int k21', 'int vkxZinv'].join(', ');
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
if (process.argv[1] && process.argv[1].endsWith('gen_singleton_minop.mjs')) {
  writeFileSync(join(here, 'groth16_minop.cash'), emitMinOp());
  console.log('wrote groth16_minop.cash');
}
