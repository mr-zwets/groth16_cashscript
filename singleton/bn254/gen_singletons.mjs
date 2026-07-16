// Generator for the OP-OPTIMIZED BN254 Groth16 singleton: groth16_minop.cash.
//
// Why only op-optimized? On the verifier benchmark's scored byte metric (locking+unlocking)
// the existing bch-groth16-singleton is already byte-optimal for a SOUND verifier: the BN254
// field tower is an irreducible ~15.8KB floor, and every cryptographic optimization either
// moves bytes into per-proof witness UNLOCKING (residue / witnessed inverses — the score counts
// these) or ADDS locking (lazy tower / fast-G2 / GLV). Dropping the G2 subgroup check is the
// only large byte lever and is a soundness regression, so it is rejected. The genuine win is
// OP-COST: min-op runs ~53% fewer ops than the baseline.
//
// min-op stacks every op-lowering optimization ported from the chunked verifier:
//   - LAZY field tower for the Miller loop (deferred reductions; ~31% cheaper than reduced);
//   - QUOTIENT-TORUS residue final exponentiation (ePrint 2024/640 in Fp12*/Fp6*): the root is
//     ONE gated 6-limb witness u ([c]=[1+u*W]); c-folds are 2-Fp6-product fp12MulTorus; the
//     terminal verdict is a projective cross-multiplication with explicit [0:0] rejection;
//   - AFFINE runtime-B Miller steps with prover-witnessed slopes (verified mod p) and
//     normalized UNIT lines through the sparse direct kernel;
//   - the Miller-endpoint endomorphism relation doubles as the EXACT G2 subgroup check
//     (the standalone fast-endo walk is gone);
//   - e(alpha,beta) baked as a torus constant; (vk_x,gamma)/(C,delta) lines baked;
//   - GLV vk_x: 4-scalar ~128-bit Straus over a baked subset-sum table (gated witnesses).
// MODE=staged additionally emits the older pre-torus comparison variants.
//
// All field/curve arithmetic comes from the verified lazy lib (lib/lazy/Bn254LazyG.cash, which
// imports Bn254Lazy.cash); this generator only bakes the instance constants and stitches calls.
//   node gen_singletons.mjs   [MODE=staged emits the fast-G2-only / lazy-only comparisons too]
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const C = await import('../../chunked/pairing/_millermath.mjs');
const R = await import('../../chunked/pairing/_residuemath.mjs');
const G = await import('../../chunked/pairing/gen_vkx_glv.mjs');

const here = dirname(fileURLToPath(import.meta.url));

// ---- instance constants pulled from the verified JS (kept in sync, never hand-typed) ----
const { vk } = C;
const f2 = (Fp2v) => [Fp2v.c0, Fp2v.c1];
const g2aff = (pt) => { const a = pt.toAffine(); return [...f2(a.x), ...f2(a.y)]; };
const g1aff = (pt) => { const a = pt.toAffine(); return [a.x, a.y]; };

const GAMMA = g2aff(vk.gamma).map(String);  // Q for pair (vk_x, gamma)
const DELTA = g2aff(vk.delta).map(String);  // Q for pair (C, delta)
const IC1 = g1aff(vk.ic[1]).map(String);
const IC2 = g1aff(vk.ic[2]).map(String);

const pairs = C.pairsFor(C.vec.publicInputs.map(BigInt));
const FAB = R.fp12limbsOf(C.singlePairMiller(pairs[1]).f).map(String);   // baked e(alpha,beta)

const B2 = ['19485874751759354771024239261021720505790618469301721065564631296452457478373',
            '266929791119991161246907387137283842545076965332900288569378510910307636690']; // twist b2
const SIXX2 = '147946756881789318990833708069417712966'; // 6*x^2 (128-bit) for the simple G2 walk (unused in full)
const P = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

const N = (n) => Array.from({ length: n }, (_, i) => i);
const list = (a) => a.join(',');
const decl12 = (p) => list(N(12).map((i) => `int ${p}${i}`));
const use12 = (p) => list(N(12).map((i) => `${p}${i}`));
const lits = (arr) => list(arr);

// ---- shared lazy blocks ----
function emitInputValidationLazy() {
  return [
    '        // ---- validate spender-supplied proof points (EIP-197; canonical limbs required',
    '        // by the affine slope-verified walk and the unit-line kernels) ----',
    `        int fieldP = ${P};`,
    '        require(within(Ax, 0, fieldP)); require(within(Ay, 0, fieldP));',
    '        require(within(Cx, 0, fieldP)); require(within(Cy, 0, fieldP));',
    '        require(within(Bxa, 0, fieldP)); require(within(Bxb, 0, fieldP));',
    '        require(within(Bya, 0, fieldP)); require(within(Byb, 0, fieldP));',
    '        require(mulFp(Ay, Ay) == mAdd(mulFp(mulFp(Ax, Ax), Ax), 3)); // A on G1',
    '        require(mulFp(Cy, Cy) == mAdd(mulFp(mulFp(Cx, Cx), Cx), 3)); // C on G1',
    '        (int bx2a,int bx2b) = r2Sqr(Bxa, Bxb);                       // B on G2',
    '        (int bx3a,int bx3b) = r2Mul(bx2a, bx2b, Bxa, Bxb);',
    `        (int onrhsa,int onrhsb) = r2Add(bx3a, bx3b, ${B2[0]}, ${B2[1]});`,
    '        (int by2a,int by2b) = r2Sqr(Bya, Byb);',
    '        require(by2a == onrhsa); require(by2b == onrhsb);',
  ];
}
function emitSimpleG2CheckLazy() {
  return [
    '        // ---- G2 subgroup membership: [6x^2]B == psi(B) (128-bit walk) ----',
    '        int GXa=0; int GXb=0; int GYa=1; int GYb=0; int GZa=0; int GZb=0;',
    '        for (int gi = 0; gi < 128; gi = gi + 1) {',
    '            (GXa,GXb,GYa,GYb,GZa,GZb) = g2Double(GXa, GXb, GYa, GYb, GZa, GZb);',
    `            if (((${SIXX2} >> (127 - gi)) % 2) == 1) {`,
    '                (GXa,GXb,GYa,GYb,GZa,GZb) = g2AddAffine(GXa, GXb, GYa, GYb, GZa, GZb, Bxa, Bxb, Bya, Byb);',
    '            }',
    '        }',
    '        (int gpxa,int gpxb,int gpya,int gpyb) = psi(Bxa, Bxb, Bya, Byb);',
    '        (int gz2a,int gz2b) = r2Sqr(GZa, GZb);',
    '        (int gz3a,int gz3b) = r2Mul(gz2a, gz2b, GZa, GZb);',
    '        (int gcxa,int gcxb) = r2Mul(gpxa, gpxb, gz2a, gz2b);',
    '        (int gcya,int gcyb) = r2Mul(gpya, gpyb, gz3a, gz3b);',
    '        require(GXa == gcxa); require(GXb == gcxb);',
    '        require(GYa == gcya); require(GYb == gcyb);',
  ];
}
// fast-endo 63-bit G2 subgroup check (ePrint 2022/348): walk |x0| (BN_X) and verify
// [x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B). zinv = (Z of [x0]B)^-1 witness.
function emitFastG2CheckLazy() {
  const BN_X = '4965661367192848881'; // |x0|, 63-bit (MSB at bit 62)
  return [
    '        // ---- G2 subgroup membership: fast-endo 63-bit walk (ePrint 2022/348) ----',
    '        int GXa=0; int GXb=0; int GYa=1; int GYb=0; int GZa=0; int GZb=0;',
    '        for (int gi = 0; gi < 63; gi = gi + 1) {',
    '            (GXa,GXb,GYa,GYb,GZa,GZb) = g2Double(GXa, GXb, GYa, GYb, GZa, GZb);',
    `            if (((${BN_X} >> (62 - gi)) % 2) == 1) {`,
    '                (GXa,GXb,GYa,GYb,GZa,GZb) = g2AddAffine(GXa, GXb, GYa, GYb, GZa, GZb, Bxa, Bxb, Bya, Byb);',
    '            }',
    '        }',
    '        // affine-ize [x0]B via witness inverse zinv of GZ (gated)',
    '        (int gza,int gzb) = r2Mul(GZa, GZb, zinvA, zinvB);',
    '        require(gza == 1); require(gzb == 0);',
    '        (int zi2a,int zi2b) = r2Sqr(zinvA, zinvB);',
    '        (int zi3a,int zi3b) = r2Mul(zi2a, zi2b, zinvA, zinvB);',
    '        (int a0xa,int a0xb) = r2Mul(GXa, GXb, zi2a, zi2b);',
    '        (int a0ya,int a0yb) = r2Mul(GYa, GYb, zi3a, zi3b);',
    '        (int e1xa,int e1xb,int e1ya,int e1yb) = psi(a0xa, a0xb, a0ya, a0yb);',
    '        (int e2xa,int e2xb,int e2ya,int e2yb) = psi(e1xa, e1xb, e1ya, e1yb);',
    '        (int e3xa,int e3xb,int e3ya,int e3yb) = psi(e2xa, e2xb, e2ya, e2yb);',
    '        // LHS = [x0]B + B + psi + psi^2',
    '        (int l1xa,int l1xb,int l1ya,int l1yb,int l1za,int l1zb) = g2AddAffine(a0xa, a0xb, a0ya, a0yb, 1, 0, Bxa, Bxb, Bya, Byb);',
    '        (int l2xa,int l2xb,int l2ya,int l2yb,int l2za,int l2zb) = g2AddAffine(l1xa, l1xb, l1ya, l1yb, l1za, l1zb, e1xa, e1xb, e1ya, e1yb);',
    '        (int lxa,int lxb,int lya,int lyb,int lza,int lzb) = g2AddAffine(l2xa, l2xb, l2ya, l2yb, l2za, l2zb, e2xa, e2xb, e2ya, e2yb);',
    '        // RHS = 2 * psi^3([x0]B)',
    '        (int rxa,int rxb,int rya,int ryb,int rza,int rzb) = g2Double(e3xa, e3xb, e3ya, e3yb, 1, 0);',
    '        // projective equality LHS == RHS',
    '        (int lz2a,int lz2b) = r2Sqr(lza, lzb); (int lz3a,int lz3b) = r2Mul(lz2a, lz2b, lza, lzb);',
    '        (int rz2a,int rz2b) = r2Sqr(rza, rzb); (int rz3a,int rz3b) = r2Mul(rz2a, rz2b, rza, rzb);',
    '        (int xl_a,int xl_b) = r2Mul(lxa, lxb, rz2a, rz2b); (int xr_a,int xr_b) = r2Mul(rxa, rxb, lz2a, lz2b);',
    '        require(xl_a == xr_a); require(xl_b == xr_b);',
    '        (int yl_a,int yl_b) = r2Mul(lya, lyb, rz3a, rz3b); (int yr_a,int yr_b) = r2Mul(rya, ryb, lz3a, lz3b);',
    '        require(yl_a == yr_a); require(yl_b == yr_b);',
  ];
}
function emitPlainVkxLazy() {
  return [
    '        // ---- vk_x = IC0 + in0*IC1 + in1*IC2 (on-chain G1 MSM) ----',
    `        (int r1x, int r1y, int r1z) = g1ScalarMul(in0, ${IC1[0]}, ${IC1[1]});`,
    `        (int r2x, int r2y, int r2z) = g1ScalarMul(in1, ${IC2[0]}, ${IC2[1]});`,
    `        (int a1x, int a1y, int a1z) = jacAddG1(${g1aff(vk.ic[0])[0]}, ${g1aff(vk.ic[0])[1]}, 1, r1x, r1y, r1z);`,
    '        (int vx, int vy, int vz) = jacAddG1(a1x, a1y, a1z, r2x, r2y, r2z);',
    '        (int vkxX, int vkxY) = jacToAffine(vx, vy, vz);',
  ];
}
// GLV vk_x: 4-scalar ~128-bit Straus over baked {IC1,phi(IC1),IC2,phi(IC2)} + baked 16-entry
// blob table. Witnesses k10,k20,k11,k21 (k1+k2*lambda==in mod r) + vkxZinv. `nbLoop` upgrades
// this to the op-optimal form:
//   - witnessed top-bit index nb: every k is gated to < 2^(nb+1) (subsumes the old 2^128
//     bound; the arithmetic >> keeps negative k's negative, so the ==0 gate also enforces
//     k >= 0) and the Straus loop runs only nb+1 iterations — sound for ANY prover-chosen nb
//     because skipped leading iterations act on gated-zero bits, and op-cost then scales with
//     the ACTUAL scalar size (the fork compiles runtime-bound loops via BCH2026 native loops);
//   - AFFINE accumulator with prover-witnessed slopes (g1DoubleAffine/g1AddAffine: the
//     tangent/chord equation verified mod p uniquely binds each slope; O is unrepresentable
//     and zero-denominator cases are rejected), consumed 32B-LE at a time from the glvSlopes
//     bytes witness. This replaces the canonical Jacobian ops AND the final vkxZinv
//     affinization. vk_x is uniquely determined by (in0,in1); all failure paths reject.
function emitGlvVkxLazy({ nbLoop = false } = {}) {
  const LAM = G.GLV_LAMBDA.toString(), r = G.GLV_R.toString(), iters = G.VKXGLV_ITERS;
  const BOUND = (1n << 128n).toString();
  const ic0 = G.GLV_IC0.map((x) => (((x % BigInt(P)) + BigInt(P)) % BigInt(P)).toString());
  const L = [];
  L.push('        // ---- vk_x via GLV 4-scalar Straus (baked table) ----');
  if (nbLoop) {
    L.push('        require(within(nb, 0, 128));');
    L.push('        require((k10 >> (nb + 1)) == 0); require((k20 >> (nb + 1)) == 0);');
    L.push('        require((k11 >> (nb + 1)) == 0); require((k21 >> (nb + 1)) == 0);');
  } else {
    L.push(`        require(k10 < ${BOUND}); require(k20 < ${BOUND}); require(k11 < ${BOUND}); require(k21 < ${BOUND});`);
  }
  L.push(`        require((k10 + k20 * ${LAM}) % ${r} == in0);`);
  L.push(`        require((k11 + k21 * ${LAM}) % ${r} == in1);`);
  L.push(`        bytes glvTable = ${G.GLV_TABLE_HEX};`);
  if (nbLoop) {
    L.push('        bytes gs = glvSlopes;');
    L.push('        int gInit = 0; int gX = 0; int gY = 0;');
    L.push('        for (int gk = 0; gk <= nb; gk = gk + 1) {');
    L.push('            int gidx = nb - gk;');
    L.push('            if (gInit != 0) {');
    L.push('                (bytes sdb, bytes gsd) = gs.split(32); gs = gsd;');
    L.push('                (int gdx, int gdy) = g1DoubleAffine(gX, gY, int(sdb)); gX = gdx; gY = gdy;');
    L.push('            }');
    L.push('            int idx = (k10 >> gidx) % 2 + 2 * ((k20 >> gidx) % 2) + 4 * ((k11 >> gidx) % 2) + 8 * ((k21 >> gidx) % 2);');
    L.push('            if (idx != 0) {');
    L.push('                bytes ent = glvTable.split((idx - 1) * 64)[1].split(64)[0];');
    L.push('                int aX = int(ent.split(32)[0]); int aY = int(ent.split(32)[1]);');
    L.push('                if (gInit == 0) { gX = aX; gY = aY; gInit = 1; }');
    L.push('                else {');
    L.push('                    (bytes sab, bytes gsa) = gs.split(32); gs = gsa;');
    L.push('                    (int gax, int gay) = g1AddAffine(gX, gY, aX, aY, int(sab)); gX = gax; gY = gay;');
    L.push('                }');
    L.push('            }');
    L.push('        }');
    // vk_x = acc + IC0 (affine, witnessed chord); if all digits were zero, vk_x = IC0.
    L.push(`        int vkxX = ${ic0[0]}; int vkxY = ${ic0[1]};`);
    L.push('        if (gInit != 0) {');
    L.push(`            (int fX, int fY) = g1AddAffine(gX, gY, ${ic0[0]}, ${ic0[1]}, int(gs.split(32)[0]));`);
    L.push('            vkxX = fX; vkxY = fY;');
    L.push('        }');
    return L;
  }
  L.push('        int gX = 0; int gY = 1; int gZ = 0;');
  L.push(`        for (int gk = 0; gk < ${iters}; gk = gk + 1) {`);
  L.push(`            int gidx = ${iters - 1} - gk;`);
  L.push('            if (gZ != 0) { (int gdx, int gdy, int gdz) = jacDoubleG1(gX, gY, gZ); gX = gdx; gY = gdy; gZ = gdz; }');
  L.push('            int idx = (k10 >> gidx) % 2 + 2 * ((k20 >> gidx) % 2) + 4 * ((k11 >> gidx) % 2) + 8 * ((k21 >> gidx) % 2);');
  L.push('            if (idx != 0) {');
  L.push('                bytes ent = glvTable.split((idx - 1) * 64)[1].split(64)[0];');
  L.push('                int aX = int(ent.split(32)[0]); int aY = int(ent.split(32)[1]);');
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

// Batched c^-(6x+2)-fused Miller (lazy). Only the runtime pair (-A, B) runs on-chain G2 point
// arithmetic; the fixed-VK pairs (vk_x,gamma) and (C,delta) have proof-independent line
// coefficients, so they are BAKED (per-step blobs) and only their line eval at the runtime G1
// point remains. e(alpha,beta) is the baked constant fAB. f is squared ONCE per step (shared),
// and c^-(6x+2) is folded in-loop (genesis f = cInv folds the MSB term). Mirrors
// chunked _residuemath.millerFusedOps; the witnessed-residue verdict replaces the final exp.
// UNROLLED to baked literals (no blob split, which the op-cost model charges by size). OP_PICK
// is constant-cost regardless of stack depth, so unrolling costs bytecode (irrelevant for the
// op-target variant) but is op-optimal.
function bakedLineLits(triple, Px, Py) {
  const lim = triple.flatMap((f) => [f.c0.toString(), f.c1.toString()]);
  return `        (${use12('F')}) = line(${use12('F')}, ${lim.join(', ')}, ${Px}, ${Py});`;
}
function emitMillerTailLazy() {
  const lp = C.pairsFor(C.vec.publicInputs.map(BigInt));
  const base = C.millerBatchOps(lp, { skipPairs: new Set([1]) });
  const NAF = C.ATE_NAF;
  const Pof = { 0: ['Ax', 'nAy'], 2: ['vkxX', 'vkxY'], 3: ['Cx', 'Cy'] };
  const L = [];
  L.push('        // ---- batched c^-(6x+2)-fused Miller (unrolled): (-A,B) runtime G2; (vk_x,gamma)/(C,delta) baked ----');
  L.push('        int nAy = mSub(0, Ay);');
  L.push(`        ${N(12).map((i) => `int F${i}=ci${i};`).join(' ')}`); // genesis f = cInv (folds the 2^65 c-term)
  L.push('        int Rbxa=Bxa; int Rbxb=Bxb; int Rbya=Bya; int Rbyb=Byb; int Rbza=1; int Rbzb=0;');
  let uid = 0, k = -1;
  for (const op of base.ops) {
    if (op.t === 'sqr') {
      k++;
      L.push(`        (${use12('F')}) = fp12Sqr(${use12('F')});`);
      if (NAF[k] !== 0) {
        // fold c^-(6x+2): digit +1 -> x cInv, digit -1 -> x c
        L.push(`        (${use12('F')}) = fp12Mul(${use12('F')}, ${NAF[k] === -1 ? use12('c') : use12('ci')});`);
      }
    } else if (op.t === 'dl') {
      const [px, py] = Pof[op.j];
      if (op.j === 0) {
        const d = N(6).map((i) => `d${uid}_${i}`), r = N(6).map((i) => `dr${uid}_${i}`); uid++;
        L.push(`        (${d.map((n) => 'int ' + n).join(',')}, ${r.map((n) => 'int ' + n).join(',')}) = pointDouble(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb);`);
        L.push(`        Rbxa=${r[0]}; Rbxb=${r[1]}; Rbya=${r[2]}; Rbyb=${r[3]}; Rbza=${r[4]}; Rbzb=${r[5]};`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${d.join(',')}, ${px}, ${py});`);
      } else {
        L.push(bakedLineLits(op.coeffs, px, py));
      }
    } else if (op.t === 'al') {
      const [px, py] = Pof[op.j];
      if (op.j === 0) {
        const a = N(6).map((i) => `a${uid}_${i}`), r = N(6).map((i) => `ar${uid}_${i}`); const u = `uy${uid}`; uid++;
        L.push(`        int ${u}a = Bya; int ${u}b = Byb;`);
        if (op.neg) L.push(`        (${u}a,${u}b) = fp2Neg(Bya, Byb, 64);`);
        L.push(`        (${a.map((n) => 'int ' + n).join(',')}, ${r.map((n) => 'int ' + n).join(',')}) = pointAdd(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb, Bxa,Bxb,${u}a,${u}b);`);
        L.push(`        Rbxa=${r[0]}; Rbxb=${r[1]}; Rbya=${r[2]}; Rbyb=${r[3]}; Rbza=${r[4]}; Rbzb=${r[5]};`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${a.join(',')}, ${px}, ${py});`);
      } else {
        L.push(bakedLineLits(op.coeffs, px, py));
      }
    } else if (op.t === 'pp') {
      const [px, py] = Pof[op.j];
      if (op.j === 0) {
        const b = N(6).map((i) => `pb${uid}_${i}`), rb = N(6).map((i) => `pbr${uid}_${i}`);
        const cc = N(6).map((i) => `pc${uid}_${i}`), rc = N(6).map((i) => `pcr${uid}_${i}`); const q = uid; uid++;
        L.push(`        (int q1${q}xa,int q1${q}xb,int q1${q}ya,int q1${q}yb) = psi(Bxa,Bxb,Bya,Byb);`);
        L.push(`        (${b.map((n) => 'int ' + n).join(',')}, ${rb.map((n) => 'int ' + n).join(',')}) = pointAdd(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb, q1${q}xa,q1${q}xb,q1${q}ya,q1${q}yb);`);
        L.push(`        Rbxa=${rb[0]}; Rbxb=${rb[1]}; Rbya=${rb[2]}; Rbyb=${rb[3]}; Rbza=${rb[4]}; Rbzb=${rb[5]};`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${b.join(',')}, ${px}, ${py});`);
        L.push(`        (int q2${q}xa,int q2${q}xb,int q2${q}ya,int q2${q}yb) = psi(q1${q}xa,q1${q}xb,q1${q}ya,q1${q}yb);`);
        L.push(`        (int q2${q}nya,int q2${q}nyb) = fp2Neg(q2${q}ya, q2${q}yb, 64);`);
        L.push(`        (${cc.map((n) => 'int ' + n).join(',')}, ${rc.map((n) => 'int ' + n).join(',')}) = pointAdd(Rbxa,Rbxb,Rbya,Rbyb,Rbza,Rbzb, q2${q}xa,q2${q}xb,q2${q}nya,q2${q}nyb);`);
        L.push(`        Rbxa=${rc[0]}; Rbxb=${rc[1]}; Rbya=${rc[2]}; Rbyb=${rc[3]}; Rbza=${rc[4]}; Rbzb=${rc[5]}; // consume final R`);
        L.push(`        (${use12('F')}) = line(${use12('F')}, ${cc.join(',')}, ${px}, ${py});`);
      } else {
        L.push(bakedLineLits(op.coeffs[0], px, py));
        L.push(bakedLineLits(op.coeffs[1], px, py));
      }
    }
  }
  // multiply in the baked e(alpha,beta); F is now fF = fRaw * c^-(6x+2)
  L.push(`        (${use12('F')}) = fp12Mul(${use12('F')}, ${lits(FAB)});`);
  L.push(`        require(residueVerdict(${use12('F')}, ${use12('c')}, ${use12('ci')}, ${use12('w')}));`);
  return L;
}
// ---- QUOTIENT-TORUS construction (ports the chunked MILLER_TORUS track into ONE contract) ----
// The Miller accumulator lives in Q = Fp12*/Fp6*: the residue root is carried as the SIX-limb
// canonical witness u with [c]=[1+uW] and [cInv]=[1-uW] (W^2=v), so the 36-limb c/cInv/w
// witness disappears and every c-fold is a 2-Fp6-product fp12MulTorus. Runtime B walks in
// AFFINE coordinates with prover-witnessed slopes (tangent/chord equations verified mod p;
// O is unrepresentable and the zero-denominator cases are rejected inside the kernels), all
// lines are normalized UNIT lines folded with the sparse direct kernel, and the Miller-endpoint
// endomorphism relation R+psi(B)-psi^2(B) == -psi^3(B) doubles as the EXACT G2 subgroup check
// (prove_miller_endpoint_subgroup.mjs) — the standalone fast-endo 63-bit walk disappears.
// Terminal verdict: [F*c^(p^2)] == [c^p*c^(p^3)] by projective cross-multiplication with an
// explicit [0:0] rejection on canonical limbs. Every accepting boundary has a finite six-limb
// lambda-root witness thanks to the fixed r-torsion kernel shift (_residuemath.mjs).
// Mirrors chunked/pairing/gen_miller_residue.mjs (MILLER_TORUS=1) unrolled with baked literals.
const KX = '21888242871839275220042445260109153167277707414472061641714758635765020556616'; // psi^2 x-coeff
function buildTorusTrace() {
  const lp = C.pairsFor(C.vec.publicInputs.map(BigInt));
  const fRawPlan = R.millerFusedAffineOps(lp, C.Fp12.ONE, C.Fp12.ONE, { unitLines: true }).boundary;
  const rootPlan = R.residueTorusWitness(fRawPlan);
  const trace = R.millerFusedAffineOps(lp, rootPlan.c, rootPlan.cInv, { unitLines: true, torusU: rootPlan.u });
  const fABq = C.Fp6.mul(trace.fAB.c1, C.Fp6.inv(trace.fAB.c0)); // baked e(alpha,beta) torus coordinate
  const FABT = [fABq.c0.c0, fABq.c0.c1, fABq.c1.c0, fABq.c1.c1, fABq.c2.c0, fABq.c2.c1].map(String);
  return { trace, FABT };
}
function emitTorusMillerLazy(trace, FABT) {
  const F = use12('F');
  const uL = list(N(6).map((i) => `u${i}`));
  const nuL = list(N(6).map((i) => `nu${i}`));
  const Puv = { 0: ['Pu0', 'Pv0'], 2: ['Pu2', 'Pv2'], 3: ['Pu3', 'Pv3'] };
  const L = [];
  const slopeParams = [];
  let sIdx = 0, uid = 0;
  const slope = () => { const n = [`s${sIdx}a`, `s${sIdx}b`]; sIdx++; slopeParams.push(...n); return n; };
  const needsNegB = trace.ops.some((op) => op.t === 'al' && op.j === 0 && op.neg);
  L.push('        // ---- torus-fused Miller (unrolled): genesis F = [cInv] = [1 - u*W]; runtime (-A,B)');
  L.push('        // walks affine with witnessed slopes; (vk_x,gamma)/(C,delta) unit lines baked ----');
  L.push('        (int nu0,int nu1,int nu2,int nu3,int nu4,int nu5) = fp6Neg(u0,u1,u2,u3,u4,u5, 64);');
  L.push('        int F0=1; int F1=0; int F2=0; int F3=0; int F4=0; int F5=0;');
  L.push('        int F6=nu0; int F7=nu1; int F8=nu2; int F9=nu3; int F10=nu4; int F11=nu5;');
  L.push('        int Rxa=Bxa; int Rxb=Bxb; int Rya=Bya; int Ryb=Byb;');
  if (needsNegB) L.push('        (int nBya,int nByb) = fp2Neg(Bya, Byb, 64);');
  const unitLine = (triple, pu, pv) =>
    L.push(`        (${F}) = lineUnitDirectInline(${F}, ${triple[0].c0}, ${triple[0].c1}, ${triple[1].c0}, ${triple[1].c1}, ${pu}, ${pv});`);
  for (const op of trace.ops) {
    if (op.t === 'sqr') {
      // Match the proved chunked torus hot path: signed representatives avoid the
      // canonicalization branch on all twelve limbs at every Miller square.
      L.push(`        (${F}) = fp12SqrSigned(${F});`);
    } else if (op.t === 'cf') {
      // fold c^-(6x+2): digit +1 -> x [cInv] = [1-u*W], digit -1 -> x [c] = [1+u*W]
      L.push(`        (${F}) = fp12MulTorus(${F}, ${op.neg ? uL : nuL});`);
    } else if (op.t === 'cmul1') {
      L.push(`        (${F}) = fp12MulTorus(${F}, ${list(FABT)}); // baked e(alpha,beta)`);
    } else if (op.j !== 0) {
      const [pu, pv] = Puv[op.j];
      for (const t of (op.t === 'pp' ? op.coeffs : [op.coeffs])) unitLine(t, pu, pv);
    } else if (op.t === 'dl') {
      const [sa, sb] = slope();
      const c = N(4).map((k) => `d${uid}_${k}`), r = N(4).map((k) => `dr${uid}_${k}`); uid++;
      L.push(`        (${c.map((n) => 'int ' + n).join(',')}, ${r.map((n) => 'int ' + n).join(',')}) = pointDoubleAffine(Rxa,Rxb,Rya,Ryb, ${sa}, ${sb});`);
      L.push(`        Rxa=${r[0]}; Rxb=${r[1]}; Rya=${r[2]}; Ryb=${r[3]};`);
      L.push(`        (${F}) = lineUnitDirectInline(${F}, ${c.join(',')}, Pu0, Pv0);`);
    } else if (op.t === 'al') {
      const [sa, sb] = slope();
      const c = N(4).map((k) => `a${uid}_${k}`), r = N(4).map((k) => `ar${uid}_${k}`); uid++;
      const Y = op.neg ? 'nBya, nByb' : 'Bya, Byb';
      L.push(`        (${c.map((n) => 'int ' + n).join(',')}, ${r.map((n) => 'int ' + n).join(',')}) = pointAddAffine(Rxa,Rxb,Rya,Ryb, Bxa, Bxb, ${Y}, ${sa}, ${sb});`);
      L.push(`        Rxa=${r[0]}; Rxb=${r[1]}; Rya=${r[2]}; Ryb=${r[3]};`);
      L.push(`        (${F}) = lineUnitDirectInline(${F}, ${c.join(',')}, Pu0, Pv0);`);
    } else { // pp j=0: the runtime Miller endpoint; fuses the EXACT G2 subgroup check
      const [s1a, s1b] = slope(); const [s2a, s2b] = slope();
      L.push('        (int q1xa,int q1xb,int q1ya,int q1yb) = psi(Bxa, Bxb, Bya, Byb);');
      L.push(`        (int h1_0,int h1_1,int h1_2,int h1_3, int er0,int er1,int er2,int er3) = pointAddAffine(Rxa,Rxb,Rya,Ryb, q1xa,q1xb,q1ya,q1yb, ${s1a}, ${s1b});`);
      L.push('        Rxa=er0; Rxb=er1; Rya=er2; Ryb=er3;');
      L.push(`        (${F}) = lineUnitDirectInline(${F}, h1_0,h1_1,h1_2,h1_3, Pu0, Pv0);`);
      L.push('        (int q2xa,int q2xb,int q2ya,int q2yb) = psi(q1xa, q1xb, q1ya, q1yb);');
      L.push('        (int q2nya,int q2nyb) = fp2Neg(q2ya, q2yb, 64);');
      L.push(`        (int h2_0,int h2_1,int h2_2,int h2_3, int fr0,int fr1,int fr2,int fr3) = pointAddAffine(Rxa,Rxb,Rya,Ryb, q2xa,q2xb,q2nya,q2nyb, ${s2a}, ${s2b});`);
      L.push('        Rxa=fr0; Rxb=fr1; Rya=fr2; Ryb=fr3;');
      L.push('        // The two checked affine additions compute R+psi(B)-psi^2(B). Requiring the');
      L.push('        // result to equal -psi^3(B) proves EXACT G2 membership for the runtime B');
      L.push('        // chained through the slope-verified walk from genesis R=B.');
      L.push(`        (int q3xa,int q3xb) = fp2Scale(q1xa, q1xb, ${KX});`);
      L.push('        require((Rxa - q3xa) % fieldP == 0); require((Rxb - q3xb) % fieldP == 0);');
      L.push('        require((Rya - q1ya) % fieldP == 0); require((Ryb - q1yb) % fieldP == 0);');
      L.push(`        (${F}) = lineUnitDirectInline(${F}, h2_0,h2_1,h2_2,h2_3, Pu0, Pv0);`);
    }
  }
  // terminal verdict: [F * c^(p^2)] == [c^p * c^(p^3)] via projective cross-multiplication
  L.push('        // ---- terminal verdict: [F*c^(p^2)] == [c^p*c^(p^3)] (residue method, quotient torus) ----');
  L.push('        (int t10,int t11,int t12,int t13,int t14,int t15) = torusFrob1(u0,u1,u2,u3,u4,u5);');
  L.push('        (int t20,int t21,int t22,int t23,int t24,int t25) = torusFrob2(u0,u1,u2,u3,u4,u5);');
  L.push('        (int t30,int t31,int t32,int t33,int t34,int t35) = torusFrob2(t10,t11,t12,t13,t14,t15);');
  L.push(`        (${F}) = fp12MulTorus(${F}, t20,t21,t22,t23,t24,t25);`);
  L.push('        // These limbs are canonical and nonnegative, so their integer sum is zero');
  L.push('        // exactly for the vacuous projective representative [0:0].');
  L.push(`        require(${N(12).map((i) => `F${i}`).join(' + ')} != 0);`);
  L.push('        (int q0,int q1,int q2,int q3,int q4,int q5) = fp6MulRaw(t10,t11,t12,t13,t14,t15, t30,t31,t32,t33,t34,t35);');
  L.push('        (int cl0,int cl1,int cl2,int cl3,int cl4,int cl5) = fp6MulRaw(F0,F1,F2,F3,F4,F5, t10+t30,t11+t31,t12+t32,t13+t33,t14+t34,t15+t35);');
  L.push('        (int cr0,int cr1,int cr2,int cr3,int cr4,int cr5) = fp6MulRaw(F6,F7,F8,F9,F10,F11, 1+9*q4-q5, q4+9*q5, q0, q1, q2, q3);');
  L.push('        ' + N(6).map((i) => `require(mulFp(cl${i} - cr${i}, 1) == 0);`).join(' '));
  return { lines: L, slopeParams };
}
function emitUnitCoordsLazy() {
  return [
    '        // ---- unit-line coordinates (u,v) = (-P.x/P.y, -1/P.y) from gated witness inverses:',
    '        // P0 = -A (so u=Ax/Ay, v=1/Ay), P2 = vk_x (runtime, from GLV), P3 = C ----',
    '        require(within(iAy, 0, fieldP)); require(mulFp(Ay, iAy) == 1);',
    '        int Pu0 = mulFp(Ax, iAy); int Pv0 = iAy;',
    '        require(within(iVy, 0, fieldP)); require(mulFp(vkxY, iVy) == 1);',
    '        int Pu2 = canonicalFp(0 - mulFp(vkxX, iVy)); int Pv2 = canonicalFp(0 - iVy);',
    '        require(within(iCy, 0, fieldP)); require(mulFp(Cy, iCy) == 1);',
    '        int Pu3 = canonicalFp(0 - mulFp(Cx, iCy)); int Pv3 = canonicalFp(0 - iCy);',
  ];
}
function emitMinOpTorus() {
  const { trace, FABT } = buildTorusTrace();
  const { lines: millerLines, slopeParams } = emitTorusMillerLazy(trace, FABT);
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push('');
  L.push('// GENERATED by gen_singletons.mjs — op-optimized BN254 Groth16 singleton (quotient torus).');
  L.push('// ONE torus-fused Miller (UNROLLED): accumulator in Fp12*/Fp6* with the 6-limb residue root');
  L.push('// witness u ([c]=[1+u*W]); runtime (-A,B) in AFFINE coords with witnessed slopes and unit');
  L.push('// lines; e(alpha,beta) + (vk_x,gamma)/(C,delta) lines baked; the Miller-endpoint endomorphism');
  L.push('// relation IS the exact G2 subgroup check; terminal projective cross-multiplied verdict');
  L.push('// replaces the final exponentiation; GLV vk_x. Mirrors the chunked quotient-torus verifier.');
  L.push('// Large by design — bytes are not this variant\'s axis; needs the cashc fork large-contract');
  L.push('// compile fix (COMPILER_FIX_NOTE.md Fix 2). Regenerate: node gen_singletons.mjs.');
  L.push('import "./lib/lazy/Bn254LazyG.cash";');
  L.push('');
  L.push('contract Groth16VerifyMinOp() {');
  const sig = ['int Ax', 'int Ay', 'int Bxa', 'int Bxb', 'int Bya', 'int Byb', 'int Cx', 'int Cy', 'int in0', 'int in1',
    ...N(6).map((i) => `int u${i}`), 'int iAy', 'int iVy', 'int iCy',
    ...slopeParams.map((n) => `int ${n}`),
    'int k10', 'int k20', 'int k11', 'int k21', 'int nb', 'bytes glvSlopes'].join(', ');
  L.push(`    function spend(${sig}) {`);
  for (const ln of emitInputValidationLazy()) L.push(ln);
  L.push('        // residue-root witness: canonical limbs only (rejects u+p aliases)');
  L.push('        ' + N(6).map((i) => `require(within(u${i}, 0, fieldP));`).join(' '));
  for (const ln of emitGlvVkxLazy({ nbLoop: true })) L.push(ln);
  for (const ln of emitUnitCoordsLazy()) L.push(ln);
  for (const ln of millerLines) L.push(ln);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
function emitMinOp({ fastG2, glv }) {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push('');
  L.push('// GENERATED by gen_singletons.mjs — op-optimized BN254 Groth16 singleton (lazy tower).');
  L.push('// ONE batched c^-(6x+2)-fused Miller (UNROLLED): only (-A,B) runs on-chain G2 arithmetic;');
  L.push('// e(alpha,beta)=baked fAB, (vk_x,gamma)/(C,delta) lines baked; witnessed-residue final-exp;');
  L.push(`// ${fastG2 ? 'fast-endo 63-bit' : '128-bit'} G2 check; ${glv ? 'GLV' : 'plain'} vk_x. ~78% less op-cost than the baseline.`);
  L.push('// Large (~67KB) by design — bytes are not this variant\'s axis; needs the cashc fork large-contract');
  L.push('// compile fix (COMPILER_FIX_NOTE.md Fix 2). Regenerate: node gen_singletons.mjs.');
  L.push('import "./lib/lazy/Bn254LazyG.cash";');
  L.push('');
  L.push('contract Groth16VerifyMinOp() {');
  const extra = [];
  if (fastG2) extra.push('int zinvA', 'int zinvB');
  if (glv) extra.push('int k10', 'int k20', 'int k11', 'int k21', 'int vkxZinv');
  const sig = ['int Ax', 'int Ay', 'int Bxa', 'int Bxb', 'int Bya', 'int Byb', 'int Cx', 'int Cy', 'int in0', 'int in1',
    decl12('c'), decl12('ci'), decl12('w'), ...extra].join(', ');
  L.push(`    function spend(${sig}) {`);
  for (const ln of emitInputValidationLazy()) L.push(ln);
  for (const ln of (fastG2 ? emitFastG2CheckLazy() : emitSimpleG2CheckLazy())) L.push(ln);
  for (const ln of (glv ? emitGlvVkxLazy() : emitPlainVkxLazy())) L.push(ln);
  for (const ln of emitMillerTailLazy()) L.push(ln);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- write ----
const MODE = process.env.MODE ?? 'full';
if (MODE === 'staged') {
  writeFileSync(join(here, 'groth16_minop_lazy.cash'), emitMinOp({ fastG2: false, glv: false }));
  writeFileSync(join(here, 'groth16_minop_fastg2.cash'), emitMinOp({ fastG2: true, glv: false }));
}
writeFileSync(join(here, 'groth16_minop.cash'), emitMinOpTorus());
console.log('wrote groth16_minop.cash (MODE=' + MODE + ')');
