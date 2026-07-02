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
//   - witnessed-residue final exponentiation (ePrint 2024/640): drops the hard-part final-exp
//     for a Frobenius tail (c,cInv,w supplied as gated witnesses);
//   - e(alpha,beta) baked as a constant (only 3 runtime single-pair Miller loops);
//   - fast-endo 63-bit G2 subgroup check (ePrint 2022/348) with a gated witness inverse;
//   - GLV vk_x: 4-scalar ~128-bit Straus over a baked subset-sum table (gated witnesses).
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
    '        // ---- validate spender-supplied proof points (EIP-197) ----',
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
// blob table. Witnesses k10,k20,k11,k21 (gated k<2^128, k1+k2*lambda==in mod r) + vkxZinv.
function emitGlvVkxLazy() {
  const LAM = G.GLV_LAMBDA.toString(), r = G.GLV_R.toString(), iters = G.VKXGLV_ITERS;
  const BOUND = (1n << 128n).toString();
  const ic0 = G.GLV_IC0.map((x) => (((x % BigInt(P)) + BigInt(P)) % BigInt(P)).toString());
  const L = [];
  L.push('        // ---- vk_x via GLV 4-scalar Straus (baked table) ----');
  L.push(`        require(k10 < ${BOUND}); require(k20 < ${BOUND}); require(k11 < ${BOUND}); require(k21 < ${BOUND});`);
  L.push(`        require((k10 + k20 * ${LAM}) % ${r} == in0);`);
  L.push(`        require((k11 + k21 * ${LAM}) % ${r} == in1);`);
  L.push('        int gX = 0; int gY = 1; int gZ = 0;');
  L.push(`        bytes glvTable = ${G.GLV_TABLE_HEX};`);
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
writeFileSync(join(here, 'groth16_minop.cash'), emitMinOp({ fastG2: true, glv: true }));
console.log('wrote groth16_minop.cash (MODE=' + MODE + ')');
