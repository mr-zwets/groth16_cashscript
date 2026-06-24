// Assemble verify.cash and groth16.cash from the already-verified component files
// (finalexp.cash, miller4.cash, vkx.cash) by extracting function bodies in
// dependency order. This reuses byte-for-byte-graded code instead of re-typing it.
// Run: node singleton/bls12-381/assemble.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

// extract a top-level `    internal function NAME(...) {...}` block (brace-matched)
function extractor(path) {
  const src = readFileSync(path, 'utf8').split('\n');
  return (name) => {
    const out = []; let p = false, depth = 0;
    for (const ln of src) {
      if (!p && ln.startsWith(`    internal function ${name}(`)) p = true;
      if (p) {
        out.push(ln);
        depth += (ln.match(/\{/g) || []).length - (ln.match(/\}/g) || []).length;
        if (depth === 0 && ln.includes('}')) break;
      }
    }
    if (!out.length) throw new Error(`function ${name} not found in ${path}`);
    return out.join('\n');
  };
}

const fe = extractor(join(here, 'finalexp.cash'));
const mi = extractor(join(here, 'miller4.cash'));

// all finalexp functions, in file (dependency) order
const FE_FNS = [
  'addFp', 'subFp', 'mulFp', 'inverseFp',
  'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2MulXi', 'fp2Conj', 'fp2Inv',
  'fp6Add', 'fp6Sub', 'fp6Neg', 'fp6MulByV', 'fp6Mul', 'fp6Inv', 'fp6FrobOdd', 'fp6FrobEven', 'fp6MulByFp2',
  'fp12Mul', 'fp12Conj', 'fp12Inv', 'fp12Frob1', 'fp12Frob2', 'fp12Frob3',
  'fp4Square', 'cycSqr', 'cycExpX', 'powMinusX', 'finalExp',
];
// miller-only functions (not already defined above), in dependency order
const MI_FNS = [
  'fp2Scale', 'fp2MulByB', 'fp2Half', 'fp6Mul01', 'fp6Mul1', 'fp12Sqr',
  'mul014', 'line', 'pointDouble', 'pointAdd', 'millerSingle',
];

const towerBlock = FE_FNS.map(fe).join('\n\n');
const millerBlock = MI_FNS.map(mi).join('\n\n');

// ---- verify.cash: 4-pair pairing verdict (trusts vkx as the pair-3 G1 input) ----
const verifySpend = `    // pairing verdict: e(-A,B)*e(alpha,beta)*e(vkx,gamma)*e(C,delta) == 1.
    // Four single Miller loops -> product -> conjugate (xNegative) -> finalExp -> require ONE.
    function spend(
        int Q1xa,int Q1xb,int Q1ya,int Q1yb,int P1x,int P1y,
        int Q2xa,int Q2xb,int Q2ya,int Q2yb,int P2x,int P2y,
        int Q3xa,int Q3xb,int Q3ya,int Q3yb,int P3x,int P3y,
        int Q4xa,int Q4xb,int Q4ya,int Q4yb,int P4x,int P4y
    ) {
        (int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) =
            millerSingle(Q1xa,Q1xb,Q1ya,Q1yb,P1x,P1y);
        (int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11) =
            millerSingle(Q2xa,Q2xb,Q2ya,Q2yb,P2x,P2y);
        (int c0,int c1,int c2,int c3,int c4,int c5,int c6,int c7,int c8,int c9,int c10,int c11) =
            millerSingle(Q3xa,Q3xb,Q3ya,Q3yb,P3x,P3y);
        (int d0,int d1,int d2,int d3,int d4,int d5,int d6,int d7,int d8,int d9,int d10,int d11) =
            millerSingle(Q4xa,Q4xb,Q4ya,Q4yb,P4x,P4y);
        (int ab0,int ab1,int ab2,int ab3,int ab4,int ab5,int ab6,int ab7,int ab8,int ab9,int ab10,int ab11) =
            fp12Mul(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11, b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11);
        (int abc0,int abc1,int abc2,int abc3,int abc4,int abc5,int abc6,int abc7,int abc8,int abc9,int abc10,int abc11) =
            fp12Mul(ab0,ab1,ab2,ab3,ab4,ab5,ab6,ab7,ab8,ab9,ab10,ab11, c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11);
        (int pr0,int pr1,int pr2,int pr3,int pr4,int pr5,int pr6,int pr7,int pr8,int pr9,int pr10,int pr11) =
            fp12Mul(abc0,abc1,abc2,abc3,abc4,abc5,abc6,abc7,abc8,abc9,abc10,abc11, d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,d11);
        (int bd0,int bd1,int bd2,int bd3,int bd4,int bd5,int bd6,int bd7,int bd8,int bd9,int bd10,int bd11) =
            fp12Conj(pr0,pr1,pr2,pr3,pr4,pr5,pr6,pr7,pr8,pr9,pr10,pr11);
        (int o0,int o1,int o2,int o3,int o4,int o5,int o6,int o7,int o8,int o9,int o10,int o11) =
            finalExp(bd0,bd1,bd2,bd3,bd4,bd5,bd6,bd7,bd8,bd9,bd10,bd11);
        require(o0==1); require(o1==0); require(o2==0); require(o3==0); require(o4==0); require(o5==0);
        require(o6==0); require(o7==0); require(o8==0); require(o9==0); require(o10==0); require(o11==0);
    }`;

const header = (name, doc) => `pragma cashscript ^0.13.0;

${doc}
contract ${name}() {

`;

const verifyDoc = `// BLS12-381 full Groth16 pairing verdict in ONE contract (singleton oracle):
// e(-A,B)*e(alpha,beta)*e(vkx,gamma)*e(C,delta) == 1. Four optimal-ate Miller loops
// (M-twist, |x| NAF), product, conjugate (xNegative), and the BLS final
// exponentiation, then require() the result is Fp12 ONE. RUNTIME pair inputs (the
// caller supplies vkx as the pair-3 G1 point). ASSEMBLED from the graded
// finalexp.cash + miller4.cash by assemble.mjs. Graded by verify.mjs.`;

writeFileSync(join(here, 'verify.cash'),
  header('GrothVerify', verifyDoc) + towerBlock + '\n\n' + millerBlock + '\n\n' + verifySpend + '\n}\n');
console.log('wrote verify.cash');

// ============================ vkx.cash + groth16.cash ============================
const PB = '4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787';
const baked = JSON.parse(readFileSync(join(here, '_baked.json'), 'utf8'));

// G1 Jacobian double-and-add term (scalar * base accumulated into acc). Uses only
// the reducing fp functions (addFp/subFp/mulFp/sqrFp) -> prime-independent text;
// loop is 255 (ceil(log2 r)) for BLS12-381. Identical algebra to ../bn254/vkx.cash.
const loopAcc = (scalar) => `        for (int i = 0; i < 255; i = i + 1) {
            if (((${scalar} >> i) % 2) == 1) {
                if (rZ == 0) {
                    rX = bX; rY = bY; rZ = bZ;
                } else {
                    int z1z1 = sqrFp(rZ);
                    int z2z2 = sqrFp(bZ);
                    int u1 = mulFp(rX, z2z2);
                    int u2 = mulFp(bX, z1z1);
                    int s1 = mulFp(mulFp(rY, bZ), z2z2);
                    int s2 = mulFp(mulFp(bY, rZ), z1z1);
                    if (u1 == u2 && s1 == s2) {
                        int a = sqrFp(rX);
                        int b = sqrFp(rY);
                        int c = sqrFp(b);
                        int dd = mulFp(2, subFp(subFp(sqrFp(addFp(rX, b)), a), c));
                        int ee = mulFp(3, a);
                        int ff = sqrFp(ee);
                        int nx = subFp(ff, mulFp(2, dd));
                        int ny = subFp(mulFp(ee, subFp(dd, nx)), mulFp(8, c));
                        int nz = mulFp(2, mulFp(rY, rZ));
                        rX = nx; rY = ny; rZ = nz;
                    } else {
                        int h = subFp(u2, u1);
                        int i2 = sqrFp(mulFp(2, h));
                        int j = mulFp(h, i2);
                        int rr = mulFp(2, subFp(s2, s1));
                        int v = mulFp(u1, i2);
                        int nx = subFp(subFp(sqrFp(rr), j), mulFp(2, v));
                        int ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2, mulFp(s1, j)));
                        int nz = mulFp(subFp(subFp(sqrFp(addFp(rZ, bZ)), z1z1), z2z2), h);
                        rX = nx; rY = ny; rZ = nz;
                    }
                }
            }
            if (bZ != 0 && bY != 0) {
                int a = sqrFp(bX);
                int b = sqrFp(bY);
                int c = sqrFp(b);
                int dd = mulFp(2, subFp(subFp(sqrFp(addFp(bX, b)), a), c));
                int ee = mulFp(3, a);
                int ff = sqrFp(ee);
                int nx = subFp(ff, mulFp(2, dd));
                int ny = subFp(mulFp(ee, subFp(dd, nx)), mulFp(8, c));
                int nz = mulFp(2, mulFp(bY, bZ));
                bX = nx; bY = ny; bZ = nz;
            }
        }
        // acc = acc + r
        if (rZ != 0) {
            int z1z1 = sqrFp(accZ);
            int z2z2 = sqrFp(rZ);
            int u1 = mulFp(accX, z2z2);
            int u2 = mulFp(rX, z1z1);
            int s1 = mulFp(mulFp(accY, rZ), z2z2);
            int s2 = mulFp(mulFp(rY, accZ), z1z1);
            if (u1 == u2 && s1 == s2) {
                int a = sqrFp(accX);
                int b = sqrFp(accY);
                int c = sqrFp(b);
                int dd = mulFp(2, subFp(subFp(sqrFp(addFp(accX, b)), a), c));
                int ee = mulFp(3, a);
                int ff = sqrFp(ee);
                int nx = subFp(ff, mulFp(2, dd));
                int ny = subFp(mulFp(ee, subFp(dd, nx)), mulFp(8, c));
                int nz = mulFp(2, mulFp(accY, accZ));
                accX = nx; accY = ny; accZ = nz;
            } else {
                int h = subFp(u2, u1);
                int i2 = sqrFp(mulFp(2, h));
                int j = mulFp(h, i2);
                int rr = mulFp(2, subFp(s2, s1));
                int v = mulFp(u1, i2);
                int nx = subFp(subFp(sqrFp(rr), j), mulFp(2, v));
                int ny = subFp(mulFp(rr, subFp(v, nx)), mulFp(2, mulFp(s1, j)));
                int nz = mulFp(subFp(subFp(sqrFp(addFp(accZ, rZ)), z1z1), z2z2), h);
                accX = nx; accY = ny; accZ = nz;
            }
        }`;

// the full on-chain vk_x computation -> (affX, affY), given baked IC consts.
const vkxCompute = (in0, in1) => `        int ic0X = ${baked.ic0[0]};
        int ic0Y = ${baked.ic0[1]};
        int ic1X = ${baked.ic1[0]};
        int ic1Y = ${baked.ic1[1]};
        int ic2X = ${baked.ic2[0]};
        int ic2Y = ${baked.ic2[1]};
        int accX = ic0X; int accY = ic0Y; int accZ = 1;
        int rX = 0; int rY = 1; int rZ = 0;
        int bX = ic1X; int bY = ic1Y; int bZ = 1;
${loopAcc(in0)}
        rX = 0; rY = 1; rZ = 0;
        bX = ic2X; bY = ic2Y; bZ = 1;
${loopAcc(in1)}
        int zInv = inverseFp(accZ);
        int zInv2 = sqrFp(zInv);
        int zInv3 = mulFp(zInv2, zInv);
        int affX = mulFp(accX, zInv2);
        int affY = mulFp(accY, zInv3);`;

// reducing fp helpers needed by the G1 block (negFp/sqrFp not in the pairing block)
const FP_EXTRA = `    internal function negFp(int x) returns (int) { return (${PB} - x) % ${PB}; }
    internal function sqrFp(int x) returns (int) { return (x * x) % ${PB}; }`;

// ---- vkx.cash: standalone vk_x checkpoint (bakes IC + expected affine point) ----
const vkxFns = ['addFp', 'subFp', 'mulFp', 'inverseFp'].map(fe).join('\n\n');
const vkxDoc = `// VkX (BLS12-381): Groth16 public-input aggregation checkpoint:
//   vk_x = IC0 + input0*IC1 + input1*IC2   (all G1 points on BLS12-381, b=4)
// G1 Jacobian double-and-add with a SINGLE Fermat inverse to affine at the end;
// the Jacobian formulas are b-independent so only the prime differs from BN254.
// IC baked; input0/input1 + claimed affine (expectedX,expectedY) at RUNTIME.
// Generated by assemble.mjs. Graded by vkx.mjs.`;
const vkxContract = `pragma cashscript ^0.13.0;

${vkxDoc}
contract VkX(int expectedX, int expectedY) {

${vkxFns}

${FP_EXTRA}

    function spend(bytes unused zeroPadding, int input0, int input1) {
${vkxCompute('input0', 'input1')}
        require(affX == expectedX);
        require(affY == expectedY);
    }
}
`;
writeFileSync(join(here, 'vkx.cash'), vkxContract);
console.log('wrote vkx.cash');

// ---- groth16.cash: full verifier (vk_x on-chain + pairing) ----
const groth16Spend = `    // Full Groth16: compute vk_x on-chain, negate A, run the 4-pair pairing, require ONE.
    // Baked VK: alpha (G1), beta/gamma/delta (G2), IC0..IC2 (G1). RUNTIME: proof
    // (Ax,Ay,Bx*,By*,Cx,Cy) + public inputs (in0,in1).
    function spend(
        int Ax, int Ay,
        int Bxa, int Bxb, int Bya, int Byb,
        int Cx, int Cy,
        int in0, int in1
    ) {
${vkxCompute('in0', 'in1')}
        // baked VK G1/G2 points
        int alphaX = ${baked.alpha[0]};
        int alphaY = ${baked.alpha[1]};
        int betaXa = ${baked.beta[0]};  int betaXb = ${baked.beta[1]};
        int betaYa = ${baked.beta[2]};  int betaYb = ${baked.beta[3]};
        int gammaXa = ${baked.gamma[0]}; int gammaXb = ${baked.gamma[1]};
        int gammaYa = ${baked.gamma[2]}; int gammaYb = ${baked.gamma[3]};
        int deltaXa = ${baked.delta[0]}; int deltaXb = ${baked.delta[1]};
        int deltaYa = ${baked.delta[2]}; int deltaYb = ${baked.delta[3]};
        // negate A: -A = (Ax, p - Ay)
        int nAy = negFp(Ay);
        // pair1 = (-A, B), pair2 = (alpha, beta), pair3 = (vkx, gamma), pair4 = (C, delta)
        (int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) =
            millerSingle(Bxa,Bxb,Bya,Byb, Ax, nAy);
        (int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11) =
            millerSingle(betaXa,betaXb,betaYa,betaYb, alphaX, alphaY);
        (int c0,int c1,int c2,int c3,int c4,int c5,int c6,int c7,int c8,int c9,int c10,int c11) =
            millerSingle(gammaXa,gammaXb,gammaYa,gammaYb, affX, affY);
        (int d0,int d1,int d2,int d3,int d4,int d5,int d6,int d7,int d8,int d9,int d10,int d11) =
            millerSingle(deltaXa,deltaXb,deltaYa,deltaYb, Cx, Cy);
        (int ab0,int ab1,int ab2,int ab3,int ab4,int ab5,int ab6,int ab7,int ab8,int ab9,int ab10,int ab11) =
            fp12Mul(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11, b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11);
        (int abc0,int abc1,int abc2,int abc3,int abc4,int abc5,int abc6,int abc7,int abc8,int abc9,int abc10,int abc11) =
            fp12Mul(ab0,ab1,ab2,ab3,ab4,ab5,ab6,ab7,ab8,ab9,ab10,ab11, c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11);
        (int pr0,int pr1,int pr2,int pr3,int pr4,int pr5,int pr6,int pr7,int pr8,int pr9,int pr10,int pr11) =
            fp12Mul(abc0,abc1,abc2,abc3,abc4,abc5,abc6,abc7,abc8,abc9,abc10,abc11, d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,d10,d11);
        (int bd0,int bd1,int bd2,int bd3,int bd4,int bd5,int bd6,int bd7,int bd8,int bd9,int bd10,int bd11) =
            fp12Conj(pr0,pr1,pr2,pr3,pr4,pr5,pr6,pr7,pr8,pr9,pr10,pr11);
        (int o0,int o1,int o2,int o3,int o4,int o5,int o6,int o7,int o8,int o9,int o10,int o11) =
            finalExp(bd0,bd1,bd2,bd3,bd4,bd5,bd6,bd7,bd8,bd9,bd10,bd11);
        require(o0==1); require(o1==0); require(o2==0); require(o3==0); require(o4==0); require(o5==0);
        require(o6==0); require(o7==0); require(o8==0); require(o9==0); require(o10==0); require(o11==0);
    }`;
const groth16Doc = `// BLS12-381 COMPLETE Groth16 verifier in ONE contract (singleton oracle). Runtime
// proof (A,B,C) + public inputs (in0,in1); VK hardcoded. Computes vk_x =
// IC0 + in0*IC1 + in1*IC2 ON-CHAIN (G1 Jacobian double-and-add + Fermat inverse),
// negates A in-script, runs the 4-pair BLS pairing e(-A,B)*e(alpha,beta)*
// e(vkx,gamma)*e(C,delta), and require()s == 1. ASSEMBLED by assemble.mjs from the
// graded finalexp.cash + miller4.cash + the G1 block. Graded by groth16.mjs.`;
writeFileSync(join(here, 'groth16.cash'),
  header('Groth16Verify', groth16Doc) + towerBlock + '\n\n' + FP_EXTRA + '\n\n' + millerBlock + '\n\n' + groth16Spend + '\n}\n');
console.log('wrote groth16.cash');
