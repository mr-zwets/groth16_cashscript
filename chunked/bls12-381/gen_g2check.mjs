// Generator for the BLS12-381 G2 input-validation PROLOGUE (EIP-197 rigor), multi-tx.
// Validates the prover's points before the pairing: G1 on-curve (A,C: y^2=x^3+4), G2
// on-curve (B: y^2=x^3+(4+4u)), and the G2 subgroup test psi(B) == [-x]B — a [x] scalar-
// multiply of B (x = 0xd201000000010000, ~64-bit, double-and-add) compared to the GLV
// endomorphism psi(B). GENERIC covenant: the running accumulator R + the points A,B,C live
// in the token NFT commitment, so one fixed set of lockings validates ANY proof. The G2
// math comes from the shared lib (lib/G2Check.cash + lib/Fp2.cash), so the chunks IMPORT it.
// The first chunk consumes only the exact (-A,B,C,vk_x) stage tuple and derives R=B;
// intermediate chunks carry (R,-A,B,C,vk_x), and the final chunk emits the original
// stage tuple unchanged for the prepared Miller genesis.
//   node gen_g2check.mjs   plan + emit generated/g2check_NN.cash + manifest_g2check.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { covIn, covOut, planChunk, measureCovenantFile, bls12_381, PUBLIC_INPUTS, computeVkx } from './_vkxmath.mjs';
import { proof } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const LIB = '../../../singleton/bls12-381/lib';
const PROBE = join(GEN, '_probe_g2.cash');
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

const BLS_X = 0xd201000000010000n; // |x|; subgroup test is psi(B) == [-x]B
const NBITS = 64; // bitLen(BLS_X); MSB (bit 0) is folded into the R=B initialisation
const bit = (k) => (BLS_X >> BigInt(NBITS - 1 - k)) & 1n; // MSB-first, k in [0,NBITS)

// ---- JS reference: the SAME a=0 G2 Jacobian formulas as lib/G2Check.cash, over noble Fp2
const { Fp, Fp2 } = bls12_381.fields;
const scF = (a, k) => Fp2.create({ c0: Fp.mul(a.c0, BigInt(k)), c1: Fp.mul(a.c1, BigInt(k)) });
function g2DoubleJS(X, Y, Z) {
  const A = Fp2.sqr(X), B = Fp2.sqr(Y), C = Fp2.sqr(B);
  const D = scF(Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(X, B)), A), C), 2);
  const E = scF(A, 3), F = Fp2.sqr(E);
  const nX = Fp2.sub(F, scF(D, 2));
  const nY = Fp2.sub(Fp2.mul(E, Fp2.sub(D, nX)), scF(C, 8));
  const nZ = scF(Fp2.mul(Y, Z), 2);
  return { x: nX, y: nY, z: nZ };
}
function g2AddAffineJS(R, Qx, Qy) {
  const z11 = Fp2.sqr(R.z), u2 = Fp2.mul(Qx, z11), s2 = Fp2.mul(Fp2.mul(Qy, R.z), z11);
  const h = Fp2.sub(u2, R.x), i2 = Fp2.sqr(scF(h, 2)), j = Fp2.mul(h, i2);
  const rr = scF(Fp2.sub(s2, R.y), 2), v = Fp2.mul(R.x, i2);
  const nX = Fp2.sub(Fp2.sub(Fp2.sqr(rr), j), scF(v, 2));
  const nY = Fp2.sub(Fp2.mul(rr, Fp2.sub(v, nX)), scF(Fp2.mul(R.y, j), 2));
  const nZ = scF(Fp2.mul(R.z, h), 2); // Z3 = 2*Z1*H (madd-2007-bl)
  return { x: nX, y: nY, z: nZ };
}
// accumulator R after processing bits [1,upto) of [x]B, started at R=B (MSB skipped). upto in [1,NBITS].
function g2checkAccAt(Bx, By, upto) {
  let R = { x: Bx, y: By, z: Fp2.ONE };
  for (let k = 1; k < upto; k++) { R = g2DoubleJS(R.x, R.y, R.z); if (bit(k)) R = g2AddAffineJS(R, Bx, By); }
  return R;
}

// ---- the committed instance's points — the reference run for chunk planning ----
const Baff = proof.b.toAffine(), Aaff = proof.a.negate().toAffine(), Caff = proof.c.toAffine();
const vkxAff = computeVkx(PUBLIC_INPUTS).toAffine();
const Bx = Baff.x, By = Baff.y;
const f2 = (v) => [v.c0, v.c1];
const rLimbs = (R) => [...f2(R.x), ...f2(R.y), ...f2(R.z)];
const Blimbs = [...f2(Bx), ...f2(By)];
const STAGE_LIMBS = [Aaff.x, Aaff.y, ...Blimbs, Caff.x, Caff.y, vkxAff.x, vkxAff.y];
const stateLimbs = (R) => [...rLimbs(R), ...STAGE_LIMBS]; // R(6)+(-A,B,C,vk_x)(10)=16

// ---- contract emitter (imports the shared BLS lib) ----
const RN = ['RXa', 'RXb', 'RYa', 'RYb', 'RZa', 'RZb'];
const STAGE = ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'vkxX', 'vkxY'];
const BN = STAGE.slice(2, 6);
const decl = (names) => names.map((n) => `int ${n}`).join(',');

function genChunk(lo, hi, isFirst, isLast) {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB}/Fp.cash";`);
  L.push(`import "${LIB}/Fp2.cash";`);
  L.push(`import "${LIB}/G2Check.cash";`);
  L.push(`// BLS12-381 G2 input-validation chunk: [x]B double-and-add bits [${lo},${hi}); first=${isFirst} last=${isLast}.`);
  L.push('contract G2CheckBls() {');
  const inNames = isFirst ? STAGE : [...RN, ...STAGE];
  L.push(`    function spend(${decl(inNames)}, bytes unused zeroPadding) {`);
  L.push(covIn(inNames));
  if (isFirst) {
    for (const name of STAGE) L.push(`        require(within(${name}, 0, ${Fp.ORDER}));`);
    L.push('        require(mulFp(Ay, Ay) == addFp(mulFp(mulFp(Ax, Ax), Ax), 4));'); // A on G1 (b=4)
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 4));'); // C on G1
    L.push('        (int bx2a,int bx2b) = fp2Sqr(Bxa, Bxb);'); // B on G2: y^2 == x^3 + (4+4u)
    L.push('        (int bx3a,int bx3b) = fp2Mul(bx2a, bx2b, Bxa, Bxb);');
    L.push('        (int rhsa,int rhsb) = fp2Add(bx3a, bx3b, 4, 4);');
    L.push('        (int by2a,int by2b) = fp2Sqr(Bya, Byb);');
    L.push('        require(by2a == rhsa); require(by2b == rhsb);');
    L.push('        int RXa = Bxa; int RXb = Bxb;');
    L.push('        int RYa = Bya; int RYb = Byb;');
    L.push('        int RZa = 1; int RZb = 0;');
  }
  let r = RN.slice(), uid = 0;
  const fresh = () => Array.from({ length: 6 }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    const d = fresh();
    L.push(`        (${decl(d)}) = g2Double(${r.join(',')});`); r = d;
    if (bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AddAffine(${r.join(',')}, ${BN.join(',')});`); r = a; }
  }
  if (isLast) {
    // require psi(B) == [-x]B, i.e. [x]B (=R, Jacobian) == -psi(B) (affine): cross-multiply.
    L.push(`        (int psxa,int psxb,int psya,int psyb) = g2psi(${BN.join(',')});`);
    L.push('        (int npya,int npyb) = fp2Neg(psya, psyb);');
    L.push(`        (int z2a,int z2b) = fp2Sqr(${r[4]}, ${r[5]});`);
    L.push(`        (int z3a,int z3b) = fp2Mul(z2a, z2b, ${r[4]}, ${r[5]});`);
    L.push('        (int cxa,int cxb) = fp2Mul(psxa, psxb, z2a, z2b);');
    L.push('        (int cya,int cyb) = fp2Mul(npya, npyb, z3a, z3b);');
    L.push(`        require(${r[0]} == cxa); require(${r[1]} == cxb); require(${r[2]} == cya); require(${r[3]} == cyb);`);
    L.push(covOut(STAGE, STAGE)); // validated tuple becomes the exact Miller genesis state
  } else L.push(covOut([...r, ...STAGE], [...r, ...STAGE]));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- plan windows by measured op-cost (only when run as the main script) ----
if (process.argv[1] && process.argv[1].endsWith('gen_g2check.mjs')) {
console.error(`planning BLS G2-check chunks (${NBITS}-bit [x]B)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 1; const planState = { perUnit: null }; // start at bit 1 (R=B init)
while (lo < NBITS) {
  const first = lo === 1;
  const inLimbs = first ? STAGE_LIMBS : stateLimbs(g2checkAccAt(Bx, By, lo));
  const tryHi = (hi) => {
    const last = hi === NBITS;
    const outLimbs = last ? STAGE_LIMBS : stateLimbs(g2checkAccAt(Bx, By, hi));
    const src = genChunk(lo, hi, first, last);
    const m = measureCovenantFile(src, inLimbs, inLimbs, outLimbs, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, last, src, m };
  };
  const best = planChunk(lo, NBITS, OP_TARGET, tryHi, planState);
  if (!best) throw new Error(`no fitting g2check window at bit ${lo}`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `g2check_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, lo, hi: best.hi, first: lo === 1, last: best.last, lockingBytes: best.m.lockingBytes, operationCost: best.operationCost });
  console.error(`  g2check chunk ${idx}: bits[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.operationCost.toLocaleString()} last=${best.last}`);
  lo = best.hi;
}
writeFileSync(join(GEN, 'manifest_g2check.json'), JSON.stringify({
  numChunks: chunks.length, nbits: NBITS, stageBound: true, genesisDerived: true,
  carriesVkx: true, stageLayout: STAGE,
  chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, last: c.last })),
}, null, 2));
console.error(`BLS G2-check: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}

// exported for build_vectors_pairing (build the per-chunk in/out state for ANY proof's B)
export { g2checkAccAt, NBITS, STAGE };
export const g2Fp2 = Fp2;
