// Generator for the G2 input-validation PROLOGUE (EIP-197 rigor), multi-tx.
// Validates the prover's points before the pairing: G1 on-curve (A,C), G2 on-curve
// (B), and the G2 subgroup test [6x^2]B == psi(B) (a 128-bit G2 scalar-multiply,
// double-and-add). GENERIC covenant: the running accumulator R + the points A,B,C
// live in the token NFT commitment (no baked instance), so one fixed set of lockings
// validates ANY proof. Reuses the VERIFIED g2Double/g2AddAffine/psi from groth16.cash.
//   node gen_g2check.mjs        plan + emit generated/g2check_NN.cash + manifest_g2check.json
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { measureCovenantFile, planChunk, covIn, covOut, decl, proof } from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const PROBE = join(GEN, `_probe_g2check_${process.pid}.cash`); // planner compiles candidates from file so the lib import resolves
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_900_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const SIX_X2 = 147946756881789318990833708069417712966n; // 6 * BN_X^2 (EIP-197 G2 order test)
const NBITS = 128; // SIX_X2 < 2^127; the leading zero bit is a harmless double
const bit = (k) => (SIX_X2 >> BigInt(NBITS - 1 - k)) & 1n; // MSB-first, k in [0,NBITS)

// ---- JS reference for the SAME (reducing) Fp2 / G2 Jacobian formulas as the contract
const aF = (x, y) => [(x[0] + y[0]) % P, (x[1] + y[1]) % P];
const sF = (x, y) => [((x[0] - y[0]) % P + P) % P, ((x[1] - y[1]) % P + P) % P];
const mF = (x, y) => { const v0 = (x[0] * y[0]) % P, v1 = (x[1] * y[1]) % P; const c0 = ((v0 - v1) % P + P) % P; const c1 = ((((x[0] + x[1]) * (y[0] + y[1])) % P - v0 - v1) % P + P) % P; return [c0, c1]; };
const sqF = (x) => mF(x, x);
const scF = (x, k) => [(x[0] * k) % P, (x[1] * k) % P];
const eqF = (x, y) => x[0] === y[0] && x[1] === y[1];
const ZERO = [0n, 0n], ONE2 = [1n, 0n];
function g2DoubleJS(X, Y, Z) {
  const A = sqF(X), B = sqF(Y), C = sqF(B);
  const D = scF(sF(sF(sqF(aF(X, B)), A), C), 2n);
  const E = scF(A, 3n), F = sqF(E);
  const nX = sF(F, scF(D, 2n));
  const nY = sF(mF(E, sF(D, nX)), scF(C, 8n));
  const nZ = scF(mF(Y, Z), 2n);
  return [nX, nY, nZ];
}
function g2AddAffineJS(X, Y, Z, bX, bY) {
  if (eqF(Z, ZERO)) return [bX, bY, ONE2];
  const z11 = sqF(Z), u2 = mF(bX, z11), s2 = mF(mF(bY, Z), z11);
  if (eqF(X, u2) && eqF(Y, s2)) return g2DoubleJS(X, Y, Z);
  const h = sF(u2, X), i2 = sqF(scF(h, 2n)), j = mF(h, i2);
  const rr = scF(sF(s2, Y), 2n), v = mF(X, i2);
  const nX = sF(sF(sqF(rr), j), scF(v, 2n));
  const nY = sF(mF(rr, sF(v, nX)), scF(mF(Y, j), 2n));
  const nZ = mF(sF(sF(sqF(aF(Z, ONE2)), z11), ONE2), h);
  return [nX, nY, nZ];
}
// accumulator (X,Y,Z) after processing bits [0,upto) of SIX_X2 (double-and-add from MSB)
export function g2checkAccAt(B, upto) {
  let X = ZERO, Y = ONE2, Z = ZERO;
  for (let k = 0; k < upto; k++) { [X, Y, Z] = g2DoubleJS(X, Y, Z); if (bit(k)) [X, Y, Z] = g2AddAffineJS(X, Y, Z, B[0], B[1]); }
  return [X, Y, Z];
}
const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];

// ---- the committed instance's points — the reference run for chunk planning
const Baff = proof.b.toAffine(), Aaff = proof.a.toAffine(), Caff = proof.c.toAffine();
const B = [[Baff.x.c0, Baff.x.c1], [Baff.y.c0, Baff.y.c1]];
const Blimbs = [B[0][0], B[0][1], B[1][0], B[1][1]];
const AClimbs = [Aaff.x, Aaff.y, Caff.x, Caff.y];
const stateLimbs = (R) => [...rLimbs(R), ...Blimbs, ...AClimbs]; // R(6)+B(4)+A(2)+C(2)=14
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n]; // twist b2

// ---- contract emitter (reuses verified groth16 tower via the shared singleton library) ----
// Miller.cash transitively pulls in the whole non-lazy field tower (Fp12->...->Fp2->Fp) plus
// psi/g2Double/g2AddAffine; cashc tree-shakes the unused functions. Tracks the singleton's library
// migration, which moved these out of groth16.cash (so fnExtractor-inlining no longer resolves).
const LIB_IMPORT = '../../../singleton/bn254/lib/Miller.cash';
const RN = ['RXa', 'RXb', 'RYa', 'RYb', 'RZa', 'RZb'], BN = ['Bxa', 'Bxb', 'Bya', 'Byb'], ACN = ['Ax', 'Ay', 'Cx', 'Cy'];
const ALL = [...RN, ...BN, ...ACN];

function genChunk(lo, hi, isFirst, isLast) {
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// G2 input-validation chunk: [6x^2]B double-and-add bits [${lo},${hi}); first=${isFirst} last=${isLast}.`);
  L.push('contract G2Check() {');
  L.push(`    function spend(${decl(ALL)}, bytes unused zeroPadding) {`);
  L.push(covIn(ALL)); // incoming (R,B,A,C) == spent token commitment
  if (isFirst) {
    L.push('        require(mulFp(Ay, Ay) == addFp(mulFp(mulFp(Ax, Ax), Ax), 3));'); // A on G1
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));'); // C on G1
    L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);'); // B on G2: y^2 == x^3 + b2
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  let r = RN.slice(), uid = 0;
  const fresh = () => Array.from({ length: 6 }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    const d = fresh();
    L.push(`        (${decl(d)}) = g2Double(${r.join(',')});`); r = d;
    if (bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AddAffine(${r.join(',')}, ${BN.join(',')});`); r = a; }
  }
  if (isLast) {
    // require [6x^2]B == psi(B): cross-multiply R (Jacobian) vs psi(B) (affine)
    L.push(`        (int psxa,int psxb,int psya,int psyb) = psi(${BN.join(',')});`);
    L.push(`        (int z2a,int z2b) = fp2Sqr(${r[4]}, ${r[5]});`);
    L.push(`        (int z3a,int z3b) = fp2Mul(z2a, z2b, ${r[4]}, ${r[5]});`);
    L.push('        (int cxa,int cxb) = fp2Mul(psxa, psxb, z2a, z2b);');
    L.push('        (int cya,int cyb) = fp2Mul(psya, psyb, z3a, z3b);');
    L.push(`        require(${r[0]} == cxa); require(${r[1]} == cxb); require(${r[2]} == cya); require(${r[3]} == cyb);`);
  } else {
    L.push(covOut([...r, ...BN, ...ACN])); // carry (R', B, A, C) forward
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- plan windows by measured op-cost (only when run as the main script) ----
if (process.argv[1] && process.argv[1].endsWith('gen_g2check.mjs')) {
console.error(`planning G2-check chunks (128-bit [6x^2]B)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < NBITS) {
  const inLimbs = stateLimbs(g2checkAccAt(B, lo));
  const tryHi = (hi) => {
    const last = hi === NBITS;
    const outLimbs = last ? [] : stateLimbs(g2checkAccAt(B, hi));
    const src = genChunk(lo, hi, lo === 0, last);
    const m = measureCovenantFile(src, inLimbs, outLimbs, PROBE);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, last, src, m };
  };
  const best = planChunk(lo, NBITS, OP_TARGET, tryHi, planState);
  const idx = chunks.length;
  writeFileSync(join(GEN, `g2check_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, lo, hi: best.hi, first: lo === 0, last: best.last, lockingBytes: best.m.lockingBytes, operationCost: best.m.operationCost });
  console.error(`  g2check chunk ${idx}: bits[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} last=${best.last}`);
  lo = best.hi;
}
writeFileSync(join(GEN, 'manifest_g2check.json'), JSON.stringify({ numChunks: chunks.length, nbits: NBITS, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, last: c.last })) }, null, 2));
console.error(`G2-check: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}
