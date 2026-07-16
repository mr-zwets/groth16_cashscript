// Executable certificate for the identity-complete BLS12-381 G1 line coordinates.
//
// Fp6 = Fp2[V]/(V^3-xi), Fp12 = Fp6[W]/(W^2-V), xi=1+i. The raw M-twist line is
//   L = c0 + c1*x*V + c2*y*W*V.
// For u=-x/(2y), v=-1/(2y), the generated sparse factor is
//   S = c2 - (2*c0*v/xi)*W*V - (2*c1*u/xi)*W*V^2
//     = L * (-2v/(W*V)).
// The scale lies in Fp4*, and p^4-1 divides the final exponent. At the canonical identity
// (u,v)=(0,0), S=c2 is in Fp2*; the NAF-prefix checks below prove c2 cannot vanish for any
// nonzero order-r G2 input accepted by the verifier.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bls12_381 } from '@noble/curves/bls12-381.js';

import {
  ATE_NAF,
  B_IDENTITY_SUBSTITUTE,
  Fp,
  Fp2,
  Fp6,
  Fp12,
  PT_CFG,
  f12limbs,
  lineFn,
  lineUnitScaledFn,
  millerBatchOps,
  pairsFor,
  unitG1,
} from './_pairingmath.mjs';
import {
  BLS_X,
  millerFusedOps,
  millerFusedTorusOps,
  residueTorusWitness,
  residueWitness,
} from './_residuemath.mjs';
import { LINKED_RESIDUE_NAMESPACE } from './_residue_linked_plan.mjs';
import { PUBLIC_INPUTS, proof } from '../../singleton/bls12-381/bls_instance.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const r = bls12_381.fields.Fr.ORDER;
const p = Fp.ORDER;
const finalExponent = (p ** 12n - 1n) / r;
const fp4Order = p ** 4n - 1n;
const xi = Fp2.fromBigTuple([1n, 1n]);
const xiInv = Fp2.inv(xi);
const embedFp2 = (value) => Fp12.create({
  c0: Fp6.create({ c0: value, c1: Fp2.ZERO, c2: Fp2.ZERO }),
  c1: Fp6.ZERO,
});
const vBasis = Fp6.create({ c0: Fp2.ZERO, c1: Fp2.ONE, c2: Fp2.ZERO });
const wv = Fp12.create({ c0: Fp6.ZERO, c1: vBasis });
const wvInv = Fp12.inv(wv);
const lineScale = (v) => Fp12.mul(
  embedFp2(Fp2.fromBigTuple([Fp.neg(Fp.mul(2n, v)), 0n])),
  wvInv,
);
const inFp4 = (value) => Fp12.eql(Fp12.frobeniusMap(value, 4), value);
const finalEqual = (a, b) => Fp12.eql(
  Fp12.finalExponentiate(a),
  Fp12.finalExponentiate(b),
);

assert(finalExponent % fp4Order === 0n, 'p^4-1 does not divide the BLS12-381 final exponent');
assert(Fp12.eql(Fp12.sqr(wv), embedFp2(xi)), '(W*V)^2 is not xi');
assert(inFp4(wv), 'W*V is not in the embedded Fp4');
B_IDENTITY_SUBSTITUTE.assertValidity();
assert(!B_IDENTITY_SUBSTITUTE.is0(), 'B identity substitute is zero');
assert(B_IDENTITY_SUBSTITUTE.isTorsionFree(), 'B identity substitute is not in the order-r subgroup');

const committedPairs = pairsFor(PUBLIC_INPUTS, proof);
const coordinatePoints = [
  bls12_381.G1.Point.BASE,
  bls12_381.G1.Point.BASE.multiply(2n),
  ...committedPairs.filter((_, index) => PT_CFG[index].P).map(({ P }) => P),
];
for (const [index, point] of coordinatePoints.entries()) {
  const { x, y } = point.toAffine();
  const { u, v } = unitG1(point);
  assert(v !== 0n, `finite coordinate ${index} has v=0`);
  assert(
    v === Fp.add(Fp.mul(4n, Fp.mul(Fp.sqr(u), u)), Fp.mul(16n, Fp.mul(Fp.sqr(v), v))),
    `finite coordinate ${index} misses the quartic`,
  );
  assert(Fp.mul(u, Fp.inv(v)) === x, `finite coordinate ${index} did not recover x`);
  assert(Fp.neg(Fp.inv(Fp.mul(2n, v))) === y, `finite coordinate ${index} did not recover y`);
}
const zeroUnit = unitG1(bls12_381.G1.Point.ZERO);
assert(zeroUnit.u === 0n && zeroUnit.v === 0n, 'G1 identity is not encoded as (0,0)');
assert(Fp.mul(4n, Fp.inv(4n)) === 1n, 'quartic identity coefficient is not invertible');

// Exact finite-line identity for every generated runtime fold. Verifying the three coefficient
// positions independently is unnecessary here: lineFn and lineUnitScaledFn are the exact factor
// constructors used by the trace, and every actual coefficient triple is checked below.
const rawTrace = millerBatchOps(committedPairs);
let finiteLineCount = 0;
for (const op of rawTrace.ops) {
  if (op.t === 'sqr' || !PT_CFG[op.j].P) continue;
  const { x, y } = committedPairs[op.j].P.toAffine();
  const { u, v } = unitG1(committedPairs[op.j].P);
  const rawFactor = lineFn(Fp12.ONE, ...op.coeffs, x, y);
  const sparseFactor = lineUnitScaledFn(Fp12.ONE, ...op.coeffs, u, v);
  const scale = lineScale(v);
  assert(Fp12.eql(sparseFactor, Fp12.mul(rawFactor, scale)), `sparse line mismatch at fold ${finiteLineCount}`);
  assert(inFp4(scale), `line scale is outside Fp4 at fold ${finiteLineCount}`);
  const expectedSquare = embedFp2(Fp2.mul(
    Fp2.fromBigTuple([Fp.mul(4n, Fp.sqr(v)), 0n]),
    xiInv,
  ));
  assert(Fp12.eql(Fp12.sqr(scale), expectedSquare), `line-scale square mismatch at fold ${finiteLineCount}`);
  finiteLineCount += 1;
}
assert(finiteLineCount === 207, `expected 207 generated runtime lines, got ${finiteLineCount}`);

const unitTrace = millerBatchOps(committedPairs, { unitLines: true });
const traceQuotient = Fp12.mul(unitTrace.boundary, Fp12.inv(rawTrace.boundary));
assert(inFp4(traceQuotient), 'complete unit/raw trace quotient is outside Fp4');
assert(Fp12.eql(Fp12.pow(traceQuotient, fp4Order), Fp12.ONE), 'complete trace quotient is not in Fp4*');
assert(finalEqual(unitTrace.boundary, rawTrace.boundary), 'complete unit/raw traces disagree after final exponentiation');

// The generated residue path interleaves the same line folds with c/cInv folds and the prepared
// alpha/beta multiplication. Using the same nonzero c values proves that exact 277-op ordering.
const rawFused = millerFusedOps(committedPairs, Fp12.ONE, Fp12.ONE);
const unitFused = millerFusedOps(committedPairs, Fp12.ONE, Fp12.ONE, { unitLines: true });
const fusedQuotient = Fp12.mul(unitFused.boundary, Fp12.inv(rawFused.boundary));
assert(rawFused.ops.length === 277 && unitFused.ops.length === 277, 'generated fused Miller op count changed');
assert(inFp4(fusedQuotient), 'fused unit/raw quotient is outside Fp4');
assert(finalEqual(unitFused.boundary, rawFused.boundary), 'fused unit/raw traces disagree after final exponentiation');

// For a nonzero order-r Q, every Miller accumulator is [prefix]Q. Double-line c2=-2YZ is
// nonzero because the prefix is nonzero and odd r excludes affine two-torsion. Add-line
// c2=X-Qx*Z can vanish only when [2*prefix]Q=+/-Q; the exact NAF schedule excludes both.
let prefix = 1n;
let addLineCount = 0;
for (const digit of ATE_NAF) {
  assert(prefix > 0n && prefix < r, 'Miller prefix left the nonzero order-r range');
  const doubled = 2n * prefix;
  assert(doubled < r, 'Miller doubled prefix wrapped modulo r');
  if (digit !== 0) {
    assert(doubled !== 1n && doubled !== r - 1n, 'Miller add-line can meet +/-Q');
    addLineCount += 1;
  }
  prefix = doubled + BigInt(digit);
}
assert(prefix === BLS_X, 'Miller NAF schedule does not end at |x|');
assert(addLineCount === 5, `expected 5 Miller add-lines, got ${addLineCount}`);

const identityTags = ['A', 'B', 'C', 'AB', 'AC', 'BC', 'ABC', 'vkx'];
let identityLineCount = 0;
for (const tag of identityTags) {
  const pairs = committedPairs.map((pair) => ({ ...pair }));
  const omitted = new Set();
  if (tag.includes('A') || tag.includes('B')) {
    pairs[0].P = bls12_381.G1.Point.ZERO;
    omitted.add(0);
  }
  if (tag.includes('B')) pairs[0].Q = B_IDENTITY_SUBSTITUTE;
  if (tag.includes('C')) {
    pairs[3].P = bls12_381.G1.Point.ZERO;
    omitted.add(3);
  }
  if (tag === 'vkx') {
    pairs[2].P = bls12_381.G1.Point.ZERO;
    omitted.add(2);
  }

  const reference = millerBatchOps(pairs, { skipPairs: omitted });
  const identityComplete = millerBatchOps(pairs, { unitLines: true });
  for (const op of identityComplete.ops) {
    if (op.t === 'sqr' || !omitted.has(op.j)) continue;
    assert(!Fp2.eql(op.coeffs[2], Fp2.ZERO), `${tag} identity line has c2=0`);
    const factor = lineUnitScaledFn(Fp12.ONE, ...op.coeffs, 0n, 0n);
    assert(Fp12.eql(factor, embedFp2(op.coeffs[2])), `${tag} identity line is not the Fp2 c2 factor`);
    identityLineCount += 1;
  }
  const quotient = Fp12.mul(identityComplete.boundary, Fp12.inv(reference.boundary));
  assert(inFp4(quotient), `${tag} identity trace quotient is outside Fp4`);
  assert(Fp12.eql(Fp12.pow(quotient, fp4Order), Fp12.ONE), `${tag} identity trace quotient is not in Fp4*`);
  assert(finalEqual(identityComplete.boundary, reference.boundary), `${tag} identity trace changed the pairing result`);
}

// Bind this certificate to the generated linked contracts. The manifest records the coordinate
// mode and exact boundary, and each runtime fold must call the CashScript sparse implementation.
assert(process.env.BLS_UNIT_G1 === '1', 'run the unit-line certificate with BLS_UNIT_G1=1');
const generated = join(here, 'generated', LINKED_RESIDUE_NAMESPACE);
const manifest = JSON.parse(readFileSync(join(generated, 'manifest_millerres.json'), 'utf8'));
assert(manifest.unitG1Lines === true, 'generated Miller manifest is not half-normalized');
assert((manifest.quotientTorus === true) === QUOTIENT_TORUS, 'generated Miller arithmetic mode changed');
assert(manifest.numOps === 277, 'generated Miller manifest op count changed');
const rawUnitBoundary = millerBatchOps(committedPairs, { unitLines: true }).boundary;
const { c, cInv, u } = QUOTIENT_TORUS
  ? residueTorusWitness(rawUnitBoundary)
  : residueWitness(rawUnitBoundary);
const generatedTrace = QUOTIENT_TORUS
  ? millerFusedTorusOps(committedPairs, c, cInv, u, { unitLines: true })
  : millerFusedOps(committedPairs, c, cInv, { unitLines: true });
assert(
  manifest.boundary.length === 12 && manifest.boundary.every((limb, index) => limb === String(f12limbs(generatedTrace.boundary)[index])),
  'generated Miller manifest boundary does not match the certified trace',
);
let generatedCallCount = 0;
for (const chunk of manifest.chunks) {
  const source = readFileSync(join(generated, `millerres_${String(chunk.idx).padStart(2, '0')}.cash`), 'utf8');
  generatedCallCount += source.match(/= lineUnitScaled\(/g)?.length ?? 0;
}
assert(generatedCallCount === finiteLineCount, `expected ${finiteLineCount} generated sparse calls, got ${generatedCallCount}`);

const cashSource = readFileSync(join(here, '..', '..', 'singleton', 'bls12-381', 'lib', 'lazy', 'Bls12381Lazy.cash'), 'utf8');
for (const formula of [
  'int o4a = mulFp(subFp(0, addFp(c0a, c0b), 128), v);',
  'int o4b = mulFp(subFp(c0a, c0b, 64), v);',
  'int o5a = mulFp(subFp(0, addFp(c1a, c1b), 128), u);',
  'int o5b = mulFp(subFp(c1a, c1b, 64), u);',
  'fp6Mul(sf0,sf1,sf2,sf3,sf4,sf5, c2a,c2b,o4a,o4b,o5a,o5b);',
]) {
  assert(cashSource.includes(formula), `CashScript sparse formula changed: ${formula}`);
}
const generatorSource = readFileSync(join(here, 'gen_miller_residue.mjs'), 'utf8');
for (const formula of [
  'const Y = op.neg ? negY[op.j] : [pairQyae(pi), pairQybe(pi)];',
  'psi(${pairQxae(PINFO[0])}, ${pairQxbe(PINFO[0])}, ${pairQyae(PINFO[0])}, ${pairQybe(PINFO[0])})',
]) {
  assert(generatorSource.includes(formula), `generated identity substitute is layout-dependent: ${formula}`);
}

console.log('BLS12-381 half-normalized Miller certificate: PASS');
console.log(`  exact generated finite folds: ${finiteLineCount}`);
console.log(`  identity Fp2 unit folds: ${identityLineCount} across ${identityTags.length} cases`);
console.log(`  generated CashScript sparse calls: ${generatedCallCount}`);
console.log('  p^4-1 divides the final exponent; finite and identity scales vanish');
