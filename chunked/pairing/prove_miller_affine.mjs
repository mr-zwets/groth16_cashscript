// Executable completeness/equivalence checks for the affine runtime-G2 Miller path.
//
// Each runtime tangent/chord has a canonical Fp2 slope witness. The CashScript gates the
// corresponding slope equation and rejects a zero denominator before computing the next affine
// state. This file proves those exceptional cases are unreachable for every nonzero G2[r] input,
// and checks that normalizing each line only changes the Miller value by an Fp2 factor. Such a
// factor vanishes in BN254 final exponentiation because p^2-1 divides (p^12-1)/r.

import {
  bn254, Fp, Fp2, Fp12, BN_X, pairsFor, proof, vec,
} from './_millermath.mjs';
import {
  eq12, millerFusedOps, millerFusedAffineOps,
} from './_residuemath.mjs';

const P = Fp.ORDER;
const R = bn254.fields.Fr.ORDER;
const S = 6n * BN_X + 2n;
const Z = (6n * BN_X * BN_X) % R;
const modR = (value) => ((value % R) + R) % R;

if (((P ** 12n - 1n) / R) % (P ** 2n - 1n) !== 0n) {
  throw new Error('Fp2 line scales do not vanish in final exponentiation');
}

const baseTrace = millerFusedAffineOps(pairsFor(vec.publicInputs, proof), Fp12.ONE, Fp12.ONE);
let scalar = 1n;
let runtimeDoubles = 0;
let runtimeAdds = 0;
for (const op of baseTrace.ops) {
  if (op.j !== 0) continue;
  if (op.t === 'dl') {
    // On the odd prime-order subgroup, [k]B has y=0 only if it is both 2-torsion and
    // r-torsion, hence infinity. The trace check below excludes k=0 mod r.
    if (modR(scalar) === 0n) throw new Error('runtime affine double reaches infinity');
    scalar = modR(2n * scalar);
    runtimeDoubles += 1;
  } else if (op.t === 'al') {
    const addend = op.neg ? -1n : 1n;
    // For finite points on this short Weierstrass curve, equal x-coordinates mean P=Q or
    // P=-Q. Either case makes the affine chord denominator zero.
    if (modR(scalar - addend) === 0n || modR(scalar + addend) === 0n) {
      throw new Error('runtime affine add reaches an equal/inverse case');
    }
    scalar = modR(scalar + addend);
    runtimeAdds += 1;
  } else if (op.t === 'pp') {
    if (scalar !== S % R) throw new Error('unexpected Miller endpoint scalar');
    // The complete-twist resultant proof in prove_miller_endpoint_subgroup.mjs is stronger;
    // these subgroup identities make the two affine denominators explicit here.
    if (modR(S - Z) === 0n || modR(S + Z) === 0n) {
      throw new Error('first post-processing addition is exceptional');
    }
    const afterFirst = modR(S + Z);
    const secondAddend = modR(-Z * Z);
    if (modR(afterFirst - secondAddend) === 0n || modR(afterFirst + secondAddend) === 0n) {
      throw new Error('second post-processing addition is exceptional');
    }
    runtimeAdds += 2;
  }
}

for (const state of baseTrace.states) {
  const point = state.Rs[0];
  for (const limb of [point.x.c0, point.x.c1, point.y.c0, point.y.c1]) {
    if (limb < 0n || limb >= P) throw new Error('affine state limb is not canonical');
  }
}
for (const op of baseTrace.ops) {
  for (const slope of op.affineSlopes) {
    if (slope.c0 < 0n || slope.c0 >= P || slope.c1 < 0n || slope.c1 >= P) {
      throw new Error('affine slope limb is not canonical');
    }
  }
}

const scalars = [1n, 2n, 7n, BN_X];
for (const k of scalars) {
  const scaledProof = k === 1n ? proof : {
    a: proof.a.multiply(bn254.fields.Fr.inv(k)),
    b: proof.b.multiply(k),
    c: proof.c,
  };
  const pairs = pairsFor(vec.publicInputs, scaledProof);
  const projective = millerFusedOps(pairs, Fp12.ONE, Fp12.ONE).boundary;
  const affine = millerFusedAffineOps(pairs, Fp12.ONE, Fp12.ONE).boundary;
  const scale = Fp12.mul(affine, Fp12.inv(projective));
  if (!eq12(Fp12.frobeniusMap(scale, 2), scale)) {
    throw new Error(`normalized/projective quotient is not in Fp2 for scalar ${k}`);
  }
}

console.log('Affine Miller proof passed');
console.log(`${runtimeDoubles} runtime doubles and ${runtimeAdds} runtime additions are nonexceptional on G2[r]`);
console.log('normalized/projective quotients are in Fp2; p^2-1 divides the BN254 final exponent');
