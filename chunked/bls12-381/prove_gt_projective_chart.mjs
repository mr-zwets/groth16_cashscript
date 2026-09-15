// Mathematical certificate, not a cache generator or transaction verifier.
// See BLS_PROJECTIVE_GT_MATH.md for the universal arguments and scope limits.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const { Fp, Fp2, Fp6, Fp12 } = bls12_381.fields;
const p = Fp.ORDER;
const r = bls12_381.G1.Point.Fn.ORDER;
const mod = (value) => ((value % p) + p) % p;

// Independent Fp2 arithmetic in the basis (1,i), with i^2=-1.
const add2 = (a, b) => a.map((value, index) => mod(value + b[index]));
const sub2 = (a, b) => a.map((value, index) => mod(value - b[index]));
const mul2 = (a, b) => [mod(a[0] * b[0] - a[1] * b[1]), mod(a[0] * b[1] + a[1] * b[0])];
const scale2 = (a, value) => a.map((limb) => mod(limb * value));
const pow2 = (value, exponent) => {
  let result = [1n, 0n];
  for (; exponent !== 0n; exponent >>= 1n, value = mul2(value, value)) {
    if (exponent & 1n) result = mul2(result, value);
  }
  return result;
};
const zero2 = [0n, 0n];
const xi = [1n, 1n];
const third = pow2([3n, 0n], p - 2n)[0];
const half = pow2([2n, 0n], p - 2n)[0];
const inverseXi = [half, mod(-half)];
assert.deepEqual(mul2(xi, inverseXi), [1n, 0n]);
assert.equal(mod(3n * third), 1n);
assert.equal(p % 4n, 3n, 'i^2+1 must be irreducible over Fp');
assert.notDeepEqual(pow2(xi, (p * p - 1n) / 3n), [1n, 0n], 'Z^3-xi must be irreducible over Fp2');
assert.deepEqual(pow2(xi, (p * p - 1n) / 2n), [p - 1n, 0n], 'Norm(Z)=xi must be nonsquare');

const decode = (s, t) => {
  assert([...s, ...t].every((limb) => limb >= 0n && limb < p), 'noncanonical parameter');
  const h = add2(sub2(mul2(s, s), t), scale2(mul2(xi, mul2(t, t)), third));
  return {
    D: [s, add2(h, t), add2(scale2(sub2(h, t), third), inverseXi)],
    N: [zero2, h, zero2],
    h,
  };
};
const flat6 = ([a, b, c]) => [mod(a[0] - a[1]), mod(b[0] - b[1]), mod(c[0] - c[1]), a[1], b[1], c[1]];
const flat12 = (D, N) => {
  const numerator = flat6(N);
  return flat6(D).flatMap((value, index) => [value, numerator[index]]);
};
const fromNoble6 = (value) => [value.c0, value.c1, value.c2].map((limb) => [limb.c0, limb.c1]);
const fromNoble12 = (value) => flat12(fromNoble6(value.c0), fromNoble6(value.c1));
const one12 = [1n, ...Array(11).fill(0n)];

// Independent Fp[W]/(W^12-2W^6+2), with Z=W^2 and i=W^6-1.
const mul12 = (a, b) => {
  const result = Array(23).fill(0n);
  a.forEach((left, i) => b.forEach((right, j) => { result[i + j] += left * right; }));
  for (let degree = 22; degree >= 12; degree -= 1) {
    result[degree - 6] += 2n * result[degree];
    result[degree - 12] -= 2n * result[degree];
  }
  return result.slice(0, 12).map(mod);
};
const pow12 = (value, exponent) => {
  let result = one12;
  for (; exponent !== 0n; exponent >>= 1n, value = mul12(value, value)) {
    if (exponent & 1n) result = mul12(result, value);
  }
  return result;
};
const conjugate12 = (value) => value.map((limb, index) => index % 2 === 0 ? limb : mod(-limb));

// Exact integer polynomials: monomials are sorted variable names, not sampled values.
const constant = (value) => new Map(value === 0n ? [] : [['', value]]);
const variable = (name) => new Map([[name, 1n]]);
const scale = (polynomial, value) => new Map([...polynomial].map(([term, coefficient]) => [term, coefficient * value]));
const add = (...polynomials) => {
  const result = new Map();
  polynomials.forEach((polynomial) => polynomial.forEach((coefficient, term) => {
    const total = (result.get(term) ?? 0n) + coefficient;
    if (total === 0n) result.delete(term); else result.set(term, total);
  }));
  return result;
};
const multiply = (left, right) => {
  const terms = [];
  left.forEach((leftCoefficient, leftTerm) => right.forEach((rightCoefficient, rightTerm) => {
    const term = [leftTerm, rightTerm].filter(Boolean).join('*').split('*').sort().join('*');
    terms.push(new Map([[term, leftCoefficient * rightCoefficient]]));
  }));
  return add(...terms);
};

// Clear the original map's denominators by the nonzero scalar 9*xi.
const [s, t, x] = ['s', 't', 'xi'].map(variable);
const H = add(scale(multiply(s, s), 3n), scale(t, -3n), multiply(x, multiply(t, t)));
const A = scale(multiply(x, s), 9n);
const B = add(scale(multiply(x, H), 3n), scale(multiply(x, t), 9n));
const C = add(multiply(x, H), scale(multiply(x, t), -3n), constant(9n));
const homogeneousH = scale(multiply(x, H), 3n);
assert.equal(add(
  scale(multiply(A, A), 3n),
  scale(multiply(x, multiply(B, C)), -3n),
  multiply(x, multiply(homogeneousH, homogeneousH)),
).size, 0, 'homogeneous quadric identity');
assert.equal(add(
  multiply(x, add(B, scale(C, 3n), scale(homogeneousH, -2n))), scale(x, -27n),
).size, 0, 'inverse chart identity ell(D/h)*h=1');

// Norm(a+theta) is a 3x3 determinant over Fp4, theta^2=xi.
const [a0, a1, a2, thetaVariable] = ['a0', 'a1', 'a2', 'theta'].map(variable);
const diagonal = add(a0, thetaVariable);
// Multiplication matrix in basis (1,Z,Z^2):
// [[diagonal,xi*a2,xi*a1],[a1,diagonal,xi*a2],[a2,a1,diagonal]].
const xiA1 = multiply(x, a1);
const xiA2 = multiply(x, a2);
const norm = add(
  multiply(multiply(diagonal, diagonal), diagonal),
  multiply(multiply(xiA2, xiA2), a2),
  multiply(multiply(xiA1, a1), a1),
  scale(multiply(multiply(xiA1, diagonal), a2), -1n),
  scale(multiply(multiply(xiA2, a1), diagonal), -1n),
  scale(multiply(multiply(diagonal, xiA2), a1), -1n),
);
const oddTerms = [];
norm.forEach((coefficient, term) => {
  const variables = term === '' ? [] : term.split('*');
  const thetaCount = variables.filter((name) => name === 'theta').length;
  if (thetaCount % 2 === 1) {
    const reduced = [...variables.filter((name) => name !== 'theta'),
      ...Array(Math.floor(thetaCount / 2)).fill('xi')].sort().join('*');
    oddTerms.push(new Map([[reduced, coefficient]]));
  }
});
assert.equal(add(
  ...oddTerms, scale(multiply(a0, a0), -3n),
  scale(multiply(x, multiply(a1, a2)), 3n), scale(x, -1n),
).size, 0, 'norm odd coefficient must be 3*(a0^2-xi*a1*a2)+xi');

// Expand the scaled factor in Fp2 symbolically, then flatten. This is separate
// from the runtime helper: it establishes the polynomial coefficients it must use.
const [s0, s1, t0, t1, h0, h1, prime] = ['s0', 's1', 't0', 't1', 'H0', 'H1', 'p'].map(variable);
const scaledTower = [
  [scale(add(s0, scale(s1, -1n)), 9n), scale(add(s0, s1), 9n)],
  [scale(add(h0, scale(t0, 3n), scale(h1, -1n), scale(t1, -3n)), 3n),
    scale(add(h0, h1, scale(t0, 3n), scale(t1, 3n)), 3n)],
  [add(h0, scale(t0, -3n), scale(h1, -1n), scale(t1, 3n), constant(9n)),
    add(h0, h1, scale(t0, -3n), scale(t1, -3n))],
];
const flatD = [...scaledTower.map(([real, imaginary]) => add(real, scale(imaginary, -1n))),
  ...scaledTower.map(([, imaginary]) => imaginary)];
const expectedD = [scale(s1, -18n), add(scale(h1, -6n), scale(t1, -18n)),
  add(scale(h1, -2n), scale(t1, 6n), constant(9n)), scale(add(s0, s1), 9n),
  scale(add(h0, h1, scale(t0, 3n), scale(t1, 3n)), 3n),
  add(h0, h1, scale(t0, -3n), scale(t1, -3n))];
flatD.forEach((coefficient, index) => {
  assert.equal(add(coefficient, scale(expectedD[index], -1n)).size, 0, `scaled D coefficient ${index}`);
});
const flatN1 = add(scale(add(h0, scale(h1, -1n)), 3n), scale(add(h0, h1), -3n));
assert.equal(add(flatN1, scale(h1, 6n)).size, 0, 'scaled N coefficient at Y');
// Replacing -v with p-v changes only multiples of p. The internal p endpoint
// is intentional; authenticated s,t remain canonical. These are not alpha identities.
const complement = (value) => add(prime, scale(value, -1n));
const nonnegativeD = [scale(complement(s1), 18n),
  add(scale(complement(h1), 6n), scale(complement(t1), 18n)),
  add(scale(complement(h1), 2n), scale(t1, 6n), constant(9n)),
  expectedD[3], expectedD[4], add(h0, h1, scale(complement(t0), 3n), scale(complement(t1), 3n))];
nonnegativeD.forEach((coefficient, index) => {
  assert.equal(add(coefficient, scale(flatD[index], -1n),
    scale(prime, -[18n, 24n, 2n, 0n, 0n, 6n][index])).size, 0, `positive D representative ${index}`);
});
assert.equal(add(scale(complement(h1), 6n), scale(flatN1, -1n), scale(prime, -6n)).size, 0);

// GT has odd order and norm1 to Fp4. The anisotropic tangent leaves only one
// finite chart exception; its image is explicitly outside GT.
assert.equal(r & 1n, 1n);
assert.equal((p ** 4n - p ** 2n + 1n) % r, 0n);
assert.equal((p ** 8n + p ** 4n + 1n) % r, 0n);
assert.deepEqual(pow2(scale2(xi, -third), (p * p - 1n) / 2n), [p - 1n, 0n]);
const theta = Fp12.create({
  c0: Fp6.ZERO,
  c1: Fp6.create({ c0: Fp2.ZERO, c1: Fp2.ONE, c2: Fp2.ZERO }),
});
const basepoint = Fp12.create({
  c0: Fp6.create({ c0: Fp2.ZERO, c1: Fp2.ONE, c2: Fp2.fromBigTuple([third, 0n]) }),
  c1: Fp6.ZERO,
});
const excludedImage = Fp12.div(Fp12.add(basepoint, theta), Fp12.sub(basepoint, theta));
const excludedPowR = pow12(fromNoble12(excludedImage), r);
assert.notDeepEqual(excludedPowR, one12, 'omitted basepoint must lie outside GT');
assert.deepEqual(excludedPowR, fromNoble12(Fp12.pow(excludedImage, r)));

// Noble performs only the off-chain encoder and supplies public pairing inputs;
// independent flat arithmetic checks the decoded class and its scaled variant.
const generator = bls12_381.pairing(bls12_381.G1.Point.BASE, bls12_381.G2.Point.BASE);
const exponents = [0n, 1n, 2n, 7n, r - 1n, ...Array.from({ length: 8 }, (_, index) =>
  BigInt('0x' + createHash('sha512').update(`gt-projective-chart/${index}`).digest('hex')) % r)];
let gtChecks = 0;
for (const exponent of exponents) {
  const original = Fp12.pow(generator, exponent);
  for (const target of [original, Fp12.conjugate(original)]) {
    let parameters = [zero2, zero2];
    if (!Fp12.eql(target, Fp12.ONE)) {
      const squared = Fp12.sqr(target);
      const cayley = Fp12.mul(theta,
        Fp12.div(Fp12.add(squared, Fp12.ONE), Fp12.sub(squared, Fp12.ONE)));
      assert(Fp6.eql(cayley.c1, Fp6.ZERO));
      const a = cayley.c0;
      const ell = Fp2.mul(Fp2.fromBigTuple(xi), Fp2.add(
        Fp2.mul(Fp2.sub(a.c1, Fp2.ONE), Fp2.fromBigTuple([third, 0n])),
        Fp2.sub(a.c2, Fp2.fromBigTuple([third, 0n])),
      ));
      assert(!Fp2.eql(ell, Fp2.ZERO));
      parameters = [Fp2.div(a.c0, ell), Fp2.div(Fp2.sub(a.c1, Fp2.ONE), ell)]
        .map((value) => [value.c0, value.c1]);
    }
    const { D, N, h } = decode(...parameters);
    const targetFlat = fromNoble12(target);
    const factors = [flat12(D, N), flat12(
      D.map((value) => scale2(mul2(xi, value), 9n)),
      N.map((value) => scale2(mul2(xi, value), 9n)),
    )];
    factors.forEach((factor) => {
      const quotient = mul12(factor, conjugate12(targetFlat));
      assert(quotient.some((value) => value !== 0n));
      assert(quotient.every((value, index) => index % 2 === 0 || value === 0n), 'factor/g is not in Fp6');
      assert.deepEqual(factor, mul12(conjugate12(factor), mul12(targetFlat, targetFlat)));
    });
    assert.equal(h.every((value) => value === 0n), exponent === 0n);
    gtChecks += 1;
  }
}

const extremes = [0n, 1n, p - 1n, p - 2n, (p - 1n) / 2n];
let canonicalChecks = 0;
for (const a of extremes) for (const b of extremes) for (const c of extremes) for (const d of extremes) {
  const { D, N, h } = decode([a, b], [c, d]);
  assert.deepEqual(add2(sub2(mul2(D[0], D[0]), mul2(xi, mul2(D[1], D[2]))),
    scale2(mul2(xi, mul2(h, h)), third)), zero2);
  assert(D.flat().some((value) => value !== 0n));
  assert(flat12(D, N).every((value, index) => index <= 10 || value === 0n));
  canonicalChecks += 1;
}
for (const identityT of [zero2, scale2(inverseXi, 3n)]) {
  const identity = decode(zero2, identityT);
  assert.deepEqual(identity.h, zero2);
  assert(identity.N.flat().every((value) => value === 0n));
  assert(identity.D.flat().some((value) => value !== 0n));
}
assert.throws(() => decode([p, 0n], zero2), /noncanonical/);
assert.throws(() => decode([-1n, 0n], zero2), /noncanonical/);

// Fixed schedule certificate using polynomial support convolution, with no
// fixture coefficient cancellations and no dependency on a generated cache.
const union = (...sets) => new Set(sets.flatMap((set) => [...set]));
const product = (a, b, shift = 0) => new Set([...a].flatMap((i) => [...b].map((j) => i + j + shift)));
const generic = (degree) => new Set(Array.from({ length: degree + 1 }, (_, index) => index));
const pairProduct = ([a, b], [c, d]) => [
  union(product(a, c), product(b, d, 1)), union(product(a, d), product(b, c)),
];
const normalized = [generic(0), generic(5)];
const projective = [generic(5), new Set([1, 4])];
const inputCharts = [normalized, [new Set(), generic(0)]];
const digits = Array.from((0xd201000000010000n).toString(2).slice(1), Number);
const carriers = [2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19];
const segments = [];
let operationCount = 0;
for (let block = 0; block < 21; block += 1) {
  const operations = digits.slice(3 * block, 3 * block + 3).flatMap((digit) => [
    'square', ...(digit ? ['factor'] : []),
    'factor', ...(digit ? ['factor'] : []), 'factor', ...(digit ? ['factor'] : []),
  ]);
  operationCount += operations.length;
  const parts = [0, 15].includes(block) ? [operations.slice(0, 6), operations.slice(6)] : [operations];
  parts.forEach((part, index) => {
    const trailing = carriers.includes(block) && index === parts.length - 1 ? 2 : 0;
    const bounds = [normalized, projective].map((pic) => Math.max(...inputCharts.map((input) => {
      let pair = input;
      part.forEach((operation) => { pair = pairProduct(pair, operation === 'square' ? pair : normalized); });
      for (let count = 0; count < trailing; count += 1) pair = pairProduct(pair, pic);
      return Math.max(...union(pair[0], pair[1], product(pair[0], generic(5))));
    })));
    assert(bounds[1] <= bounds[0]);
    segments.push({ block, segment: index, picFactors: trailing, oldDegree: bounds[0], newDegree: bounds[1] });
  });
}
assert.equal(digits.length, 63);
assert.equal(operationCount, 204);
assert.equal(segments.length, 23);
assert.equal(Math.max(...segments.map((segment) => segment.newDegree)), 137);
const terminalDegree = Math.max(...inputCharts.map((input) => {
  const pair = pairProduct(input, normalized);
  return Math.max(...union(pair[0], pair[1], product(pair[0], generic(5))));
}));
assert.equal(terminalDegree, 16);

console.log(JSON.stringify({
  scope: 'Standalone mathematical certificate; no cache coverage, runtime bytecode, transcript, or resource gate claim.',
  field: { p: String(p), r: String(r), xi: ['1', '1'], towerIrreducible: true },
  exactIdentities: ['homogeneous quadric', 'inverse chart', 'norm odd coefficient',
    'scaled 9xi flat coefficients', 'positive representatives differ by multiples of p'],
  universalNonzero: 'Homogeneous identity: D=0 forces h=t=0, then C=1/xi != 0.',
  chartCoverage: { tangentAnisotropic: true, omittedImageInGT: false, omittedImagePowR: excludedPowR.map(String) },
  gtChecks, canonicalChecks, factorDegrees: { D: 5, N: 4, inW: 10 },
  fixedSchedule: { loopDigits: digits.join(''), activePairs: 2, carriers,
    splitBlocks: [0, 15], splitAfterOperations: 6, operationCount, segments,
    terminalDegree, maximumRelationDegree: 137, maximumQuotientCoefficients: 132 },
  limitations: ['Fixed schedule assumptions must match the owning generator.',
    'Canonical probe input checks are not runtime parsing checks.',
    'Only exact authenticated table bytes bind public inputs; the decoder is not a GT membership test.'],
}, null, 2));
