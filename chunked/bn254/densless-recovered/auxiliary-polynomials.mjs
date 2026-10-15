// Public-input-only auxiliary polynomial producer. No artifact, challenge,
// transcript, root, witness, or setup-scalar file is read by this module.
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
const P = bn254.fields.Fp.ORDER;
const mod = x => (x % P + P) % P;
const half = (P + 1n) / 2n;

// The logarithmic derivative of a nonvertical line contributes slope/2
// to the regular numerator coefficient. Vertical lines contribute zero.
function addLine(a, b) {
  if (a.is0()) return {point: b, slope: 0n};
  if (b.is0()) return {point: a, slope: 0n};
  const left = a.toAffine(), right = b.toAffine();
  if (left.x === right.x && mod(left.y + right.y) === 0n) return {point: bn254.G1.Point.ZERO, slope: 0n};
  const slope = a.equals(b)
    ? mod(3n * left.x ** 2n * bn254.fields.Fp.inv(mod(2n * left.y)))
    : mod((right.y - left.y) * bn254.fields.Fp.inv(mod(right.x - left.x)));
  return {point: a.add(b), slope};
}

function multiplyPolynomials(a, b) {
  const out = Array(a.length + b.length - 1).fill(0n);
  a.forEach((x, i) => b.forEach((y, j) => { out[i + j] = mod(out[i + j] + x * y); }));
  return out;
}

export function produceAuxiliary(vk, publicInputs) {
  assert.equal(publicInputs.length, 2);
  const scalars = publicInputs.map(BigInt);
  scalars.forEach(n => assert(n >= 0n && n < bn254.fields.Fr.ORDER));
  assert.equal(vk.ic.length, 3);
  const ic = vk.ic.map(p => bn254.G1.Point.fromAffine({x: BigInt(p.x), y: BigInt(p.y)}));
  ic.forEach(p => p.assertValidity());
  const expansions = [], products = [];
  for (let input = 0; input < 2; input++) {
    let n = scalars[input], power = 1n, plus = 0n, minus = 0n;
    const digits = [];
    for (let i = 0; i < 161; i++) {
      let digit = (n % 3n + 3n) % 3n;
      if (digit === 2n) digit = -1n;
      digits.push(Number(digit));
      if (digit === 1n) plus += power;
      if (digit === -1n) minus += power;
      n = (digit - n) / 3n;
      power *= -3n;
    }
    assert.equal(n, 0n, 'public scalar exceeds the fixed ternary loop');
    assert.equal(plus - minus, scalars[input]);
    expansions.push({plus, minus, digits});

    let point = bn254.G1.Point.ZERO, k = 0n;
    for (const bit of scalars[input].toString(2)) {
      const doubling = addLine(point, point);
      k = mod(2n * k + half * doubling.slope);
      point = doubling.point;
      if (bit === '1') {
        const addition = addLine(point, ic[input + 1]);
        k = mod(k + half * addition.slope);
        point = addition.point;
      }
    }
    products.push({point, k});
  }
  let vkx = ic[0], k = mod(products[0].k + products[1].k);
  for (const product of products) {
    const addition = addLine(vkx, product.point);
    k = mod(k + half * addition.slope);
    vkx = addition.point;
  }
  assert(!vkx.is0(), 'this deployed auxiliary frame requires a finite MSM point');
  const points = [...ic, vkx].map(p => p.toAffine());
  const multiplicities = [1n, ...scalars, -1n];
  const symmetricMultiplicities = [1n, ...expansions.map(e => e.plus + e.minus), 1n];
  let denominator = [1n];
  for (const point of points) denominator = multiplyPolynomials(denominator, [mod(-point.x), 1n]);
  const numerator = Array(4).fill(0n), secondNumerator = denominator.map(c => mod(k * c));
  for (let i = 0; i < points.length; i++) {
    let quotient = [1n];
    for (let j = 0; j < points.length; j++) if (i !== j) {
      quotient = multiplyPolynomials(quotient, [mod(-points[j].x), 1n]);
    }
    quotient.forEach((coefficient, degree) => {
      numerator[degree] = mod(numerator[degree] + half * symmetricMultiplicities[i] * coefficient);
      secondNumerator[degree] = mod(secondNumerator[degree] + half * multiplicities[i] * points[i].y * coefficient);
    });
  }
  const secondDenominator = multiplyPolynomials(denominator, [3n, 0n, 0n, 1n]);
  const words = [...numerator, ...denominator, ...secondNumerator, ...secondDenominator];
  assert.equal(words.length, 22);
  const blob = Buffer.concat(words.map(n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse()));
  assert.equal(blob.length, 704);
  return {blob, words, vkx: points[3], numerator, denominator, secondNumerator, secondDenominator, k, expansions};
}
