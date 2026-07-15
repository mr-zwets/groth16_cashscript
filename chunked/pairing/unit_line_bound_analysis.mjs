// Inclusive BigInt interval proof for Bn254Lazy.cash::mul034Unit and the
// eight-Fp2-product Bn254Lazy.cash::lineUnitDirect.
//
// mul034Unit receives canonical Fp12 and sparse-line limbs; its only enlarged
// sparse value is qa=1+o3a, in [1,p]. lineUnitDirect receives the signed
// representatives emitted by the torus Miller hot path, while its four reduced
// sparse limbs remain canonical. This script mirrors both CashScript kernels
// without sampling, proves every interpolation >>1 is exact (also for negative
// numerators), and bounds every VM-number intermediate and output.

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const RAW_BIAS = 63620485708775397116398918488458420026955112869114471513803213004724729950895225285411156794258613332669998933780976023070021894424298169671600468685695583977n;

const interval = (lo, hi) => ({ lo, hi });
const add = (a, b) => interval(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => interval(a.lo - b.hi, a.hi - b.lo);
const mul = (a, b) => {
  const products = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi];
  return interval(products.reduce((x, y) => x < y ? x : y), products.reduce((x, y) => x > y ? x : y));
};
const scale = (k, a) => k >= 0n
  ? interval(k * a.lo, k * a.hi)
  : interval(k * a.hi, k * a.lo);
const fp2Raw = (a, b) => [
  sub(mul(a[0], b[0]), mul(a[1], b[1])),
  add(mul(a[0], b[1]), mul(a[1], b[0])),
];
const fp2Add = (a, b) => [add(a[0], b[0]), add(a[1], b[1])];
const fp2Sub = (a, b) => [sub(a[0], b[0]), sub(a[1], b[1])];
const fp2Scale = (k, a) => [scale(k, a[0]), scale(k, a[1])];
const maximumAbsolute = (a) => {
  const lo = a.lo < 0n ? -a.lo : a.lo;
  const hi = a.hi < 0n ? -a.hi : a.hi;
  return lo > hi ? lo : hi;
};
const vmNumberBytes = (a) => {
  const maximum = maximumAbsolute(a);
  return maximum === 0n ? 0 : Math.floor(maximum.toString(2).length / 8) + 1;
};
const remainderModP = (a) => interval(a.lo < 0n ? 1n - P : 0n, a.hi > 0n ? P - 1n : 0n);

const F = Array.from({ length: 12 }, () => interval(0n, P - 1n));
const o3 = [interval(0n, P - 1n), interval(0n, P - 1n)];
const o4 = [interval(0n, P - 1n), interval(0n, P - 1n)];

const bt0 = fp2Raw(F.slice(6, 8), o3);
const bt1 = fp2Raw(F.slice(8, 10), o4);
const bm12 = fp2Raw(fp2Add(F.slice(8, 10), F.slice(10, 12)), o4);
const bu0 = fp2Sub(bm12, bt1);
const B = [
  add(sub(scale(9n, bu0[0]), bu0[1]), bt0[0]),
  add(add(bu0[0], scale(9n, bu0[1])), bt0[1]),
];
const bm1 = fp2Raw(fp2Add(o3, o4), fp2Add(F.slice(6, 8), F.slice(8, 10)));
B.push(...fp2Sub(fp2Sub(bm1, bt0), bt1));
const bm2 = fp2Raw(fp2Add(F.slice(6, 8), F.slice(10, 12)), o3);
B.push(...fp2Add(fp2Sub(bm2, bt0), bt1));

const S = F.slice(0, 6).map((x, i) => add(x, F[i + 6]));
const q = [add(interval(1n, 1n), o3[0]), o3[1]];
const gt0 = fp2Raw(S.slice(0, 2), q);
const gt1 = fp2Raw(S.slice(2, 4), o4);
const gm12 = fp2Raw(fp2Add(S.slice(2, 4), S.slice(4, 6)), o4);
const gu0 = fp2Sub(gm12, gt1);
const G = [
  add(sub(scale(9n, gu0[0]), gu0[1]), gt0[0]),
  add(add(gu0[0], scale(9n, gu0[1])), gt0[1]),
];
const gm1 = fp2Raw(fp2Add(q, o4), fp2Add(S.slice(0, 2), S.slice(2, 4)));
G.push(...fp2Sub(fp2Sub(gm1, gt0), gt1));
const gm2 = fp2Raw(fp2Add(S.slice(0, 2), S.slice(4, 6)), q);
G.push(...fp2Add(fp2Sub(gm2, gt0), gt1));

const karatsubaOutputs = [
  add(sub(scale(9n, B[4]), B[5]), F[0]),
  add(add(B[4], scale(9n, B[5])), F[1]),
  add(B[0], F[2]),
  add(B[1], F[3]),
  add(B[2], F[4]),
  add(B[3], F[5]),
  sub(sub(G[0], F[0]), B[0]),
  sub(sub(G[1], F[1]), B[1]),
  sub(sub(G[2], F[2]), B[2]),
  sub(sub(G[3], F[3]), B[3]),
  sub(sub(G[4], F[4]), B[4]),
  sub(sub(G[5], F[5]), B[5]),
];

// lineUnitDirect computes each Fp6 sparse product from evaluations at 0, 1,
// and -1. F is inductively signed: genesis is a subset, and fp12SqrSigned,
// fp12MulTorus, and this function all return Script remainders in (-p,p).
const signedField = interval(1n - P, P - 1n);
const directF = Array.from({ length: 12 }, () => signedField);
const canonical = interval(0n, P - 1n);
const runtimeC0 = interval(1n, 2n * P - 1n);
const fixedC0 = canonical;
const anyC0 = interval(fixedC0.lo, runtimeC0.hi);
const directIntermediates = [];
const record = (label, value) => {
  directIntermediates.push([label, value]);
  return value;
};
const recordPair = (label, value) => value.map((limb, index) => record(`${label}.${index}`, limb));
const triple = (a, b, c) => fp2Add(fp2Add(a, b), c);
const halfExact = (label, value) => recordPair(label, value.map((limb) => {
  // The symbolic proof below establishes that every represented value is even.
  // Arithmetic right shift is therefore exact throughout this inclusive range,
  // including its negative half.
  return interval(limb.lo >> 1n, limb.hi >> 1n);
}));

// c1/u and c0/v products are nonnegative, so Script % p makes o3/o4
// canonical. Include the pre-reduction products in the VM-width inventory.
const directO3 = recordPair('o3', [
  record('o3a.raw', mul(canonical, canonical)),
  record('o3b.raw', mul(canonical, canonical)),
].map(remainderModP));
const directO4 = recordPair('o4', [
  record('o4a.raw', mul(anyC0, canonical)),
  record('o4b.raw', mul(anyC0, canonical)),
].map(remainderModP));
const directOp = recordPair('op', fp2Add(directO3, directO4));
const directOm = recordPair('om', fp2Sub(directO3, directO4));

const sparseProduct = (label, limbs) => {
  const y0 = limbs.slice(0, 2);
  const y1 = limbs.slice(2, 4);
  const y2 = limbs.slice(4, 6);
  const m0 = recordPair(`${label}m0`, fp2Raw(y0, directO3));
  const m3 = recordPair(`${label}m3`, fp2Raw(y2, directO4));
  const plusInput = recordPair(`${label}.plusInput`, triple(y0, y1, y2));
  const minusInput = recordPair(`${label}.minusInput`, fp2Add(fp2Sub(y0, y1), y2));
  const mp = recordPair(`${label}mp`, fp2Raw(plusInput, directOp));
  const mm = recordPair(`${label}mm`, fp2Raw(minusInput, directOm));
  const differenceNumerator = recordPair(`${label}.differenceNumerator`, fp2Sub(mp, mm));
  const sumNumerator = recordPair(`${label}.sumNumerator`, fp2Add(mp, mm));
  const differenceHalf = halfExact(`${label}.differenceHalf`, differenceNumerator);
  const sumHalf = halfExact(`${label}.sumHalf`, sumNumerator);
  return [
    record(`${label}t0`, sub(add(m0[0], scale(9n, m3[0])), m3[1])),
    record(`${label}t1`, add(add(m0[1], m3[0]), scale(9n, m3[1]))),
    ...recordPair(`${label}t2`, fp2Sub(differenceHalf, m3)),
    ...recordPair(`${label}t4`, fp2Sub(sumHalf, m0)),
  ];
};

const yt = sparseProduct('y', directF.slice(6, 12));
const xt = sparseProduct('x', directF.slice(0, 6));
const directRawOutputs = [
  sub(add(directF[0], scale(9n, yt[4])), yt[5]),
  add(add(directF[1], yt[4]), scale(9n, yt[5])),
  add(directF[2], yt[0]),
  add(directF[3], yt[1]),
  add(directF[4], yt[2]),
  add(directF[5], yt[3]),
  add(directF[6], xt[0]),
  add(directF[7], xt[1]),
  add(directF[8], xt[2]),
  add(directF[9], xt[3]),
  add(directF[10], xt[4]),
  add(directF[11], xt[5]),
].map((output, index) => record(`output${index}.raw`, output));

// Sparse polynomial replay proves the four interpolation numerators for each
// Fp6 product are coefficientwise even. This is stronger than sampling parity:
// it holds for all integer inputs, including values that make a numerator
// negative, and it also pins the intended two-product coefficients.
const polynomial = (name) => new Map([[name, 1n]]);
const polynomialAdd = (a, b) => {
  const output = new Map(a);
  for (const [key, coefficient] of b) {
    const next = (output.get(key) ?? 0n) + coefficient;
    if (next === 0n) output.delete(key);
    else output.set(key, next);
  }
  return output;
};
const polynomialScale = (coefficient, value) => new Map(
  [...value].map(([key, itemCoefficient]) => [key, coefficient * itemCoefficient]),
);
const polynomialSub = (a, b) => polynomialAdd(a, polynomialScale(-1n, b));
const polynomialMul = (a, b) => {
  const output = new Map();
  for (const [left, leftCoefficient] of a) {
    for (const [right, rightCoefficient] of b) {
      const key = [left, right].sort().join('*');
      output.set(key, (output.get(key) ?? 0n) + leftCoefficient * rightCoefficient);
    }
  }
  return new Map([...output].filter(([, coefficient]) => coefficient !== 0n));
};
const polynomialFp2Add = (a, b) => [polynomialAdd(a[0], b[0]), polynomialAdd(a[1], b[1])];
const polynomialFp2Sub = (a, b) => [polynomialSub(a[0], b[0]), polynomialSub(a[1], b[1])];
const polynomialFp2Raw = (a, b) => [
  polynomialSub(polynomialMul(a[0], b[0]), polynomialMul(a[1], b[1])),
  polynomialAdd(polynomialMul(a[0], b[1]), polynomialMul(a[1], b[0])),
];
const polynomialTriple = (a, b, c) => polynomialFp2Add(polynomialFp2Add(a, b), c);
const sortedPolynomial = (value) => [...value].sort(([left], [right]) => left.localeCompare(right));
const requirePolynomialPair = (label, actual, expected) => {
  actual.forEach((limb, index) => {
    if (JSON.stringify(sortedPolynomial(limb), (_, value) =>
      typeof value === 'bigint' ? value.toString() : value) !==
      JSON.stringify(sortedPolynomial(expected[index]), (_, value) =>
        typeof value === 'bigint' ? value.toString() : value)) {
      throw new Error(`${label}.${index} polynomial identity failed`);
    }
  });
};
const provePolynomialSparseProduct = (label, limbs, numeratorIntervals) => {
  const y0 = limbs.slice(0, 2);
  const y1 = limbs.slice(2, 4);
  const y2 = limbs.slice(4, 6);
  const op = polynomialFp2Add(symbolicO3, symbolicO4);
  const om = polynomialFp2Sub(symbolicO3, symbolicO4);
  const m0 = polynomialFp2Raw(y0, symbolicO3);
  const m3 = polynomialFp2Raw(y2, symbolicO4);
  const mp = polynomialFp2Raw(polynomialTriple(y0, y1, y2), op);
  const mm = polynomialFp2Raw(polynomialFp2Add(polynomialFp2Sub(y0, y1), y2), om);
  const numerators = [...polynomialFp2Sub(mp, mm), ...polynomialFp2Add(mp, mm)];
  if (numerators.length !== numeratorIntervals.length) throw new Error(`${label} numerator inventory changed`);
  const halves = numerators.map((numerator, index) => {
    if (![...numerator.values()].every((coefficient) => coefficient % 2n === 0n)) {
      throw new Error(`${label} interpolation numerator ${index} is not identically even`);
    }
    if (numeratorIntervals[index].lo >= 0n || numeratorIntervals[index].hi <= 0n) {
      throw new Error(`${label} interpolation numerator ${index} no longer covers negative and positive values`);
    }
    return new Map([...numerator].map(([key, coefficient]) => [key, coefficient / 2n]));
  });
  const differenceHalf = halves.slice(0, 2);
  const sumHalf = halves.slice(2, 4);
  requirePolynomialPair(`${label}.differenceHalf`, differenceHalf,
    polynomialFp2Add(polynomialFp2Raw(y0, symbolicO4),
      polynomialFp2Add(polynomialFp2Raw(y1, symbolicO3), polynomialFp2Raw(y2, symbolicO4))));
  requirePolynomialPair(`${label}.sumHalf`, sumHalf,
    polynomialFp2Add(polynomialFp2Raw(y0, symbolicO3),
      polynomialFp2Add(polynomialFp2Raw(y1, symbolicO4), polynomialFp2Raw(y2, symbolicO3))));
  requirePolynomialPair(`${label}.t2`, polynomialFp2Sub(differenceHalf, m3),
    polynomialFp2Add(polynomialFp2Raw(y0, symbolicO4), polynomialFp2Raw(y1, symbolicO3)));
  requirePolynomialPair(`${label}.t4`, polynomialFp2Sub(sumHalf, m0),
    polynomialFp2Add(polynomialFp2Raw(y1, symbolicO4), polynomialFp2Raw(y2, symbolicO3)));
};
const symbolicF = Array.from({ length: 12 }, (_, index) => polynomial(`F${index}`));
const symbolicO3 = [polynomial('o3a'), polynomial('o3b')];
const symbolicO4 = [polynomial('o4a'), polynomial('o4b')];
const numeratorIntervals = (label) => directIntermediates
  .filter(([name]) => name.startsWith(`${label}.differenceNumerator.`) ||
    name.startsWith(`${label}.sumNumerator.`))
  .map(([, value]) => value);
provePolynomialSparseProduct('y', symbolicF.slice(6, 12), numeratorIntervals('y'));
provePolynomialSparseProduct('x', symbolicF.slice(0, 6), numeratorIntervals('x'));

if (RAW_BIAS !== 132793n * P * P || RAW_BIAS % P !== 0n) {
  throw new Error('mul034Unit bias is not exactly 132,793*p^2');
}
karatsubaOutputs.forEach((output, index) => {
  if (output.lo + RAW_BIAS <= 0n) {
    throw new Error(`mul034Unit output ${index} can remain nonpositive after bias`);
  }
  if (output.hi + RAW_BIAS >= 1n << 536n) {
    throw new Error(`mul034Unit output ${index} exceeds 67 unsigned bytes`);
  }
});

// Line source ranges. Runtime c0=Y-mX+p is in [1,2p-1], runtime c1 is a
// canonical slope, fixed coefficients are normalized canonically, and u/v are
// canonical after canonicalFp. The direct pre-products are therefore
// nonnegative, and %p makes o3/o4 canonical in all cases.
if (runtimeC0.lo < 0n || runtimeC0.hi >= 2n * P) throw new Error('runtime c0 source bound changed');
for (const [label, source] of [
  ['runtime c0', runtimeC0],
  ['runtime c1', canonical],
  ['fixed c0', fixedC0],
  ['fixed c1', canonical],
]) {
  if (source.lo < 0n || canonical.lo < 0n) throw new Error(`${label} product source can be negative`);
  if (canonical.lo !== 0n || canonical.hi !== P - 1n) {
    throw new Error(`${label} sparse product is not canonical after reduction`);
  }
}

const directReducedOutputs = directRawOutputs.map(remainderModP);
directReducedOutputs.forEach((output, index) => {
  if (output.lo !== 1n - P || output.hi !== P - 1n || vmNumberBytes(output) !== 32) {
    throw new Error(`lineUnitDirect output ${index} signed remainder bound changed`);
  }
});
const widestDirectIntermediate = directIntermediates.reduce((widest, item) =>
  vmNumberBytes(item[1]) > vmNumberBytes(widest[1]) ? item : widest);
const BCH_2026_VM_NUMBER_LIMIT = 10_000;
if (vmNumberBytes(widestDirectIntermediate[1]) > BCH_2026_VM_NUMBER_LIMIT) {
  throw new Error(`lineUnitDirect exceeds the BCH 2026 VM-number limit at ${widestDirectIntermediate[0]}`);
}
// Keep this tight enough to catch an accidental return to much wider algebra,
// while the consensus check above states the actual protocol limit.
if (vmNumberBytes(widestDirectIntermediate[1]) !== 65) {
  throw new Error(`lineUnitDirect maximum intermediate width changed: ` +
    `${widestDirectIntermediate[0]}=${vmNumberBytes(widestDirectIntermediate[1])} bytes`);
}

const min = karatsubaOutputs.reduce((x, y) => x < y.lo ? x : y.lo, karatsubaOutputs[0].lo);
const max = karatsubaOutputs.reduce((x, y) => x > y.hi ? x : y.hi, karatsubaOutputs[0].hi);
const directMin = directRawOutputs.reduce((x, y) => x < y.lo ? x : y.lo, directRawOutputs[0].lo);
const directMax = directRawOutputs.reduce((x, y) => x > y.hi ? x : y.hi, directRawOutputs[0].hi);
const ceiling = (x, y) => (x + y - 1n) / y;
console.log('mul034Unit interval proof passed');
console.log(`raw outputs: [-${ceiling(-min, P * P)}, ${ceiling(max, P * P)}] * p^2 (inclusive outer bound)`);
console.log(`biased maximum: ${(max + RAW_BIAS).toString(2).length} bits; all 12 biased minima are positive`);
console.log('lineUnitDirect eight-product interval/parity proof passed');
console.log(`direct raw outputs: [-${ceiling(-directMin, P * P)}, ${ceiling(directMax, P * P)}] * p^2 (inclusive outer bound)`);
console.log(`all 8 signed interpolation numerators are identically even; >>1 is exact`);
console.log(`widest direct intermediate: ${widestDirectIntermediate[0]} ` +
  `(${vmNumberBytes(widestDirectIntermediate[1])} bytes); outputs are signed 32-byte remainders`);
console.log('runtime and fixed line products reduce to canonical sparse limbs');
