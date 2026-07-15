// Whole-source bound analysis for the lazy BLS12-381 tower.
//
// Every number is an upper bound in field-modulus units: b means 0 <= x < b*p.
// The model follows Bls12381Lazy.cash top to bottom. Multiplication and scaling reduce
// modulo p; addition sums bounds; a subtraction x-y+k*p is nonnegative when k >= bound(y)
// and then has bound(x)+k. The direct fp2Mul and mul014 kernels reduce their final limbs,
// but retain their former lazy output bounds here so their own input proofs are not circular.
//
// Run: node singleton/bls12-381/bound_analysis.mjs

import assert from 'node:assert/strict';
import { bigIntToVmNumber } from '@bitauth/libauth';

const P = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;

const sites = new Map();
const record = (site, bias) => {
  sites.set(site, Math.max(sites.get(site) ?? 0, bias));
  return bias;
};

const f2add = (a, b) => [a[0] + b[0], a[1] + b[1]];
const f2sub = (site, a, b) => {
  const bias = record(site, Math.max(...b));
  return [a[0] + bias, a[1] + bias];
};
const f2neg = (site, a) => {
  const bias = record(site, Math.max(...a));
  return [bias, bias];
};
const f2scale = () => [1, 1];

let maxFp2MulInput = 0;
let maxFp2MulNegative = 0;
let maxFp2SqrInput = 0;
const f2mul = (a, b) => {
  maxFp2MulInput = Math.max(maxFp2MulInput, ...a, ...b);
  maxFp2MulNegative = Math.max(maxFp2MulNegative, a[1] * b[1]);
  return [2, 3];
};
const f2sqr = (site, a) => {
  maxFp2SqrInput = Math.max(maxFp2SqrInput, ...a);
  record(site, a[1]);
  return [1, 1];
};
const f2mulXi = (site, a) => {
  const bias = record(site, a[1]);
  return [a[0] + bias, a[0] + a[1]];
};
const f2mulByB = () => {
  record('fp2MulByB.c0', 1);
  return [2, 2];
};
const f2half = () => [1, 1];
const f2conj = (site, a) => {
  record(site, a[1]);
  return a.slice();
};

const split6 = (x) => [x.slice(0, 2), x.slice(2, 4), x.slice(4, 6)];
const join6 = (a, b, c) => [...a, ...b, ...c];
const f6add = (a, b) => {
  const A = split6(a), B = split6(b);
  return join6(f2add(A[0], B[0]), f2add(A[1], B[1]), f2add(A[2], B[2]));
};
const f6sub = (site, a, b) => {
  const bias = record(site, Math.max(...b));
  return a.map((bound) => bound + bias);
};
const f6neg = (site, a) => {
  const bias = record(site, Math.max(...a));
  return a.map(() => bias);
};
const f6mulByV = (site, a) => {
  const A = split6(a);
  return join6(f2mulXi(site, A[2]), A[0], A[1]);
};

function f6mul(a, b) {
  const A = split6(a), B = split6(b);
  const t0 = f2mul(A[0], B[0]);
  const t1 = f2mul(A[1], B[1]);
  const t2 = f2mul(A[2], B[2]);
  const p1 = f2mul(f2add(A[1], A[2]), f2add(B[1], B[2]));
  const d1 = f2sub('fp6Mul.d1', p1, t1);
  const d2 = f2sub('fp6Mul.d2', d1, t2);
  const c0 = f2add(t0, f2mulXi('fp6Mul.x1', d2));
  const p2 = f2mul(f2add(A[0], A[1]), f2add(B[0], B[1]));
  const d3 = f2sub('fp6Mul.d3', p2, t0);
  const d4 = f2sub('fp6Mul.d4', d3, t1);
  const c1 = f2add(d4, f2mulXi('fp6Mul.x2', t2));
  const p3 = f2mul(f2add(A[0], A[2]), f2add(B[0], B[2]));
  const d5 = f2sub('fp6Mul.d5', p3, t0);
  const d6 = f2sub('fp6Mul.d6', d5, t2);
  return join6(c0, c1, f2add(d6, t1));
}

function f6mul01(c, b0, b1, prefix = 'fp6Mul01') {
  const C = split6(c);
  const t0 = f2mul(C[0], b0), t1 = f2mul(C[1], b1);
  const m12 = f2mul(f2add(C[1], C[2]), b1);
  const u0 = f2sub(`${prefix}.u0`, m12, t1);
  const r0 = f2add(f2mulXi(`${prefix}.xu0`, u0), t0);
  const m1 = f2mul(f2add(b0, b1), f2add(C[0], C[1]));
  const u1 = f2sub(`${prefix}.u1`, m1, t0);
  const r1 = f2sub(`${prefix}.r1`, u1, t1);
  const m2 = f2mul(f2add(C[0], C[2]), b0);
  const u2 = f2sub(`${prefix}.u2`, m2, t0);
  return join6(r0, r1, f2add(u2, t1));
}

function f6mul1(c, b1) {
  const C = split6(c);
  const m2 = f2mul(C[2], b1);
  return join6(f2mulXi('fp6Mul1.r0', m2), f2mul(C[0], b1), f2mul(C[1], b1));
}

const split12 = (x) => [x.slice(0, 6), x.slice(6, 12)];
function f12sqr(a) {
  const [a0, a1] = split12(a);
  const t0 = f6mul(a0, a1);
  const t1 = f6mul(f6add(a0, a1), f6add(a0, f6mulByV('fp12Sqr.vc', a1)));
  const c6 = f6add(t0, t0);
  const d = f6sub('fp12Sqr.d', t1, t0);
  return [...f6sub('fp12Sqr.c0', d, f6mulByV('fp12Sqr.vt0', t0)), ...c6];
}

function f12mul(a, b) {
  const [a0, a1] = split12(a), [b0, b1] = split12(b);
  const t0 = f6mul(a0, b0), t1 = f6mul(a1, b1);
  const c0 = f6add(t0, f6mulByV('fp12Mul.vt', t1));
  const pr = f6mul(f6add(a0, a1), f6add(b0, b1));
  const q = f6sub('fp12Mul.q', pr, t0);
  return [...c0, ...f6sub('fp12Mul.c6', q, t1)];
}

const f12conj = (a) => {
  const [a0, a1] = split12(a);
  return [...a0, ...f6neg('fp12Conj.neg', a1)];
};
const f6frobOdd = (x, prefix) => {
  const X = split6(x);
  return join6(
    f2conj(`${prefix}.d0`, X[0]),
    f2mul(f2conj(`${prefix}.c1`, X[1]), [1, 1]),
    f2mul(f2conj(`${prefix}.c2`, X[2]), [1, 1]),
  );
};
const f6frobEven = (x) => {
  const X = split6(x);
  return join6(X[0], f2mul(X[1], [1, 1]), f2mul(X[2], [1, 1]));
};
const f6mulByFp2 = (x) => {
  const X = split6(x);
  return join6(f2mul(X[0], [1, 1]), f2mul(X[1], [1, 1]), f2mul(X[2], [1, 1]));
};
const f12frobOdd = (a, prefix) => {
  const [a0, a1] = split12(a);
  return [...f6frobOdd(a0, `${prefix}.a`), ...f6mulByFp2(f6frobOdd(a1, `${prefix}.b`))];
};
const f12frobEven = (a) => {
  const [a0, a1] = split12(a);
  return [...f6frobEven(a0), ...f6mulByFp2(f6frobEven(a1))];
};

function fp4square(a, b) {
  const a2 = f2sqr('fp2Sqr.diff', a), b2 = f2sqr('fp2Sqr.diff', b);
  const f = f2add(f2mulXi('fp4Square.xbi', b2), a2);
  const absq = f2sqr('fp2Sqr.diff', f2add(a, b));
  const sub1 = f2sub('fp4Square.sub1', absq, a2);
  return [f, f2sub('fp4Square.s0', sub1, b2)];
}

function cycSqr(a) {
  const A = Array.from({ length: 6 }, (_, i) => a.slice(i * 2, i * 2 + 2));
  const [t3, t4] = fp4square(A[0], A[4]);
  const [t5, t6] = fp4square(A[3], A[2]);
  const [t7, t8] = fp4square(A[1], A[5]);
  const t9 = f2mulXi('cycSqr.t9', t8);
  const z0 = f2sub('cycSqr.z0', t3, A[0]);
  const z1 = f2sub('cycSqr.z1', t5, A[1]);
  const z2 = f2sub('cycSqr.z2', t7, A[2]);
  const z3 = f2add(t9, A[3]);
  const z4 = f2add(t4, A[4]);
  const z5 = f2add(t6, A[5]);
  return [
    ...f2add(f2scale(z0), t3),
    ...f2add(f2scale(z1), t5),
    ...f2add(f2scale(z2), t7),
    ...f2add(f2scale(z3), t9),
    ...f2add(f2scale(z4), t4),
    ...f2add(f2scale(z5), t6),
  ];
}

const interval = (lo, hi) => ({ lo, hi });
const intervalAdd = (a, b) => interval(a.lo + b.lo, a.hi + b.hi);
const intervalSub = (a, b) => interval(a.lo - b.hi, a.hi - b.lo);
const rawFp2 = (a, b) => [
  interval(-a[1] * b[1], a[0] * b[0]),
  interval(0, a[0] * b[1] + a[1] * b[0]),
];
const rawFp2Add = (a, b) => [intervalAdd(a[0], b[0]), intervalAdd(a[1], b[1])];
const rawFp2Sub = (a, b) => [intervalSub(a[0], b[0]), intervalSub(a[1], b[1])];
const rawFp2Xi = (a) => [intervalSub(a[0], a[1]), intervalAdd(a[0], a[1])];
const boundsAdd = (a, b) => [a[0] + b[0], a[1] + b[1]];

const rawFp6Mul01 = (c, b0, b1) => {
  const C = split6(c);
  const t0 = rawFp2(C[0], b0), t1 = rawFp2(C[1], b1);
  const m12 = rawFp2(boundsAdd(C[1], C[2]), b1);
  const r0 = rawFp2Add(rawFp2Xi(rawFp2Sub(m12, t1)), t0);
  const m1 = rawFp2(boundsAdd(b0, b1), boundsAdd(C[0], C[1]));
  const r1 = rawFp2Sub(rawFp2Sub(m1, t0), t1);
  const m2 = rawFp2(boundsAdd(C[0], C[2]), b0);
  const r2 = rawFp2Add(rawFp2Sub(m2, t0), t1);
  return [...r0, ...r1, ...r2];
};
const rawFp6Mul1 = (c, b1) => {
  const C = split6(c);
  return [
    ...rawFp2Xi(rawFp2(C[2], b1)),
    ...rawFp2(C[0], b1),
    ...rawFp2(C[1], b1),
  ];
};
const rawFp6Add = (a, b) => a.map((value, i) => intervalAdd(value, b[i]));
const rawFp6Sub = (a, b) => a.map((value, i) => intervalSub(value, b[i]));
const rawFp6MulByV = (a) => [...rawFp2Xi(a.slice(4, 6)), ...a.slice(0, 4)];

let maxMul014Input = 0;
let maxMul014Negative = 0;
let maxMul014Positive = 0;
function recordRawMul014(f, o0, o1, o4) {
  maxMul014Input = Math.max(maxMul014Input, ...f, ...o0, ...o1, ...o4);
  const [f0, f1] = split12(f);
  const T = rawFp6Mul01(f0, o0, o1);
  const U = rawFp6Mul1(f1, o4);
  const c0 = rawFp6Add(rawFp6MulByV(U), T);
  const G = rawFp6Mul01(f6add(f1, f0), o0, f2add(o1, o4));
  const c6 = rawFp6Sub(rawFp6Sub(G, T), U);
  const outputs = [...c0, ...c6];
  maxMul014Negative = Math.max(maxMul014Negative, ...outputs.map(({ lo }) => Math.max(0, -lo)));
  maxMul014Positive = Math.max(maxMul014Positive, ...outputs.map(({ hi }) => hi));
}

function mul014(f, o0, o1, o4) {
  recordRawMul014(f, o0, o1, o4);
  const [f0, f1] = split12(f);
  const T = f6mul01(f0, o0, o1, 'mul014.T');
  const U = f6mul1(f1, o4);
  const c0 = f6add(f6mulByV('mul014.V', U), T);
  const G = f6mul01(f6add(f1, f0), o0, f2add(o1, o4), 'mul014.G');
  const H = f6sub('mul014.H', G, T);
  return [...c0, ...f6sub('mul014.C6', H, U)];
}
const line = (f, c0) => mul014(f, c0, [1, 1], [1, 1]);

function pointDouble(X, Y, Z) {
  const t0 = f2sqr('fp2Sqr.diff', Y), t1 = f2sqr('fp2Sqr.diff', Z);
  const t2 = f2mulByB(f2scale(t1)), t3 = f2scale(t2);
  const sq = f2sqr('fp2Sqr.diff', f2add(Y, Z));
  const u4 = f2sub('pointDouble.u4', sq, t1);
  const t4 = f2sub('pointDouble.t4', u4, t0);
  const c0 = f2sub('pointDouble.c0', t2, t0);
  const c1 = f2scale(f2sqr('fp2Sqr.diff', X));
  const c2 = f2neg('pointDouble.c2', t4);
  const d = f2sub('pointDouble.d', t0, t3);
  const nx = f2half(f2mul(f2mul(d, X), Y));
  const sh2 = f2sqr('fp2Sqr.diff', f2half(f2add(t0, t3)));
  const ny = f2sub('pointDouble.ny', sh2, f2scale(f2sqr('fp2Sqr.diff', t2)));
  const nz = f2mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: [nx, ny, nz] };
}

function pointAdd(X, Y, Z, Qx, Qy) {
  const t0 = f2sub('pointAdd.t0', Y, f2mul(Qy, Z));
  const t1 = f2sub('pointAdd.t1', X, f2mul(Qx, Z));
  const c0 = f2sub('pointAdd.c0', f2mul(t0, Qx), f2mul(t1, Qy));
  const c1 = f2neg('pointAdd.c1', t0);
  const t2 = f2sqr('fp2Sqr.diff', t1);
  const t3 = f2mul(t2, t1), t4 = f2mul(t2, X);
  const d35 = f2sub('pointAdd.d35', t3, f2scale(t4));
  const t5 = f2add(d35, f2mul(f2sqr('fp2Sqr.diff', t0), Z));
  const nx = f2mul(t1, t5);
  const d45 = f2sub('pointAdd.d45', t4, t5);
  const ny = f2sub('pointAdd.ny', f2mul(d45, t0), f2mul(t3, Y));
  return { coeffs: [c0, c1, t1], R: [nx, ny, f2mul(Z, t3)] };
}

const maxBound = (value) => Math.max(...value.flat(Infinity));
const ONE12 = Array(12).fill(1);

let f = ONE12.slice();
let R = [[1, 1], [1, 1], [1, 1]];
let millerConverged = false;
for (let iteration = 0; iteration < 200; iteration += 1) {
  let next = f12sqr(f);
  next = f12mul(next, ONE12);
  const doubled = pointDouble(R[0], R[1], R[2]);
  next = line(next, doubled.coeffs[0]);
  next = line(next, [1, 1]);
  next = line(next, [1, 1]);
  const added = pointAdd(doubled.R[0], doubled.R[1], doubled.R[2], [1, 1], [1, 1]);
  next = line(next, added.coeffs[0]);
  const before = JSON.stringify([f, R]);
  f = next;
  R = added.R;
  if (JSON.stringify([f, R]) === before) {
    console.log(`Miller bounds stabilize after ${iteration + 1} iterations`);
    millerConverged = true;
    break;
  }
}
assert(millerConverged, 'Miller bounds did not converge');
console.log(`Miller carried f <= ${maxBound(f)}p, R <= ${maxBound(R)}p`);

let tail = ONE12.slice();
let tailConverged = false;
for (let iteration = 0; iteration < 200; iteration += 1) {
  const next = f12mul(f12sqr(tail), ONE12);
  if (JSON.stringify(next) === JSON.stringify(tail)) {
    console.log(`residue-tail bounds stabilize after ${iteration + 1} iterations`);
    tailConverged = true;
    break;
  }
  tail = next;
}
assert(tailConverged, 'residue-tail bounds did not converge');
console.log(`residue-tail carried value <= ${maxBound(tail)}p`);

let global = Math.max(maxBound(f), maxBound(R), maxBound(tail));
let sourceConverged = false;
for (let iteration = 0; iteration < 100; iteration += 1) {
  const high12 = Array(12).fill(global);
  const next = Math.max(
    global,
    maxBound(f12sqr(high12)),
    maxBound(f12mul(high12, high12)),
    maxBound(f12conj(high12)),
    maxBound(f12frobOdd(high12, 'fp12FrobOdd')),
    maxBound(f12frobEven(high12)),
    maxBound(cycSqr(high12)),
  );
  if (next === global) {
    console.log(`whole-source bound stabilizes at ${global}p after ${iteration + 1} iterations`);
    sourceConverged = true;
    break;
  }
  global = next;
}
assert(sourceConverged, 'whole-source bounds did not converge');
// The non-residue Miller generator can terminate after any whole-source fp12 path.
record('generator.finalConj', global);

// Exercise the canonical proof-input negations emitted by the residue generator.
f2neg('generator.negY', [1, 1]);
f2neg('generator.negPsiY', [1, 1]);

const expectedBiases = new Map(Object.entries({
  'cycSqr.t9': 3,
  'cycSqr.z0': 62,
  'cycSqr.z1': 62,
  'cycSqr.z2': 62,
  'fp12Conj.neg': 62,
  'fp12FrobOdd.a.c1': 62,
  'fp12FrobOdd.a.c2': 62,
  'fp12FrobOdd.a.d0': 62,
  'fp12FrobOdd.b.c1': 62,
  'fp12FrobOdd.b.c2': 62,
  'fp12FrobOdd.b.d0': 62,
  'fp12Mul.c6': 20,
  'fp12Mul.q': 20,
  'fp12Mul.vt': 12,
  'fp12Sqr.c0': 22,
  'fp12Sqr.d': 20,
  'fp12Sqr.vc': 62,
  'fp12Sqr.vt0': 12,
  'fp2MulByB.c0': 1,
  'fp2Sqr.diff': 124,
  'fp4Square.s0': 1,
  'fp4Square.sub1': 1,
  'fp4Square.xbi': 1,
  'fp6Mul.d1': 3,
  'fp6Mul.d2': 3,
  'fp6Mul.d3': 3,
  'fp6Mul.d4': 3,
  'fp6Mul.d5': 3,
  'fp6Mul.d6': 3,
  'fp6Mul.x1': 9,
  'fp6Mul.x2': 3,
  'fp6Mul1.r0': 3,
  'generator.finalConj': 62,
  'generator.negPsiY': 1,
  'generator.negY': 1,
  'mul014.C6': 5,
  'mul014.G.r1': 3,
  'mul014.G.u0': 3,
  'mul014.G.u1': 3,
  'mul014.G.u2': 3,
  'mul014.G.xu0': 6,
  'mul014.H': 14,
  'mul014.T.r1': 3,
  'mul014.T.u0': 3,
  'mul014.T.u1': 3,
  'mul014.T.u2': 3,
  'mul014.T.xu0': 6,
  'mul014.V': 3,
  'pointAdd.c0': 3,
  'pointAdd.c1': 5,
  'pointAdd.d35': 1,
  'pointAdd.d45': 7,
  'pointAdd.ny': 3,
  'pointAdd.t0': 3,
  'pointAdd.t1': 3,
  'pointDouble.c0': 1,
  'pointDouble.c2': 3,
  'pointDouble.d': 1,
  'pointDouble.ny': 1,
  'pointDouble.t4': 1,
  'pointDouble.u4': 1,
}));
assert.deepEqual([...sites].sort(), [...expectedBiases].sort(), 'source subtraction biases changed');
assert.equal(maxFp2MulInput, 310);
assert.equal(maxFp2MulNegative, 76880);
assert.equal(maxFp2SqrInput, 124);
assert.equal(2 * maxFp2SqrInput * maxFp2SqrInput, 30752);
assert.equal(maxMul014Input, 60);
assert.equal(maxMul014Negative, 1931);
assert.equal(maxMul014Positive, 2190);
assert.equal(76880n * P * P, 1231562419205459752070235395775242614848400833236532888490220123203481892424015537184642439376752630896474493160328325763231266643412666928375071562129281185156830842074816964836301444694877978129857433900347334309803230379471635168720n);
assert.equal(1931n * P * P, 30933234020366061150463378632179936124769276911807297186194264540919921101336810643906666889132535513281636918478069680655561601046174035362802590875021357551220608169178870435729683789097416438199202716721783331844823593428196247539n);
assert.equal(bigIntToVmNumber(30752n * P * P).length, 98);
assert.equal(bigIntToVmNumber(76880n * P * P).length, 98);

console.log(`max fp2Mul input: ${maxFp2MulInput}p`);
console.log(`max fp2Mul negative term: ${maxFp2MulNegative}p^2`);
console.log(`max fp2Sqr input: ${maxFp2SqrInput}p`);
console.log(`max fp2Sqr direct imaginary product: ${2 * maxFp2SqrInput * maxFp2SqrInput}p^2 (98 signed bytes)`);
console.log(`max mul014 input: ${maxMul014Input}p`);
console.log(`max mul014 negative output: ${maxMul014Negative}p^2`);
console.log(`max mul014 positive output: ${maxMul014Positive}p^2`);
console.log('\nsubtraction bias table:');
for (const [site, bias] of [...sites].sort(([a], [b]) => a.localeCompare(b))) {
  console.log(`  ${site.padEnd(24)} ${bias}p`);
}
console.log(`\nmax subtraction bias: ${Math.max(...sites.values())}p`);
