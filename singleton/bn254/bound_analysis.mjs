// Bound-propagation analyzer for LAZY subtraction (option B) — BAKE-TABLE mode.
//
// Models the EXACT dataflow of miller.cash + finalexp.cash, tracking each value's
// magnitude bound b (0 <= value < b*p) as an integer. Rules:
//   addFp(x,y)        -> b_x + b_y
//   subFp(x,y) bias k -> needs k >= b_y; out bound = b_x + k  (minimal k = b_y)
//   mulFp/scale       -> 1   (reduces);   neg(0,y) -> b_y
//   fp2Mul/mul034     -> 1 per source limb (raw expressions are biased nonnegative, then reduced)
// The fp2Mul model intentionally returns its former [2,3] bounds after recording safety data, so
// its proof cannot depend on the canonical output it is proving. The mul034 model returns [1,...].
//
// Sites are labeled FUNCTION-LOCALLY (not caller-prefixed). Because every field
// function's internal sub biases are caller-INDEPENDENT (internal muls reset input
// dependence), recordSub() taking the max across all callers yields exactly the
// constant bias to bake at each source location. The few input-subtracting sites
// (cycSqr.z*, fp12conj, frob conj) are pinned by the worst-case probe (global max
// carried bound). One bias per fp2Sub/fp6Sub CALL (coarse: max over limbs).
// Run: node bound_analysis.mjs

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const FP2_INPUT_BOUND = 149;
const FP2_NEGATIVE_BIAS = FP2_INPUT_BOUND ** 2;
const MUL034_INPUT_BOUND = 37;
const MUL034_NEGATIVE_COEFFICIENT = 97;
const MUL034_RAW_BIAS = MUL034_NEGATIVE_COEFFICIENT * MUL034_INPUT_BOUND ** 2;
const FP2_NEGATIVE_BIAS_LITERAL = 10636392002745043725054576591855484724484200679306969358911577657842610149931283249579519191443340195632349945621165638913026711333532969846898571500690003689n;
const MUL034_RAW_BIAS_LITERAL = 63620485708775397116398918488458420026955112869114471513803213004724729950895225285411156794258613332669998933780976023070021894424298169671600468685695583977n;

if (FP2_NEGATIVE_BIAS_LITERAL !== BigInt(FP2_NEGATIVE_BIAS) * P * P) {
  throw new Error('fp2Mul bias literal is not exactly 22,201*p^2');
}
if (MUL034_RAW_BIAS_LITERAL !== BigInt(MUL034_RAW_BIAS) * P * P) {
  throw new Error('mul034 bias literal is not exactly 132,793*p^2');
}

const sites = new Map();
function rec(site, by) { if (!sites.has(site) || sites.get(site) < by) sites.set(site, by); return by; }

const add = (x, y) => x + y;
const mul = () => 1;

// Fp2 = [b0,b1]. Each wrapper records ONE bias = max over its limb y-operands.
const f2add = (a, b) => [a[0] + b[0], a[1] + b[1]];
const f2sub = (s, a, b) => { const k = rec(s, Math.max(b[0], b[1])); return [a[0] + k, a[1] + k]; };
const f2neg = (s, a) => { const k = rec(s, Math.max(a[0], a[1])); return [k, k]; };
const f2scale = () => [1, 1];
let maxF2MulInputBound = 0;
let maxF2MulNegativeBound = 0;
const f2mul = (a, b) => {
  maxF2MulInputBound = Math.max(maxF2MulInputBound, ...a, ...b);
  // The first raw limb is a0*b0-a1*b1; the second is a0*b1+a1*b0 >= 0.
  maxF2MulNegativeBound = Math.max(maxF2MulNegativeBound, a[1] * b[1]);
  // Keep the former lazy-output bounds here. This deliberately avoids using
  // fp2Mul's new canonical output to prove the input domain that makes it safe.
  return [2, 3];
};
const f2sqr = () => { rec('f2sqr.s', 36); return [1, 1]; }; // subFp(a0,a1) feeds mulFp; bias=max input (36); out reduced
const f2mulxi = (s, a) => { const k = rec(s, a[1]); return [1 + k, 1 + a[0]]; };
const f2conj = (s, a) => { rec(s, a[1]); return [a[0], a[1]]; };
const f2mulByB = (a) => f2mul(a, [1, 1]);
const f2half = () => [1, 1];

const split6 = (x) => [[x[0], x[1]], [x[2], x[3]], [x[4], x[5]]];
const join6 = (a, b, c) => [...a, ...b, ...c];
const f6add = (a, b) => { const A = split6(a), B = split6(b); return join6(f2add(A[0], B[0]), f2add(A[1], B[1]), f2add(A[2], B[2])); };
const f6sub = (s, a, b) => { const k = rec(s, Math.max(...b)); return a.map((x) => x + k); };
const f6neg = (s, a) => { const k = rec(s, Math.max(...a)); return a.map(() => k); };
const f6mulByV = (s, a) => { const A = split6(a); return join6(f2mulxi(s, A[2]), A[0], A[1]); };
function f6mul(a, b) {
  const A = split6(a), B = split6(b);
  const t0 = f2mul(A[0], B[0]), t1 = f2mul(A[1], B[1]), t2 = f2mul(A[2], B[2]);
  const p1 = f2mul(f2add(A[1], A[2]), f2add(B[1], B[2]));
  const d1 = f2sub('f6mul.d1', p1, t1); const d2 = f2sub('f6mul.d2', d1, t2);
  const x1 = f2mulxi('f6mul.x1', d2); const c0 = f2add(t0, x1);
  const p2 = f2mul(f2add(A[0], A[1]), f2add(B[0], B[1]));
  const d3 = f2sub('f6mul.d3', p2, t0); const d4 = f2sub('f6mul.d4', d3, t1);
  const x2 = f2mulxi('f6mul.x2', t2); const c1 = f2add(d4, x2);
  const p3 = f2mul(f2add(A[0], A[2]), f2add(B[0], B[2]));
  const d5 = f2sub('f6mul.d5', p3, t0); const d6 = f2sub('f6mul.d6', d5, t2);
  const c2 = f2add(d6, t1);
  return join6(c0, c1, c2);
}
function f6mul01(c, b0, b1) {
  const C = split6(c);
  const t0 = f2mul(C[0], b0), t1 = f2mul(C[1], b1);
  const m12 = f2mul(f2add(C[1], C[2]), b1);
  const u0 = f2sub('f6mul01.u0', m12, t1); const xu0 = f2mulxi('f6mul01.xu0', u0); const r0 = f2add(xu0, t0);
  const m1 = f2mul(f2add(b0, b1), f2add(C[0], C[1]));
  const u1 = f2sub('f6mul01.u1', m1, t0); const r1 = f2sub('f6mul01.r1', u1, t1);
  const m2 = f2mul(f2add(C[0], C[2]), b0);
  const u2 = f2sub('f6mul01.u2', m2, t0); const r2 = f2add(u2, t1);
  return join6(r0, r1, r2);
}
const split12 = (x) => [x.slice(0, 6), x.slice(6, 12)];
function f12mul(A, B) {
  const [a0, a1] = split12(A), [b0, b1] = split12(B);
  const t0 = f6mul(a0, b0), t1 = f6mul(a1, b1);
  const C0 = f6add(t0, f6mulByV('f12mul.vt', t1));
  const pr = f6mul(f6add(a0, a1), f6add(b0, b1));
  const qq = f6sub('f12mul.qq', pr, t0);
  const C6 = f6sub('f12mul.C6', qq, t1);
  return [...C0, ...C6];
}
function f12sqr(A) {
  const [a0, a1] = split12(A);
  const t0 = f6mul(a0, a1);
  const t1 = f6mul(f6add(a0, a1), f6add(a0, f6mulByV('f12sqr.vc', a1)));
  const C6 = f6add(t0, t0);
  const d = f6sub('f12sqr.d', t1, t0);
  const C0 = f6sub('f12sqr.C0', d, f6mulByV('f12sqr.vt0', t0));
  return [...C0, ...C6];
}
const f12conj = (A) => { const [a0, a1] = split12(A); return [...a0, ...f6neg('f12conj.neg', a1)]; };

const interval = (lo, hi) => ({ lo, hi });
const intervalAdd = (a, b) => interval(a.lo + b.lo, a.hi + b.hi);
const intervalSub = (a, b) => interval(a.lo - b.hi, a.hi - b.lo);
const intervalScale = (k, a) => k >= 0
  ? interval(k * a.lo, k * a.hi)
  : interval(k * a.hi, k * a.lo);
const rawFp2Bounds = (a, b) => [
  interval(-a[1] * b[1], a[0] * b[0]),
  interval(0, a[0] * b[1] + a[1] * b[0]),
];

let maxMul034InputBound = 0;
let maxMul034NegativeBound = 0;
let maxMul034PositiveBound = 0;
function mul034(F, o0, o3, o4) {
  const M = Math.max(...F, ...o0, ...o3, ...o4);
  maxMul034InputBound = Math.max(maxMul034InputBound, M);

  // Re-run the direct CashScript algebra over intervals. All source limbs are
  // nonnegative and less than M*p; the resulting intervals are in p^2 units.
  const f = Array(12).fill(M);
  const q0 = [M, M];
  const q3 = [M, M];
  const q4 = [M, M];

  const A = [
    ...rawFp2Bounds(f.slice(0, 2), q0),
    ...rawFp2Bounds(f.slice(2, 4), q0),
    ...rawFp2Bounds(f.slice(4, 6), q0),
  ];

  const bt0 = rawFp2Bounds(f.slice(6, 8), q3);
  const bt1 = rawFp2Bounds(f.slice(8, 10), q4);
  const bm12 = rawFp2Bounds([f[8] + f[10], f[9] + f[11]], q4);
  const bu0 = [intervalSub(bm12[0], bt1[0]), intervalSub(bm12[1], bt1[1])];
  const B = [
    intervalAdd(intervalSub(intervalScale(9, bu0[0]), bu0[1]), bt0[0]),
    intervalAdd(intervalAdd(bu0[0], intervalScale(9, bu0[1])), bt0[1]),
  ];
  const bm1 = rawFp2Bounds(
    [q3[0] + q4[0], q3[1] + q4[1]],
    [f[6] + f[8], f[7] + f[9]],
  );
  B.push(
    intervalSub(intervalSub(bm1[0], bt0[0]), bt1[0]),
    intervalSub(intervalSub(bm1[1], bt0[1]), bt1[1]),
  );
  const bm2 = rawFp2Bounds([f[6] + f[10], f[7] + f[11]], q3);
  B.push(
    intervalAdd(intervalSub(bm2[0], bt0[0]), bt1[0]),
    intervalAdd(intervalSub(bm2[1], bt0[1]), bt1[1]),
  );

  const S = f.slice(0, 6).map((x, i) => x + f[i + 6]);
  const q = [q0[0] + q3[0], q0[1] + q3[1]];
  const gt0 = rawFp2Bounds(S.slice(0, 2), q);
  const gt1 = rawFp2Bounds(S.slice(2, 4), q4);
  const gm12 = rawFp2Bounds([S[2] + S[4], S[3] + S[5]], q4);
  const gu0 = [intervalSub(gm12[0], gt1[0]), intervalSub(gm12[1], gt1[1])];
  const G = [
    intervalAdd(intervalSub(intervalScale(9, gu0[0]), gu0[1]), gt0[0]),
    intervalAdd(intervalAdd(gu0[0], intervalScale(9, gu0[1])), gt0[1]),
  ];
  const gm1 = rawFp2Bounds(
    [q[0] + q4[0], q[1] + q4[1]],
    [S[0] + S[2], S[1] + S[3]],
  );
  G.push(
    intervalSub(intervalSub(gm1[0], gt0[0]), gt1[0]),
    intervalSub(intervalSub(gm1[1], gt0[1]), gt1[1]),
  );
  const gm2 = rawFp2Bounds([S[0] + S[4], S[1] + S[5]], q);
  G.push(
    intervalAdd(intervalSub(gm2[0], gt0[0]), gt1[0]),
    intervalAdd(intervalSub(gm2[1], gt0[1]), gt1[1]),
  );

  const outputs = [
    intervalAdd(intervalSub(intervalScale(9, B[4]), B[5]), A[0]),
    intervalAdd(intervalAdd(B[4], intervalScale(9, B[5])), A[1]),
    intervalAdd(B[0], A[2]),
    intervalAdd(B[1], A[3]),
    intervalAdd(B[2], A[4]),
    intervalAdd(B[3], A[5]),
    intervalSub(intervalSub(G[0], A[0]), B[0]),
    intervalSub(intervalSub(G[1], A[1]), B[1]),
    intervalSub(intervalSub(G[2], A[2]), B[2]),
    intervalSub(intervalSub(G[3], A[3]), B[3]),
    intervalSub(intervalSub(G[4], A[4]), B[4]),
    intervalSub(intervalSub(G[5], A[5]), B[5]),
  ];
  maxMul034NegativeBound = Math.max(maxMul034NegativeBound, ...outputs.map((x) => -x.lo));
  maxMul034PositiveBound = Math.max(maxMul034PositiveBound, ...outputs.map((x) => x.hi));
  return Array(12).fill(1);
}
const line = (F, c0, c1, c2) => mul034(F, [1, 1], [1, 1], c0);
function pointDouble(X, Y, Z) {
  const t0 = f2sqr(), t1 = f2sqr();
  const t2 = f2mulByB(f2scale()); const t3 = f2scale();
  const sq = f2sqr();
  const u4 = f2sub('pD.u4', sq, t1); const t4 = f2sub('pD.t4', u4, t0);
  const c0 = f2sub('pD.c0', t2, t0);
  const c1 = f2scale(); const c2 = f2neg('pD.c2', t4);
  const d = f2sub('pD.d', t0, t3);
  const dx = f2mul(d, X); const dxy = f2mul(dx, Y); const nx = f2half();
  const sh2 = f2sqr(); const t2s3 = f2scale();
  const ny = f2sub('pD.ny', sh2, t2s3);
  const nz = f2mul(t0, t4);
  return { coeffs: [c0, c1, c2], R: [nx, ny, nz] };
}
function pointAdd(X, Y, Z, Qx, Qy) {
  const qyz = f2mul(Qy, Z); const t0 = f2sub('pA.t0', Y, qyz);
  const qxz = f2mul(Qx, Z); const t1 = f2sub('pA.t1', X, qxz);
  const t0qx = f2mul(t0, Qx); const t1qy = f2mul(t1, Qy);
  const c0 = f2sub('pA.c0', t0qx, t1qy); const c1 = f2neg('pA.c1', t0); const c2 = t1;
  const t2 = f2sqr(); const t3 = f2mul(t2, t1); const t4 = f2mul(t2, X);
  const d35 = f2sub('pA.d35', t3, f2scale());
  const t0s = f2sqr(); const t0sz = f2mul(t0s, Z); const t5 = f2add(d35, t0sz);
  const nx = f2mul(t1, t5);
  const d45 = f2sub('pA.d45', t4, t5); const d45t0 = f2mul(d45, t0);
  const t3ry = f2mul(t3, Y); const ny = f2sub('pA.ny', d45t0, t3ry);
  const nz = f2mul(Z, t3);
  return { coeffs: [c0, c1, c2], R: [nx, ny, nz] };
}
function psi(x, y) {
  const px = f2mul(f2conj('psi.cx', x), [1, 1]);
  const py = f2mul(f2conj('psi.cy', y), [1, 1]);
  return [px, py];
}
// finalexp
function fp2inv(s, a) { return [1, rec(s, 1)]; } // factor reduced; negFp(mul) bias 1
function fp6inv(c) {
  const C = split6(c);
  const sq0 = f2sqr(); const m21 = f2mul(C[2], C[1]); const xm21 = f2mulxi('f6inv.xm21', m21);
  const t0 = f2sub('f6inv.t0', sq0, xm21);
  const xsq2 = f2mulxi('f6inv.xsq2', f2sqr()); const m01 = f2mul(C[0], C[1]);
  const t1 = f2sub('f6inv.t1', xsq2, m01);
  const m02 = f2mul(C[0], C[2]); const t2 = f2sub('f6inv.t2', f2sqr(), m02);
  const ct1 = f2mul(C[2], t1); const ct2 = f2mul(C[1], t2);
  const x = f2mulxi('f6inv.x', f2add(ct1, ct2));
  const n = f2add(x, f2mul(C[0], t0));
  const f = fp2inv('f6inv.fa', n);
  return join6(f2mul(f, t0), f2mul(f, t1), f2mul(f, t2));
}
const f6frobOdd = (x) => { const X = split6(x); return join6(f2conj('frobO.d0', X[0]), f2mul(f2conj('frobO.c1', X[1]), [1, 1]), f2mul(f2conj('frobO.c2', X[2]), [1, 1])); };
const f6frobEven = (x) => { const X = split6(x); return join6(X[0], f2mul(X[1], [1, 1]), f2mul(X[2], [1, 1])); };
const f6mulByFp2 = (x) => { const X = split6(x); return join6(f2mul(X[0], [1, 1]), f2mul(X[1], [1, 1]), f2mul(X[2], [1, 1])); };
function f12inv(A) {
  const [a0, a1] = split12(A);
  const dn = f6sub('f12inv.dn', f6mul(a0, a0), f6mulByV('f12inv.vc', f6mul(a1, a1)));
  const t = fp6inv(dn);
  return [...f6mul(a0, t), ...f6neg('f12inv.w', f6mul(a1, t))];
}
const f12frob1 = (A) => { const [a0, a1] = split12(A); return [...f6frobOdd(a0), ...f6mulByFp2(f6frobOdd(a1))]; };
const f12frob2 = (A) => { const [a0, a1] = split12(A); return [...f6frobEven(a0), ...f6mulByFp2(f6frobEven(a1))]; };
const f12frob3 = (A) => { const [a0, a1] = split12(A); return [...f6frobOdd(a0), ...f6mulByFp2(f6frobOdd(a1))]; };
function fp4sq(a, b) {
  const a2 = f2sqr(), b2 = f2sqr(); const f = f2add(f2mulxi('fp4.xbi', b2), a2);
  const absq = f2sqr();
  const s0 = f2sub('fp4.s0', f2sub('fp4.sub1', absq, a2), b2);
  return [f, s0];
}
function cycSqr(A) {
  const a = [[A[0], A[1]], [A[2], A[3]], [A[4], A[5]], [A[6], A[7]], [A[8], A[9]], [A[10], A[11]]];
  const [t3, t4] = fp4sq(a[0], a[4]); const [t5, t6] = fp4sq(a[3], a[2]); const [t7, t8] = fp4sq(a[1], a[5]);
  const t9 = f2mulxi('cyc.t9', t8);
  const o0 = f2add([1, 1], t3); f2sub('cyc.z0', t3, a[0]);
  const o1 = f2add([1, 1], t5); f2sub('cyc.z1', t5, a[1]);
  const o2 = f2add([1, 1], t7); f2sub('cyc.z2', t7, a[2]);
  const o3 = f2add([1, 1], t9); const o4 = f2add([1, 1], t4); const o5 = f2add([1, 1], t6);
  return [...o0, ...o1, ...o2, ...o3, ...o4, ...o5];
}

const bmax = (x) => Math.max(...(Array.isArray(x[0]) ? x.flat() : x));
const ONE12 = Array(12).fill(1);

// Miller loop -> fixed point
let f = ONE12.slice(), R = [[1, 1], [1, 1], [1, 1]], prev = '';
for (let it = 0; it < 200; it++) {
  let nf = f12sqr(f);
  const dbl = pointDouble(R[0], R[1], R[2]); nf = line(nf, dbl.coeffs[0], dbl.coeffs[1], dbl.coeffs[2]);
  const ad = pointAdd(dbl.R[0], dbl.R[1], dbl.R[2], [1, 1], [1, 1]); nf = line(nf, ad.coeffs[0], ad.coeffs[1], ad.coeffs[2]);
  f = nf; R = ad.R;
  const sig = JSON.stringify([f, R]); if (sig === prev) { console.log(`miller fixed point iter ${it}`); break; } prev = sig;
}
console.log('miller f max =', bmax(f), 'R max =', bmax(R));

// cyc loop -> fixed point
let Z = ONE12.slice(); prev = '';
for (let it = 0; it < 200; it++) {
  Z = f12mul(cycSqr(Z), ONE12);
  const sig = JSON.stringify(Z); if (sig === prev) { console.log(`cyc fixed point iter ${it}`); break; } prev = sig;
}
console.log('cyc Z max =', bmax(Z));

// worst-case: feed BOTH inputs at running global max until stable
let G = Math.max(bmax(f), bmax(Z));
for (let it = 0; it < 50; it++) {
  const HI = Array(12).fill(G);
  const nG = Math.max(bmax(f12mul(HI, HI)), bmax(cycSqr(HI)), bmax(f12conj(HI)), bmax(f12inv(HI)),
    bmax(f12frob1(HI)), bmax(f12frob2(HI)), bmax(f12frob3(HI)), bmax(f12sqr(HI)), G);
  if (nG === G) { console.log(`worst-case stable at ${G}p (iter ${it})`); break; } G = nG;
}
psi([1, 1], [1, 1]); // body psi (Q reduced)
console.log('GLOBAL max carried bound =', G, 'p\n');
console.log('max fp2Mul input bound =', maxF2MulInputBound, 'p');
console.log('max fp2Mul negative bound =', maxF2MulNegativeBound, 'p^2');
console.log('max mul034 input bound =', maxMul034InputBound, 'p');
console.log('max mul034 negative bound =', maxMul034NegativeBound, 'p^2');
console.log('max mul034 positive bound =', maxMul034PositiveBound, 'p^2\n');

if (maxF2MulInputBound > FP2_INPUT_BOUND) {
  throw new Error(`fp2Mul input bound ${maxF2MulInputBound}p exceeds ${FP2_INPUT_BOUND}p`);
}
if (maxF2MulNegativeBound > FP2_NEGATIVE_BIAS) {
  throw new Error(`fp2Mul needs ${maxF2MulNegativeBound}p^2, bias is ${FP2_NEGATIVE_BIAS}p^2`);
}
if (maxMul034InputBound > MUL034_INPUT_BOUND) {
  throw new Error(`mul034 input bound ${maxMul034InputBound}p exceeds ${MUL034_INPUT_BOUND}p`);
}
if (maxMul034NegativeBound !== MUL034_NEGATIVE_COEFFICIENT * maxMul034InputBound ** 2) {
  throw new Error('mul034 interval expansion no longer has a 97*M^2 negative bound');
}
if (maxMul034NegativeBound > MUL034_RAW_BIAS) {
  throw new Error(`mul034 needs ${maxMul034NegativeBound}p^2, bias is ${MUL034_RAW_BIAS}p^2`);
}

// ===== bake-table =====
const tab = [...sites.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
console.log('=== BAKE TABLE (function-local site : minimal bias in p-units) ===');
for (const [s, k] of tab) console.log(`  ${s.padEnd(16)} ${k}p`);
console.log('\nmax bias =', Math.max(...sites.values()), 'p, distinct biases =',
  [...new Set(sites.values())].sort((a, b) => a - b).join(','));
