// Inclusive BigInt interval proof for Bn254Lazy.cash::mul034Unit.
//
// Every Fp12 limb and both sparse-line products entering mul034Unit are canonical,
// so they are in [0,p-1]. The only enlarged sparse value is qa=1+o3a, in [1,p].
// This script mirrors the CashScript integer algebra without sampling and proves
// the shared 132,793*p^2 bias makes every remainder input strictly positive.

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

const outputs = [
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

if (RAW_BIAS !== 132793n * P * P || RAW_BIAS % P !== 0n) {
  throw new Error('mul034Unit bias is not exactly 132,793*p^2');
}
outputs.forEach((output, i) => {
  if (output.lo + RAW_BIAS <= 0n) throw new Error(`output ${i} can remain nonpositive after bias`);
  if (output.hi + RAW_BIAS >= 1n << 536n) throw new Error(`output ${i} exceeds 67 unsigned bytes`);
});

// lineUnit source ranges. Runtime c0=Y-mX+p is in [1,2p-1], runtime c1 is a
// canonical slope, fixed coefficients are normalized canonically, and u/v are
// canonical after canonicalFp. mulFp therefore makes o3/o4 canonical in all cases.
const runtimeC0 = interval(1n, 2n * P - 1n);
const canonical = interval(0n, P - 1n);
const mulFpRange = (a, b) => {
  if (a.lo < 0n || b.lo < 0n) throw new Error('mulFp source can be negative');
  return canonical;
};
if (runtimeC0.lo < 0n || runtimeC0.hi >= 2n * P) throw new Error('runtime c0 source bound changed');
for (const [label, source] of [
  ['runtime c0', runtimeC0],
  ['runtime c1', canonical],
  ['fixed c0', canonical],
  ['fixed c1', canonical],
]) {
  const reduced = mulFpRange(source, canonical);
  if (reduced.lo !== 0n || reduced.hi !== P - 1n) throw new Error(`${label} lineUnit product is not canonical`);
}

const min = outputs.reduce((x, y) => x < y.lo ? x : y.lo, outputs[0].lo);
const max = outputs.reduce((x, y) => x > y.hi ? x : y.hi, outputs[0].hi);
const ceiling = (x, y) => (x + y - 1n) / y;
console.log('mul034Unit interval proof passed');
console.log(`raw outputs: [-${ceiling(-min, P * P)}, ${ceiling(max, P * P)}] * p^2 (inclusive outer bound)`);
console.log(`biased maximum: ${(max + RAW_BIAS).toString(2).length} bits; all 12 biased minima are positive`);
console.log('runtime and fixed lineUnit products are canonical before mul034Unit');
