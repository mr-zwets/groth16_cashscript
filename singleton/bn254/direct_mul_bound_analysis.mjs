// Executable interval proof for fp12Mul's unreduced integer kernel.
// Bounds are coefficients of p^2 over the lazy input domain [0,64p).
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const INPUT_BOUND = 64n;
const I = (lo, hi) => ({ lo: BigInt(lo), hi: BigInt(hi) });
const add = (a, b) => I(a.lo + b.lo, a.hi + b.hi);
const sub = (a, b) => I(a.lo - b.hi, a.hi - b.lo);
const scale = (k, a) => k >= 0n ? I(k * a.lo, k * a.hi) : I(k * a.hi, k * a.lo);
const mul = (a, b) => {
  const values = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi];
  return I(values.reduce((x, y) => x < y ? x : y), values.reduce((x, y) => x > y ? x : y));
};
const fp2MulRaw = (a0, a1, b0, b1) => [
  sub(mul(a0, b0), mul(a1, b1)),
  add(mul(a0, b1), mul(a1, b0)),
];
const xi = (a, b) => [sub(scale(9n, a), b), add(a, scale(9n, b))];
const fp6MulRaw = (a, b) => {
  const t0 = fp2MulRaw(a[0], a[1], b[0], b[1]);
  const t1 = fp2MulRaw(a[2], a[3], b[2], b[3]);
  const t2 = fp2MulRaw(a[4], a[5], b[4], b[5]);
  const p1 = fp2MulRaw(add(a[2], a[4]), add(a[3], a[5]), add(b[2], b[4]), add(b[3], b[5]));
  const d2 = [sub(sub(p1[0], t1[0]), t2[0]), sub(sub(p1[1], t1[1]), t2[1])];
  const xd2 = xi(d2[0], d2[1]);
  const p2 = fp2MulRaw(add(a[0], a[2]), add(a[1], a[3]), add(b[0], b[2]), add(b[1], b[3]));
  const d4 = [sub(sub(p2[0], t0[0]), t1[0]), sub(sub(p2[1], t0[1]), t1[1])];
  const xt2 = xi(t2[0], t2[1]);
  const p3 = fp2MulRaw(add(a[0], a[4]), add(a[1], a[5]), add(b[0], b[4]), add(b[1], b[5]));
  return [
    add(t0[0], xd2[0]), add(t0[1], xd2[1]),
    add(d4[0], xt2[0]), add(d4[1], xt2[1]),
    add(sub(sub(p3[0], t0[0]), t2[0]), t1[0]),
    add(sub(sub(p3[1], t0[1]), t2[1]), t1[1]),
  ];
};

const a = Array.from({ length: 12 }, () => I(0n, INPUT_BOUND));
const b = Array.from({ length: 12 }, () => I(0n, INPUT_BOUND));
const t0 = fp6MulRaw(a.slice(0, 6), b.slice(0, 6));
const t1 = fp6MulRaw(a.slice(6), b.slice(6));
const pr = fp6MulRaw(a.slice(0, 6).map((v, i) => add(v, a[i + 6])), b.slice(0, 6).map((v, i) => add(v, b[i + 6])));
const vt1 = [...xi(t1[4], t1[5]), t1[0], t1[1], t1[2], t1[3]];
const out = t0.map((v, i) => add(v, vt1[i])).concat(pr.map((v, i) => sub(sub(v, t0[i]), t1[i])));
const biases = out.map(({ lo }) => lo < 0n ? -lo : 0n);
const uniform = biases.reduce((x, y) => x > y ? x : y);
out.forEach((v, i) => console.log(`C${i}: [${v.lo}, ${v.hi}] p^2; bias=${biases[i]} p^2`));
console.log(`uniform bias: ${uniform} p^2`);
console.log(`uniform literal: ${uniform * P * P}`);
if (out.some((v, i) => v.lo + biases[i] < 0n)) throw new Error('bias proof failed');

