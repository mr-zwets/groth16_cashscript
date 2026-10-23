// The vk_x MSM of ../pairfold5-msm/vkx-msm.mjs (sourceFull), restated as a library function for
// the single-input verifier:
//
//   function vkxMsm(int n0, int n1, bytes w, int zInv) returns (bytes)
//
// Same math and the same witness (zInv, w, n1, n0): range checks 0 <= n0, n1 < r, a 4-scalar
// GLV Straus over {IC1, phi(IC1), IC2, phi(IC2)} in two 64-bit halves sharing 64 doublings
// (accumulator starting at the G1 generator, final constant IC0 - [2^64]G, exceptional mixed
// adds rejected), affine conversion with the witnessed Z inverse, and the GLV binding
// S0 = k10 + lambda*k20 = n0, S1 = k11 + lambda*k21 = n1 (mod r) rebuilt from w. Two changes:
//  - it RETURNS vk_x (x || y, 32-byte little-endian each) instead of comparing it with bytes
//    131..195 of the genesis push in its own unlocking; the caller splices it into that block;
//  - the two 960-byte Straus tables are computed on-chain from IC1, IC2, [2^64]IC1, [2^64]IC2
//    and beta (phi(x, y) = (beta*x, y)) with 22 mixed adds and a batch normalization whose final
//    inverse is a per-half constant. Everything there is input-independent; build.mjs checks the
//    computed tables against GLV_SPLIT_TABLE_HEX byte for byte.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';

const G = '../../pairing/';
const glv = await import(G + 'gen_vkx_glv.mjs');
const mm = await import(G + '_millermath.mjs');
// Compiler: cashc from mr-zwets/cashscript branch zk-language, commit efc6ab8 (built), expected as a
// checkout next to this repository (../cashscript-zk) or at CASHC_ZK (path to its cashc dist/index.js).
// The compiled bytes are hash-guarded below, so another compiler cannot silently change the build.
const CASHC_ZK = process.env.CASHC_ZK ?? new URL('../../../../cashscript-zk/packages/cashc/dist/index.js', import.meta.url).href;
const {compileString, utils} = await import(CASHC_ZK);

const Fp = bn254.fields.Fp;
const G1 = bn254.G1.Point;
export const P = Fp.ORDER, R = glv.GLV_R, LAM = glv.GLV_LAMBDA;
export const TABLE = Buffer.from(glv.GLV_SPLIT_TABLE_HEX.slice(2), 'hex');
const Q0 = G1.BASE.toAffine();
const FINAL = mm.vk.ic[0].subtract(G1.BASE.multiply(1n << 64n)).toAffine();
const IC = [mm.vk.ic[1], mm.vk.ic[2]];
const mod = (x) => ((x % P) + P) % P;

// beta: the cube root of unity with phi(P) = [lambda]P on G1
const roots = [Fp.pow(3n, (P - 1n) / 3n), Fp.pow(Fp.pow(3n, (P - 1n) / 3n), 2n)].filter((b) => b !== 1n);
export const BETA = roots.find((b) => { const a = IC[0].toAffine(), l = IC[0].multiply(LAM).toAffine(); return mod(b * a.x) === l.x && a.y === l.y; });
assert(BETA !== undefined, 'no cube root of unity matches lambda');

// Reference (JS) of the on-chain table construction: returns the 960-byte half table and the
// product of the 11 Jacobian Z's it normalizes (whose inverse the script embeds).
const maddJ = ([X, Y, Z], [bx, by]) => {
  const z1z1 = mod(Z * Z), u2 = mod(bx * z1z1);
  assert(u2 !== X, 'exceptional add in table construction');
  const s2 = mod(mod(z1z1 * Z) * by), h = mod(u2 - X), rr = mod(s2 - Y);
  const hh = mod(h * h), hhh = mod(h * hh), vv = mod(hh * X), nx = mod(rr * rr - hhh - 2n * vv);
  return [nx, mod((vv - nx) * rr - Y * hhh), mod(Z * h)];
};
// index bits: 1 = A, 2 = phi(A), 4 = B, 8 = phi(B); every composite entry is entry[i - top] + base[top]
const PLAN = [[3, 1, 2], [5, 1, 4], [6, 2, 4], [7, 3, 4], [9, 1, 8], [10, 2, 8], [11, 3, 8], [12, 4, 8], [13, 5, 8], [14, 6, 8], [15, 7, 8]];
const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();
export function halfReference(a, b) {
  const base = {1: [a.x, a.y], 2: [mod(BETA * a.x), a.y], 4: [b.x, b.y], 8: [mod(BETA * b.x), b.y]};
  const jac = {1: [...base[1], 1n], 2: [...base[2], 1n], 4: [...base[4], 1n], 8: [...base[8], 1n]};
  for (const [i, from, add] of PLAN) jac[i] = maddJ(jac[from], base[add]);
  const zProduct = PLAN.reduce((acc, [i]) => mod(acc * jac[i][2]), 1n);
  const entries = Array.from({length: 15}, (_, k) => {
    const [X, Y, Z] = jac[k + 1], zi = Fp.inv(Z);
    return Buffer.concat([le32(mod(X * zi * zi)), le32(mod(Y * zi * zi * zi))]);
  });
  return {table: Buffer.concat(entries), zProduct};
}
export const halves = [0n, 64n].map((s) => {
  const a = IC[0].multiply(1n << s).toAffine(), b = IC[1].multiply(1n << s).toAffine();
  const {table, zProduct} = halfReference(a, b);
  return {a, b, table, zInverse: Fp.inv(zProduct)};
});
halves.forEach((h, i) => assert(h.table.equals(TABLE.subarray(960 * i, 960 * (i + 1))), `reference half ${i} differs from GLV_SPLIT_TABLE_HEX`));

// CashScript source. The half-table builder is unrolled from PLAN.
const half = () => {
  const lines = [];
  lines.push(`        int x1 = ax; int y1 = ay; int x2 = ${BETA} * ax % ${P}; int y2 = ay;`);
  lines.push(`        int x4 = bx; int y4 = by; int x8 = ${BETA} * bx % ${P}; int y8 = by;`);
  const isBase = (i) => [1, 2, 4, 8].includes(i);
  for (const [i, from, add] of PLAN) {
    const z = isBase(from) ? '1' : `z${from}`;
    lines.push(`        (int x${i}, int y${i}, int z${i}) = madd(x${from}, y${from}, ${z}, x${add}, y${add});`);
  }
  // prefix products c_k of the Z's in PLAN order, then back-substitution from zi = 1 / c_last
  const order = PLAN.map(([i]) => i);
  lines.push(`        int c${order[0]} = z${order[0]};`);
  for (let k = 1; k < order.length - 1; k++) lines.push(`        int c${order[k]} = c${order[k - 1]} * z${order[k]} % ${P};`);
  for (let k = order.length - 1; k >= 0; k--) {
    const i = order[k];
    lines.push(k > 0 ? `        int i${i} = zi * c${order[k - 1]} % ${P}; zi = zi * z${i} % ${P};` : `        int i${i} = zi;`);
  }
  const entry = (i) => (isBase(i) ? `toPaddedBytes(x${i}, 32) + toPaddedBytes(y${i}, 32)` : `aff(x${i}, y${i}, i${i})`);
  lines.push(`        return ${Array.from({length: 15}, (_, k) => entry(k + 1)).join(' +\n            ')};`);
  return lines.join('\n');
};

export const source = () => `pragma cashscript ^0.14.0;
function dbl(int x, int y, int z) returns (int, int, int) {
    int a = (x * x) % ${P}; int b = (y * y) % ${P}; int c = (b * b) % ${P};
    int d = (4 * x * b) % ${P};
    int e = a * 3; int f = (e * e) % ${P};
    int nx = (f - 2 * d + ${2n * P}) % ${P};
    int ny = ((d - nx + ${P}) * e + ${8n * P} - c * 8) % ${P};
    int nz = (2 * y * z) % ${P};
    return nx, ny, nz;
}
function madd(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int z1z1 = (aZ * aZ) % ${P};
    int u2 = (bX * z1z1) % ${P};
    require(u2 != aX);
    int s2 = (z1z1 * aZ % ${P} * bY) % ${P};
    int h = u2 + ${P} - aX;
    int rr = s2 + ${P} - aY;
    int hh = (h * h) % ${P}; int hhh = (h * hh) % ${P};
    int vv = (hh * aX) % ${P};
    int nx = (rr * rr + ${3n * P} - hhh - 2 * vv) % ${P};
    int ny = ((vv - nx + ${P}) * rr + ${P * P} - aY * hhh) % ${P};
    int nz = (aZ * h) % ${P};
    return nx, ny, nz;
}
function aff(int x, int y, int zi) returns (bytes) {
    int zi2 = (zi * zi) % ${P};
    return toPaddedBytes((x * zi2) % ${P}, 32) + toPaddedBytes((y * (zi2 * zi % ${P})) % ${P}, 32);
}
function tbl(int ax, int ay, int bx, int by, int zi) returns (bytes) {
${half()}
}
function ent(bytes t, int idx) returns (int, int) {
    bytes e = t.split((idx - 1) * 64)[1].split(64)[0];
    return int(e.split(32)[0]), int(e.split(32)[1]);
}
function vkxMsm(int n0, int n1, bytes w, int zInv) returns (bytes) {
    require(w.length == 64);
    require(within(n0, 0, ${R})); require(within(n1, 0, ${R}));
    bytes t0 = tbl(${halves[0].a.x}, ${halves[0].a.y}, ${halves[0].b.x}, ${halves[0].b.y}, ${halves[0].zInverse});
    bytes t64 = tbl(${halves[1].a.x}, ${halves[1].a.y}, ${halves[1].b.x}, ${halves[1].b.y}, ${halves[1].zInverse});
    int rX = ${Q0.x}; int rY = ${Q0.y}; int rZ = 1;
    for (int t = 0; t < 64; t = t + 1) {
        int b = int(w.split(t + 1)[0].split(t)[1] + 0x00);
        (rX, rY, rZ) = dbl(rX, rY, rZ);
        if (b % 16 != 0) { (int x0, int y0) = ent(t0, b % 16); (rX, rY, rZ) = madd(rX, rY, rZ, x0, y0); }
        if (b / 16 != 0) { (int x1, int y1) = ent(t64, b / 16); (rX, rY, rZ) = madd(rX, rY, rZ, x1, y1); }
    }
    (rX, rY, rZ) = madd(rX, rY, rZ, ${FINAL.x}, ${FINAL.y});
    require((rZ * zInv) % ${P} == 1);
    int s0lo = 0; int s1lo = 0; int s0hi = 0; int s1hi = 0;
    for (int t = 0; t < 64; t = t + 1) {
        int b = int(w.split(t + 1)[0].split(t)[1] + 0x00);
        int lo = b % 16; int hi = b / 16;
        s0lo = 2 * s0lo + lo % 2 + lo / 2 % 2 * ${LAM};
        s1lo = 2 * s1lo + lo / 4 % 2 + lo / 8 * ${LAM};
        s0hi = 2 * s0hi + hi % 2 + hi / 2 % 2 * ${LAM};
        s1hi = 2 * s1hi + hi / 4 % 2 + hi / 8 * ${LAM};
    }
    require((s0hi * ${1n << 64n} + s0lo) % ${R} == n0);
    require((s1hi * ${1n << 64n} + s1lo) % ${R} == n1);
    int zi2 = (zInv * zInv) % ${P};
    return toPaddedBytes((rX * zi2) % ${P}, 32) + toPaddedBytes((rY * (zi2 * zInv % ${P})) % ${P}, 32);
}
contract VkxMsmSingle() {
    function spend(int n0, int n1, bytes w, int zInv) {
        require(vkxMsm(n0, n1, w, zInv).length == 64);
    }
}
`;

// Compiled bytes; disableInlining keeps every helper (and vkxMsm itself) an OP_DEFINE'd function.
// sha256 of the zk-language (efc6ab8) output; co-8 (dab3f89) gives 3,944 different bytes.
export const MSM_SHA256 = '1831e0d3ab61d66a5aeb9a5ee79a5fb25e8708623b20f46c639a3e516d137ddc';
export const compile = () => {
  const bytes = Buffer.from(utils.asmToBytecode(compileString(source(), {rescheduleStacks: true, disableInlining: true}).bytecode));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), MSM_SHA256,
    'MSM compiled to different bytes: build with cashc zk-language efc6ab8 (CASHC_ZK)');
  return bytes;
};
