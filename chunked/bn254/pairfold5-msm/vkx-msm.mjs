// Two-input sound vk_x MSM for the PairFold-5 repair: vk_x = IC0 + n0*IC1 + n1*IC2.
//
// 4-scalar GLV Straus over the fixed bases {IC1, phi(IC1), IC2, phi(IC2)}, grouped as two
// 64-bit halves sharing 64 doublings (tables for P and [2^64]P). The prover supplies one
// witness byte per position, idx0 + 16*idx64 (the 4-bit table indices of both halves); the
// contract selects table entries from it and rebuilds the four GLV sub-scalars bit by bit,
// so every k is < 2^128 by construction and the GLV split is checked against the claimed
// public inputs at the end.
//
// The accumulator starts at a fixed offset point Q0 = G1 generator instead of infinity, so
// the Jacobian formulas need no infinity branches; the final step adds the constant
// IC0 - [2^64]Q0. The exceptional mixed-add case (equal x) is rejected: rejecting is always
// safe for soundness and an honest prover hits it with negligible probability.
//
// Input A (index bIdx - 1): walks the genesis unlocking (push-only under P2SH, so the walk
//   matches the VM's parse) to the claimed n1, n0 (pushes 36, 37), range-checks them, runs
//   positions 63..split and requires input B's state push to equal its end state.
// Input B (index bIdx): finishes positions split-1..0, adds the constant, converts to affine
//   with a witnessed Z inverse, checks the GLV split against n0, n1, and requires the result
//   to equal its own front push (vk_x.x || vk_x.y, LE32). The terminal requires that push to
//   equal vk_x in genesis push 0 (the proof/vk_x block the Miller loop consumes).
const G = '../../pairing/';
const glv = await import(G + 'gen_vkx_glv.mjs');
const mm = await import(G + '_millermath.mjs');
const { compileString, utils } = await import('cashc');

const { bn254 } = mm;
const G1 = bn254.G1.Point;
const P = bn254.fields.Fp.ORDER, R = glv.GLV_R, LAM = glv.GLV_LAMBDA;
const TABLE = glv.GLV_SPLIT_TABLE_HEX;
const Q0 = G1.BASE;
const IC0 = mm.vk.ic[0];
const FINAL = IC0.subtract(Q0.multiply(1n << 64n)).toAffine();
const Q0A = Q0.toAffine();
const STATE_FIELDS = 13; // X, Y, Z, k10hi, k10lo, k20hi, k20lo, k11hi, k11lo, k21hi, k21lo, n0, n1
const STATE_BYTES = STATE_FIELDS * 32;
const STATE_PUSH_HEADER = '0x4da001'; // PUSHDATA2 416

const helpers = `function dbl(int x, int y, int z) returns (int, int, int) {
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
function tab0(int idx) returns (int, int) {
    bytes ent = ${TABLE.slice(0, 2 + 1920)}.split((idx - 1) * 64)[1].split(64)[0];
    return int(ent.split(32)[0]), int(ent.split(32)[1]);
}
function tab64(int idx) returns (int, int) {
    bytes ent = 0x${TABLE.slice(2 + 1920)}.split((idx - 1) * 64)[1].split(64)[0];
    return int(ent.split(32)[0]), int(ent.split(32)[1]);
}`;

// One Straus position per witness byte (MSB-first). The hot loop carries only X, Y, Z.
const straus = (count, wName) => `        for (int t = 0; t < ${count}; t = t + 1) {
            int b = int(${wName}.split(t + 1)[0].split(t)[1] + 0x00);
            (rX, rY, rZ) = dbl(rX, rY, rZ);
            if (b % 16 != 0) { (int x0, int y0) = tab0(b % 16); (rX, rY, rZ) = madd(rX, rY, rZ, x0, y0); }
            if (b / 16 != 0) { (int x1, int y1) = tab64(b / 16); (rX, rY, rZ) = madd(rX, rY, rZ, x1, y1); }
        }`;
// Rebuild the eight 64-bit GLV halves from the witness bytes (cheap loop over small ints).
const recon = (count, wName) => `        for (int t = 0; t < ${count}; t = t + 1) {
            int b = int(${wName}.split(t + 1)[0].split(t)[1] + 0x00);
            int i0 = b % 16; int i64 = b / 16;
            k10lo = 2 * k10lo + i0 % 2; k20lo = 2 * k20lo + i0 / 2 % 2;
            k11lo = 2 * k11lo + i0 / 4 % 2; k21lo = 2 * k21lo + i0 / 8;
            k10hi = 2 * k10hi + i64 % 2; k20hi = 2 * k20hi + i64 / 2 % 2;
            k11hi = 2 * k11hi + i64 / 4 % 2; k21hi = 2 * k21hi + i64 / 8;
        }`;

export const sourceA = ({ split, genIdx, bIdx, genesisRedeemPushBytes }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmA() {
    function spend(bytes wa, bytes unused pad) {
        require(wa.length == ${64 - split});
        bytes g = tx.inputs[${genIdx}].unlockingBytecode;
        require(g.split(3)[0] == 0x4dc001);
        // window = pushes 1..37 (after the 451-byte push 0, before the genesis redeem push)
        bytes w = g.split(g.length - ${genesisRedeemPushBytes})[0].split(451)[1];
        int off = 0;
        for (int p = 1; p < 36; p = p + 1) {
            int op = int(w.split(off + 1)[0].split(off)[1] + 0x00);
            if (op <= 75) { off = off + 1 + op; }
            else {
                if (op == 76) { off = off + 2 + int(w.split(off + 2)[0].split(off + 1)[1] + 0x00); }
                else {
                    if (op == 77) { off = off + 3 + int(w.split(off + 3)[0].split(off + 1)[1] + 0x00); }
                    else { require(op == 79 || (op >= 81 && op <= 96)); off = off + 1; }
                }
            }
        }
        bytes tail = w.split(off)[1];
        int op1 = int(tail.split(1)[0] + 0x00);
        require(op1 <= 33 || (op1 >= 81 && op1 <= 96));
        int n1 = 0; int l1 = 0;
        if (op1 >= 81) { n1 = op1 - 80; } else { l1 = op1; if (op1 != 0) { n1 = int(tail.split(1 + op1)[0].split(1)[1]); } }
        bytes tail0 = tail.split(1 + l1)[1];
        int op0 = int(tail0.split(1)[0] + 0x00);
        require(op0 <= 33 || (op0 >= 81 && op0 <= 96));
        int n0 = 0; int l0 = 0;
        if (op0 >= 81) { n0 = op0 - 80; } else { l0 = op0; if (op0 != 0) { n0 = int(tail0.split(1 + op0)[0].split(1)[1]); } }
        require(tail0.length == 1 + l0);
        require(n0 >= 0); require(n0 < ${R});
        require(n1 >= 0); require(n1 < ${R});
        int rX = ${Q0A.x}; int rY = ${Q0A.y}; int rZ = 1;
${straus(64 - split, 'wa')}
        int k10hi = 0; int k10lo = 0; int k20hi = 0; int k20lo = 0;
        int k11hi = 0; int k11lo = 0; int k21hi = 0; int k21lo = 0;
${recon(64 - split, 'wa')}
        bytes st = toPaddedBytes(rX, 32) + toPaddedBytes(rY, 32) + toPaddedBytes(rZ, 32) +
            toPaddedBytes(k10hi, 32) + toPaddedBytes(k10lo, 32) + toPaddedBytes(k20hi, 32) + toPaddedBytes(k20lo, 32) +
            toPaddedBytes(k11hi, 32) + toPaddedBytes(k11lo, 32) + toPaddedBytes(k21hi, 32) + toPaddedBytes(k21lo, 32) +
            toPaddedBytes(n0, 32) + toPaddedBytes(n1, 32);
        require(tx.inputs[${bIdx}].unlockingBytecode.split(${65 + 3 + STATE_BYTES})[0].split(65)[1] == ${STATE_PUSH_HEADER} + st);
    }
}
`;

const field = (k) => `int(st.split(${32 * (k + 1)})[0].split(${32 * k})[1])`;
export const sourceB = ({ split }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmB() {
    function spend(int zInv, bytes unused pad, bytes wb, bytes st, bytes vkx) {
        require(st.length == ${STATE_BYTES}); require(vkx.length == 64); require(wb.length == ${split});
        int rX = ${field(0)}; int rY = ${field(1)}; int rZ = ${field(2)};
        int vx = int(vkx.split(32)[0]); int vy = int(vkx.split(32)[1]);
${straus(split, 'wb')}
        int k10hi = ${field(3)}; int k10lo = ${field(4)}; int k20hi = ${field(5)}; int k20lo = ${field(6)};
        int k11hi = ${field(7)}; int k11lo = ${field(8)}; int k21hi = ${field(9)}; int k21lo = ${field(10)};
        int n0 = ${field(11)}; int n1 = ${field(12)};
${recon(split, 'wb')}
        int k10 = k10hi * ${1n << 64n} + k10lo; int k20 = k20hi * ${1n << 64n} + k20lo;
        int k11 = k11hi * ${1n << 64n} + k11lo; int k21 = k21hi * ${1n << 64n} + k21lo;
        require((k10 + k20 * ${LAM}) % ${R} == n0);
        require((k11 + k21 * ${LAM}) % ${R} == n1);
        (rX, rY, rZ) = madd(rX, rY, rZ, ${FINAL.x}, ${FINAL.y});
        require((rZ * zInv) % ${P} == 1);
        int zi2 = (zInv * zInv) % ${P};
        require((rX * zi2) % ${P} == vx);
        require((rY * (zi2 * zInv % ${P})) % ${P} == vy);
    }
}
`;

export const compile = (src, options = { rescheduleStacks: true }) =>
  Buffer.from(utils.asmToBytecode(compileString(src, options).bytecode));

const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();

// ---- JS reference matching the contract ----
const mod = (x) => ((x % P) + P) % P;
const dblJ = ([X, Y, Z]) => {
  const a = mod(X * X), b = mod(Y * Y), c = mod(b * b), d = mod(4n * X * b);
  const e = 3n * a, f = mod(e * e), nx = mod(f - 2n * d);
  return [nx, mod((d - nx) * e - 8n * c), mod(2n * Y * Z)];
};
const maddJ = ([X, Y, Z], [bx, by]) => {
  const z1z1 = mod(Z * Z), u2 = mod(bx * z1z1);
  if (u2 === X) throw new Error('exceptional mixed add (equal x)');
  const s2 = mod(mod(z1z1 * Z) * by), h = mod(u2 - X), rr = mod(s2 - Y);
  const hh = mod(h * h), hhh = mod(h * hh), vv = mod(hh * X), nx = mod(rr * rr - hhh - 2n * vv);
  return [nx, mod((vv - nx) * rr - Y * hhh), mod(Z * h)];
};
const tableEntry = (half, idx) => {
  const off = 2 + (half * 960 + (idx - 1) * 64) * 2;
  const e = Buffer.from(TABLE.slice(off, off + 128), 'hex');
  return [BigInt('0x' + Buffer.from(e.subarray(0, 32)).reverse().toString('hex')), BigInt('0x' + Buffer.from(e.subarray(32, 64)).reverse().toString('hex'))];
};

/** Witness for claimed (n0, n1): nibble strings for A and B, A's end state, Z inverse, vk_x. */
export const witness = (n0, n1, split) => {
  const ks = glv.glvDecomposeJoint(n0, n1);
  const bit = (k, i) => Number((k >> BigInt(i)) & 1n);
  const nib = (i) => ks.reduce((a, k, j) => a + (bit(k, i) << j), 0);
  const bytes = Buffer.from(Array.from({ length: 64 }, (_, t) => nib(63 - t) + 16 * nib(127 - t)));
  let acc = [Q0A.x, Q0A.y, 1n];
  const halves = ks.map(() => [0n, 0n]); // [hi, lo]
  let stA = null;
  for (let t = 0; t < 64; t++) {
    const i0 = bytes[t] % 16, i64 = bytes[t] >> 4;
    acc = dblJ(acc);
    if (i0) acc = maddJ(acc, tableEntry(0, i0));
    if (i64) acc = maddJ(acc, tableEntry(1, i64));
    ks.forEach((_, j) => { halves[j][1] = 2n * halves[j][1] + BigInt((i0 >> j) & 1); halves[j][0] = 2n * halves[j][0] + BigInt((i64 >> j) & 1); });
    if (t === 64 - split - 1) {
      stA = Buffer.concat([...acc, ...halves.flat(), n0, n1].map(le32));
    }
  }
  acc = maddJ(acc, [FINAL.x, FINAL.y]);
  const zInv = bn254.fields.Fp.inv(acc[2]);
  const vx = mod(acc[0] * zInv * zInv), vy = mod(acc[1] * zInv * zInv * zInv);
  const ic = mm.vk.ic;
  let v = ic[0];
  if (n0 !== 0n) v = v.add(ic[1].multiply(n0));
  if (n1 !== 0n) v = v.add(ic[2].multiply(n1));
  const a = v.toAffine();
  if (a.x !== vx || a.y !== vy) throw new Error('MSM reference mismatch');
  return { wa: bytes.subarray(0, 64 - split), wb: bytes.subarray(64 - split), st: stA, zInv, vkx: Buffer.concat([le32(vx), le32(vy)]) };
};
