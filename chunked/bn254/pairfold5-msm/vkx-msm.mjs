// CashScript source of the two sound vk_x MSM inputs: vk_x = IC0 + n0*IC1 + n1*IC2.
// Same math and the same witness layout as the hand-scheduled vkx-msm-asm.mjs, so either
// build can be dropped into a transaction (programs differ, witnesses are identical).
//
// 4-scalar GLV Straus over {IC1, phi(IC1), IC2, phi(IC2)}, two 64-bit halves sharing 64
// doublings (tables for P and [2^64]P). Witness: one byte per position (MSB-first),
// idx0 + 16*idx64. The accumulator starts at Q0 = G1 generator (no infinity branches) and the
// final step adds the constant IC0 - [2^64]Q0; an exceptional mixed add (equal x) is rejected.
//
// Input A (unlocking: pad, wa, n1, n0 with ownInputs; otherwise pad, wa and the claimed n1, n0
//   are read by walking the genesis unlocking to pushes pubIdx, pubIdx + 1): range-checks n0, n1,
//   runs positions 63..split and requires input B's state push to equal (X, Y, Z, n0, n1, wa).
// Input B (unlocking: vkx, st, wb, pad, zInv): finishes positions split-1..0, adds the
//   constant, converts to affine with the witnessed Z inverse and requires it to equal its
//   front push vkx (the terminal ties vkx to the genesis vk_x). It then rebuilds
//   S0 = k10 + lambda*k20 and S1 = k11 + lambda*k21 by Horner over wa (from the state A pins,
//   never from A's unlocking, whose pad length is free) and its own wb, and requires S0 = n0,
//   S1 = n1 (mod r); since phi(P) = [lambda]P on G1, the MSM equals IC0 + S0*IC1 + S1*IC2.
const G = '../../pairing/';
const glv = await import(G + 'gen_vkx_glv.mjs');
const mm = await import(G + '_millermath.mjs');
const { compileString, utils } = await import('cashc');
export { witness } from './vkx-msm-asm.mjs';

const { bn254 } = mm;
const G1 = bn254.G1.Point;
export const P = bn254.fields.Fp.ORDER, R = glv.GLV_R, LAM = glv.GLV_LAMBDA;
const TABLE = glv.GLV_SPLIT_TABLE_HEX;
export const Q0 = G1.BASE.toAffine();
export const FINAL = mm.vk.ic[0].subtract(G1.BASE.multiply(1n << 64n)).toAffine();
// Input A pins input B's state push: X, Y, Z, n0, n1 (32 bytes each) and A's witness bytes wa,
// so B never parses A's unlocking (A's pad length is unconstrained).
export const stateBytes = (split) => 5 * 32 + (64 - split);
const stateHeader = (split) => '0x4c' + stateBytes(split).toString(16).padStart(2, '0');

export const helpers = `function dbl(int x, int y, int z) returns (int, int, int) {
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

// One Straus position per witness byte (MSB-first).
const straus = (count, wName) => `        for (int t = 0; t < ${count}; t = t + 1) {
            int b = int(${wName}.split(t + 1)[0].split(t)[1] + 0x00);
            (rX, rY, rZ) = dbl(rX, rY, rZ);
            if (b % 16 != 0) { (int x0, int y0) = tab0(b % 16); (rX, rY, rZ) = madd(rX, rY, rZ, x0, y0); }
            if (b / 16 != 0) { (int x1, int y1) = tab64(b / 16); (rX, rY, rZ) = madd(rX, rY, rZ, x1, y1); }
        }`;

// ownInputs: the claimed n0, n1 are input A's own pushes (unlocking: pad, wa, n1, n0) instead of
// genesis pushes pubIdx, pubIdx + 1.
// noPad: no pad parameter (when input A's code is carried by another input that has its own pad).
// pinEnd {idx, back, size}: pin the state as the prefix of input idx's size-byte push that ends
// `back` bytes before the end of its unlocking (instead of input bIdx's front push).
export const sourceA = ({ split, genIdx, bIdx, genesisRedeemPushBytes, pubIdx = 36, ownInputs = false, noPad = false, pinEnd = null, pinN = null }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmA() {
    function spend(${ownInputs ? 'int n0, int n1' : ''}${pinN ? '' : `${ownInputs ? ', ' : ''}bytes wa`}${noPad ? '' : ', bytes unused pad'}) {
${pinN ? `        bytes un = tx.inputs[${pinN.idx}].unlockingBytecode;
        bytes tn = un.split(un.length - ${pinN.back + 96})[0].split(un.length - ${pinN.back + 224})[1];
        bytes wa = tn.split(64)[1].split(${64 - split})[0];
` : `        require(wa.length == ${64 - split});
`}
${ownInputs ? '' : `        bytes g = tx.inputs[${genIdx}].unlockingBytecode;
        require(g.split(3)[0] == 0x4dc001);
        // window = pushes 1..pubIdx+1 (after the 451-byte push 0, before the genesis redeem push)
        bytes w = g.split(g.length - ${genesisRedeemPushBytes})[0].split(451)[1];
        for (int p = 1; p < ${pubIdx}; p = p + 1) {
            int op = int(w.split(1)[0] + 0x00);
            int skip = 1;
            if (op == 77) { skip = 3 + int(w.split(3)[0].split(1)[1] + 0x00); }
            else {
                if (op < 76) { skip = op + 1; }
                else { require(op >= 81 && op <= 96); }
            }
            w = w.split(skip)[1];
        }
        int op1 = int(w.split(1)[0] + 0x00);
        int n1 = 0; int l1 = 1;
        if (op1 >= 81 && op1 <= 96) { n1 = op1 - 80; }
        else { require(op1 < 34); if (op1 != 0) { n1 = int(w.split(op1 + 1)[0].split(1)[1]); l1 = op1 + 1; } }
        bytes w0 = w.split(l1)[1];
        int op0 = int(w0.split(1)[0] + 0x00);
        int n0 = 0; int l0 = 1;
        if (op0 >= 81 && op0 <= 96) { n0 = op0 - 80; }
        else { require(op0 < 34); if (op0 != 0) { n0 = int(w0.split(op0 + 1)[0].split(1)[1]); l0 = op0 + 1; } }
        require(w0.length == l0);
`}        require(within(n0, 0, ${R})); require(within(n1, 0, ${R}));
        int rX = ${Q0.x}; int rY = ${Q0.y}; int rZ = 1;
${straus(64 - split, 'wa')}
${pinN ? `        bytes st = toPaddedBytes(rX, 32) + toPaddedBytes(rY, 32) + toPaddedBytes(rZ, 32);
        require(tn.split(64)[0] == toPaddedBytes(n0, 32) + toPaddedBytes(n1, 32));
` : `        bytes st = toPaddedBytes(rX, 32) + toPaddedBytes(rY, 32) + toPaddedBytes(rZ, 32) +
            toPaddedBytes(n0, 32) + toPaddedBytes(n1, 32) + wa;
`}${pinEnd ? `        bytes u = tx.inputs[${pinEnd.idx}].unlockingBytecode;
        require(u.split(u.length - ${pinEnd.back})[0].split(u.length - ${pinEnd.back + pinEnd.size})[1]${pinN ? '' : `.split(${stateBytes(split)})[0]`} == st);`
  : `        require(tx.inputs[${bIdx}].unlockingBytecode.split(${65 + 2 + stateBytes(split)})[0].split(65)[1] == ${stateHeader(split)} + st);`}
    }
}
`;

export const sourceB = ({ split }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmB() {
    function spend(int zInv, bytes unused pad, bytes wb, bytes st, bytes vkx) {
        require(st.length == ${stateBytes(split)}); require(vkx.length == 64); require(wb.length == ${split});
        int rX = int(st.split(32)[0]);
        int rY = int(st.split(64)[0].split(32)[1]);
        int rZ = int(st.split(96)[0].split(64)[1]);
        int n0 = int(st.split(128)[0].split(96)[1]);
        int n1 = int(st.split(160)[0].split(128)[1]);
${straus(split, 'wb')}
        (rX, rY, rZ) = madd(rX, rY, rZ, ${FINAL.x}, ${FINAL.y});
        require((rZ * zInv) % ${P} == 1);
        int zi2 = (zInv * zInv) % ${P};
        require((rX * zi2) % ${P} == int(vkx.split(32)[0]));
        require((rY * (zi2 * zInv % ${P})) % ${P} == int(vkx.split(32)[1]));
        // GLV binding: Horner over A's and B's witness bytes, MSB-first
        bytes w = st.split(160)[1] + wb;
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
    }
}
`;

// The whole MSM in one program, for a carrier whose budget fits all 64 positions (the proposed
// bch-spec VM gives every input an 8M op base budget). It runs inside the genesis input and
// checks the result against the vk_x in genesis push 0 of its own unlocking (the block the Miller
// loop consumes; vk_x.x at bytes 131..163, vk_x.y at 163..195), so no other input has to bind it.
// Carried pushes (bottom to top): zInv, w (64 witness bytes), n1, n0.
export const sourceFull = () => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmFull() {
    function spend(int n0, int n1, bytes w, int zInv) {
        require(w.length == 64);
        require(within(n0, 0, ${R})); require(within(n1, 0, ${R}));
        int rX = ${Q0.x}; int rY = ${Q0.y}; int rZ = 1;
${straus(64, 'w')}
        (rX, rY, rZ) = madd(rX, rY, rZ, ${FINAL.x}, ${FINAL.y});
        require((rZ * zInv) % ${P} == 1);
        int zi2 = (zInv * zInv) % ${P};
        bytes g = tx.inputs[this.activeInputIndex].unlockingBytecode;
        require(g.split(3)[0] == 0x4dc001);
        require((rX * zi2) % ${P} == int(g.split(163)[0].split(131)[1]));
        require((rY * (zi2 * zInv % ${P})) % ${P} == int(g.split(195)[0].split(163)[1]));
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
    }
}
`;

export const compile = (src, options = { rescheduleStacks: true }) =>
  Buffer.from(utils.asmToBytecode(compileString(src, options).bytecode));
