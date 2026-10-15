// Two-input sound vk_x MSM for the PairFold-5 repair.
// Input A (index A_IDX): parses the claimed public inputs n1, n0 (pushes 36, 37) out of the
//   genesis unlocking (input GEN_IDX; P2SH unlockings are push-only, so the walk is exact),
//   range-checks them, checks the GLV split, runs Straus positions 63..SPLIT, and requires the
//   front push of input B to equal its end state (X, Y, Z, k10, k20, k11, k21).
// Input B (index B_IDX): finishes positions SPLIT-1..0, adds IC0, converts to affine with a
//   witnessed Z inverse, and requires the result to equal its own front push (vk_x.x || vk_x.y,
//   LE32). The terminal requires that push to equal vk_x in genesis push 0 (the 14-field
//   proof/vk_x block the Miller loop consumes; vk_x.x at byte 131, vk_x.y at 163).
const G = '../../pairing/';
const glv = await import(G + 'gen_vkx_glv.mjs');
const mm = await import(G + '_millermath.mjs');
const { compileString, utils } = await import('cashc');

const { bn254 } = mm;
const P = bn254.fields.Fp.ORDER, R = glv.GLV_R, LAM = glv.GLV_LAMBDA;
const [IC0x, IC0y] = glv.GLV_IC0;
const TABLE = glv.GLV_SPLIT_TABLE_HEX;
const STATE_BYTES = 7 * 32;

const helpers = `function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = (x * x) % ${P}; int b = (y * y) % ${P}; int c = (b * b) % ${P};
    int d = (4 * x * b) % ${P};
    int e = a * 3; int f = (e * e) % ${P};
    int nx = (f - 2 * d + ${2n * P}) % ${P};
    int ny = ((d - nx + ${P}) * e + ${8n * P} - c * 8) % ${P};
    int nz = (2 * y * z) % ${P};
    return nx, ny, nz;
}
function jacAddAffine(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = 1;
    if (aZ != 0) {
        int z1z1 = (aZ * aZ) % ${P};
        int u2 = (bX * z1z1) % ${P};
        int s2 = (z1z1 * aZ % ${P} * bY) % ${P};
        int h = (u2 + ${P} - aX) % ${P};
        int rr = (s2 + ${P} - aY) % ${P};
        if (h == 0) {
            require(rr != 0);
            (rx, ry, rz) = jacDouble(aX, aY, aZ);
        } else {
            int hh = (h * h) % ${P}; int hhh = (h * hh) % ${P};
            int vv = (hh * aX) % ${P};
            rx = (rr * rr + ${3n * P} - hhh - 2 * vv) % ${P};
            ry = ((vv - rx + ${P}) * rr + ${P * P} - aY * hhh) % ${P};
            rz = (aZ * h) % ${P};
        }
    }
    return rx, ry, rz;
}
function pushLength(bytes rest) returns (int, int) {
    // (header bytes, data bytes) of the push at the front of a push-only script
    int op = int(rest.split(1)[0] + 0x00);
    int hdr = 1; int len = 0;
    if (op <= 75) { len = op; }
    else if (op == 76) { hdr = 2; len = int(rest.split(2)[0].split(1)[1] + 0x00); }
    else if (op == 77) { hdr = 3; len = int(rest.split(3)[0].split(1)[1] + 0x00); }
    else { require(op == 79 || (op >= 81 && op <= 96)); }
    return hdr, len;
}
function pushValue(bytes rest) returns (int) {
    // numeric value of a minimally encoded numeric push (OP_0, OP_1..OP_16 or direct push)
    int op = int(rest.split(1)[0] + 0x00);
    int v = 0;
    if (op >= 81 && op <= 96) { v = op - 80; }
    else if (op != 0) { require(op <= 33); v = int(rest.split(1 + op)[0].split(1)[1]); }
    return v;
}`;

const straus = (from, to) => `        for (int i = ${from}; i >= ${to}; i = i - 1) {
            if (rZ != 0) { (rX, rY, rZ) = jacDouble(rX, rY, rZ); }
            int idx = (k10 >> i) % 2 + 2 * ((k20 >> i) % 2) + 4 * ((k11 >> i) % 2) + 8 * ((k21 >> i) % 2);
            if (idx != 0) {
                bytes ent = t0.split((idx - 1) * 64)[1].split(64)[0];
                (rX, rY, rZ) = jacAddAffine(rX, rY, rZ, int(ent.split(32)[0]), int(ent.split(32)[1]));
            }
            int j = i + 64;
            int idx2 = (k10 >> j) % 2 + 2 * ((k20 >> j) % 2) + 4 * ((k11 >> j) % 2) + 8 * ((k21 >> j) % 2);
            if (idx2 != 0) {
                bytes ent2 = t64.split((idx2 - 1) * 64)[1].split(64)[0];
                (rX, rY, rZ) = jacAddAffine(rX, rY, rZ, int(ent2.split(32)[0]), int(ent2.split(32)[1]));
            }
        }`;

export const sourceA = ({ split, genIdx, bIdx }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmA() {
    function spend(int k10, int k20, int k11, int k21, bytes unused pad) {
        bytes g = tx.inputs[${genIdx}].unlockingBytecode;
        require(g.split(3)[0] == 0x4dc001);
        bytes rest = g.split(451)[1];
        for (int t = 1; t < 36; t = t + 1) {
            (int hdr, int len) = pushLength(rest);
            rest = rest.split(hdr + len)[1];
        }
        int n1 = pushValue(rest);
        (int hdr1, int len1) = pushLength(rest);
        rest = rest.split(hdr1 + len1)[1];
        int n0 = pushValue(rest);
        require(n0 >= 0); require(n0 < ${R});
        require(n1 >= 0); require(n1 < ${R});
        require(k10 >= 0 && k20 >= 0 && k11 >= 0 && k21 >= 0);
        require(k10 < ${1n << 128n}); require(k20 < ${1n << 128n}); require(k11 < ${1n << 128n}); require(k21 < ${1n << 128n});
        require((k10 + k20 * ${LAM}) % ${R} == n0);
        require((k11 + k21 * ${LAM}) % ${R} == n1);
        bytes t0, bytes t64 = ${TABLE}.split(960);
        int rX = 0; int rY = 1; int rZ = 0;
${straus(63, split)}
        bytes st = toPaddedBytes(rX, 32) + toPaddedBytes(rY, 32) + toPaddedBytes(rZ, 32) +
            toPaddedBytes(k10, 32) + toPaddedBytes(k20, 32) + toPaddedBytes(k11, 32) + toPaddedBytes(k21, 32);
        require(tx.inputs[${bIdx}].unlockingBytecode.split(${STATE_BYTES + 2 + 65})[0].split(65)[1] == 0x4ce0 + st);
    }
}
`;

export const sourceB = ({ split, genIdx }) => `pragma cashscript ^0.14.0;
${helpers}
contract VkxMsmB() {
    function spend(int zInv, bytes unused pad, bytes st, bytes vkx) {
        require(st.length == ${STATE_BYTES}); require(vkx.length == 64);
        int rX = int(st.split(32)[0]);
        int rY = int(st.split(64)[0].split(32)[1]);
        int rZ = int(st.split(96)[0].split(64)[1]);
        int k10 = int(st.split(128)[0].split(96)[1]);
        int k20 = int(st.split(160)[0].split(128)[1]);
        int k11 = int(st.split(192)[0].split(160)[1]);
        int k21 = int(st.split(192)[1]);
        bytes t0, bytes t64 = ${TABLE}.split(960);
${straus(split - 1, 0)}
        (rX, rY, rZ) = jacAddAffine(rX, rY, rZ, ${IC0x}, ${IC0y});
        require((rZ * zInv) % ${P} == 1);
        int zi2 = (zInv * zInv) % ${P};
        require((rX * zi2) % ${P} == int(vkx.split(32)[0]));
        require((rY * (zi2 * zInv % ${P})) % ${P} == int(vkx.split(32)[1]));
    }
}
`;

export const compile = (src, options = { rescheduleStacks: true }) =>
  Buffer.from(utils.asmToBytecode(compileString(src, options).bytecode));

const le32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();

/** Witness pieces for claimed (n0, n1) at a given split position. */
export const witness = (n0, n1, split) => {
  const [k10, k20, k11, k21] = glv.glvDecomposeJoint(n0, n1);
  const [X, Y, Z] = glv.vkxGlvSplitStateAt(k10, k20, k11, k21, 64 - split);
  const zInv = glv.vkxGlvSplitZinv(k10, k20, k11, k21);
  const st = Buffer.concat([X, Y, Z, k10, k20, k11, k21].map(le32));
  const ic = mm.vk.ic;
  let v = ic[0];
  if (n0 !== 0n) v = v.add(ic[1].multiply(n0));
  if (n1 !== 0n) v = v.add(ic[2].multiply(n1));
  const a = v.toAffine();
  return { ks: [k10, k20, k11, k21], zInv, st, vkx: Buffer.concat([le32(a.x), le32(a.y)]) };
};
