// Hand-scheduled assembly for the two sound vk_x MSM inputs (same math as the CashScript
// reference in vkx-msm.mjs, which stays as the readable spec and differential oracle).
//
// vk_x = IC0 + n0*IC1 + n1*IC2 via 4-scalar GLV Straus over {IC1, phi(IC1), IC2, phi(IC2)}, two
// 64-bit halves sharing 64 doublings. Witness: one byte per position (MSB-first),
// idx0 + 16*idx64. The accumulator starts at Q0 = G1 generator (no infinity branches) and the
// final step adds the constant IC0 - [2^64]Q0. An exceptional mixed add (equal x) is rejected.
//
// Input A: walks the genesis unlocking (push-only under P2SH) to the claimed n1, n0 (pushes
//   pubIdx, pubIdx + 1), range-checks them, runs positions 63..split and requires input B's state push to
//   equal (X, Y, Z, n0, n1).
// Input B: finishes positions split-1..0, adds the constant, converts to affine with the
//   witnessed Z inverse and requires it to equal its front push (vk_x, which the terminal ties
//   to the genesis vk_x). It then rebuilds S0 = k10 + lambda*k20 and S1 = k11 + lambda*k21 by
//   Horner over A's witness bytes (carried in the state A pins) and its own, and requires
//   S0 = n0, S1 = n1 (mod r). Since phi(P) = [lambda]P on G1, the MSM equals IC0 + S0*IC1 + S1*IC2, and every k is < 2^128.
import { OpcodesBCH, bigIntToVmNumber, encodeDataPush } from '@bitauth/libauth';

const G = '../../pairing/';
const glv = await import(G + 'gen_vkx_glv.mjs');
const mm = await import(G + '_millermath.mjs');

const { bn254 } = mm;
const G1 = bn254.G1.Point;
export const P = bn254.fields.Fp.ORDER;
const R = glv.GLV_R, LAM = glv.GLV_LAMBDA;
const TABLE = Buffer.from(glv.GLV_SPLIT_TABLE_HEX.slice(2), 'hex');
const Q0 = G1.BASE.toAffine();
const FINAL = mm.vk.ic[0].subtract(G1.BASE.multiply(1n << 64n)).toAffine();
// Input A pins input B's state push: X, Y, Z, n0, n1 (32 bytes each) and A's witness bytes wa,
// so B never parses A's unlocking (A's pad length is unconstrained).
export const stateBytes = (split) => 5 * 32 + (64 - split);

// ---- tiny assembler: opcode names, BigInt numbers, Buffer data, nested arrays ----
const asm = (...parts) => {
  const out = [];
  const emit = (x) => {
    if (Array.isArray(x)) return x.forEach(emit);
    if (Buffer.isBuffer(x)) return out.push(...encodeDataPush(x));
    if (typeof x === 'bigint') return out.push(...encodeDataPush(bigIntToVmNumber(x)));
    if (typeof x === 'number') return emit(BigInt(x));
    const op = OpcodesBCH[x.startsWith('OP_') ? x : `OP_${x}`];
    if (op === undefined) throw new Error(`unknown opcode ${x}`);
    out.push(op);
  };
  parts.forEach(emit);
  return Buffer.from(out);
};
const F = { DBL: 1, MADD: 2, TAB0: 3, TAB64: 4 };
const call = (f) => [F[f], 'INVOKE'];
const define = (f, body) => [body, F[f], 'DEFINE'];
const MODP = [P, 'MOD'];

// [x y z] -> [nx ny nz]
const DBL = asm(
  'OVER', 'MUL', 'DUP', 'ADD', MODP, 'TOALTSTACK',          // nz = 2yz
  'DUP', 'MUL', MODP,                                       // [x b]
  'DUP', 'DUP', 'MUL', MODP, 'TOALTSTACK',                  // c = b^2
  'OVER', 'MUL', 4, 'MUL', MODP,                            // [x d]
  'SWAP', 'DUP', 'MUL', MODP, 3, 'MUL',                     // [d e]
  'DUP', 'DUP', 'MUL', MODP,                                // [d e f]
  2, 'PICK', 'DUP', 'ADD', 'SUB', 2n * P, 'ADD', MODP,      // [d e nx]
  'ROT', 'OVER', 'SUB', P, 'ADD', 'ROT', 'MUL',             // [nx (d-nx+P)e]
  'FROMALTSTACK', 8, 'MUL', 'SUB', 8n * P, 'ADD', MODP,     // [nx ny]
  'FROMALTSTACK',                                           // [nx ny nz]
);

// [aX aY aZ bX bY] -> [nx ny nz]
const MADD = asm(
  2, 'PICK', 'DUP', 'MUL', MODP,                            // z1z1
  2, 'ROLL', 'OVER', 'MUL', MODP,                           // [aX aY aZ bY z1z1 u2]
  'DUP', 6, 'PICK', 'NUMNOTEQUAL', 'VERIFY',                // exceptional add rejected
  P, 'ADD', 5, 'PICK', 'SUB',                               // h = u2 + P - aX
  'SWAP', 3, 'PICK', 'MUL', MODP, 2, 'ROLL', 'MUL', MODP,   // [aX aY aZ h s2]
  P, 'ADD', 3, 'PICK', 'SUB',                               // rr = s2 + P - aY
  2, 'ROLL', 2, 'PICK', 'MUL', MODP, 'TOALTSTACK',          // nz = aZ h
  'OVER', 'DUP', 'MUL', MODP,                               // [aX aY h rr hh]
  2, 'ROLL', 'OVER', 'MUL', MODP,                           // [aX aY rr hh hhh]
  'SWAP', 4, 'ROLL', 'MUL', MODP,                           // [aY rr hhh vv]
  2, 'PICK', 'DUP', 'MUL', 3n * P, 'ADD', 2, 'PICK', 'SUB', 'OVER', 'DUP', 'ADD', 'SUB', MODP, // nx
  'DUP', 'ROT', 'SWAP', 'SUB', P, 'ADD', 3, 'ROLL', 'MUL', P * P, 'ADD',
  3, 'ROLL', 3, 'ROLL', 'MUL', 'SUB', MODP,                 // [nx ny]
  'FROMALTSTACK',
);

// [idx] -> [x y] from a 15-entry table (idx 1..15), entries x(LE32) || y(LE32)
const tab = (bytes) => asm(
  1, 'SUB', 64, 'MUL', bytes, 'SWAP', 'SPLIT', 'NIP', 64, 'SPLIT', 'DROP',
  32, 'SPLIT', 'SWAP', 'BIN2NUM', 'SWAP', 'BIN2NUM',
);

const prologue = [
  define('DBL', DBL), define('MADD', MADD),
  define('TAB0', tab(TABLE.subarray(0, 960))), define('TAB64', tab(TABLE.subarray(960))),
];

// Straus loop over `count` witness bytes. Layout [w ... X Y Z] with w at depth wDepth (from X);
// leaves [w ... X Y Z].
const straus = (count, wDepth) => [
  0, 'BEGIN',
  wDepth + 1, 'PICK', 'OVER', 'OVER', 'OVER', '1ADD', 'SPLIT', 'DROP', 'SWAP', 'SPLIT', 'NIP',
  Buffer.from([0]), 'CAT', 'BIN2NUM', 'NIP',                // [.. X Y Z t b]
  'SWAP', 'TOALTSTACK', 'DUP', 16, 'DIV', 'TOALTSTACK', 16, 'MOD', 'TOALTSTACK', // alt [t i64 i0]
  call('DBL'),
  'FROMALTSTACK', 'DUP', 'IF', call('TAB0'), call('MADD'), 'ELSE', 'DROP', 'ENDIF',
  'FROMALTSTACK', 'DUP', 'IF', call('TAB64'), call('MADD'), 'ELSE', 'DROP', 'ENDIF',
  'FROMALTSTACK', '1ADD', 'DUP', count, 'NUMEQUAL', 'UNTIL', 'DROP',
];

// [rest] where rest begins with a push-only script: -> [rest skip] (header + data bytes)
const pushSkip = [
  'DUP', 1, 'SPLIT', 'DROP', Buffer.from([0]), 'CAT', 'BIN2NUM',
  'DUP', 77, 'NUMEQUAL', 'IF',
  'DROP', 'DUP', 3, 'SPLIT', 'DROP', 1, 'SPLIT', 'NIP', Buffer.from([0]), 'CAT', 'BIN2NUM', 3, 'ADD',
  'ELSE', 'DUP', 76, 'LESSTHAN', 'IF', '1ADD', 'ELSE', 81, 97, 'WITHIN', 'VERIFY', 1, 'ENDIF', 'ENDIF',
];
// [rest] where rest begins with a minimally encoded non-negative number push -> [rest value skip]
const pushNumber = [
  'DUP', 1, 'SPLIT', 'DROP', Buffer.from([0]), 'CAT', 'BIN2NUM',
  'DUP', 81, 97, 'WITHIN', 'IF', 80, 'SUB', 1,
  'ELSE', 'DUP', 34, 'LESSTHAN', 'VERIFY',
  'DUP', 'IF', 'OVER', 'OVER', '1ADD', 'SPLIT', 'DROP', 1, 'SPLIT', 'NIP', 'BIN2NUM', 'SWAP', '1ADD',
  'ELSE', 1, 'ENDIF', 'ENDIF',
];
const le32 = ['NUM2BIN']; // used as [x 32 NUM2BIN]

// pubIdx: genesis push index of the claimed n1 (n0 follows it, then the genesis redeem).
// ownInputs: the claimed n0, n1 are input A's own pushes (unlocking: pad, wa, n1, n0).
export const programA = ({ split, genIdx, bIdx, genesisRedeemPushBytes, pubIdx = 36, ownInputs = false, noPad = false }) => asm(
  prologue,
  ownInputs
    ? [noPad ? [] : [3, 'ROLL', 'DROP'], 2, 'PICK', 'SIZE', 'NIP', 64 - split, 'NUMEQUALVERIFY'] // [wa n1 n0]
    : [
  'NIP',                                                    // drop the pad: [wa]
  'SIZE', 64 - split, 'NUMEQUALVERIFY',
  genIdx, 'INPUTBYTECODE', 'DUP', 3, 'SPLIT', 'DROP', Buffer.from('4dc001', 'hex'), 'EQUALVERIFY',
  'SIZE', genesisRedeemPushBytes, 'SUB', 'SPLIT', 'DROP', 451, 'SPLIT', 'NIP', // window: pushes 1..pubIdx+1
  Array.from({ length: pubIdx - 1 }, () => [pushSkip, 'SPLIT', 'NIP']),        // skip pushes 1..pubIdx-1
  pushNumber, 'ROT', 'SWAP', 'SPLIT', 'NIP',                // [wa n1 rest]
  pushNumber, 'ROT', 'SIZE', 'NIP', 'NUMEQUALVERIFY',       // [wa n1 n0], n0 ends the window
    ],
  'DUP', 0, R, 'WITHIN', 'VERIFY', 'OVER', 0, R, 'WITHIN', 'VERIFY',
  'ROT',                                                    // [n1 n0 wa]
  Q0.x, Q0.y, 1,                                            // [n1 n0 wa X Y Z]
  straus(64 - split, 3),
  32, le32, 'ROT', 32, le32, 'ROT', 32, le32, 'ROT', 'CAT', 'CAT', // [n1 n0 wa X||Y||Z]
  'SWAP', 'TOALTSTACK',                                     // [n1 n0 X||Y||Z], alt [wa]
  'SWAP', 32, le32, 'CAT', 'SWAP', 32, le32, 'CAT', 'FROMALTSTACK', 'CAT', // [X||Y||Z||n0||n1||wa]
  Buffer.from([0x4c, stateBytes(split)]), 'SWAP', 'CAT',
  bIdx, 'INPUTBYTECODE', 65 + 2 + stateBytes(split), 'SPLIT', 'DROP', 65, 'SPLIT', 'NIP', 'EQUAL',
);

export const programB = ({ split }) => asm(
  prologue,
  // unlocking pushes: vkx, st, wb, pad, zInv
  'NIP', 'ROT',                                             // [vkx wb zInv st]
  'SIZE', stateBytes(split), 'NUMEQUALVERIFY',
  32, 'SPLIT', 'SWAP', 'BIN2NUM', 'SWAP', 32, 'SPLIT', 'SWAP', 'BIN2NUM', 'SWAP',
  32, 'SPLIT', 'SWAP', 'BIN2NUM', 'SWAP', 32, 'SPLIT', 'TOALTSTACK', 'BIN2NUM', // alt [wa]
  'TOALTSTACK', 'TOALTSTACK',                               // alt [wa n1 n0]; [vkx wb zInv X Y Z]
  4, 'PICK', 'SIZE', 'NIP', split, 'NUMEQUALVERIFY',
  straus(split, 4),
  FINAL.x, FINAL.y, call('MADD'),                           // [vkx wb zInv X Y Z]
  3, 'PICK', 'MUL', MODP, 1, 'NUMEQUALVERIFY',              // Z * zInv == 1
  2, 'ROLL', 'DUP', 'DUP', 'MUL', MODP,                     // [vkx wb X Y zInv zi2]
  'SWAP', 'OVER', 'MUL', MODP,                              // [vkx wb X Y zi2 zi3]
  'ROT', 'MUL', MODP, 'ROT', 'ROT', 'MUL', MODP,            // [vkx wb y x]
  3, 'ROLL', 'SIZE', 64, 'NUMEQUALVERIFY', 32, 'SPLIT', 'BIN2NUM', 3, 'ROLL', 'NUMEQUALVERIFY',
  'BIN2NUM', 'NUMEQUALVERIFY',                              // [wb]
  // GLV binding: Horner over wa || wb (MSB-first), four accumulators
  'FROMALTSTACK', 'FROMALTSTACK', 'FROMALTSTACK', 3, 'ROLL', 'CAT', // [n0 n1 wa||wb]
  'ROT', 'ROT', 'TOALTSTACK', 'TOALTSTACK',                // [wa||wb], alt [n1 n0]
  0, 0, 0, 0, 0,                                            // [w s0lo s1lo s0hi s1hi t]
  'BEGIN',
  5, 'PICK', 'OVER', 'OVER', 'OVER', '1ADD', 'SPLIT', 'DROP', 'SWAP', 'SPLIT', 'NIP',
  Buffer.from([0]), 'CAT', 'BIN2NUM', 'NIP',                // [w a b c d t byte]
  'SWAP', 'TOALTSTACK',
  'DUP', 16, 'MOD', 'SWAP', 16, 'DIV',                      // [w a b c d lo hi]
  // c0(n) = n%2 + lambda*(n/2%2), c1(n) = n/4%2 + lambda*(n/8)
  'DUP', 4, 'DIV', 'DUP', 2, 'MOD', 'SWAP', 2, 'DIV', LAM, 'MUL', 'ADD', // c1(hi)
  'SWAP', 4, 'MOD', 'DUP', 2, 'MOD', 'SWAP', 2, 'DIV', LAM, 'MUL', 'ADD', // [.. lo c1hi c0hi]
  4, 'ROLL', 'DUP', 'ADD', 'ADD',                           // s0hi' = 2 s0hi + c0hi
  'SWAP', 3, 'ROLL', 'DUP', 'ADD', 'ADD',                   // s1hi'
  // stack: [w s0lo s1lo lo s0hi' s1hi']
  'ROT',
  'DUP', 4, 'DIV', 'DUP', 2, 'MOD', 'SWAP', 2, 'DIV', LAM, 'MUL', 'ADD',
  'SWAP', 4, 'MOD', 'DUP', 2, 'MOD', 'SWAP', 2, 'DIV', LAM, 'MUL', 'ADD', // [w s0lo s1lo s0hi s1hi c1lo c0lo]
  5, 'ROLL', 'DUP', 'ADD', 'ADD',                           // s0lo'
  'SWAP', 4, 'ROLL', 'DUP', 'ADD', 'ADD',                   // s1lo'  [w s0hi s1hi s0lo s1lo]
  3, 'ROLL', 3, 'ROLL',                                     // [w s0lo s1lo s0hi s1hi]
  'FROMALTSTACK', '1ADD', 'DUP', 64, 'NUMEQUAL', 'UNTIL', 'DROP',
  'SWAP', 1n << 64n, 'MUL', 3, 'ROLL', 'ADD', R, 'MOD',     // [w s1lo s1hi S0]
  'FROMALTSTACK', 'NUMEQUALVERIFY',                         // S0 == n0
  1n << 64n, 'MUL', 'ADD', R, 'MOD', 'FROMALTSTACK', 'NUMEQUALVERIFY', // S1 == n1
  'DROP', 1,
);

// ---- witness (JS reference identical to the contracts) ----
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
const entry = (half, idx) => {
  const e = TABLE.subarray(half * 960 + (idx - 1) * 64, half * 960 + idx * 64);
  return [BigInt('0x' + Buffer.from(e.subarray(0, 32)).reverse().toString('hex')), BigInt('0x' + Buffer.from(e.subarray(32)).reverse().toString('hex'))];
};
const fixed32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex').reverse();

export const witness = (n0, n1, split) => {
  const ks = glv.glvDecomposeJoint(n0, n1);
  const nib = (i) => ks.reduce((a, k, j) => a + (Number((k >> BigInt(i)) & 1n) << j), 0);
  const bytes = Buffer.from(Array.from({ length: 64 }, (_, t) => nib(63 - t) + 16 * nib(127 - t)));
  let acc = [Q0.x, Q0.y, 1n], st = null;
  for (let t = 0; t < 64; t++) {
    acc = dblJ(acc);
    if (bytes[t] % 16) acc = maddJ(acc, entry(0, bytes[t] % 16));
    if (bytes[t] >> 4) acc = maddJ(acc, entry(1, bytes[t] >> 4));
    if (t === 63 - split) st = Buffer.concat([...[...acc, n0, n1].map(fixed32), bytes.subarray(0, 64 - split)]);
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
  return { wa: bytes.subarray(0, 64 - split), wb: bytes.subarray(64 - split), st, zInv, vkx: Buffer.concat([fixed32(vx), fixed32(vy)]) };
};
