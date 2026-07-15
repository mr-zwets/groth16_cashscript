// GLV vk_x generator: vk_x = IC0 + in0*IC1 + in1*IC2 via the BN254 G1 endomorphism.
// Each public input k is decomposed (GLV) into NON-NEGATIVE k1 + k2*lambda (mod r) with k1,k2
// ~127 bits, turning the 2-scalar 254-bit MSM into a 4-scalar ~128-bit Straus over the FIXED
// points {IC1, phi(IC1), IC2, phi(IC2)} (phi(x,y)=(beta*x,y)). A baked 16-entry subset-sum table
// folds all 4 scalars into ONE add per iteration -> ~half the doublings (vkx ~9 -> ~4 chunks).
// The current-BCH intratx residue builder opts into a grouped schedule: three 43-bit groups
// share 43 doublings and use tables for P, [2^43]P, and [2^86]P.
// The decomposition witnesses k10,k20,k11,k21 are checked on-chain at genesis
// (k1 + k2*lambda == in mod r); phi(IC1),phi(IC2) and the table are baked (proof-independent).
// State (committed, 9 limbs): rX,rY,rZ, in0,in1, k10,k20,k11,k21. The
// covenant-residue layout carries the validated (-A,B,C) tuple beside this state
// and emits (-A,B,C,vk_x) for the Miller stage.
//   node gen_vkx_glv.mjs    plan + emit vkxglv_NN.cash + manifest_vkxglv.json
import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bn254, vk, proof, measureCovenant, covIn, covOut } from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const Fp = bn254.fields.Fp, Fr = bn254.fields.Fr, G1 = bn254.G1.Point;
const p = Fp.ORDER, r = Fr.ORDER;
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
const P2str = (2n * P).toString();
const P3str = (3n * P).toString();
const P8str = (8n * P).toString();
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const STAGE_BOUND = process.env.STAGE_BOUND_LAYOUT === '1';
const COVENANT_RESIDUE = STAGE_BOUND && process.env.COVENANT_RESIDUE_LAYOUT === '1';
const PROJECTIVE_OUTPUT = process.env.MILLER_PROJECTIVE_VKX === '1';
const ITERS = 128; // GLV sub-scalars are <= 127 bits; 128 MSB-first positions

// ---- GLV constants (computed; proof-independent) ----
const modpow = (b, e, m) => { let R = 1n; b = ((b % m) + m) % m; while (e > 0n) { if (e & 1n) R = (R * b) % m; b = (b * b) % m; e >>= 1n; } return R; };
const cru = (m) => { for (let g = 2n; g < 100n; g++) { const w = modpow(g, (m - 1n) / 3n, m); if (w !== 1n && (w * w % m * w % m) === 1n) return w; } };
const phiPt = (Pt, beta) => { const a = Pt.toAffine(); return G1.fromAffine({ x: (a.x * beta) % p, y: a.y }); };
let BETA = null, LAM = null;
for (const be of [cru(p), (cru(p) ** 2n) % p]) for (const la of [cru(r), (cru(r) ** 2n) % r]) if (phiPt(vk.ic[1], be).equals(vk.ic[1].multiplyUnsafe(la))) { BETA = be; LAM = la; }
const isqrt = (n) => { let x = n, y = (n + 1n) / 2n; while (y < x) { x = y; y = (x + n / x) / 2n; } return x; };
function glvBasis(n, lam) {
  let r0 = n, r1 = lam, t0 = 0n, t1 = 1n; const s = isqrt(n);
  const seq = [{ r: r0, t: t0 }, { r: r1, t: t1 }];
  while (r1 >= s) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; seq.push({ r: r1, t: t1 }); }
  const l = seq.findIndex((e) => e.r < s);
  const v1 = { a: seq[l].r, b: -seq[l].t };
  const c1 = { a: seq[l - 1].r, b: -seq[l - 1].t }, c2 = seq[l + 1] ? { a: seq[l + 1].r, b: -seq[l + 1].t } : c1;
  const nrm = (v) => v.a * v.a + v.b * v.b;
  const v2 = nrm(c1) <= nrm(c2) ? c1 : c2;
  return { a1: v1.a, b1: v1.b, a2: v2.a, b2: v2.b };
}
const { a1, b1, a2, b2 } = glvBasis(r, LAM);
const rnd = (num, den) => { const q = num / den, rem = num - q * den, t = 2n * (rem < 0n ? -rem : rem); let res = q; if (t > den) res += ((num < 0n) !== (den < 0n)) ? -1n : 1n; return res; };
const GLV_BOUND = 1n << 128n;
/** GLV decomposition of k into NON-NEGATIVE (k1,k2), k = k1 + k2*lambda (mod r), <=128 bits. */
export function glvDecompose(k) {
  const c1 = rnd(b2 * k, r), c2 = rnd(-b1 * k, r);
  let k1 = k - c1 * a1 - c2 * a2, k2 = -c1 * b1 - c2 * b2;
  let best = null;
  for (let i = -1n; i <= 1n; i++) for (let j = -1n; j <= 1n; j++) { const x = k1 + i * a1 + j * a2, y = k2 + i * b1 + j * b2; if (x >= 0n && y >= 0n) { const sc = x > y ? x : y; if (best === null || sc < best.s) best = { x, y, s: sc }; } }
  return [best.x, best.y];
}

/**
 * Jointly choose exact bounded GLV representatives with the fewest Straus additions.
 *
 * Every other representative differs by i*(a1,b1)+j*(a2,b2). Both the returned
 * representative and the nearest-plane seed lie in [0,2^128)^2, so |dx|,|dy|<2^128.
 * Cramer's rule therefore bounds |i| and |j| by the finite limits below; the search is
 * exhaustive. Ties prefer the shorter combined bit length, then the lexicographically
 * smaller witness tuple for deterministic vector generation.
 */
export function glvDecomposeJoint(k0, k1) {
  if (k0 < 0n || k0 >= r || k1 < 0n || k1 >= r) {
    throw new Error('joint GLV inputs must be canonical scalars');
  }
  const determinant = a1 * b2 - a2 * b1;
  if ((determinant < 0n ? -determinant : determinant) !== r) {
    throw new Error('invalid GLV lattice determinant');
  }
  if ((a1 + b1 * LAM) % r !== 0n || (a2 + b2 * LAM) % r !== 0n) {
    throw new Error('invalid GLV lattice basis');
  }
  const abs = (value) => value < 0n ? -value : value;
  const iBound = Number((GLV_BOUND * (abs(a2) + abs(b2)) + r - 1n) / r + 1n);
  const jBound = Number((GLV_BOUND * (abs(a1) + abs(b1)) + r - 1n) / r + 1n);
  const candidates = [k0, k1].map((scalar) => {
    const [baseX, baseY] = glvDecompose(scalar);
    if (baseX < 0n || baseX >= GLV_BOUND || baseY < 0n || baseY >= GLV_BOUND) {
      throw new Error('nearest-plane GLV seed is outside the exhaustive search box');
    }
    const bounded = [];
    for (let i = -iBound; i <= iBound; i++) {
      for (let j = -jBound; j <= jBound; j++) {
        const x = baseX + BigInt(i) * a1 + BigInt(j) * a2;
        const y = baseY + BigInt(i) * b1 + BigInt(j) * b2;
        if (x >= 0n && x < GLV_BOUND && y >= 0n && y < GLV_BOUND) bounded.push([x, y]);
      }
    }
    return bounded;
  });
  let best = null;
  for (const [k10, k20] of candidates[0]) {
    for (const [k11, k21] of candidates[1]) {
      const scalars = [k10, k20, k11, k21];
      const union = k10 | k20 | k11 | k21;
      const bits = union.toString(2);
      const score = [bits.replaceAll('0', '').length, union === 0n ? 0 : bits.length, ...scalars];
      let better = best === null;
      if (best !== null) {
        for (let index = 0; index < score.length; index++) {
          if (score[index] === best.score[index]) continue;
          better = score[index] < best.score[index];
          break;
        }
      }
      if (better) best = { scalars, score };
    }
  }
  if (best === null) throw new Error('no bounded joint GLV decomposition');
  return best.scalars;
}
export const GLV_LAMBDA = LAM, GLV_R = r;
export const GLV_BASIS = { a1, b1, a2, b2 };

// ---- the 4 fixed base points + the baked 16-entry Straus subset-sum table ----
const _ic0 = vk.ic[0].toAffine();
const IC0 = [_ic0.x, _ic0.y];
const BP = [vk.ic[1], phiPt(vk.ic[1], BETA), vk.ic[2], phiPt(vk.ic[2], BETA)]; // P1..P4
// table[idx] (idx 1..15) = sum of BP[i] for bit i set in idx ; affine [x,y]
const TABLE = [];
for (let idx = 1; idx < 16; idx++) {
  let acc = G1.ZERO;
  for (let i = 0; i < 4; i++) if (idx & (1 << i)) acc = acc.add(BP[i]);
  const a = acc.toAffine(); TABLE[idx] = [a.x, a.y];
}
if (TABLE.slice(1).some(([x]) => x === 0n)) throw new Error('x=0 is reserved for the GLV no-add sentinel');
const SPLIT_WIDTH = 43;
const SPLIT_GROUPS = 3;
const shiftedTables = Array.from({ length: SPLIT_GROUPS }, (_, group) => group * SPLIT_WIDTH).map((shift) => {
  const bases = BP.map((point) => point.multiplyUnsafe(1n << BigInt(shift)));
  const table = [];
  for (let idx = 1; idx < 16; idx++) {
    let acc = G1.ZERO;
    for (let i = 0; i < 4; i++) if (idx & (1 << i)) acc = acc.add(bases[i]);
    const a = acc.toAffine(); table[idx] = [a.x, a.y];
  }
  if (table.slice(1).some(([x]) => x === 0n)) throw new Error('x=0 is reserved for the split GLV no-add sentinel');
  return table;
});
// Encode the original 15-entry table as a 960-byte blob and the three grouped tables as
// one 2,880-byte blob. Each entry is x(LE32) || y(LE32).
// A runtime `split` reads entry idx in O(1) (one indexed slice) — ~74% cheaper op-cost than the
// 15-deep if/else dispatch, which costs ~3.5M op in branch comparisons over the 128-iter Straus.
// 32-byte LE is safe (field elements < P < 2^255 -> sign bit clear -> int() recovers them positive).
// Full rationale, measurements, and correctness argument: ./select16-blob-table.md
const le32 = (v) => { v = ((v % P) + P) % P; let s = ''; for (let b = 0; b < 32; b++) s += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0'); return s; };
const TABLE_HEX = '0x' + Array.from({ length: 15 }, (_, k) => le32(TABLE[k + 1][0]) + le32(TABLE[k + 1][1])).join('');
const tableBytes = Buffer.from(TABLE_HEX.slice(2), 'hex');
const SPLIT_TABLE_HEX = '0x' + shiftedTables.flatMap((table) =>
  Array.from({ length: 15 }, (_, k) => le32(table[k + 1][0]) + le32(table[k + 1][1]))).join('');
const splitTableBytes = Buffer.from(SPLIT_TABLE_HEX.slice(2), 'hex');
// The carrier chunk checks this SHA-256 digest, so every
// sibling reading the same transaction input uses the fixed VK-derived table.
const TABLE_HASH_HEX = '0x' + createHash('sha256').update(tableBytes).digest('hex');
const SPLIT_TABLE_HASH_HEX = '0x' + createHash('sha256').update(splitTableBytes).digest('hex');

// ---- contract template ----
const STATE = ['rX', 'rY', 'rZ', 'in0', 'in1', 'k10', 'k20', 'k11', 'k21'];
const GENESIS_STATE = STATE.slice(3);
const PROOF_STATE = ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy'];
const proofA = proof.a.negate().toAffine();
const proofB = proof.b.toAffine();
const proofC = proof.c.toAffine();
const PROOF_LIMBS = [proofA.x, proofA.y, proofB.x.c0, proofB.x.c1, proofB.y.c0, proofB.y.c1, proofC.x, proofC.y];
const legacyPrologue = (sharedTable) => `function addFp(int x, int y) returns (int) { return (x + y) % ${Pstr}; }
function subFp(int x, int y) returns (int) { return (x - y + ${Pstr}) % ${Pstr}; }
function mulFp(int x, int y) returns (int) { return (x * y) % ${Pstr}; }
function sqrFp(int x) returns (int) { return (x * x) % ${Pstr}; }
function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = sqrFp(x); int b = sqrFp(y); int c = sqrFp(b);
    int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
    int e = mulFp(3, a); int f = sqrFp(e);
    int nx = subFp(f, mulFp(2, d));
    int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
    int nz = mulFp(2, mulFp(y, z));
    return nx, ny, nz;
}
function jacAddAffine(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = 1;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ);
        int u2 = mulFp(bX, z1z1);
        int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (aX == u2 && aY == s2) {
            int da = sqrFp(aX); int db = sqrFp(aY); int dc = sqrFp(db);
            int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
            int de = mulFp(3, da); int df = sqrFp(de);
            int dnx = subFp(df, mulFp(2, dd));
            int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
            int dnz = mulFp(2, mulFp(aY, aZ));
            rx = dnx; ry = dny; rz = dnz;
        } else {
            int h = subFp(u2, aX); int i2 = sqrFp(mulFp(2, h)); int jj = mulFp(h, i2);
            int rr = mulFp(2, subFp(s2, aY)); int vv = mulFp(aX, i2);
            int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(aY, jj)));
            int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, 1)), z1z1), 1), h);
            rx = anx; ry = any; rz = anz;
        }
    }
    return rx, ry, rz;
}
function select16(int idx${sharedTable ? ', bytes table' : ''}) returns (int, int) {
    // idx=0 keeps aX=0; every fixed affine table entry has nonzero x.
    int aX = 0; int aY = 0;
    if (idx != 0) {
        ${sharedTable ? '' : `bytes table = ${TABLE_HEX};`}
        bytes ent = table.split(idx * 64)[0].split((idx - 1) * 64)[1];
        aX = int(ent.split(32)[0]);
        aY = int(ent.split(32)[1]);
    }
    return aX, aY;
}`;

const groupedPrologue = (sharedTable) => `function jacDouble(int x, int y, int z) returns (int, int, int) {
    int a = (x * x) % ${Pstr}; int b = (y * y) % ${Pstr}; int c = (b * b) % ${Pstr};
    int d = (4 * x * b) % ${Pstr};
    int e = (a * 3) % ${Pstr}; int f = (e * e) % ${Pstr};
    int nx = (f - 2 * d + ${P2str}) % ${Pstr};
    int ny = ((d - nx + ${Pstr}) * e + ${P8str} - c * 8) % ${Pstr};
    int nz = (2 * y * z) % ${Pstr};
    return nx, ny, nz;
}
function jacAddAffine(int aX, int aY, int aZ, int bX, int bY) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = 1;
    if (aZ != 0) {
        int z1z1 = (aZ * aZ) % ${Pstr};
        int u2 = (bX * z1z1) % ${Pstr};
        int s2 = (z1z1 * aZ * bY) % ${Pstr};
        int h = (u2 + ${Pstr} - aX) % ${Pstr}; int hh = (h * h) % ${Pstr}; int hhh = (h * hh) % ${Pstr};
        int rr = (s2 + ${Pstr} - aY) % ${Pstr}; int vv = (hh * aX) % ${Pstr};
        int anx = (rr * rr + ${P3str} - hhh - 2 * vv) % ${Pstr};
        int ayhhh = (aY * hhh) % ${Pstr};
        int any = ((vv - anx + ${Pstr}) * rr + ${Pstr} - ayhhh) % ${Pstr};
        int anz = (aZ * h) % ${Pstr};
        rx = anx; ry = any; rz = anz;
    }
    return rx, ry, rz;
}`;

export function genCash(
  lo,
  hi,
  first,
  final,
  stageBound = false,
  sharedTable = null,
  covenantResidue = false,
  grouped = false,
  projectiveOutput = false,
) {
  if (sharedTable !== null && (!Number.isSafeInteger(sharedTable.inputIndex) || sharedTable.inputIndex < 0 ||
    !Number.isSafeInteger(sharedTable.dataOffset) || sharedTable.dataOffset < 0)) {
    throw new Error(`invalid shared GLV table source: ${JSON.stringify(sharedTable)}`);
  }
  const iterations = grouped ? SPLIT_WIDTH : ITERS;
  const count = hi - lo, hiBit = (iterations - 1) - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`// GLV vk_x chunk: 4-scalar Straus window [${lo},${hi}), first=${first} final=${final}.`);
  L.push(grouped ? groupedPrologue(sharedTable !== null) : legacyPrologue(sharedTable !== null));
  L.push('contract VkxGlvChunk() {');
  const stateParams = covenantResidue
    ? (first ? [...PROOF_STATE, ...GENESIS_STATE] : [...STATE, ...PROOF_STATE])
    : stageBound && first ? GENESIS_STATE : STATE;
  const committedParams = covenantResidue && first ? PROOF_STATE : stateParams;
  const extraParams = [final && !projectiveOutput ? 'int zInv' : null, sharedTable !== null && final ? 'bytes glvTable' : null]
    .filter(Boolean);
  L.push(`    function spend(${[...stateParams.map((s) => `int ${s}`), ...extraParams, 'bytes unused zeroPadding'].join(', ')}) {`);
  L.push(covIn(committedParams));
  if (sharedTable !== null) {
    const selectedBytes = grouped ? splitTableBytes : tableBytes;
    if (final) L.push(`        require(sha256(glvTable) == ${grouped ? SPLIT_TABLE_HASH_HEX : TABLE_HASH_HEX});`);
    else L.push(`        bytes glvTable = tx.inputs[${sharedTable.inputIndex}].unlockingBytecode.split(${sharedTable.dataOffset + selectedBytes.length})[0].split(${sharedTable.dataOffset})[1];`);
  }
  if (first) {
    if (stageBound) L.push('        int rX = 0; int rY = 1; int rZ = 0;');
    // bind the GLV witnesses to the committed public inputs: k1 + k2*lambda == in (mod r),
    // AND bound their magnitude to < 2^128 so the selected schedule processes every bit (else
    // a prover could add r to a scalar — same residue mod r, but bits above 127 would be
    // silently dropped, computing the wrong vk_x).
    if (covenantResidue) {
      L.push(`        require(in0 >= 0); require(in0 < ${r});`);
      L.push(`        require(in1 >= 0); require(in1 < ${r});`);
    }
    L.push('        require(k10 >= 0 && k20 >= 0 && k11 >= 0 && k21 >= 0);');
    L.push(`        require(k10 < ${GLV_BOUND}); require(k20 < ${GLV_BOUND}); require(k11 < ${GLV_BOUND}); require(k21 < ${GLV_BOUND});`);
    L.push(`        require((k10 + k20 * ${LAM}) % ${r} == in0);`);
    L.push(`        require((k11 + k21 * ${LAM}) % ${r} == in1);`);
  }
  if (grouped && sharedTable === null) L.push(`        bytes glvTable = ${SPLIT_TABLE_HEX};`);
  if (grouped) {
    L.push(`        bytes glvTable0, bytes glvTableTail = glvTable.split(${tableBytes.length});`);
    L.push(`        bytes glvTable${SPLIT_WIDTH}, bytes glvTable${2 * SPLIT_WIDTH} = glvTableTail.split(${tableBytes.length});`);
  }
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx, int dy, int dz) = jacDouble(rX, rY, rZ); rX = dx; rY = dy; rZ = dz; }');
  L.push('            int idx = (k10 >> i) % 2 + 2 * ((k20 >> i) % 2) + 4 * ((k11 >> i) % 2) + 8 * ((k21 >> i) % 2);');
  if (grouped) {
    L.push('            int aX = 0; int aY = 0;');
    L.push('            if (idx != 0) { bytes ent = glvTable0.split((idx - 1) * 64)[1].split(64)[0]; aX = int(ent.split(32)[0]); aY = int(ent.split(32)[1]); }');
  } else {
    L.push(`            (int aX, int aY) = select16(idx${sharedTable !== null ? ', glvTable' : ''});`);
  }
  L.push(grouped
    ? '            if (aX != 0) { (int ax, int ay, int az) = jacAddAffine(rX, rY, rZ, aX, aY); if (ay == 0) { (ax, ay, az) = jacDouble(rX, rY, rZ); } rX = ax; rY = ay; rZ = az; }'
    : '            if (aX != 0) { (int ax, int ay, int az) = jacAddAffine(rX, rY, rZ, aX, aY); rX = ax; rY = ay; rZ = az; }');
  if (grouped) {
    for (let group = 1; group < SPLIT_GROUPS; group++) {
      const shift = group * SPLIT_WIDTH;
      L.push(`            int idx${shift} = (k10 >> (i + ${shift})) % 2 + 2 * ((k20 >> (i + ${shift})) % 2) + 4 * ((k11 >> (i + ${shift})) % 2) + 8 * ((k21 >> (i + ${shift})) % 2);`);
      L.push(`            int aX${shift} = 0; int aY${shift} = 0;`);
      L.push(`            if (idx${shift} != 0) { bytes ent${shift} = glvTable${shift}.split((idx${shift} - 1) * 64)[1].split(64)[0]; aX${shift} = int(ent${shift}.split(32)[0]); aY${shift} = int(ent${shift}.split(32)[1]); }`);
      L.push(`            if (aX${shift} != 0) { (int ax${shift}, int ay${shift}, int az${shift}) = jacAddAffine(rX, rY, rZ, aX${shift}, aY${shift}); if (ay${shift} == 0) { (ax${shift}, ay${shift}, az${shift}) = jacDouble(rX, rY, rZ); } rX = ax${shift}; rY = ay${shift}; rZ = az${shift}; }`);
    }
  }
  L.push('        }');
  if (final) {
    if (!projectiveOutput) {
      L.push(`        (int icx, int icy, int icz) = jacAddAffine(rX, rY, rZ, ${IC0[0]}, ${IC0[1]});`);
      L.push('        require(mulFp(icz, zInv) == 1);');
      L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
      L.push('        int vkxX = mulFp(icx, zInv2);');
      L.push('        int vkxY = mulFp(icy, zInv3);');
    }
    const vkxState = projectiveOutput ? ['rX', 'rY', 'rZ'] : ['vkxX', 'vkxY'];
    const finalState = covenantResidue ? [...PROOF_STATE, ...vkxState] : vkxState;
    L.push(covOut(finalState, finalState));
  } else {
    // Upstream G2 bounds the proof tuple and its exact commitment seam carries it here; this
    // genesis bounds inputs/GLV witnesses, and the Jacobian helpers reduce derived coordinates.
    // Legacy layouts still reduce here.
    const nextState = covenantResidue ? [...STATE, ...PROOF_STATE] : STATE;
    L.push(covOut(nextState, covenantResidue || stageBound || !first ? nextState : []));
  }
  L.push('    }');
  L.push('}');
  return (L.join('\n') + '\n');
}

// ---- JS reference: Jacobian MSM matching the contract (for planning + build) ----
const aF = (x, y) => (x + y) % P, sF = (x, y) => (x - y + P) % P, mF = (x, y) => (x * y) % P, qF = (x) => (x * x) % P;
function jacDouble(X, Y, Z) { const a = qF(X), b = qF(Y), c = qF(b); const d = mF(2n, sF(sF(qF(aF(X, b)), a), c)); const e = mF(3n, a), f = qF(e); const nx = sF(f, mF(2n, d)); return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y, Z))]; }
function jacAdd(aX, aY, aZ, bX, bY, bZ) { if (aZ === 0n) return [bX, bY, bZ]; const z1 = qF(aZ), z2 = qF(bZ); const u1 = mF(aX, z2), u2 = mF(bX, z1); const s1 = mF(mF(aY, bZ), z2), s2 = mF(mF(bY, aZ), z1); if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ); const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2); const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2); const nx = sF(sF(qF(rr), j), mF(2n, v)); return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1), z2), h)]; }
function jacDoubleSplit(X, Y, Z) {
  const a = qF(X), b = qF(Y), c = qF(b), d = (4n * X * b) % P;
  const e = (3n * a) % P, f = qF(e), nx = (f + 2n * P - 2n * d) % P;
  return [nx, (e * (d + P - nx) + 8n * P - 8n * c) % P, (2n * Y * Z) % P];
}
function jacAddSplit(aX, aY, aZ, bX, bY) {
  if (aZ === 0n) return [bX, bY, 1n];
  const z1z1 = qF(aZ), u2 = mF(bX, z1z1), s2 = (z1z1 * aZ * bY) % P;
  if (aX === u2 && aY === s2) return jacDoubleSplit(aX, aY, aZ);
  const h = (u2 + P - aX) % P, hh = qF(h), hhh = mF(h, hh);
  const rr = (s2 + P - aY) % P, vv = mF(aX, hh);
  const nx = (rr * rr + 3n * P - hhh - 2n * vv) % P, ayhhh = mF(aY, hhh);
  return [nx, (rr * (vv + P - nx) + P - ayhhh) % P, mF(aZ, h)];
}
const TBL = TABLE.map((pt) => pt ? [((pt[0] % P) + P) % P, ((pt[1] % P) + P) % P] : null);
const SPLIT_TBLS = shiftedTables.map((table) => table.map((pt) =>
  pt ? [((pt[0] % P) + P) % P, ((pt[1] % P) + P) % P] : null));
/** accumulator [X,Y,Z] after MSM windows [0,upto) for scalars (k10,k20,k11,k21). */
export function vkxGlvStateAt(k10, k20, k11, k21, upto) {
  let X = 0n, Y = 1n, Z = 0n;
  for (let w = 0; w < upto; w++) {
    const i = BigInt((ITERS - 1) - w);
    if (Z !== 0n) [X, Y, Z] = jacDouble(X, Y, Z);
    const idx = Number(((k10 >> i) & 1n) + 2n * ((k20 >> i) & 1n) + 4n * ((k11 >> i) & 1n) + 8n * ((k21 >> i) & 1n));
    if (idx > 0) { const t = TBL[idx]; [X, Y, Z] = jacAdd(X, Y, Z, t[0], t[1], 1n); }
  }
  return [X, Y, Z];
}
/** Grouped accumulator: three fixed-table base groups over 43 positions. */
export function vkxGlvSplitStateAt(k10, k20, k11, k21, upto) {
  let X = 0n, Y = 1n, Z = 0n;
  for (let w = 0; w < upto; w++) {
    const i = BigInt((SPLIT_WIDTH - 1) - w);
    if (Z !== 0n) [X, Y, Z] = jacDoubleSplit(X, Y, Z);
    for (let group = 0; group < SPLIT_GROUPS; group++) {
      const bit = i + BigInt(group * SPLIT_WIDTH);
      const idx = Number(((k10 >> bit) & 1n) + 2n * ((k20 >> bit) & 1n) +
        4n * ((k11 >> bit) & 1n) + 8n * ((k21 >> bit) & 1n));
      if (idx > 0) { const t = SPLIT_TBLS[group][idx]; [X, Y, Z] = jacAddSplit(X, Y, Z, t[0], t[1]); }
    }
  }
  return [X, Y, Z];
}
const modinvP = (a) => modpow(((a % P) + P) % P, P - 2n, P);
/** final zInv = (Z of (acc + IC0))^-1 mod p. */
export function vkxGlvZinv(k10, k20, k11, k21) {
  const acc = vkxGlvStateAt(k10, k20, k11, k21, ITERS);
  const ic0 = [((IC0[0] % P) + P) % P, ((IC0[1] % P) + P) % P];
  const [, , fz] = jacAdd(acc[0], acc[1], acc[2], ic0[0], ic0[1], 1n);
  return fz === 0n ? 0n : modinvP(fz);
}
export function vkxGlvSplitZinv(k10, k20, k11, k21) {
  const acc = vkxGlvSplitStateAt(k10, k20, k11, k21, SPLIT_WIDTH);
  const ic0 = [((IC0[0] % P) + P) % P, ((IC0[1] % P) + P) % P];
  const [, , fz] = jacAddSplit(acc[0], acc[1], acc[2], ic0[0], ic0[1]);
  return fz === 0n ? 0n : modinvP(fz);
}
export { ITERS as VKXGLV_ITERS };
export { SPLIT_WIDTH as VKXGLV_SPLIT_ITERS };
export { SPLIT_GROUPS as VKXGLV_SPLIT_GROUPS };
export const GLV_TABLE_HEX = TABLE_HEX, GLV_SPLIT_TABLE_HEX = SPLIT_TABLE_HEX, GLV_IC0 = IC0;

// ---- plan + emit (worst-case-ish planning scalars: dense ~127-bit) ----
if (process.argv[1] && process.argv[1].endsWith('gen_vkx_glv.mjs')) {
  // worst-case planning: a public input near r-1 decomposes to dense ~127-bit (k1,k2)
  const [wk10, wk20] = glvDecompose(r - 1n), [wk11, wk21] = glvDecompose((1n << 253n) - 1n);
  const win0 = ((wk10 + wk20 * LAM) % r + r) % r, win1 = ((wk11 + wk21 * LAM) % r + r) % r;
  const SER_state = (X, Y, Z) => [X, Y, Z, win0, win1, wk10, wk20, wk11, wk21];
  const { commit } = await import('./_millermath.mjs');
  console.error(`planning GLV vk_x chunks (${ITERS}-bit 4-scalar Straus)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
  const chunks = []; let lo = 0;
  while (lo < ITERS) {
    const [X0, Y0, Z0] = vkxGlvStateAt(wk10, wk20, wk11, wk21, lo);
    const tryHi = (hi) => {
      const final = hi === ITERS, first = lo === 0;
      const fullIn = SER_state(X0, Y0, Z0).map(String);
      const proofState = PROOF_LIMBS.map(String);
      const inSt = COVENANT_RESIDUE
        ? (first ? proofState : [...fullIn, ...proofState])
        : STAGE_BOUND && first ? fullIn.slice(3) : fullIn;
      const firstArgs = COVENANT_RESIDUE && first ? [...proofState, ...fullIn.slice(3)] : inSt;
      let outLimbs, args;
      if (final) {
        const acc = vkxGlvStateAt(wk10, wk20, wk11, wk21, ITERS);
        if (PROJECTIVE_OUTPUT) {
          const vkx = acc.map(String);
          outLimbs = COVENANT_RESIDUE ? [...proofState, ...vkx] : vkx;
          args = firstArgs;
        } else {
          const zinv = vkxGlvZinv(wk10, wk20, wk11, wk21);
          const ic0 = [((IC0[0] % P) + P) % P, ((IC0[1] % P) + P) % P];
          const [fx, fy] = jacAdd(acc[0], acc[1], acc[2], ic0[0], ic0[1], 1n);
          const z2 = qF(zinv), z3 = mF(z2, zinv);
          const vkx = [mF(fx, z2), mF(fy, z3)].map(String);
          outLimbs = COVENANT_RESIDUE ? [...proofState, ...vkx] : vkx;
          args = [...firstArgs, String(zinv)];
        }
      }
      else { const [X, Y, Z] = vkxGlvStateAt(wk10, wk20, wk11, wk21, hi); const next = SER_state(X, Y, Z).map(String); outLimbs = COVENANT_RESIDUE ? [...next, ...proofState] : next; args = firstArgs; }
      const src = genCash(
        lo,
        hi,
        first,
        final,
        STAGE_BOUND,
        null,
        COVENANT_RESIDUE,
        false,
        PROJECTIVE_OUTPUT,
      );
      const committed = COVENANT_RESIDUE && first ? proofState : inSt;
      const m = measureCovenant(src, args.map(BigInt), outLimbs.map(BigInt), committed.map(BigInt));
      return { hi, final, src, m, fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET };
    };
    let best = tryHi(lo + 1);
    for (let hi = lo + 2; hi <= ITERS; hi++) { const c = tryHi(hi); if (c.fits) best = c; else break; }
    const idx = chunks.length;
    writeFileSync(join(GEN, `vkxglv_${String(idx).padStart(2, '0')}.cash`), best.src);
    chunks.push({ idx, lo, hi: best.hi, first: lo === 0, final: best.final, operationCost: best.m.operationCost, lockingBytes: best.m.lockingBytes });
    console.error(`  vkxglv chunk ${idx}: [${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} accepted=${best.m.accepted} final=${best.final}`);
    lo = best.hi;
  }
  const vkxState = PROJECTIVE_OUTPUT ? ['rX', 'rY', 'rZ'] : ['vkxX', 'vkxY'];
  writeFileSync(join(GEN, 'manifest_vkxglv.json'), JSON.stringify({ numChunks: chunks.length, iters: ITERS, glv: true, stageBound: STAGE_BOUND, covenantResidue: COVENANT_RESIDUE, ...(PROJECTIVE_OUTPUT ? { projectiveOutput: true } : {}), genesisDerived: STAGE_BOUND, exactProofHandoff: COVENANT_RESIDUE, stageLayout: COVENANT_RESIDUE ? [...PROOF_STATE, ...vkxState] : undefined, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, final: c.final })) }, null, 2));
  console.error(`GLV vk_x: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}
