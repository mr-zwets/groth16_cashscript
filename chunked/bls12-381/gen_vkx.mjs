// Generator for the chunked BLS12-381 vk_x = IC0 + in0*IC1 + in1*IC2 covenant.
// BLS12-381 port of chunked/pairing/gen_vkx.mjs: a single MSB-first double-and-add
// over one Jacobian accumulator R, per bit adding one of {IC1, IC2, T=IC1+IC2}
// chosen in-script from (bit_i(in0), bit_i(in1)); IC0 folded at the end, then a
// verified-inverse-on-stack -> affine, COMMITTING the computed vk_x to output[0]
// (proof-agnostic: no baked instance). Public inputs in0,in1 are RUNTIME (carried,
// committed state = rX,rY,rZ,in0,in1 in the token NFT commitment).
//
// MAGNITUDE-INDEPENDENT: the loop tiles ALL 255 scalar-field bit positions, and the
// chunk windows are sized against a WORST-CASE planning input with every bit set (so
// every position executes both a doubling and an add). One fixed set of lockings
// therefore aggregates ANY public inputs < r, exactly like the EVM ecMul precompile
// (flat cost, no small-input optimization) -- not a small-input-only aggregator.
//
//   node gen_vkx.mjs           # plan + emit (measures real-VM op-cost per window)
//   node gen_vkx.mjs probe     # fast fixed-window probe (no planner)
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, ITERS, MSBASE, IC0, IC1, IC2, T, covIn, covOut, measureCovenant,
  vkxStateAt, vkxFinalZinv, jacAdd, planChunk, OP_BUDGET,
} from './_vkxmath.mjs';

// outgoing limbs of the FINAL chunk: fold IC0 into acc, invert, -> affine vk_x.
const finalOut = (acc, zInv) => {
  const fold = jacAdd(acc[0], acc[1], acc[2], IC0[0], IC0[1], 1n);
  const z2 = (zInv * zInv) % P, z3 = (z2 * zInv) % P;
  return [(fold[0] * z2) % P, (fold[1] * z3) % P];
};

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const Pstr = P.toString();
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_900_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);

// WORST-CASE planning input: every bit set -> every position does double + add.
// Sizing windows against this makes the covenant work for ANY input < r.
const PLAN = (1n << BigInt(ITERS)) - 1n;

// ---- contract template (loop-based, runtime-input committed state) ----
const prologue = () => `function addFp(int x, int y) returns (int) { return (x + y) % ${Pstr}; }
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
function jacAdd(int aX, int aY, int aZ, int bX, int bY, int bZ) returns (int, int, int) {
    int rx = bX; int ry = bY; int rz = bZ;
    if (aZ != 0) {
        int z1z1 = sqrFp(aZ); int z2z2 = sqrFp(bZ);
        int u1 = mulFp(aX, z2z2); int u2 = mulFp(bX, z1z1);
        int s1 = mulFp(mulFp(aY, bZ), z2z2); int s2 = mulFp(mulFp(bY, aZ), z1z1);
        if (u1 == u2 && s1 == s2) {
            int da = sqrFp(aX); int db = sqrFp(aY); int dc = sqrFp(db);
            int dd = mulFp(2, subFp(subFp(sqrFp(addFp(aX, db)), da), dc));
            int de = mulFp(3, da); int df = sqrFp(de);
            int dnx = subFp(df, mulFp(2, dd));
            int dny = subFp(mulFp(de, subFp(dd, dnx)), mulFp(8, dc));
            int dnz = mulFp(2, mulFp(aY, aZ));
            rx = dnx; ry = dny; rz = dnz;
        } else {
            int h = subFp(u2, u1); int i2 = sqrFp(mulFp(2, h)); int jj = mulFp(h, i2);
            int rr = mulFp(2, subFp(s2, s1)); int vv = mulFp(u1, i2);
            int anx = subFp(subFp(sqrFp(rr), jj), mulFp(2, vv));
            int any = subFp(mulFp(rr, subFp(vv, anx)), mulFp(2, mulFp(s1, jj)));
            int anz = mulFp(subFp(subFp(sqrFp(addFp(aZ, bZ)), z1z1), z2z2), h);
            rx = anx; ry = any; rz = anz;
        }
    }
    return rx, ry, rz;
}
function selectPoint(int b0, int b1) returns (int, int, int) {
    int aX = 0; int aY = 0; int doAdd = 0;
    if (b0 == 1 && b1 == 1) { aX = ${T[0]}; aY = ${T[1]}; doAdd = 1; }
    else { if (b0 == 1) { aX = ${IC1[0]}; aY = ${IC1[1]}; doAdd = 1; }
           else { if (b1 == 1) { aX = ${IC2[0]}; aY = ${IC2[1]}; doAdd = 1; } } }
    return aX, aY, doAdd;
}`;

function genCash(lo, hi, final) {
  const count = hi - lo, hiBit = MSBASE - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`// BLS12-381 vk_x chunk: Shamir window [${lo},${hi}), final=${final}.`);
  L.push(prologue());
  L.push('contract VkxBlsChunk() {');
  L.push(final ? '    function spend(int rX, int rY, int rZ, int input0, int input1, int zInv, bytes unused zeroPadding) {' : '    function spend(int rX, int rY, int rZ, int input0, int input1, bytes unused zeroPadding) {');
  L.push(covIn(['rX', 'rY', 'rZ', 'input0', 'input1'])); // incoming accumulator+inputs == spent token commitment
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx, int dy, int dz) = jacDouble(rX, rY, rZ); rX = dx; rY = dy; rZ = dz; }');
  L.push('            int b0 = (input0 >> i) % 2;');
  L.push('            int b1 = (input1 >> i) % 2;');
  L.push('            (int aX, int aY, int doAdd) = selectPoint(b0, b1);');
  L.push('            if (doAdd == 1) { (int ax, int ay, int az) = jacAdd(rX, rY, rZ, aX, aY, 1); rX = ax; rY = ay; rZ = az; }');
  L.push('        }');
  if (final) {
    L.push(`        (int icx, int icy, int icz) = jacAdd(rX, rY, rZ, ${IC0[0]}, ${IC0[1]}, 1);`);
    L.push('        rX = icx; rY = icy; rZ = icz;');
    L.push('        require(mulFp(rZ, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(rX, zInv2);');
    L.push('        int vkxY = mulFp(rY, zInv3);');
    // commit the computed vk_x to output[0] (consumed by the pairing's pair-2);
    // NOT compared to a baked point, so this aggregates any instance's inputs.
    L.push(covOut(['vkxX', 'vkxY']));
  } else {
    L.push(covOut(['rX', 'rY', 'rZ', 'input0', 'input1']));
  }
  L.push('    }');
  L.push('}');
  return (L.join('\n') + '\n');
}

// ---- fast probe (no planner): one fixed window, report op-cost ----
if (process.argv[2] === 'probe') {
  const lo = Number(process.argv[3] ?? 0), hi = Number(process.argv[4] ?? lo + 1), final = hi === ITERS;
  const [rX0, rY0, rZ0] = vkxStateAt(PLAN, PLAN, lo);
  const [rX, rY, rZ] = vkxStateAt(PLAN, PLAN, hi);
  const acc = vkxStateAt(PLAN, PLAN, hi);
  const commitInts = [rX0, rY0, rZ0, PLAN, PLAN];
  const zInv = final ? vkxFinalZinv(PLAN, PLAN) : null;
  const stateInts = final ? [...commitInts, zInv] : commitInts;
  const outLimbs = final ? finalOut(acc, zInv) : [acc[0], acc[1], acc[2], PLAN, PLAN];
  const m = measureCovenant(genCash(lo, hi, final), stateInts, commitInts, outLimbs);
  console.error(`probe [${lo},${hi}) final=${final}: lock=${m.lockingBytes}B op=${m.operationCost.toLocaleString()} accepted=${m.accepted}${m.error ? ' err=' + m.error : ''}`);
  process.exit(0);
}

// ---- plan + emit (worst-case windows; predict-and-adjust greedy growth) ----
console.error(`planning BLS12-381 vk_x chunks (WORST-CASE all-bits-set, ${ITERS} positions)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const chunks = []; let lo = 0; const planState = { perUnit: null };
while (lo < ITERS) {
  const [rX0, rY0, rZ0] = vkxStateAt(PLAN, PLAN, lo);
  const commitInts = [rX0, rY0, rZ0, PLAN, PLAN];
  const tryAt = (hi) => {
    const final = hi === ITERS;
    const acc = vkxStateAt(PLAN, PLAN, hi);
    let outLimbs, zInv = null, stateInts;
    if (final) { zInv = vkxFinalZinv(PLAN, PLAN); outLimbs = finalOut(acc, zInv); stateInts = [...commitInts, zInv]; }
    else { outLimbs = [acc[0], acc[1], acc[2], PLAN, PLAN]; stateInts = commitInts; }
    const src = genCash(lo, hi, final);
    const m = measureCovenant(src, stateInts, commitInts, outLimbs);
    return { src, final, zInv, operationCost: m.operationCost, lockingBytes: m.lockingBytes, fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET };
  };
  const best = planChunk(lo, ITERS, OP_TARGET, tryAt, planState);
  if (!best) throw new Error(`no fitting window at lo=${lo} (single step exceeds budget?)`);
  const idx = chunks.length;
  writeFileSync(join(GEN, `vkx_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, lo, hi: best.hi, final: best.final, operationCost: best.operationCost, lockingBytes: best.lockingBytes });
  console.error(`  vkx chunk ${idx}: [${lo},${best.hi}) iters=${best.hi - lo} lock=${best.lockingBytes}B op=${best.operationCost.toLocaleString()} final=${best.final}`);
  lo = best.hi;
}
const totalOp = chunks.reduce((a, c) => a + c.operationCost, 0);
console.error(`vk_x: ${chunks.length} chunks, total op=${totalOp.toLocaleString()} (worst-case sizing)`);
writeFileSync(join(GEN, 'manifest_vkx.json'), JSON.stringify({
  curve: 'BLS12-381', iters: ITERS, worstCaseSized: true, numChunks: chunks.length, totalOperationCost: totalOp,
  chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, final: c.final })),
}, null, 2));
console.error('wrote generated/manifest_vkx.json');
