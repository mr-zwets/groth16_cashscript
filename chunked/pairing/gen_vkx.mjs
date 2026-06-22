// Generator for the chunked vk_x = IC0 + in0*IC1 + in1*IC2 for the PAIRING
// instance (so it composes with the pairing chunks into a full chunked Groth16
// verifier). Ports the shamir Shamir/Straus approach: a single MSB-first
// double-and-add over one accumulator R, per bit adding one of {IC1, IC2,
// T=IC1+IC2} chosen in-script from (bit_i(in0), bit_i(in1)); IC0 folded at the
// end, then a verified-inverse-on-stack -> affine, asserting == the baked vk_x
// (the same point the pairing's pair-2 bakes). Public inputs in0,in1 are RUNTIME
// (carried, hash256-committed state = rX,rY,rZ,in0,in1). EC ops are reusable
// functions; the per-chunk loop body compiles once (op-cost binds). Windows are
// sized by measured real-VM op-cost.  node gen_vkx.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bn254, vec, commit, measureCovenant, covIn, covOut } from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, `_probe_${process.pid}.cash`);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
// Slightly conservative target (vs 7.9M elsewhere): the worst-case planning value
// below leaves position 253 un-set, so a real input with bit 253 set turns the
// accumulator non-zero one step earlier -> at most one extra jacDouble (~150k) in
// chunk 0. The headroom to the 8,032,800 budget absorbs it.
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const ITERS = 254;

// ---- instance constants ----
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const IC = vec.vk.ic.map(g1);
const ic0 = IC[0].toAffine(), ic1 = IC[1].toAffine(), ic2 = IC[2].toAffine();
const Ta = IC[1].add(IC[2]).toAffine();
const IC0 = [ic0.x, ic0.y], IC1 = [ic1.x, ic1.y], IC2 = [ic2.x, ic2.y], T = [Ta.x, Ta.y];
// WORST-CASE planning inputs: all low bits set, so the planner costs (nearly) every
// of the 254 positions as a doubling AND an add. Sizing the chunk windows against
// this makes the deployed covenant aggregate ANY public inputs < r (magnitude-
// independent, full-width) -- the EVM ecMul-equivalent property, NOT a small-input-
// only aggregator. The contract bodies are input-agnostic (they read the input bits
// at runtime), so only the WINDOW BOUNDARIES come from here; build_vectors.mjs
// rebuilds every step for the real committed/extra instances.
//
// Value MUST be < P: the non-final covOut re-commits the pass-through input limbs as
// `input % P`, so a planning value >= P (e.g. all 254 bits = 2^254-1 > the BN254
// prime) would mismatch the un-reduced commitment and every chunk would reject. The
// largest contiguous-low-bits value below P is 2^253-1 (bit 253 clear); the one
// uncosted high position is handled by the OP_TARGET margin above. (For BLS12-381 the
// 381-bit field dwarfs the 255-bit scalar, so 2^255-1 < P there and no margin is
// needed.)
const [in0, in1] = [(1n << 253n) - 1n, (1n << 253n) - 1n];
// EXP (the expected affine vk_x for the planning bit-pattern) is computed from the
// SAME Jacobian double-and-add the contract runs -- NOT noble.multiply, since the
// all-bits-set planning value is not a valid in-range scalar. Defined after the
// Jacobian helpers below.

// ---- G1 Jacobian reference math (Fp) ----
const aF = (x, y) => (x + y) % P, sF = (x, y) => (x - y + P) % P, mF = (x, y) => (x * y) % P, qF = (x) => (x * x) % P;
function jacDouble(X, Y, Z) {
  const a = qF(X), b = qF(Y), c = qF(b);
  const d = mF(2n, sF(sF(qF(aF(X, b)), a), c));
  const e = mF(3n, a), f = qF(e);
  const nx = sF(f, mF(2n, d));
  const ny = sF(mF(e, sF(d, nx)), mF(8n, c));
  const nz = mF(2n, mF(Y, Z));
  return [nx, ny, nz];
}
function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  if (aZ === 0n) return [bX, bY, bZ];
  const z1z1 = qF(aZ), z2z2 = qF(bZ);
  const u1 = mF(aX, z2z2), u2 = mF(bX, z1z1);
  const s1 = mF(mF(aY, bZ), z2z2), s2 = mF(mF(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2);
  const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2);
  const nx = sF(sF(qF(rr), j), mF(2n, v));
  const ny = sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j)));
  const nz = mF(sF(sF(qF(aF(aZ, bZ)), z1z1), z2z2), h);
  return [nx, ny, nz];
}
const addedPoint = (i) => { const b0 = (in0 >> BigInt(i)) & 1n, b1 = (in1 >> BigInt(i)) & 1n; if (b0 && b1) return T; if (b0) return IC1; if (b1) return IC2; return null; };
function runWindow(lo, hi, rX, rY, rZ) {
  for (let j = lo; j < hi; j++) { const i = 253 - j; if (rZ !== 0n)[rX, rY, rZ] = jacDouble(rX, rY, rZ); const ap = addedPoint(i); if (ap)[rX, rY, rZ] = jacAdd(rX, rY, rZ, ap[0], ap[1], 1n); }
  return [rX, rY, rZ];
}

// ---- contract template (shamir, loop-based, 5-var runtime-input state) ----
const SER = 'hash256(toPaddedBytes(rX, 40) + toPaddedBytes(rY, 40) + toPaddedBytes(rZ, 40) + toPaddedBytes(input0, 40) + toPaddedBytes(input1, 40))';
const prologue = () => `    internal function addFp(int x, int y) returns (int) { return (x + y) % ${Pstr}; }
    internal function subFp(int x, int y) returns (int) { return (x - y + ${Pstr}) % ${Pstr}; }
    internal function mulFp(int x, int y) returns (int) { return (x * y) % ${Pstr}; }
    internal function sqrFp(int x) returns (int) { return (x * x) % ${Pstr}; }
    internal function jacDouble(int x, int y, int z) returns (int, int, int) {
        int a = sqrFp(x); int b = sqrFp(y); int c = sqrFp(b);
        int d = mulFp(2, subFp(subFp(sqrFp(addFp(x, b)), a), c));
        int e = mulFp(3, a); int f = sqrFp(e);
        int nx = subFp(f, mulFp(2, d));
        int ny = subFp(mulFp(e, subFp(d, nx)), mulFp(8, c));
        int nz = mulFp(2, mulFp(y, z));
        return nx, ny, nz;
    }
    internal function jacAdd(int aX, int aY, int aZ, int bX, int bY, int bZ) returns (int, int, int) {
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
    internal function selectPoint(int b0, int b1) returns (int, int, int) {
        int aX = 0; int aY = 0; int doAdd = 0;
        if (b0 == 1 && b1 == 1) { aX = ${T[0]}; aY = ${T[1]}; doAdd = 1; }
        else { if (b0 == 1) { aX = ${IC1[0]}; aY = ${IC1[1]}; doAdd = 1; }
               else { if (b1 == 1) { aX = ${IC2[0]}; aY = ${IC2[1]}; doAdd = 1; } } }
        return aX, aY, doAdd;
    }`;
function genCash(lo, hi, final, incoming, outgoing) {
  const count = hi - lo, hiBit = 253 - lo;
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// vk_x (pairing instance) chunk: Shamir window [${lo},${hi}), final=${final}.`);
  L.push('contract VkxChunk() {');
  L.push(prologue());
  L.push(final ? '    function spend(int rX, int rY, int rZ, int input0, int input1, int zInv) {' : '    function spend(int rX, int rY, int rZ, int input0, int input1) {');
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
    // NOT compared to a baked point, so this verifies any instance's public inputs.
    L.push(covOut(['vkxX', 'vkxY']));
  } else {
    L.push(covOut(['rX', 'rY', 'rZ', 'input0', 'input1']));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// expected vk_x of the worst-case planning bit-pattern (via the contract's own
// Jacobian math, so the final chunk's committed output matches what it computes).
const _accF = runWindow(0, ITERS, 0n, 1n, 0n);
const _foldF = jacAdd(_accF[0], _accF[1], _accF[2], IC0[0], IC0[1], 1n);
const _zE = _foldF[2] === 0n ? 0n : modpow(_foldF[2], P - 2n, P);
const _zE2 = (_zE * _zE) % P, _zE3 = (_zE2 * _zE) % P;
const EXP = [(_foldF[0] * _zE2) % P, (_foldF[1] * _zE3) % P];

// ---- plan + emit (greedy linear growth; small state -> loop body is fine) ----
console.error(`planning vk_x chunks  WORST-CASE all-bits-set (${ITERS} positions, magnitude-independent)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const commitState = (st) => commit(st.map(String)); // st = [rX,rY,rZ,in0,in1]
const chunks = []; let lo = 0; let state = [0n, 1n, 0n, in0, in1];
while (lo < ITERS) {
  const incoming = commitState(state);
  const [rX0, rY0, rZ0] = state;
  const tryHi = (hi) => {
    const final = hi === ITERS;
    const [rX, rY, rZ] = runWindow(lo, hi, rX0, rY0, rZ0);
    let outgoing = null, zInv = null, outLimbs;
    if (final) { const [fx, fy, fz] = jacAdd(rX, rY, rZ, IC0[0], IC0[1], 1n); zInv = (fz === 0n ? 0n : modpow(fz, P - 2n, P)); outLimbs = EXP; }
    else { outgoing = commitState([rX, rY, rZ, in0, in1]); outLimbs = [rX, rY, rZ, in0, in1]; }
    const src = genCash(lo, hi, final, incoming, outgoing ?? '00');
    const stateInts = final ? [rX0, rY0, rZ0, in0, in1, zInv] : [rX0, rY0, rZ0, in0, in1];
    const m = measureCovenant(src, stateInts, outLimbs);
    return { hi, final, src, m, outgoing, zInv, fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET };
  };
  let best = tryHi(lo + 1);
  for (let hi = lo + 2; hi <= ITERS; hi++) { const c = tryHi(hi); if (c.fits) best = c; else break; }
  const idx = chunks.length;
  writeFileSync(join(GEN, `vkx_${String(idx).padStart(2, '0')}.cash`), best.src);
  const inc = commitState(state);
  chunks.push({ idx, lo, hi: best.hi, final: best.final, incoming: inc, incomingState: state.map(String), zInv: best.zInv?.toString() ?? null, operationCost: best.m.operationCost, lockingBytes: best.m.lockingBytes });
  console.error(`  vkx chunk ${idx}: [${lo},${best.hi}) iters=${best.hi - lo} lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} final=${best.final}`);
  const [rX, rY, rZ] = runWindow(lo, best.hi, rX0, rY0, rZ0);
  state = [rX, rY, rZ, in0, in1];
  lo = best.hi;
}
function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
try { execFileSync('rm', [PROBE]); } catch {}
console.error(`vk_x: ${chunks.length} chunks, total op=${chunks.reduce((a, c) => a + c.operationCost, 0).toLocaleString()}`);
writeFileSync(join(GEN, 'manifest_vkx.json'), JSON.stringify({ numChunks: chunks.length, worstCaseSized: true, iters: ITERS, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, final: c.final, incoming: c.incoming, incomingState: c.incomingState, zInv: c.zInv })) }, null, 2));
