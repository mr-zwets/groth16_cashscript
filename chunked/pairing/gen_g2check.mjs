// Generator for the G2 input-validation PROLOGUE (EIP-197 rigor), multi-tx.
// Validates the prover's points before the pairing: G1 on-curve (A,C), G2 on-curve
// (B), and the G2 subgroup test via the FAST endomorphism check (gnark-crypto bn254,
// ePrint 2022/348):
//     B in G2  <=>  [x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B)
// This walks only |x0| (BN_X, ~63 bits) in the double-and-add instead of 6*x0^2 (~128
// bits, the old `[6x^2]B == psi(B)` test), more than halving the scalar-mult work (8 -> 3
// chunks). The Frobenius map psi is cheap (conjugation + constant mul). The final chunk
// finishes [x0]B (Jacobian), affine-izes it with a WITNESS Fp2 inverse zinv of R.Z
// (gated by fp2Mul(R.Z, zinv) == 1, exactly the pattern vk_x uses for its 1/Z), builds
// psi/psi^2/psi^3 with the verified affine psi, accumulates the LHS through the verified
// g2AddAffine, doubles psi^3([x0]B) to get psi^3([2x0]B), and cross-multiplies the two
// Jacobian results for equality. Every field op reuses the VERIFIED tower + g2Double /
// g2AddAffine / psi from the shared singleton library.
//
// GENERIC covenant: the running accumulator R + the points A,B,C live in the token NFT
// commitment (no baked instance), so one fixed set of lockings validates ANY proof. In
// stage-bound mode, the first chunk consumes only (-A,B,C), derives R=B, and the final
// chunk emits that exact tuple. G2_CARRIES_VKX=1 adds vk_x to the carried tuple for the
// continuously bound covenant graph and writes a separate g2checkfull namespace. The
// final chunk additionally consumes the per-proof witness zinv (2 limbs).
//   node gen_g2check.mjs        plan + emit generated/g2check_NN.cash + manifest_g2check.json
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createVirtualMachineBch2026, createVirtualMachineBchSpec, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, numberToBinUint32LE } from '@bitauth/libauth';
import { measureCovenantFile, compileFileBytecode, planChunk, covIn, covOut, decl, proof, vec, vkxPoint, commitBin, CATEGORY, TARGET_UNLOCK, OP_PUSHDATA2 } from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PROBE = join(GEN, `_probe_g2check_${process.pid}.cash`); // planner compiles candidates from file so the lib import resolves
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_900_000);
const BYTE_BUDGET = Number(process.env.BYTE_BUDGET ?? 9_700);
const LINKED_CUTS = process.env.G2_LINKED_LAYOUT === '1' ? [25, 51] : [];
const STAGE_BOUND = process.env.STAGE_BOUND_LAYOUT === '1';
const CARRIES_VKX = STAGE_BOUND && process.env.G2_CARRIES_VKX === '1';
const PREFIX = CARRIES_VKX ? 'g2checkfull' : 'g2check';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN_X = 4965661367192848881n; // BN254 seed |x0|
const NBITS = 63; // bitlength of BN_X (MSB at index 62)
const bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n; // MSB-first, k in [0,NBITS)

// ---- JS reference for the SAME (reducing) Fp2 / G2 Jacobian formulas as the contract
const aF = (x, y) => [(x[0] + y[0]) % P, (x[1] + y[1]) % P];
const sF = (x, y) => [((x[0] - y[0]) % P + P) % P, ((x[1] - y[1]) % P + P) % P];
const mF = (x, y) => { const v0 = (x[0] * y[0]) % P, v1 = (x[1] * y[1]) % P; const c0 = ((v0 - v1) % P + P) % P; const c1 = ((((x[0] + x[1]) * (y[0] + y[1])) % P - v0 - v1) % P + P) % P; return [c0, c1]; };
const sqF = (x) => mF(x, x);
const scF = (x, k) => [(x[0] * k) % P, (x[1] * k) % P];
const eqF = (x, y) => x[0] === y[0] && x[1] === y[1];
const conjF = (x) => [x[0], (P - x[1]) % P];
const ZERO = [0n, 0n], ONE2 = [1n, 0n];
const modpowFp = (b, e) => { let r = 1n; b = ((b % P) + P) % P; while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; };
// Fp2 inverse: 1/(c0+c1 u) = conj/(c0^2+c1^2) (u^2 = -1, matches contract's fp2Conj/fp2Mul gate)
const invF2 = (x) => { const d = modpowFp((x[0] * x[0] + x[1] * x[1]) % P, P - 2n); return [(x[0] * d) % P, (((P - x[1]) % P) * d) % P]; };
// psi (affine) matching the singleton library Miller.cash: x' = conj(x)*PSI_X, y' = conj(y)*PSI_Y
const PSI_X = [21575463638280843010398324269430826099269044274347216827212613867836435027261n, 10307601595873709700152284273816112264069230130616436755625194854815875713954n];
const PSI_Y = [2821565182194536844548159561693502659359617185244120367078079554186484126554n, 3505843767911556378687030309984248845540243509899259641013678093033130930403n];
const psiAff = (x, y) => [mF(conjF(x), PSI_X), mF(conjF(y), PSI_Y)];

function g2DoubleJS(X, Y, Z) {
  const A = sqF(X), B = sqF(Y), C = sqF(B);
  const D = scF(sF(sF(sqF(aF(X, B)), A), C), 2n);
  const E = scF(A, 3n), F = sqF(E);
  const nX = sF(F, scF(D, 2n));
  const nY = sF(mF(E, sF(D, nX)), scF(C, 8n));
  const nZ = scF(mF(Y, Z), 2n);
  return [nX, nY, nZ];
}
function g2AddAffineJS(X, Y, Z, bX, bY) {
  if (eqF(Z, ZERO)) return [bX, bY, ONE2];
  const z11 = sqF(Z), u2 = mF(bX, z11), s2 = mF(mF(bY, Z), z11);
  if (eqF(X, u2) && eqF(Y, s2)) return g2DoubleJS(X, Y, Z);
  const h = sF(u2, X), i2 = sqF(scF(h, 2n)), j = mF(h, i2);
  const rr = scF(sF(s2, Y), 2n), v = mF(X, i2);
  const nX = sF(sF(sqF(rr), j), scF(v, 2n));
  const nY = sF(mF(rr, sF(v, nX)), scF(mF(Y, j), 2n));
  const nZ = mF(sF(sF(sqF(aF(Z, ONE2)), z11), ONE2), h);
  return [nX, nY, nZ];
}
// accumulator (X,Y,Z) after processing bits [0,upto) of |x0| (double-and-add from MSB).
// EXPORTED name kept as g2checkAccAt so all build_vectors consumers pick up the fast walk.
export function g2checkAccAt(B, upto) {
  let X = ZERO, Y = ONE2, Z = ZERO;
  for (let k = 0; k < upto; k++) { [X, Y, Z] = g2DoubleJS(X, Y, Z); if (bit(k)) [X, Y, Z] = g2AddAffineJS(X, Y, Z, B[0], B[1]); }
  return [X, Y, Z];
}
// the final chunk's witness: zinv = (Z of [x0]B)^-1 in Fp2, supplied in the unlocking
// (gated by fp2Mul(Z, zinv) == 1). B = [[xa,xb],[ya,yb]] affine.
export function g2checkFastZinv(B) {
  const [, , Z] = g2checkAccAt(B, NBITS);
  return invF2(Z); // [zinvA, zinvB]
}
export { NBITS as G2CHECK_NBITS };
const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];

// ---- the committed instance's points — the reference run for chunk planning
const Baff = proof.b.toAffine();
const Aaff = (STAGE_BOUND ? proof.a.negate() : proof.a).toAffine();
const Caff = proof.c.toAffine();
const vkxAff = vkxPoint(vec.publicInputs).toAffine();
const B = [[Baff.x.c0, Baff.x.c1], [Baff.y.c0, Baff.y.c1]];
const Blimbs = [B[0][0], B[0][1], B[1][0], B[1][1]];
const proofLimbs = STAGE_BOUND
  ? [Aaff.x, Aaff.y, ...Blimbs, Caff.x, Caff.y, ...(CARRIES_VKX ? [vkxAff.x, vkxAff.y] : [])]
  : [...Blimbs, Aaff.x, Aaff.y, Caff.x, Caff.y];
const stateLimbs = (R) => [...rLimbs(R), ...proofLimbs];
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n]; // twist b2

// ---- contract emitter (reuses verified groth16 tower via the shared singleton library) ----
const LIB_IMPORT = '../../../singleton/bn254/lib/Miller.cash';
const RN = ['RXa', 'RXb', 'RYa', 'RYb', 'RZa', 'RZb'];
const AN = ['Ax', 'Ay'], BN = ['Bxa', 'Bxb', 'Bya', 'Byb'], CN = ['Cx', 'Cy'], VKN = ['vkxX', 'vkxY'];
const PROOF = STAGE_BOUND ? [...AN, ...BN, ...CN, ...(CARRIES_VKX ? VKN : [])] : [...BN, ...AN, ...CN];
const ALL = [...RN, ...PROOF];

function genChunk(lo, hi, isFirst, isLast) {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB_IMPORT}";`);
  L.push(`// G2 input-validation chunk: fast-endo [x0]B double-and-add bits [${lo},${hi}); first=${isFirst} last=${isLast}.`);
  L.push('contract G2Check() {');
  // the final (endo) chunk additionally takes the witnessed Fp2 inverse zinv of R.Z.
  const stateParams = STAGE_BOUND && isFirst ? PROOF : ALL;
  const sig = isLast ? `    function spend(${decl(stateParams)}, int zinvA, int zinvB, bytes unused zeroPadding) {`
                     : `    function spend(${decl(stateParams)}, bytes unused zeroPadding) {`;
  L.push(sig);
  L.push(covIn(stateParams));
  if (isFirst) {
    L.push('        int fieldP = P;');
    for (const name of [...AN, ...BN, ...CN]) {
      L.push(`        require(${name} >= 0 && ${name} < fieldP);`);
    }
    L.push('        require(mulFp(Ay, Ay) == addFp(mulFp(mulFp(Ax, Ax), Ax), 3));'); // A on G1
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));'); // C on G1
    L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);'); // B on G2: y^2 == x^3 + b2
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  let r = STAGE_BOUND && isFirst ? ['Bxa', 'Bxb', 'Bya', 'Byb', '1', '0'] : RN.slice(), uid = 0;
  const fresh = () => Array.from({ length: 6 }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    const d = fresh();
    L.push(`        (${decl(d)}) = g2Double(${r.join(',')});`); r = d;
    if (bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AddAffine(${r.join(',')}, ${BN.join(',')});`); r = a; }
  }
  if (isLast) {
    // r = [x0]B (Jacobian). Affine-ize with the witnessed inverse of R.Z, then verify
    //   [x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B).
    const [Rxa, Rxb, Rya, Ryb, Rza, Rzb] = r;
    // gate: zinv is the true Fp2 inverse of R.Z  (=> R.Z != 0, point not at infinity)
    L.push(`        (int gza,int gzb) = fp2Mul(${Rza}, ${Rzb}, zinvA, zinvB);`);
    L.push('        require(gza == 1); require(gzb == 0);');
    L.push('        (int zi2a,int zi2b) = fp2Sqr(zinvA, zinvB);');
    L.push('        (int zi3a,int zi3b) = fp2Mul(zi2a, zi2b, zinvA, zinvB);');
    L.push(`        (int a0xa,int a0xb) = fp2Mul(${Rxa}, ${Rxb}, zi2a, zi2b);`); // affine x of [x0]B
    L.push(`        (int a0ya,int a0yb) = fp2Mul(${Rya}, ${Ryb}, zi3a, zi3b);`); // affine y of [x0]B
    // psi, psi^2, psi^3 of [x0]B (affine). On BN254,
    // psi^2(x,y)=(KX*x,-y), and psi^3(x,y)=(KX*psi(x),-psi(y)).
    // Use those identities directly instead of evaluating three full psi maps.
    L.push('        (int bxa,int bxb,int bya,int byb) = psi(a0xa, a0xb, a0ya, a0yb);');
    L.push('        (int cxa,int cxb) = fp2Scale(a0xa, a0xb, 21888242871839275220042445260109153167277707414472061641714758635765020556616);');
    L.push('        (int cya,int cyb) = fp2Neg(a0ya, a0yb);');
    L.push('        (int dxa,int dxb) = fp2Scale(bxa, bxb, 21888242871839275220042445260109153167277707414472061641714758635765020556616);');
    L.push('        (int dya,int dyb) = fp2Neg(bya, byb);');
    // LHS = [x0]B + B + psi + psi^2  (start jac(a0), accumulate affine points)
    L.push('        (int l1xa,int l1xb,int l1ya,int l1yb,int l1za,int l1zb) = g2AddAffine(a0xa, a0xb, a0ya, a0yb, 1, 0, Bxa, Bxb, Bya, Byb);');
    L.push('        (int l2xa,int l2xb,int l2ya,int l2yb,int l2za,int l2zb) = g2AddAffine(l1xa, l1xb, l1ya, l1yb, l1za, l1zb, bxa, bxb, bya, byb);');
    L.push('        (int lxa,int lxb,int lya,int lyb,int lza,int lzb) = g2AddAffine(l2xa, l2xb, l2ya, l2yb, l2za, l2zb, cxa, cxb, cya, cyb);');
    // RHS = 2 * psi^3([x0]B) = psi^3([2x0]B)
    L.push('        (int rxa,int rxb,int rya,int ryb,int rza,int rzb) = g2Double(dxa, dxb, dya, dyb, 1, 0);');
    // projective equality LHS == RHS (cross-multiply by Z^2 / Z^3)
    L.push('        (int lz2a,int lz2b) = fp2Sqr(lza, lzb); (int lz3a,int lz3b) = fp2Mul(lz2a, lz2b, lza, lzb);');
    L.push('        (int rz2a,int rz2b) = fp2Sqr(rza, rzb); (int rz3a,int rz3b) = fp2Mul(rz2a, rz2b, rza, rzb);');
    L.push('        (int xl_a,int xl_b) = fp2Mul(lxa, lxb, rz2a, rz2b); (int xr_a,int xr_b) = fp2Mul(rxa, rxb, lz2a, lz2b);');
    L.push('        require(xl_a == xr_a); require(xl_b == xr_b);');
    L.push('        (int yl_a,int yl_b) = fp2Mul(lya, lyb, rz3a, rz3b); (int yr_a,int yr_b) = fp2Mul(rya, ryb, lz3a, lz3b);');
    L.push('        require(yl_a == yr_a); require(yl_b == yr_b);');
    if (STAGE_BOUND) L.push(covOut(PROOF, PROOF));
  } else {
    // Genesis bounds the proof tuple, and all Fp2 helpers return reduced limbs.
    L.push(covOut([...r, ...PROOF], [...r, ...PROOF]));
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- correct real-VM measurement for the FINAL (endo) chunk: the spent token commits
// ONLY the 14 state limbs (matching covIn) while the unlocking ALSO pushes the 2 witness
// limbs (zinv) as trailing params. (measureCovenantFile auto-commits ALL pushed ints, so
// it cannot size a chunk whose witness is excluded from the commitment.)
const realVm = (process.env.BCH_VM === 'spec' ? createVirtualMachineBchSpec : createVirtualMachineBch2026)(false);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const OP_PUSHDATA4 = 0x4e;
const padPush = (argLen, target) => {
  const budget = target - argLen;
  if (budget - 3 <= 0xffff) { const N = budget - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); }
  const N = budget - 5; return Uint8Array.from([OP_PUSHDATA4, ...numberToBinUint32LE(N), ...new Uint8Array(N)]);
};
function measureFinalEndo(src, committedState, witness, outLimbs, probePath) {
  let raw;
  try { writeFileSync(probePath, src); raw = compileFileBytecode(probePath); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([...raw]);
  const pushInts = [...committedState, ...witness];
  const argBytes = Uint8Array.from([...pushInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(committedState)) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: STAGE_BOUND
        ? [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }]
        : [{ lockingBytecode: locking, valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

// ---- plan windows by measured op-cost (only when run as the main script) ----
if (process.argv[1] && process.argv[1].endsWith('gen_g2check.mjs')) {
console.error(`planning G2-check chunks (fast-endo, ${NBITS}-bit [x0]B)  OP_TARGET=${OP_TARGET.toLocaleString()}`);
const witness = g2checkFastZinv(B);
const chunks = []; let lo = STAGE_BOUND ? 1 : 0; const planState = { perUnit: null };
while (lo < NBITS) {
  const first = chunks.length === 0;
  const inLimbs = STAGE_BOUND && first ? proofLimbs : stateLimbs(g2checkAccAt(B, lo));
  const tryHi = (hi) => {
    const last = hi === NBITS;
    const src = genChunk(lo, hi, first, last);
    const m = last
      ? measureFinalEndo(src, inLimbs, witness, STAGE_BOUND ? proofLimbs : [], PROBE)
      : measureCovenantFile(src, inLimbs, stateLimbs(g2checkAccAt(B, hi)), PROBE, true);
    return { fits: m.accepted && m.lockingBytes <= BYTE_BUDGET && m.operationCost <= OP_TARGET, operationCost: m.operationCost, hi, last, src, m };
  };
  // Linked grouped/intratx packaging has a cheaper handoff prologue. Its measured layout
  // keeps one more scalar bit in the middle chunk, reducing the assembled verifier size.
  const linkedHi = LINKED_CUTS[chunks.length];
  const best = linkedHi === undefined
    ? planChunk(lo, NBITS, OP_TARGET, tryHi, planState)
    : tryHi(linkedHi);
  const idx = chunks.length;
  writeFileSync(join(GEN, `${PREFIX}_${String(idx).padStart(2, '0')}.cash`), best.src);
  chunks.push({ idx, lo, hi: best.hi, first, last: best.last, lockingBytes: best.m.lockingBytes, operationCost: best.m.operationCost });
  console.error(`  g2check chunk ${idx}: bits[${lo},${best.hi}) lock=${best.m.lockingBytes}B op=${best.m.operationCost.toLocaleString()} accepted=${best.m.accepted} last=${best.last}`);
  lo = best.hi;
}
writeFileSync(join(GEN, `manifest_${PREFIX}.json`), JSON.stringify({ numChunks: chunks.length, nbits: NBITS, fastEndo: true, canonicalProofCoordinates: true, linkedLayout: LINKED_CUTS.length > 0, stageBound: STAGE_BOUND, genesisDerived: STAGE_BOUND, carriesVkx: CARRIES_VKX, stageLayout: STAGE_BOUND ? PROOF : undefined, chunks: chunks.map((c) => ({ idx: c.idx, lo: c.lo, hi: c.hi, first: c.first, last: c.last })) }, null, 2));
console.error(`G2-check: ${chunks.length} chunks, total op=${chunks.reduce((s, c) => s + c.operationCost, 0).toLocaleString()}`);
}
