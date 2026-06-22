// Shared helpers for the chunked BLS12-381 vk_x generators. Curve constants +
// IC points come from the singleton instance (singleton/bls12-381/bls_instance.mjs)
// so the chunked aggregator and the singleton baseline verify the SAME instance.
//
// This is the BLS12-381 counterpart of chunked/pairing/_millermath.mjs's covenant +
// vk_x sections. The only curve-specific differences from BN254 are: the 381-bit
// base-field prime, 48-byte state limbs (a 381-bit field element needs 48 bytes, not
// the 40 used for BN254's 254-bit field), the 255-bit scalar field (so the MSM tiles
// 255 bit positions, MSB-first base 254), and the BLS IC points. The Jacobian G1
// formulas are b-independent, so they are identical to BN254.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { vk, PUBLIC_INPUTS, computeVkx, Fp, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';

export { vk, PUBLIC_INPUTS, computeVkx, bls12_381 };

// ---- curve constants ----
export const P = Fp.ORDER; // BLS12-381 base-field prime (381-bit)
export const ITERS = 255;  // scalar-field bit width (group order r < 2^255)
export const MSBASE = ITERS - 1; // MSB-first: window position j -> bit index MSBASE - j

// ---- in-process cashc compile (compileString + asmToBytecode); no subprocess ----
const CASHC_LIB = pathToFileURL('C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/index.js').href;
const cashc = await import(CASHC_LIB);
const asmToBytecode = cashc.utils.asmToBytecode;
/** compile a .cash source string -> redeem bytecode (Uint8Array); throws on compile error */
export const compileBytecode = (src) => asmToBytecode(cashc.compileString(src).bytecode);

export const OP_BUDGET = (41 + 10_000) * 800; // 8,032,800 op-cost per standard input
export const TARGET_UNLOCK = 10_000, OP_DROP = 0x75, OP_PUSHDATA2 = 0x4d;

const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { bigIntToVmNumber, encodeDataPush, bigIntToBinUintLE, binToFixedLength, numberToBinUint16LE, createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

// ---- state serialization (matches cash hash256(toPaddedBytes(., 48))) ----
export const le48 = (n) => binToFixedLength(bigIntToBinUintLE(((BigInt(n) % P) + P) % P), 48);
const sha256 = (b) => createHash('sha256').update(b).digest();
const sha256d = (b) => sha256(sha256(b));
export const commit = (limbs) => sha256d(Buffer.concat(limbs.map(le48))).toString('hex');

// ---- covenant (token state-threading) helpers --------------------------------
// A GENERIC (proof-independent) chunk carries NO baked state: the running-state
// HASH lives in the spent/created token's NFT commitment. The unlocking pushes the
// raw state limbs; the contract checks them against the input token's commitment,
// recomputes, and re-commits to output[0] under the same token thread. One fixed
// locking therefore aggregates ANY public inputs (runtime-general).
export const CATEGORY = new Uint8Array(32).fill(0xbe); // BLS vk_x benchmark thread id
/** 32-byte NFT commitment of a state (decl-order limbs), as bytes. */
export const commitBin = (limbs) => new Uint8Array(sha256d(Buffer.concat(limbs.map(le48))));
export const serExpr = (names) => 'hash256(' + names.map((n) => `toPaddedBytes(${n}, 48)`).join(' + ') + ')';
/** require: the spent token commits hash(incoming state) (decl-order `names`). */
export const covIn = (names) =>
  `        require(tx.inputs[this.activeInputIndex].nftCommitment == ${serExpr(names)});`;
/** require: output[0] commits hash(outgoing, reduced) + perpetuates the token thread. */
export const covOut = (outNames) =>
  `        int P = ${P};\n` +
  `        require(tx.outputs[0].nftCommitment == hash256(${outNames.map((n) => `toPaddedBytes(${n} % P, 48)`).join(' + ')}));\n` +
  '        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);';

// ---- real-VM measurement (padded to buy op-cost budget) ----
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
export const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });

/** Real-VM measurer for a COVENANT chunk: drives it through a synthetic token tx
 * (spent UTXO = hash(incoming), output[0] = hash(outgoing)) so the introspection
 * resolves. `stateInts` = everything the unlocking pushes (decl order); `commitInts`
 * = the committed incoming state; `outLimbs` = the committed outgoing state. */
export function measureCovenant(src, stateInts, commitInts, outLimbs) {
  let raw;
  try { raw = compileBytecode(src); }
  catch (e) { return { lockingBytes: Infinity, operationCost: Infinity, accepted: false, error: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([OP_DROP, ...raw]);
  const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...argBytes, ...padPush(argBytes.length, TARGET_UNLOCK)]);
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(commitInts)) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { lockingBytes: locking.length, operationCost: st.metrics.operationCost, accepted, error: st.error ?? null };
}

// ---- G1 Jacobian reference math over Fp (matches the .cash ops bit-for-bit) ----
const aF = (x, y) => (x + y) % P, sF = (x, y) => (x - y + P) % P, mF = (x, y) => (x * y) % P, qF = (x) => (x * x) % P;
export function jacDouble(X, Y, Z) {
  const a = qF(X), b = qF(Y), c = qF(b);
  const d = mF(2n, sF(sF(qF(aF(X, b)), a), c));
  const e = mF(3n, a), f = qF(e);
  const nx = sF(f, mF(2n, d));
  return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y, Z))];
}
export function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  if (aZ === 0n) return [bX, bY, bZ];
  const z1z1 = qF(aZ), z2z2 = qF(bZ);
  const u1 = mF(aX, z2z2), u2 = mF(bX, z1z1);
  const s1 = mF(mF(aY, bZ), z2z2), s2 = mF(mF(bY, aZ), z1z1);
  if (u1 === u2 && s1 === s2) return jacDouble(aX, aY, aZ);
  const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2);
  const rr = mF(2n, sF(s2, s1)), v = mF(u1, i2);
  const nx = sF(sF(qF(rr), j), mF(2n, v));
  return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1z1), z2z2), h)];
}

// ---- IC points (affine) + the Shamir/Straus added point per bit ----
const a0 = vk.ic[0].toAffine(), a1 = vk.ic[1].toAffine(), a2 = vk.ic[2].toAffine();
const aT = vk.ic[1].add(vk.ic[2]).toAffine();
export const IC0 = [a0.x, a0.y], IC1 = [a1.x, a1.y], IC2 = [a2.x, a2.y], T = [aT.x, aT.y];
/** the point added at bit i for inputs (in0,in1): IC1, IC2, IC1+IC2, or none. */
export const addedPoint = (in0, in1, i) => {
  const b0 = (in0 >> BigInt(i)) & 1n, b1 = (in1 >> BigInt(i)) & 1n;
  if (b0 && b1) return T; if (b0) return IC1; if (b1) return IC2; return null;
};

/** Shamir/Straus vk_x accumulator after processing windows [0,upto): [rX,rY,rZ]. */
export function vkxStateAt(in0, in1, upto) {
  let X = 0n, Y = 1n, Z = 0n;
  for (let j = 0; j < upto; j++) {
    const i = MSBASE - j;
    if (Z !== 0n) [X, Y, Z] = jacDouble(X, Y, Z);
    const ap = addedPoint(in0, in1, i);
    if (ap) [X, Y, Z] = jacAdd(X, Y, Z, ap[0], ap[1], 1n);
  }
  return [X, Y, Z];
}
const modpow = (b, e) => { let r = 1n; b %= P; while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; };
/** final chunk's auxiliary zInv = (Z of (acc + IC0))^-1, supplied in the unlocking. */
export function vkxFinalZinv(in0, in1) {
  const acc = vkxStateAt(in0, in1, ITERS);
  const [, , fz] = jacAdd(acc[0], acc[1], acc[2], IC0[0], IC0[1], 1n);
  return fz === 0n ? 0n : modpow(fz, P - 2n);
}

// ---- predict-and-adjust greedy window planner (same as _millermath) ----
export function planChunk(lo, max, opTarget, tryAt, state) {
  let best = null;
  const consider = (hi) => { const r = tryAt(hi); if (r.fits) best = { hi, ...r }; return r; };
  if (state.perUnit == null) {
    consider(lo + 1);
    for (let hi = lo + 2; hi <= max; hi++) if (!consider(hi).fits) break;
  } else {
    const guess = Math.min(max, lo + Math.max(1, Math.floor(opTarget / state.perUnit)));
    if (consider(guess).fits) { for (let hi = guess + 1; hi <= max; hi++) if (!consider(hi).fits) break; }
    else { for (let hi = guess - 1; hi > lo; hi--) if (consider(hi).fits) break; }
    if (!best) consider(lo + 1);
  }
  if (best) { const u = best.hi - lo, pu = best.operationCost / u; state.perUnit = state.perUnit == null ? pu : 0.5 * state.perUnit + 0.5 * pu; }
  return best;
}
