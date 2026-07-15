// One-transaction quotient-torus verifier vectors for the fixed BLS12-381 Groth16 verification
// key. One fixed-comb public-input input feeds ten fused Miller inputs, all linked inside one
// current-BCH transaction with OP_INPUTBYTECODE.
//
// For this verification key, beta=5*G2.BASE, gamma=7*G2.BASE, and delta=11*G2.BASE, so bilinearity
// rewrites the four-pair Groth16 equation as
//
//   e(-A, B) * e(D, G2.BASE) = 1,  D = 5*alpha + 7*vk_x + 11*C.
//
// One width-six fixed-comb input assembles D. Ten Miller inputs then evaluate the two pairs with
// runtime B in affine coordinates; the first and last inputs include point and subgroup gates. The
// final Miller input performs the quotient-torus residue verdict, so the complete verifier uses
// eleven P2SH32 inputs and no state token. The 6,048-byte fixed-comb table is split across three
// Miller witnesses and hash-pinned by the final comb input. Input zero is the graph entry: every
// nonterminal program pins its immediate successor's P2SH32 locking bytecode, and every program
// requires its exact index in the eleven-input transaction. The valid portfolio includes every
// A/B/C identity combination and the vk_x identity.
//
//   node build_vectors_residue_bls.mjs -> verifier/src/bch/groth16-bls12381-intratx-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  B_IDENTITY_SUBSTITUTE, millerBatchOps, millerCollapsedAffineOps, f12limbs, r6limbs,
  pairsFor, collapsedPairsFor, ptLimbs, unitG1, PT_CFG, COLLAPSED_PT_CFG,
  FIXED_VK_SPECIALIZATION, fixedVkDScalar,
  compileBytecode, le48Exact, P, OP_DROP, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileBytecodeRaw, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import {
  residueTorusWitness, residueWitness, millerFusedOps, millerFusedTorusOps,
} from '../bls12-381/_residuemath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, vkxGlvYinv, vkxGlvUnit, GLV_TABLE_HEX,
  glvUnitCoordinates, glvCollapsedScalar, glvCollapsedProofPoint, vkxGlvSlopeLimbs,
  GLV_COLLAPSED_HIGH_COST_INPUTS, GLV_FIXED_COMB_WIDTH, GLV_FIXED_VK_COLLAPSE, GLV_SHARED_AUDITED_BOUNDS,
  VKXGLV_ITERS, regenGlvSharedAudited,
} from '../bls12-381/gen_vkx_glv.mjs';
import { LINKED_HIGH_COST_INPUTS, LINKED_RESIDUE_NAMESPACE } from '../bls12-381/_residue_linked_plan.mjs';
import { transformChunk, headerSize } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated', LINKED_RESIDUE_NAMESPACE);
const W = 48; // BLS12-381 limb width
const UNIT_G1 = process.env.BLS_UNIT_G1 === '1';
const FIXED_VK_COLLAPSE = process.env.BLS_FIXED_VK_COLLAPSE === '1';
const AFFINE_G2 = process.env.BLS_AFFINE_G2 === '1';
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
if (FIXED_VK_COLLAPSE !== GLV_FIXED_VK_COLLAPSE) throw new Error('GLV collapse mode mismatch');
const FIXED_COMB = GLV_FIXED_COMB_WIDTH !== 0;
if (!FIXED_VK_COLLAPSE || !UNIT_G1 || !AFFINE_G2 || !QUOTIENT_TORUS || GLV_FIXED_COMB_WIDTH !== 6) {
  throw new Error('run this builder through pnpm vectors:intratx:torus:bls');
}
const PAIR_CFG = FIXED_VK_COLLAPSE ? COLLAPSED_PT_CFG : PT_CFG;
const verifierPairsFor = (inputs, pf) => FIXED_VK_COLLAPSE
  ? collapsedPairsFor(inputs, pf)
  : pairsFor(inputs, pf);
const PRIME = P.toString();
import {
  hexToBin, binToHex, bigIntToVmNumber, hash256, sha256, encodeLockingBytecodeP2sh32,
  encodeDataPush, encodeTransactionBch, createVirtualMachineBch2026,
} from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));

// The fixed-comb table is reconstructed from fixed-offset Miller witness parts. The final GLV
// chunk pins the complete table with hash256, and every GLV chunk reads those same transaction-local
// inputs. Two additional Miller inputs carry proof-dependent slope slices bound by the GLV
// equations. On high-cost proofs, the parts replace bytes already required by operation-cost density.
const GLV_COUNT = GLV_SHARED_AUDITED_BOUNDS.length - 1;
if (GLV_COUNT !== 1) throw new Error(`fixed-key verifier requires one GLV input, received ${GLV_COUNT}`);
const GLV_TABLE_PART_LENGTHS = [1897, 1898, 2253];
const GLV_TABLE_PARTS = (() => {
  let offset = 0;
  return GLV_TABLE_PART_LENGTHS.map((length) => {
    const part = GLV_TABLE_BYTES.slice(offset, offset + length);
    offset += length;
    return part;
  });
})();
if (GLV_TABLE_PARTS.reduce((sum, part) => sum + part.length, 0) !== GLV_TABLE_BYTES.length) {
  throw new Error('GLV table carrier parts do not cover the complete table');
}

const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((limb) => [...le48Exact(limb)]));
const limbsEqual = (a, b) => a.length === b.length && a.every((x, i) => BigInt(x) === BigInt(b[i]));

const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));
const OP_RETURN = Uint8Array.from([0x6a]);
const OP_TRUE = Uint8Array.from([0x51]);

// ---- transaction evaluation ---------------------------------------------------------
function verificationData(inputs, sourceValueSatoshis = 1000n, outputValueSatoshis = 1000n) {
  return {
    sourceOutputs: inputs.map((inp) => ({
      lockingBytecode: inp.locking,
      valueSatoshis: sourceValueSatoshis,
    })),
    transaction: {
      version: 2,
      inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
      outputs: [{ lockingBytecode: OP_RETURN, valueSatoshis: outputValueSatoshis }],
      locktime: 0,
    },
  };
}
function evaluateInput(inputs, index, vm = realVm) {
  const st = vm.evaluate({ inputIndex: index, ...verificationData(inputs) });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// ---- instances: #0 committed, #1 distinct (same VK; only A and vk_x change) ----
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point, F2 = bls12_381.fields.Fp2;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const invR = (x) => bls12_381.fields.Fr.inv(mod(x));
const g1 = (scalar) => scalar === 0n ? G1.ZERO : G1.BASE.multiply(scalar);
const g2 = (scalar) => scalar === 0n ? G2.ZERO : G2.BASE.multiply(scalar);
const mkInstance = (inputs, bScalar = 1n, cScalar = 13n) => {
  const A = mod(fixedVkDScalar(inputs, cScalar) * invR(bScalar));
  return { inputs, proof: { a: G1.BASE.multiply(A), b: g2(bScalar), c: g1(cScalar) } };
};
const fixedVk = FIXED_VK_SPECIALIZATION;
const STRESS_INPUTS = FIXED_COMB
  ? [GLV_FIXED_COMB_WIDTH === 6 ? Rord - 1n : (Rord - 1n) / 2n, 0n]
  : FIXED_VK_COLLAPSE ? GLV_COLLAPSED_HIGH_COST_INPUTS : LINKED_HIGH_COST_INPUTS;
const FINAL_EQUAL_INPUTS = [1n, 0n];
const finalEqualCombScalar = glvCollapsedScalar(...FINAL_EQUAL_INPUTS);
const finalEqualAccumulatorScalar = mod(fixedVk.collapsedPublicBaseG1Scalar * finalEqualCombScalar);
const finalEqualOffsetScalar = mod(
  fixedVk.alphaG1Scalar * fixedVk.betaG2Scalar +
  fixedVk.icG1Scalars[0] * fixedVk.gammaG2Scalar,
);
const finalEqualCScalar = mod(
  (finalEqualAccumulatorScalar - finalEqualOffsetScalar) * invR(fixedVk.deltaG2Scalar),
);
const FINAL_EQUAL_INSTANCE = mkInstance(FINAL_EQUAL_INPUTS, 1n, finalEqualCScalar);
const finalEqualAccumulator = vkxGlvStateAt(
  finalEqualCombScalar, 0n, 0n, 0n, VKXGLV_ITERS, FINAL_EQUAL_INSTANCE.proof.c,
);
const finalEqualAddend = glvCollapsedProofPoint(FINAL_EQUAL_INSTANCE.proof.c);
if (finalEqualAddend.is0()) throw new Error('fixed-comb final-equal fixture produced the identity');
const finalEqualAddendAffine = finalEqualAddend.toAffine();
if (finalEqualAccumulator.length !== 2 ||
  finalEqualAccumulator[0] !== finalEqualAddendAffine.x ||
  finalEqualAccumulator[1] !== finalEqualAddendAffine.y) {
  throw new Error('fixed-comb final-equal fixture does not reach the affine doubling branch');
}
const INSTANCES = {
  committed: { inputs: PUBLIC_INPUTS, proof },
  proof1: mkInstance([135208n, 67633n]),
  stress: mkInstance(STRESS_INPUTS),
  nonBaseB: mkInstance([135208n, 67633n], 19n),
  combinedStress: mkInstance(STRESS_INPUTS, 19n),
  variedBC: mkInstance([9137n, 2903n], 37n, 29n),
  combinedVariedC: mkInstance(STRESS_INPUTS, 19n, 29n),
  finalEqual: FINAL_EQUAL_INSTANCE,
};
if (FIXED_VK_COLLAPSE) {
  const stressScalar = glvCollapsedScalar(...STRESS_INPUTS);
  const [stressK1, stressK2] = FIXED_COMB ? [stressScalar, 0n] : glvDecompose(stressScalar);
  const windowCount = FIXED_COMB ? Math.ceil(255 / GLV_FIXED_COMB_WIDTH) : 64;
  const nonzeroWindows = Array.from({ length: windowCount }, (_, window) => {
    if (FIXED_COMB) {
      const row = windowCount - 1 - window;
      return Array.from({ length: GLV_FIXED_COMB_WIDTH }, (_, j) => {
        const bit = row + j * windowCount;
        return bit < 255 ? Number((stressK1 >> BigInt(bit)) & 1n) << j : 0;
      }).reduce((sum, digit) => sum + digit, 0) !== 0;
    }
    const shift = BigInt(2 * (63 - window));
    return ((stressK1 >> shift) & 3n) + 4n * ((stressK2 >> shift) & 3n) !== 0n;
  }).filter(Boolean).length;
  if (nonzeroWindows !== windowCount) throw new Error(`fixed-base stress activates ${nonzeroWindows}/${windowCount} windows`);
}
const fixedVkConstant = fixedVk.alphaG1Scalar * fixedVk.betaG2Scalar +
  fixedVk.icG1Scalars[0] * fixedVk.gammaG2Scalar;
const fixedVkInputCoefficients = fixedVk.icG1Scalars.slice(1)
  .map((scalar) => scalar * fixedVk.gammaG2Scalar);
const kZeroInputs = [
  1n,
  mod((-fixedVkConstant - fixedVkInputCoefficients[0]) * invR(fixedVkInputCoefficients[1])),
];
const identityInstance = (tag) => {
  const identities = new Set(tag);
  const needsKZero = identities.has('C') && (identities.has('A') || identities.has('B'));
  const inputs = needsKZero ? kZeroInputs : PUBLIC_INPUTS.map(BigInt);
  const fixedTerms = fixedVkDScalar(inputs, 0n);
  let a = identities.has('A') ? 0n : 1n;
  const b = identities.has('B') ? 0n : 1n;
  let c = identities.has('C') ? 0n : 13n;
  if (a !== 0n && b !== 0n) a = fixedVkDScalar(inputs, c);
  else if (c !== 0n) c = mod(-fixedTerms * invR(fixedVk.deltaG2Scalar));
  if (mod(-a * b + fixedVkDScalar(inputs, c)) !== 0n) throw new Error(`identity fixture equation mismatch: ${tag}`);
  return { inputs, proof: { a: g1(a), b: g2(b), c: g1(c) }, identityTag: tag };
};
const IDENTITY_INSTANCES = ['A', 'B', 'C', 'AB', 'AC', 'BC', 'ABC'].map(identityInstance);
const MSM_IDENTITY_INSTANCE = (() => {
  const inputs = [
    1n,
    mod(-(fixedVk.icG1Scalars[0] + fixedVk.icG1Scalars[1]) * invR(fixedVk.icG1Scalars[2])),
  ];
  if (!computeVkx(inputs).is0()) throw new Error('runtime MSM identity fixture does not produce infinity');
  const c = 13n, a = fixedVkDScalar(inputs, c);
  return { inputs, proof: { a: g1(a), b: g2(1n), c: g1(c) }, identityTag: 'vkx' };
})();
const pairingEquationAccepts = (inst) => {
  const nonzero = pairsFor(inst.inputs, inst.proof)
    .filter(({ P: pointP, Q: pointQ }) => !pointP.is0() && !pointQ.is0())
    .map(({ P: pointP, Q: pointQ }) => ({ g1: pointP, g2: pointQ }));
  const miller = bls12_381.pairingBatch(nonzero, false);
  return bls12_381.fields.Fp12.eql(bls12_381.fields.Fp12.finalExponentiate(miller), bls12_381.fields.Fp12.ONE);
};

// ---- residue chunk-graph layout constants ----
// Stage-bound Miller genesis = cInv(12) + c(12) + runtime points(10) = 34 limbs.
// f=cInv and R_B=B are derived in-contract; later Miller states still carry all 52 limbs.
const dummy = verifierPairsFor(PUBLIC_INPUTS, proof);
const pointLimbs = (pair, j) => {
  const out = [];
  if (PAIR_CFG[j].P) {
    const point = UNIT_G1 ? unitG1(pair.P) : pair.P.toAffine();
    out.push(...(UNIT_G1 ? [point.u, point.v] : [point.x, point.y]));
  }
  if (PAIR_CFG[j].Q) {
    const q = pair.Q.toAffine();
    out.push(q.x.c0, q.x.c1, q.y.c0, q.y.c1);
  }
  return out;
};
const effectivePairsFor = (inst) => {
  const pairs = verifierPairsFor(inst.inputs, inst.proof);
  if (!UNIT_G1 || !inst.proof.b.is0()) return pairs;
  return pairs.map((pair, j) => j === 0 ? { ...pair, P: G1.ZERO, Q: B_IDENTITY_SUBSTITUTE } : pair);
};
const ptLof = (inst) => verifierPairsFor(inst.inputs, inst.proof).flatMap(pointLimbs);
const ROOT_LIMBS = QUOTIENT_TORUS ? 6 : 24;
const VKX_LIMB_OFFSET = ROOT_LIMBS + pointLimbs(dummy[0], 0).length;
const MILLER_IN_LIMBS = ptLof(INSTANCES.committed).length + ROOT_LIMBS;
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]
const MILLER_DYNAMIC_LIMBS = 12 + (AFFINE_G2 ? 4 : 6);
const MILLER_GENESIS_INPUT = GLV_COUNT;
const GLV_TABLE_CARRIER_OFFSETS = [4, 6, 8];
const GLV_TABLE_CARRIER_INPUTS = GLV_TABLE_CARRIER_OFFSETS.map((offset) => GLV_COUNT + offset);
const MILLER_CARRIER_IN_BYTES = MILLER_DYNAMIC_LIMBS * W;
const GLV_SLOPE_LOCAL = {
  windowStart: 1,
  windowEndExclusive: 15,
  slopeCount: 28,
  length: 28 * W,
};
const GLV_SLOPE_CARRIERS = [
  { windowStart: 15, windowEndExclusive: 29, slopeCount: 28, millerOffset: 3, includesFinalAddition: false },
  { windowStart: 29, windowEndExclusive: 43, slopeCount: 29, millerOffset: 5, includesFinalAddition: true },
].map((carrier) => {
  const length = carrier.slopeCount * W;
  return {
    ...carrier,
    inputIndex: GLV_COUNT + carrier.millerOffset,
    unlockingBytecodeOffset: headerSize(MILLER_CARRIER_IN_BYTES) +
      MILLER_CARRIER_IN_BYTES + headerSize(length),
    length,
  };
});
regenGlvSharedAudited(GEN, {
  parts: GLV_TABLE_PARTS.map((part, index) => {
    const inputBytes = GLV_TABLE_CARRIER_OFFSETS[index] === 0
      ? MILLER_IN_LIMBS * W
      : MILLER_CARRIER_IN_BYTES;
    return {
      inputIndex: GLV_TABLE_CARRIER_INPUTS[index],
      dataOffset: headerSize(inputBytes) + inputBytes + headerSize(part.length),
      length: part.length,
    };
  }),
  slopeParts: GLV_SLOPE_CARRIERS,
}, true);
const MILLER_GENESIS_NAMES = QUOTIENT_TORUS
  ? [
      ...Array.from({ length: 6 }, (_, i) => `u${i}`),
      'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu0', 'Pv0', 'Pu1', 'Pv1',
    ]
  : [
      ...Array.from({ length: 12 }, (_, i) => `ci${i}`),
      ...Array.from({ length: 12 }, (_, i) => `c${i}`),
      'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu0', 'Pv0', 'Pu1', 'Pv1',
    ];
const MILLER_STATIC_NAMES = [
  'Pu0', 'Pv0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu1', 'Pv1',
  ...(QUOTIENT_TORUS
    ? Array.from({ length: 6 }, (_, i) => `u${i}`)
    : [
        ...Array.from({ length: 12 }, (_, i) => `c${i}`),
        ...Array.from({ length: 12 }, (_, i) => `ci${i}`),
      ]),
];
const MILLER_GENESIS_OFFSETS = new Map(MILLER_GENESIS_NAMES.map((name, i) => [name, i * W]));

// ---- per-stage specs ----------------------------------------------------------------
const runtimeRLimbs = (R) => AFFINE_G2
  ? [R.x.c0, R.x.c1, R.y.c0, R.y.c1]
  : r6limbs(R);
const statePrefixLength = 12 + (AFFINE_G2 ? 4 : 6);
const uLimbs = (u) => [u.c0.c0, u.c0.c1, u.c1.c0, u.c1.c1, u.c2.c0, u.c2.c1];
const stateLimbsR = (s) => [
  ...f12limbs(s.f), ...runtimeRLimbs(s.Rs[0]),
  ...(QUOTIENT_TORUS ? uLimbs(s.u) : [...f12limbs(s.c), ...f12limbs(s.cInv)]),
];
const withPtsR = (limbs, ptL) => [...limbs.slice(0, statePrefixLength), ...ptL, ...limbs.slice(statePrefixLength)];

// g2check is no longer a standalone stage — the on-curve checks + G2 subgroup test are fused into
// the first/last fused-Miller chunks (see gen_miller_residue.mjs), reusing R_B = [|x|]B.
function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = FIXED_COMB
    ? [glvCollapsedScalar(in0, in1), 0n]
    : glvDecompose(FIXED_VK_COLLAPSE ? glvCollapsedScalar(in0, in1) : in0);
  const [k11, k21] = FIXED_VK_COLLAPSE ? [0n, 0n] : glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const collapsedProof = FIXED_VK_COLLAPSE ? glvCollapsedProofPoint(inst.proof.c) : null;
  const collapsedProofAffine = collapsedProof === null || collapsedProof.is0()
    ? { x: 0n, y: 0n }
    : collapsedProof.toAffine();
  const scal = FIXED_COMB
    ? [in0, in1]
    : FIXED_VK_COLLAPSE
    ? [in0, in1, k10, k20]
    : [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('one-transaction BLS residue requires stage-bound GLV generation');
  if (man.sharedTable !== true) throw new Error('one-transaction BLS residue requires shared-table GLV generation');
  if (JSON.stringify(man.slopeCarriers) !== JSON.stringify(GLV_SLOPE_CARRIERS)) {
    throw new Error('one-transaction BLS residue slope-carrier manifest mismatch');
  }
  let slopeCarrierParts = [];
  const specs = man.chunks.map((ch) => {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo, inst.proof.c), ...scal];
    const inLimbs = ch.first ? fullIn.slice(FIXED_VK_COLLAPSE ? 2 : 3) : fullIn;
    const allSlopeBytes = blob(vkxGlvSlopeLimbs(k10, k20, k11, k21, ch.lo, ch.hi, inst.proof.c));
    const slopeBytes = allSlopeBytes.slice(0, GLV_SLOPE_LOCAL.length);
    let offset = GLV_SLOPE_LOCAL.length;
    slopeCarrierParts = GLV_SLOPE_CARRIERS.map(({ length }) => {
      const part = allSlopeBytes.slice(offset, offset + length);
      offset += length;
      return part;
    });
    if (offset !== allSlopeBytes.length || slopeCarrierParts.some((part, index) =>
      part.length !== GLV_SLOPE_CARRIERS[index].length)) {
      throw new Error('fixed-comb slope carrier parts do not cover the complete witness');
    }
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: UNIT_G1 ? vkxGlvUnit(k10, k20, k11, k21, inst.proof.c) : [vkxAff.x, vkxAff.y],
      extras: FIXED_VK_COLLAPSE
        ? [slopeBytes, collapsedProofAffine.x, collapsedProofAffine.y, vkxGlvYinv(k10, k20, k11, k21, inst.proof.c)]
        : [UNIT_G1 ? vkxGlvYinv(k10, k20, k11, k21) : vkxGlvZinv(k10, k20, k11, k21)], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
      label: FIXED_VK_COLLAPSE ? 'GLV final -> assemble fixed-G2 sum D' : 'GLV vk_x final -> assemble vk_x',
      checkpoint: FIXED_VK_COLLAPSE ? 'fixed-g2-sum' : 'vk_x',
      enforceExactInputLength: true,
    };
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi, inst.proof.c), ...scal],
      extras: FIXED_VK_COLLAPSE ? [slopeBytes] : [], role: 'within',
      label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
      enforceExactInputLength: true,
    };
  });
  return { specs, slopeCarrierParts };
}
function specsMillerResidue(inst, c, cInv, u = null, bad = {}) {
  const originalPairs = verifierPairsFor(inst.inputs, inst.proof);
  const pairs = effectivePairsFor(inst);
  const { states, boundary, ops } = QUOTIENT_TORUS
    ? millerFusedTorusOps(pairs, c, cInv, u, {
        unitLines: UNIT_G1, ptCfg: PAIR_CFG, affineG2: AFFINE_G2,
      })
    : millerFusedOps(pairs, c, cInv, {
        unitLines: UNIT_G1, ptCfg: PAIR_CFG, affineG2: AFFINE_G2,
      });
  const ptL = pairs.flatMap(pointLimbs);
  const originalPtL = originalPairs.flatMap(pointLimbs);
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('one-transaction BLS residue requires stage-bound Miller generation');
  if (man.unitG1Lines !== UNIT_G1) throw new Error('one-transaction BLS residue Miller coordinate mode does not match the generated manifest');
  if (man.fixedVkCollapse !== FIXED_VK_COLLAPSE || man.affineG2 !== AFFINE_G2) {
    throw new Error('one-transaction BLS residue Miller specialization mismatch');
  }
  if ((man.quotientTorus === true) !== QUOTIENT_TORUS ||
    (man.terminalFused === true) !== QUOTIENT_TORUS) {
    throw new Error('one-transaction BLS residue quotient mode mismatch');
  }
  const genesisPts = [...originalPtL.slice(2, 6), ...originalPtL.slice(0, 2), ...originalPtL.slice(6)];
  if (bad.Ax !== undefined) genesisPts[4] = bad.Ax;
  if (bad.Ay !== undefined) genesisPts[5] = bad.Ay;
  if (!FIXED_VK_COLLAPSE && bad.Cy !== undefined) genesisPts[9] = bad.Cy;
  const genesis = QUOTIENT_TORUS
    ? [...uLimbs(u), ...genesisPts]
    : [...f12limbs(cInv), ...f12limbs(c), ...genesisPts];
  const specs = man.chunks.map((ch) => {
    const inLimbs = ch.opLo === 0 ? genesis : withPtsR(stateLimbsR(states[ch.opLo]), ptL);
    const slopes = AFFINE_G2
      ? ops.slice(ch.opLo, ch.opHi).flatMap((op) => op.j === 0 && op.slope !== undefined ? [op.slope.c0, op.slope.c1] : [])
      : [];
    if (ch.final) {
      if (QUOTIENT_TORUS) {
        if (ch.terminalFused !== true || ch.outgoing !== null) {
          throw new Error('quotient-torus final Miller chunk is not terminal');
        }
        return {
          file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
          inLimbs, outLimbs: [], extras: slopes, role: 'terminal',
          label: `miller ops[${ch.opLo},${ch.opHi}) + quotient verdict`, checkpoint: 'verify',
        };
      }
      const s = states[ch.opHi];
      return {
        file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [...f12limbs(s.f), ...f12limbs(s.c), ...f12limbs(s.cInv)], extras: slopes, role: 'cross',
        cmp: { cmpExpr: 'outBlob', nextFullInLen: TAIL_HANDOFF_LIMBS * W, skip: 0, cmpLen: TAIL_HANDOFF_LIMBS * W },
        label: `miller ops[${ch.opLo},${ch.opHi}) -> boundary fF`, checkpoint: 'miller-boundary',
      };
    }
    return { file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: withPtsR(stateLimbsR(states[ch.opHi]), ptL), extras: slopes, role: 'within', label: `miller ops[${ch.opLo},${ch.opHi})${ch.idx === 0 ? ' + validate inputs' : ''}`, checkpoint: ch.idx === 0 ? 'validate-inputs' : undefined };
  });
  return { specs, boundary };
}
function specsResidueTail(fF, c, cInv, w) {
  const fFl = f12limbs(fF), cl = f12limbs(c), cil = f12limbs(cInv), wl = f12limbs(w).slice(0, 6);
  const commit36 = [...fFl, ...cl, ...cil];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexpres.json'), 'utf8'));
  const chunk = man.chunks?.[0];
  if (man.residueTail !== true || man.fp6Membership !== true || man.deployment !== 'linked-hash-free' ||
    man.numChunks !== 1 || man.nwalk !== 0 || chunk?.idx !== 0 || chunk.role !== 'finalize' || chunk.final !== true ||
    chunk.witnessLimbs?.join(',') !== '0,1,2,3,4,5' || chunk.implicitZeroLimbs?.join(',') !== '6,7,8,9,10,11') {
    throw new Error('one-transaction BLS residue requires the one-chunk Fp6 tail');
  }
  return [{
    file: join(GEN, 'finalexpres_00.cash'), inLimbs: commit36, outLimbs: [], extras: wl, role: 'terminal',
    label: 'residue Fp6 verdict', checkpoint: 'verify',
  }];
}
function buildSpecs(inst) {
  // g2check is no longer a standalone stage: its on-curve checks + G2 subgroup test are fused into
  // the first/last fused-Miller chunks (the Miller loop already walks R_B = [|x|]B). See
  // gen_miller_residue.mjs. This drops ~3 chunks / ~28 KB of op-cost-bought padding.
  const { specs: vkx, slopeCarrierParts } = specsVkxGlv(inst);
  const pairs = effectivePairsFor(inst);
  const { boundary: fRaw } = AFFINE_G2
    ? millerCollapsedAffineOps(pairs)
    : millerBatchOps(pairs, { unitLines: UNIT_G1, ptCfg: PAIR_CFG });
  const root = QUOTIENT_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw);
  const { c, cInv, w, u } = root;
  const { specs: miller, boundary: fF } = specsMillerResidue(inst, c, cInv, u);
  if (FIXED_VK_COLLAPSE) {
    miller.forEach((spec, index) => {
      spec.enforceExactInputLength = true;
      if (index > 0) {
        spec.inLimbs = spec.inLimbs.slice(0, MILLER_DYNAMIC_LIMBS);
        spec.externalParams = MILLER_STATIC_NAMES.map((name) => ({
          name,
          targetSpecIndex: MILLER_GENESIS_INPUT,
          targetOffset: MILLER_GENESIS_OFFSETS.get(name),
          width: W,
        }));
      }
      const slopePartIndex = GLV_SLOPE_CARRIERS.findIndex(({ inputIndex }) => inputIndex === GLV_COUNT + index);
      if (slopePartIndex !== -1) {
        spec.extras = [...spec.extras, slopeCarrierParts[slopePartIndex]];
        spec.linkedDataLength = GLV_SLOPE_CARRIERS[slopePartIndex].length;
      }
      const tablePartIndex = GLV_TABLE_CARRIER_INPUTS.indexOf(GLV_COUNT + index);
      if (tablePartIndex !== -1) {
        spec.extras = [...spec.extras, GLV_TABLE_PARTS[tablePartIndex]];
        spec.linkedDataLength = GLV_TABLE_PARTS[tablePartIndex].length;
        spec.linkedDataFixedValue = true;
      }
      if (!spec.file.includes('millerres_') || spec.role !== 'within') return;
      spec.outLimbs = spec.outLimbs.slice(0, MILLER_DYNAMIC_LIMBS);
      spec.outputCount = MILLER_DYNAMIC_LIMBS;
    });
  }
  if (QUOTIENT_TORUS) return [...vkx, ...miller];
  const tail = specsResidueTail(fF, c, cInv, w);
  return [...vkx, ...miller, ...tail];
}

// ---- one-transaction assembly --------------------------------------------------------
const PER_INPUT_OV = 43;
function linkedConfig(spec, expectedInputIndex, expectedInputCount) {
  let forward = null;
  if (spec.role !== 'terminal') {
    if (spec.role === 'within') {
      const outLen = spec.outLimbs.length * W;
      forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen };
    } else if (spec.role === 'cross') {
      forward = spec.cmp;
    }
  }
  return {
    covInHash: false,
    epilogueMode: undefined,
    forward,
    expectedInputIndex,
    expectedInputCount,
  };
}

const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map();
const PROBE = join(GEN, '_intratx_residue_probe.cash');
const cfgKey = (spec, cfg) => `${spec.file}|${cfg.covInHash ? 'ci' : ''}|${cfg.epilogueMode ?? ''}|${cfg.nextLockingHash ?? ''}|${JSON.stringify(cfg.forward)}|layout=${cfg.expectedInputIndex ?? ''}/${cfg.expectedInputCount ?? ''}|output=${spec.outputCount ?? 'all'}|exact=${spec.enforceExactInputLength === true}|linked=${spec.linkedDataLength ?? ''}|${JSON.stringify(cfg.externalParams ?? [])}`;
function compileChunk(spec, cfg) {
  const key = cfgKey(spec, cfg);
  let v = compileCache.get(key);
  if (!v) {
    const t = transformChunk(readFileSync(spec.file, 'utf8'), {
      W, prime: PRIME, forward: cfg.forward, covInHash: cfg.covInHash,
      epilogueMode: cfg.epilogueMode, nextLockingHash: cfg.nextLockingHash,
      externalParams: cfg.externalParams, outputCount: spec.outputCount,
      enforceExactInputLength: spec.enforceExactInputLength,
      linkedDataLength: spec.linkedDataLength,
      expectedInputIndex: cfg.expectedInputIndex,
      expectedInputCount: cfg.expectedInputCount,
    });
    let resched, raw;
    if (/^import\s/m.test(t.src)) { writeFileSync(PROBE, t.src); resched = compileFileBytecode(PROBE); raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched; }
    else { resched = compileBytecode(t.src); raw = RESCHED ? compileBytecodeRaw(t.src) : resched; }
    v = { source: t.src, transform: t, resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  if (GLV_FIXED_COMB_WIDTH === 8 && spec.linkedDataLength !== undefined && v.raw) {
    chosenCache.set(key, 'raw');
    return v.raw;
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41) : Infinity);
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs))];
  for (const e of [...spec.extras].reverse()) parts.push(e instanceof Uint8Array ? pd(e) : pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

function assembleRun(specs, expectRejected = false) {
  const cfgs = specs.map((spec, index) => {
    const externalParams = (spec.externalParams ?? []).map((param) => {
      if (param.targetSpecIndex < 0 || param.targetSpecIndex >= specs.length) {
        throw new Error('static Miller context target is outside the transaction');
      }
      const target = specs[param.targetSpecIndex];
      return {
        name: param.name,
        targetInputIndex: param.targetSpecIndex,
        targetFullInLen: target.inLimbs.length * W,
        targetOffset: param.targetOffset,
        width: param.width,
      };
    });
    return {
      ...linkedConfig(spec, index, specs.length),
      externalParams,
      linkedDataLength: spec.linkedDataLength,
    };
  });
  const redeems = new Array(specs.length);
  const lockings = new Array(specs.length);
  for (let index = specs.length - 1; index >= 0; index--) {
    if (cfgs[index].forward !== null) {
      if (lockings[index + 1] === undefined) throw new Error(`input ${index} has no successor locking program`);
      cfgs[index].forward = {
        ...cfgs[index].forward,
        nextLockingHash: binToHex(sha256.hash(lockings[index + 1])),
      };
    }
    redeems[index] = compileChunk(specs[index], cfgs[index]);
    lockings[index] = p2shSpk(redeems[index]);
  }
  const rpush = redeems.map((r) => encodeDataPush(r));
  const argB = specs.map(argBytesOf);
  if (FIXED_VK_COLLAPSE) {
    specs.forEach((spec, i) => {
      const fixed = argB[i].length + rpush[i].length;
      if (fixed > 9500) console.error(`large fixed input ${i}: args=${argB[i].length} redeem=${redeems[i].length} push=${rpush[i].length} total=${fixed} ${spec.label}`);
    });
  }
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + rpush[i].length;
    const pad = padPush(0, Math.max(2, target - fixed));
    return Uint8Array.from([...argB[i], ...pad, ...rpush[i]]);
  };

  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = allInputs.map((_, index) => evaluateInput(allInputs, index));
  const standardOp1 = allInputs.map((_, index) => evaluateInput(allInputs, index, standardVm));
  // A rescheduled candidate can exceed a limit while the raw compilation still fits; defer the
  // failure until the selector below has evaluated both forms.
  if (!expectRejected && !RESCHED && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
  }

  if (RESCHED) {
    let switched = 0;
    for (let i = 0; i < specs.length; i++) {
      const key = cfgKey(specs[i], cfgs[i]);
      if (chosenCache.has(key)) continue;
      const v = compileCache.get(key);
      if (!v.raw) { chosenCache.set(key, 'resched'); continue; }
      const rawRpush = encodeDataPush(v.raw);
      const rawFixed = argB[i].length + rawRpush.length;
      const rawUnlock = Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, TARGET_UNLOCK - rawFixed)), ...rawRpush]);
      const rawInputs = allInputs.slice();
      rawInputs[i] = { locking: p2shSpk(v.raw), unlocking: rawUnlock };
      const rawOp = evaluateInput(rawInputs, i);
      const rawStandardOp = evaluateInput(rawInputs, i, standardVm);
      const tR = effLen(argB[i].length + rpush[i].length, Math.max(op1[i].operationCost, standardOp1[i].operationCost), op1[i].accepted && standardOp1[i].accepted);
      const tB = effLen(rawFixed, Math.max(rawOp.operationCost, rawStandardOp.operationCost), rawOp.accepted && rawStandardOp.accepted);
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assembleRun(specs, expectRejected);
  }
  const op2 = [];
  let standardOp2;
  let targets = specs.map((_, i) => tunedLen(argB[i].length + rpush[i].length, Math.max(op1[i].operationCost, standardOp1[i].operationCost)));
  while (true) {
    for (let i = 0; i < specs.length; i++) allInputs[i].unlocking = mkUnlock(i, targets[i]);
    standardOp2 = [];
    allInputs.forEach((_, index) => {
      op2[index] = evaluateInput(allInputs, index);
      standardOp2[index] = evaluateInput(allInputs, index, standardVm);
    });
    if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) break;
    const tightened = targets.map((target, i) => Math.min(target, tunedLen(
      argB[i].length + rpush[i].length,
      Math.max(op2[i].operationCost, standardOp2[i].operationCost),
    )));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
    console.error('tightened failures', JSON.stringify(op2.map((outcome, i) => ({ i, target: targets[i], ...outcome })).filter((outcome) => !outcome.accepted)));
    console.error('tightened standard failures', JSON.stringify(standardOp2.map((outcome, i) => ({ i, target: targets[i], ...outcome })).filter((outcome) => !outcome.accepted)));
    throw new Error('tightened input rejected during padding measurement');
  }

  const meta = specs.map((s, i) => {
    const fixedBytes = argB[i].length + rpush[i].length;
    const standardOperationCost = standardOp2[i].operationCost;
    const densityBytes = Math.ceil(Math.max(op2[i].operationCost, standardOperationCost) / 800) - 41;
    return {
      label: s.label, checkpoint: s.checkpoint,
      lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
      argumentBytes: argB[i].length, redeemBytes: redeems[i].length, redeemPushBytes: rpush[i].length,
      fixedBytes, densityBytes, targetSource: fixedBytes + 3 >= densityBytes ? 'fixed' : 'op-density',
      bytesAboveDensity: allInputs[i].unlocking.length - densityBytes,
      operationCost: op2[i].operationCost, standardOperationCost,
      accepted: op2[i].accepted, error: op2[i].error,
    };
  });
  const accepted = op2.every((o) => o.accepted);
  if (expectRejected && accepted) throw new Error('rejection fixture unexpectedly accepted');
  const transactions = expectRejected ? [] : (() => {
    const data = verificationData(allInputs, 0n, 0n);
    const wireBytes = encodeTransactionBch(data.transaction).length;
    const inputCount = BigInt(data.sourceOutputs.length);
    const valuePerInput = BigInt(wireBytes) / inputCount;
    const remainder = BigInt(wireBytes) % inputCount;
    data.sourceOutputs.forEach((sourceOutput, index) => {
      sourceOutput.valueSatoshis = valuePerInput + (BigInt(index) < remainder ? 1n : 0n);
    });
    const totalInputValue = data.sourceOutputs.reduce((total, sourceOutput) => total + sourceOutput.valueSatoshis, 0n);
    const exactWireBytes = encodeTransactionBch(data.transaction).length;
    const estimatedWireBytes = 20 + allInputs.reduce((total, input) => total + input.unlocking.length + PER_INPUT_OV, 0);
    if (exactWireBytes !== wireBytes || estimatedWireBytes !== exactWireBytes) {
      throw new Error('estimated and encoded transaction sizes differ');
    }
    const feeSatoshis = totalInputValue - data.transaction.outputs[0].valueSatoshis;
    const encodedTransaction = encodeTransactionBch(data.transaction);
    const serializedTransactionHash256 = hash256(encodedTransaction);
    return [{
      wireBytes: exactWireBytes,
      feeSatoshis: Number(feeSatoshis),
      totalInputValueSatoshis: Number(totalInputValue),
      outputValueSatoshis: Number(data.transaction.outputs[0].valueSatoshis),
      sourceOutputValuesSatoshis: data.sourceOutputs.map((sourceOutput) => Number(sourceOutput.valueSatoshis)),
      sourceTokenCount: 0,
      serializedTransactionHash256: binToHex(serializedTransactionHash256),
      transactionId: binToHex(Uint8Array.from(serializedTransactionHash256).reverse()),
      consensusVerified: realVm.verify(data) === true,
      standardVerified: standardVm.verify(data) === true,
    }];
  })();
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) &&
    accepted && transactions.every((tx) => tx.wireBytes <= 100000) &&
    transactions.every((tx) => tx.feeSatoshis === tx.wireBytes && tx.consensusVerified && tx.standardVerified);
  const resourceChunks = specs.map((spec, index) => {
    const key = cfgKey(spec, cfgs[index]);
    const compiled = compileCache.get(key);
    const redeem = compileChunk(spec, cfgs[index]);
    if (compiled === undefined || binToHex(redeem) !== binToHex(redeems[index])) {
      throw new Error(`resource chunk ${index} changed after assembly`);
    }
    if (compiled.transform.extras.length !== spec.extras.length) {
      throw new Error(`resource chunk ${index} argument layout mismatch`);
    }
    const namedExtras = compiled.transform.extras.map((name, extraIndex) => ({
      name,
      value: spec.extras[extraIndex],
    }));
    return {
      source: compiled.source,
      compilerMode: compiled.raw !== undefined && binToHex(redeem) === binToHex(compiled.raw)
        ? 'raw'
        : 'rescheduled',
      argumentPushes: [
        { type: 'bytes', name: 'inBlob', bytes: spec.inLimbs.length * W },
        ...namedExtras.reverse().map(({ name, value }) => ({
          type: value instanceof Uint8Array ? 'bytes' : 'int',
          name,
          bytes: value instanceof Uint8Array ? value.length : W,
          ...(name === 'linkedData' && spec.linkedDataFixedValue === true
            ? { fixedValueHex: binToHex(value) }
            : {}),
        })),
      ],
      redeem,
    };
  });
  return { inputs: allInputs, meta, transactions, fits, accepted, resourceChunks };
}

const toStep = (asm, i) => ({
  label: asm.meta[i].label,
  locking: binToHex(asm.inputs[i].locking),
  unlocking: binToHex(asm.inputs[i].unlocking),
  checkpoint: asm.meta[i].checkpoint,
});
const toRun = (asm) => ({
  steps: asm.inputs.map((_, i) => toStep(asm, i)),
});
const toSteps = (asm) => toRun(asm).steps;

function invalidRun(specs, idx) {
  const asm = assembleRun(specs);
  asm.inputs[idx] = { ...asm.inputs[idx], unlocking: (() => {
    const u = Uint8Array.from(asm.inputs[idx].unlocking);
    const op = u[0];
    const dataStart = op <= 75 ? 1 : op === 0x4c ? 2 : 3;
    const dataLen = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8);
    u[dataStart + Math.floor(dataLen / 2)] ^= 0x01;
    return u;
  })() };
  const res = asm.inputs.map((_, index) => evaluateInput(asm.inputs, index));
  return { run: toRun(asm), rejected: res.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  console.error(`${tag}: ${asm.meta.length} inputs, accepted=${asm.accepted} fits=${asm.fits}`);
  console.error(`  totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()} maxUnlock=${Math.max(...asm.meta.map((m) => m.unlockingBytes))}`);
  asm.meta.filter((m) => !m.accepted).slice(0, 6).forEach((m) => console.error(`  !! non-accepting: ${m.label} :: op=${m.operationCost.toLocaleString()} err=${m.error}`));
  asm.transactions.forEach((tx) => console.error(
    `  exact funded tx: ${tx.wireBytes.toLocaleString()} B fee=${tx.feeSatoshis.toLocaleString()} sat consensus=${tx.consensusVerified} standard=${tx.standardVerified}`,
  ));
};

// ===================== build =====================
console.error('building residue specs (residueWitness per instance ~seconds)...');
const cSpecs = buildSpecs(INSTANCES.committed);
const p1Specs = buildSpecs(INSTANCES.proof1);
const stressSpecs = buildSpecs(INSTANCES.stress);
const nonBaseBSpecs = buildSpecs(INSTANCES.nonBaseB);
const combinedStressSpecs = buildSpecs(INSTANCES.combinedStress);
const variedBCSpecs = buildSpecs(INSTANCES.variedBC);
const combinedVariedCSpecs = buildSpecs(INSTANCES.combinedVariedC);
const finalEqualSpecs = buildSpecs(INSTANCES.finalEqual);
function requireStageGenesis(specs, inst, label) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = FIXED_COMB
    ? [glvCollapsedScalar(in0, in1), 0n]
    : glvDecompose(FIXED_VK_COLLAPSE ? glvCollapsedScalar(in0, in1) : in0);
  const [k11, k21] = FIXED_VK_COLLAPSE ? [0n, 0n] : glvDecompose(in1);
  const expectedGenesis = FIXED_COMB
    ? [in0, in1]
    : FIXED_VK_COLLAPSE
    ? [in0, in1, k10, k20]
    : [in0, in1, k10, k20, k11, k21];
  if (!limbsEqual(specs[0].inLimbs, expectedGenesis)) {
    throw new Error(`${label} GLV genesis still exposes accumulator state`);
  }
  const pairs = verifierPairsFor(inst.inputs, inst.proof);
  const ptL = pairs.flatMap(pointLimbs);
  const expectedPoints = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
  if (specs[GLV_COUNT].inLimbs.length !== MILLER_IN_LIMBS ||
    !limbsEqual(specs[GLV_COUNT].inLimbs.slice(ROOT_LIMBS, ROOT_LIMBS + expectedPoints.length), expectedPoints)) {
    throw new Error(`${label} Miller genesis still exposes f/R_B state or misorders proof points`);
  }
}
[
  ['committed', cSpecs, INSTANCES.committed],
  ['proof#1', p1Specs, INSTANCES.proof1],
  ['stress', stressSpecs, INSTANCES.stress],
  ['non-base B', nonBaseBSpecs, INSTANCES.nonBaseB],
  ['combined stress', combinedStressSpecs, INSTANCES.combinedStress],
  ['varied B/C', variedBCSpecs, INSTANCES.variedBC],
  ['combined varied C', combinedVariedCSpecs, INSTANCES.combinedVariedC],
  ['fixed-comb final-equal', finalEqualSpecs, INSTANCES.finalEqual],
].forEach(([label, specs, inst]) => requireStageGenesis(specs, inst, label));
if (cSpecs.length !== 11) throw new Error(`fixed-key verifier requires 11 inputs, received ${cSpecs.length}`);

const asmCommitted = assembleRun(cSpecs);
report('groth16-bls-intratx-residue committed', asmCommitted);
if (process.env.PROFILE === '1') {
  console.error('  index\tlock\tunlock\topcost\tlabel');
  asmCommitted.meta.forEach((meta, index) => {
    console.error(`  ${index}\t${meta.lockingBytes}\t${meta.unlockingBytes}\t${meta.operationCost}\t${meta.label}`);
  });
}
const asmProof1 = assembleRun(p1Specs);
report('groth16-bls-intratx-residue proof#1', asmProof1);
const asmStress = assembleRun(stressSpecs);
report('groth16-bls-intratx-residue all-position stress', asmStress);
if (process.env.PROFILE === '1') {
  console.error('  stress-index\tlock\tunlock\topcost\tlabel');
  asmStress.meta.forEach((meta, index) => {
    console.error(`  ${index}\t${meta.lockingBytes}\t${meta.unlockingBytes}\t${meta.operationCost}\t${meta.label}`);
  });
}
if (!pairingEquationAccepts(INSTANCES.nonBaseB)) throw new Error('non-base B fixture does not satisfy the pairing equation');
const asmNonBaseB = assembleRun(nonBaseBSpecs);
report('groth16-bls-intratx-residue B=19G2', asmNonBaseB);
if (!pairingEquationAccepts(INSTANCES.combinedStress)) throw new Error('combined stress fixture does not satisfy the pairing equation');
const asmCombinedStress = assembleRun(combinedStressSpecs);
report('groth16-bls-intratx-residue 64/64 + B=19G2', asmCombinedStress);
if (!pairingEquationAccepts(INSTANCES.variedBC)) throw new Error('varied B/C fixture does not satisfy the pairing equation');
const asmVariedBC = assembleRun(variedBCSpecs);
report('groth16-bls-intratx-residue varied B=37G2/C=29G1', asmVariedBC);
if (!pairingEquationAccepts(INSTANCES.combinedVariedC)) throw new Error('combined varied-C fixture does not satisfy the pairing equation');
const asmCombinedVariedC = assembleRun(combinedVariedCSpecs);
report('groth16-bls-intratx-residue 64/64 + B=19G2/C=29G1', asmCombinedVariedC);
if (!pairingEquationAccepts(INSTANCES.finalEqual)) throw new Error('fixed-comb final-equal fixture does not satisfy the pairing equation');
const asmFinalEqual = assembleRun(finalEqualSpecs);
report('groth16-bls-intratx-residue fixed-comb final-equal', asmFinalEqual);
if (!asmFinalEqual.transactions.every(({ consensusVerified, standardVerified }) =>
  consensusVerified && standardVerified)) {
  throw new Error('fixed-comb final-equal fixture did not pass both BCH 2026 VMs');
}
if (process.env.PROFILE === '1') {
  console.error('  combined-index\ttarget\targs\tredeem\tfixed\tdensity\tunlock\tabove-density\topcost\tstandard-opcost\tlabel');
  asmCombinedStress.meta.forEach((meta, index) => {
    console.error(`  ${index}\t${meta.targetSource}\t${meta.argumentBytes}\t${meta.redeemBytes}\t${meta.fixedBytes}\t${meta.densityBytes}\t${meta.unlockingBytes}\t${meta.bytesAboveDensity}\t${meta.operationCost}\t${meta.standardOperationCost}\t${meta.label}`);
  });
  console.error(`  combined bytes above density: ${sum(asmCombinedStress.meta, (meta) => meta.bytesAboveDensity)}`);
  console.error('  fixture\tGLV bytes\tGLV op\tMiller bytes\tMiller op\toverhead\twire');
  [
    ['committed', asmCommitted],
    ['64/64', asmStress],
    ['B=19G2', asmNonBaseB],
    ['64/64+B=19G2', asmCombinedStress],
    ['B=37G2/C=29G1', asmVariedBC],
    ['64/64+B=19G2/C=29G1', asmCombinedVariedC],
    ['fixed-comb final-equal', asmFinalEqual],
  ].forEach(([label, asm]) => {
    const glvMeta = asm.meta.slice(0, GLV_COUNT);
    const millerMeta = asm.meta.slice(GLV_COUNT);
    const glvBytes = sum(glvMeta, (meta) => meta.unlockingBytes + PER_INPUT_OV);
    const millerBytes = sum(millerMeta, (meta) => meta.unlockingBytes + PER_INPUT_OV);
    const wireBytes = asm.transactions[0].wireBytes;
    console.error(`  ${label}\t${glvBytes}\t${sum(glvMeta, (meta) => meta.operationCost)}\t${millerBytes}\t${sum(millerMeta, (meta) => meta.operationCost)}\t${wireBytes - glvBytes - millerBytes}\t${wireBytes}`);
  });
}
const completenessInstances = [...IDENTITY_INSTANCES, MSM_IDENTITY_INSTANCE];
const completenessRuns = completenessInstances.map((inst) => {
  if (!pairingEquationAccepts(inst)) throw new Error(`${inst.identityTag} fixture does not satisfy the pairing equation`);
  const specs = buildSpecs(inst);
  requireStageGenesis(specs, inst, `${inst.identityTag} identity`);
  const asm = assembleRun(specs);
  report(`groth16-bls-intratx-residue ${inst.identityTag} identity`, asm);
  if (!asm.accepted || !asm.fits) throw new Error(`${inst.identityTag} identity fixture did not pass as a standard one-transaction verifier`);
  return { tag: inst.identityTag, specs, asm };
});

for (const [label, otherSpecs] of [['proof#1', p1Specs], ['stress', stressSpecs]]) {
  const hybridSpecs = [...cSpecs.slice(0, GLV_COUNT), ...otherSpecs.slice(GLV_COUNT)];
  const unboundSpecs = hybridSpecs.map((spec, i) => i === GLV_COUNT - 1 ? { ...spec, role: 'stage-final', cmp: null } : spec);
  GLV_SLOPE_CARRIERS.forEach(({ inputIndex }) => {
    const extras = [...unboundSpecs[inputIndex].extras];
    extras[extras.length - 1] = cSpecs[inputIndex].extras.at(-1);
    unboundSpecs[inputIndex] = { ...unboundSpecs[inputIndex], extras };
  });
  const unbound = assembleRun(unboundSpecs);
  if (!unbound.accepted) throw new Error(`${label} unbound valid-fixture hybrid was not accepted`);
  const boundInputs = [...asmCommitted.inputs.slice(0, GLV_COUNT), ...unbound.inputs.slice(GLV_COUNT)];
  const outcomes = boundInputs.map((_, index) => evaluateInput(boundInputs, index));
  if (outcomes[GLV_COUNT - 1].accepted) throw new Error(`${label} hybrid did not reject at the vk_x boundary`);
  const unrelated = outcomes.find((outcome, i) => i !== GLV_COUNT - 1 && !outcome.accepted);
  if (unrelated) throw new Error(`${label} hybrid also rejected outside the vk_x boundary`);
}
console.error('  stage genesis layouts and proof#1/stress vk_x boundaries verified');

function requireRejectedByBoth(inputs, inputIndex, label) {
  const consensusOutcome = evaluateInput(inputs, inputIndex);
  const standardOutcome = evaluateInput(inputs, inputIndex, standardVm);
  if (consensusOutcome.accepted || standardOutcome.accepted) {
    throw new Error(`${label} was accepted`);
  }
}

// shared-table fixture: flip a middle byte of the carried GLV table -> the carrier's hash256
// pin must reject (the four sibling readers consume that exact slice).
function pushBounds(unlocking, opcodeOffset = 0) {
  const op = unlocking[opcodeOffset];
  if (op <= 75) return { dataStart: opcodeOffset + 1, dataLen: op };
  if (op === 0x4c) return { dataStart: opcodeOffset + 2, dataLen: unlocking[opcodeOffset + 1] };
  if (op === 0x4d) return { dataStart: opcodeOffset + 3, dataLen: unlocking[opcodeOffset + 1] | (unlocking[opcodeOffset + 2] << 8) };
  throw new Error(`unsupported push opcode ${op}`);
}
let tableInputs = null;
GLV_TABLE_CARRIER_INPUTS.forEach((tableCarrierIndex, partIndex) => {
  const mutatedInputs = asmCommitted.inputs.slice();
  const tableUnlocking = Uint8Array.from(mutatedInputs[tableCarrierIndex].unlocking);
  const carrierBlob = pushBounds(tableUnlocking);
  const tablePush = pushBounds(tableUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
  if (tablePush.dataLen !== GLV_TABLE_PARTS[partIndex].length) {
    throw new Error("shared GLV table part has unexpected length at carrier " + tableCarrierIndex);
  }
  tableUnlocking[tablePush.dataStart + Math.floor(tablePush.dataLen / 2)] ^= 0x01;
  mutatedInputs[tableCarrierIndex] = { ...mutatedInputs[tableCarrierIndex], unlocking: tableUnlocking };
  requireRejectedByBoth(mutatedInputs, GLV_COUNT - 1, `final GLV table mutation at carrier ${tableCarrierIndex}`);
  if (partIndex === 0) tableInputs = mutatedInputs;
});
if (tableInputs === null) throw new Error("missing shared GLV table mutation fixture");
const tableMutation = { run: toRun({ ...asmCommitted, inputs: tableInputs }), rejected: true };
console.error('  shared GLV table mutation rejected at each carrier');

const slopeMutationRuns = GLV_SLOPE_CARRIERS.map(({ inputIndex: slopeCarrierIndex, length }) => {
  const mutatedInputs = asmCommitted.inputs.slice();
  const slopeUnlocking = Uint8Array.from(mutatedInputs[slopeCarrierIndex].unlocking);
  const carrierBlob = pushBounds(slopeUnlocking);
  const slopePush = pushBounds(slopeUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
  if (slopePush.dataLen !== length) {
    throw new Error(`shared GLV slope part has unexpected length at carrier ${slopeCarrierIndex}`);
  }
  slopeUnlocking[slopePush.dataStart + Math.floor(slopePush.dataLen / 2)] ^= 0x01;
  mutatedInputs[slopeCarrierIndex] = { ...mutatedInputs[slopeCarrierIndex], unlocking: slopeUnlocking };
  requireRejectedByBoth(mutatedInputs, GLV_COUNT - 1, `final GLV slope mutation at carrier ${slopeCarrierIndex}`);
  return { run: toRun({ ...asmCommitted, inputs: mutatedInputs }), rejected: true };
});
console.error('  shared GLV slope mutation rejected at each carrier');

const exactGlvStateRuns = Array.from({ length: GLV_COUNT }, (_, inputIndex) => {
  const inputs = asmCommitted.inputs.slice();
  const unlocking = inputs[inputIndex].unlocking;
  const firstPush = pushBounds(unlocking);
  const state = Uint8Array.from([
    ...unlocking.slice(firstPush.dataStart, firstPush.dataStart + firstPush.dataLen),
    0,
  ]);
  inputs[inputIndex] = {
    ...inputs[inputIndex],
    unlocking: Uint8Array.from([
      ...encodeDataPush(state),
      ...unlocking.slice(firstPush.dataStart + firstPush.dataLen),
    ]),
  };
  requireRejectedByBoth(inputs, inputIndex, `GLV input ${inputIndex} extended-state fixture`);
  return { run: toRun({ ...asmCommitted, inputs }), rejected: true };
});

const successorProgramRuns = [];
for (let successorIndex = 1; successorIndex < asmCommitted.inputs.length; successorIndex++) {
  const inputs = asmCommitted.inputs.slice();
  const locking = Uint8Array.from(inputs[successorIndex].locking);
  locking[2] ^= 0x01;
  inputs[successorIndex] = { ...inputs[successorIndex], locking };
  requireRejectedByBoth(inputs, successorIndex - 1, `successor program ${successorIndex} fixture`);
  if (successorIndex === 1 || successorIndex === asmCommitted.inputs.length - 1) {
    successorProgramRuns.push({ run: toRun({ ...asmCommitted, inputs }), rejected: true });
  }
}

const reorderedInputs = asmCommitted.inputs.slice();
[reorderedInputs[0], reorderedInputs[1]] = [reorderedInputs[1], reorderedInputs[0]];
requireRejectedByBoth(reorderedInputs, 0, 'input-order fixture');
const inputOrderRun = { run: toRun({ ...asmCommitted, inputs: reorderedInputs }), rejected: true };

const extraInputAsm = {
  ...asmCommitted,
  inputs: [...asmCommitted.inputs, { locking: OP_TRUE, unlocking: new Uint8Array() }],
  meta: [...asmCommitted.meta, { label: 'input-count fixture' }],
};
requireRejectedByBoth(extraInputAsm.inputs, 0, 'input-count fixture');
const inputCountRun = { run: toRun(extraInputAsm), rejected: true };
console.error('  exact GLV state, all successor programs, input order, and input count fixtures rejected');

const invalids = [
  invalidRun(cSpecs, Math.floor(cSpecs.length / 2)),
  invalidRun(cSpecs, 1),
  tableMutation,
  ...slopeMutationRuns,
  ...exactGlvStateRuns,
  ...successorProgramRuns,
  inputOrderRun,
  inputCountRun,
];
function changedSpecRun(specs, index, mutate, label) {
  const changed = specs.map((spec) => ({ ...spec, inLimbs: [...spec.inLimbs], outLimbs: [...spec.outLimbs], extras: [...spec.extras] }));
  mutate(changed[index]);
  const asm = assembleRun(changed, true);
  if (asm.accepted) throw new Error(`${label} was accepted`);
  return { run: toRun(asm), rejected: true };
}
const yInvMutation = changedSpecRun(cSpecs, GLV_COUNT - 1, (spec) => {
  const yInvIndex = FIXED_VK_COLLAPSE ? 3 : 0;
  spec.extras[yInvIndex] = BigInt(spec.extras[yInvIndex]) + 1n;
}, 'changed GLV Y inverse');
const alteredIdentityInput = changedSpecRun(completenessRuns.find(({ tag }) => tag === 'A').specs, 0, (spec) => {
  spec.inLimbs[0] = BigInt(spec.inLimbs[0]) + 1n;
}, 'altered public input on identity proof');
const normalizedHandoffMutation = changedSpecRun(cSpecs, GLV_COUNT, (spec) => {
  spec.inLimbs[VKX_LIMB_OFFSET] = (BigInt(spec.inLimbs[VKX_LIMB_OFFSET]) + 1n) % P;
}, 'changed normalized vk_x handoff');

// Isolate the fused A on-curve and B subgroup checks from the residue verdict.
const committedPairs = effectivePairsFor(INSTANCES.committed);
const { boundary: committedRawBoundary } = AFFINE_G2
  ? millerCollapsedAffineOps(committedPairs)
  : millerBatchOps(committedPairs, { unitLines: UNIT_G1, ptCfg: PAIR_CFG });
const committedRoot = QUOTIENT_TORUS
  ? residueTorusWitness(committedRawBoundary)
  : residueWitness(committedRawBoundary);
const { c: committedC, cInv: committedCInv, u: committedU } = committedRoot;
const isolated = (specs) => assembleRun(specs, true);
const negA = proof.a.negate().toAffine();
const firstMiller = specsMillerResidue(INSTANCES.committed, committedC, committedCInv, committedU, { Ay: (negA.y + 1n) % P }).specs[0];
firstMiller.role = 'stage-final'; firstMiller.cmp = null;
const offCurveA = isolated([firstMiller]);
const plusPFirstMiller = specsMillerResidue(INSTANCES.committed, committedC, committedCInv, committedU, { Ax: negA.x + P }).specs[0];
plusPFirstMiller.role = 'stage-final'; plusPFirstMiller.cmp = null;
const plusPRange = isolated([plusPFirstMiller]);
if (plusPRange.meta[0].accepted) throw new Error('+P proof encoding passed one-transaction Miller input validation');
const twistB = F2.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2.create({ c0: i, c1: 0n });
  const rhs = F2.add(F2.mul(F2.sqr(x), x), twistB);
  let y; try { y = F2.sqrt(rhs); } catch { continue; }
  if (!F2.eql(F2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; }
}
if (!offSub) throw new Error('could not construct the G2 subgroup-check fixture');
const subgroupControl = IDENTITY_INSTANCES.find(({ identityTag }) => identityTag === 'ABC');
if (subgroupControl === undefined) throw new Error('missing identity control for the G2 subgroup fixture');
const offSubInst = {
  inputs: subgroupControl.inputs,
  proof: { ...subgroupControl.proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const { boundary: offSubBoundary } = millerCollapsedAffineOps(effectivePairsFor(offSubInst));
if (!bls12_381.fields.Fp12.eql(
  bls12_381.fields.Fp12.finalExponentiate(offSubBoundary),
  bls12_381.fields.Fp12.ONE,
)) {
  throw new Error('G2 subgroup fixture does not isolate a pairing-neutral proof');
}
const offSubRoot = residueTorusWitness(offSubBoundary);
const offSubSpecs = specsMillerResidue(
  offSubInst, offSubRoot.c, offSubRoot.cInv, offSubRoot.u,
).specs;
offSubSpecs[offSubSpecs.length - 1].role = 'stage-final';
offSubSpecs[offSubSpecs.length - 1].cmp = null;
const offSubgroupB = isolated(offSubSpecs);
const offSubConsensus = offSubgroupB.inputs.map((_, index) => evaluateInput(offSubgroupB.inputs, index));
const offSubStandard = offSubgroupB.inputs.map((_, index) => evaluateInput(offSubgroupB.inputs, index, standardVm));
const offSubFinalIndex = offSubgroupB.inputs.length - 1;
if ([...offSubConsensus, ...offSubStandard].some((outcome, index) => {
  const inputIndex = index % offSubgroupB.inputs.length;
  return inputIndex === offSubFinalIndex ? outcome.accepted : !outcome.accepted;
})) {
  throw new Error('G2 subgroup fixture did not reject only at the terminal subgroup gate');
}
const semanticInvalids = [offCurveA, offSubgroupB, plusPRange].map((asm) => ({ run: toRun(asm), rejected: !asm.accepted }));

function rangeInvalid(spec, location, value, label) {
  const candidate = { ...spec, extras: [...spec.extras], role: 'stage-final', cmp: null, label };
  if (location.extra !== undefined) candidate.extras[location.extra] = value;
  const asm = assembleRun([candidate], location.extra !== undefined);
  if (location.limb !== undefined) {
    const unlocking = Uint8Array.from(asm.inputs[0].unlocking);
    const pushed = pushBounds(unlocking);
    if (pushed.dataLen !== candidate.inLimbs.length * W) throw new Error(`${label} has an unexpected input blob length`);
    const encoded = le48Exact(value < 0n ? -value : value);
    if (value < 0n) encoded[W - 1] |= 0x80;
    unlocking.set(encoded, pushed.dataStart + location.limb * W);
    asm.inputs[0] = { ...asm.inputs[0], unlocking };
  }
  const consensusOutcome = evaluateInput(asm.inputs, 0);
  const standardOutcome = evaluateInput(asm.inputs, 0, standardVm);
  if (consensusOutcome.accepted || standardOutcome.accepted) {
    throw new Error(`${label} passed a residue witness range gate`);
  }
  return { run: toRun(asm), rejected: true };
}

const firstRangeMiller = cSpecs[GLV_COUNT];
const firstRangeTail = cSpecs.find((spec) => spec.file.includes('finalexpres_'));
if (!firstRangeMiller || (!QUOTIENT_TORUS && !firstRangeTail)) throw new Error('missing residue witness range fixture stage');
const rangeInvalids = QUOTIENT_TORUS
  ? [
      rangeInvalid(firstRangeMiller, { limb: 0 }, -1n, 'reject negative quotient-root limb'),
      rangeInvalid(firstRangeMiller, { limb: 0 }, P, 'reject quotient-root limb at P'),
    ]
  : [
      rangeInvalid(firstRangeMiller, { limb: 0 }, -1n, 'reject negative cInv limb'),
      rangeInvalid(firstRangeMiller, { limb: 0 }, P, 'reject cInv limb at P'),
      rangeInvalid(firstRangeMiller, { limb: 12 }, -1n, 'reject negative c limb'),
      rangeInvalid(firstRangeMiller, { limb: 12 }, P, 'reject c limb at P'),
      rangeInvalid(firstRangeTail, { extra: 0 }, -1n, 'reject negative w limb'),
      rangeInvalid(firstRangeTail, { extra: 0 }, P, 'reject w limb at P'),
    ];
const aIdentityFirst = completenessRuns.find(({ tag }) => tag === 'A').specs[GLV_COUNT];
const bIdentityFirst = completenessRuns.find(({ tag }) => tag === 'B').specs[GLV_COUNT];
const cIdentityFirst = completenessRuns.find(({ tag }) => tag === 'C').specs[GLV_COUNT];
const identityEncodingInvalids = [
  rangeInvalid(aIdentityFirst, { limb: ROOT_LIMBS + 4 }, 1n, 'reject malformed A identity'),
  rangeInvalid(bIdentityFirst, { limb: ROOT_LIMBS }, 1n, 'reject partial-zero B identity'),
  rangeInvalid(aIdentityFirst, { limb: ROOT_LIMBS + 4 }, P, 'reject non-canonical A identity'),
  rangeInvalid(bIdentityFirst, { limb: ROOT_LIMBS }, P, 'reject non-canonical B identity'),
  rangeInvalid(bIdentityFirst, { limb: ROOT_LIMBS + 5 }, (BigInt(bIdentityFirst.inLimbs[ROOT_LIMBS + 5]) + 1n) % P, 'validate A even when B is identity'),
];
const cIdentityEncoding = changedSpecRun(completenessRuns.find(({ tag }) => tag === 'C').specs, GLV_COUNT - 1, (spec) => {
  spec.extras[FIXED_VK_COLLAPSE ? 1 : 0] = 1n;
}, 'reject malformed C identity');
const allInvalids = [
  ...invalids, yInvMutation, alteredIdentityInput, normalizedHandoffMutation,
  ...semanticInvalids, ...rangeInvalids, ...identityEncodingInvalids, cIdentityEncoding,
];
console.error(`  invalid runs rejected: ${allInvalids.map((r) => r.rejected).join(',')}`);
if (!asmCommitted.fits || !asmProof1.fits || !asmStress.fits || !asmNonBaseB.fits ||
  !asmCombinedStress.fits || !asmVariedBC.fits || !asmCombinedVariedC.fits || !asmFinalEqual.fits ||
  !allInvalids.every((r) => r.rejected)) {
  console.error('!! a run failed -- NOT writing vectors'); process.exit(1);
}

const primaryAsm = asmCombinedStress;
const portfolio = [
  ['committed', asmCommitted],
  ['proof#1', asmProof1],
  ['64/64', asmStress],
  ['B=19G2', asmNonBaseB],
  ['64/64+B=19G2', asmCombinedStress],
  ['B=37G2/C=29G1', asmVariedBC],
  ['64/64+B=19G2/C=29G1', asmCombinedVariedC],
  ['fixed-comb final-equal', asmFinalEqual],
  ...completenessRuns.map(({ tag, asm }) => [`${tag} identity`, asm]),
];
portfolio.forEach(([fixture, asm]) => {
  asm.inputs.forEach((input, index) => {
    if (binToHex(input.locking) !== binToHex(primaryAsm.inputs[index].locking)) {
      throw new Error(`${fixture} input ${index} uses a different verifier locking graph`);
    }
  });
});
const fixtureMetrics = portfolio.map(([fixture, asm]) => ({
  fixture,
  wireBytes: asm.transactions[0].wireBytes,
  scriptBytes: sum(asm.meta, (meta) => meta.lockingBytes + meta.unlockingBytes),
  scoreBytes: asm.transactions[0].wireBytes + sum(asm.meta, (meta) => meta.lockingBytes),
  totalOperationCost: sum(asm.meta, (meta) => meta.operationCost),
  totalStandardOperationCost: sum(asm.meta, (meta) => meta.standardOperationCost),
  maxStepOperationCost: Math.max(...asm.meta.map((meta) => meta.operationCost)),
  maxStepStandardOperationCost: Math.max(...asm.meta.map((meta) => meta.standardOperationCost)),
  maxUnlockingBytes: Math.max(...asm.meta.map((meta) => meta.unlockingBytes)),
}));
const portfolioMaximum = (field) => {
  const value = Math.max(...fixtureMetrics.map((fixture) => fixture[field]));
  return {
    value,
    fixtures: fixtureMetrics.filter((fixture) => fixture[field] === value).map((fixture) => fixture.fixture),
  };
};
const worstCaseEntry = portfolio.reduce((current, candidate) => {
  const currentMaximum = Math.max(...current[1].meta.map((meta) => meta.standardOperationCost));
  const candidateMaximum = Math.max(...candidate[1].meta.map((meta) => meta.standardOperationCost));
  return candidateMaximum > currentMaximum ? candidate : current;
});
const extraValidAsms = portfolio
  .filter(([, asm]) => asm !== primaryAsm && asm !== worstCaseEntry[1])
  .map(([, asm]) => asm);
const primaryInputBytes = sum(primaryAsm.meta, (meta) => meta.unlockingBytes + PER_INPUT_OV);
const redeemScriptHash256 = primaryAsm.inputs.map(({ locking }, index) => {
  if (locking.length !== 35 || locking[0] !== 0xaa || locking[1] !== 0x20 || locking[34] !== 0x87) {
    throw new Error(`input ${index} is not a canonical P2SH32 locking bytecode`);
  }
  return binToHex(locking.slice(2, 34));
});
const lockingBytecodeSha256 = primaryAsm.inputs.map(({ locking }) => binToHex(sha256.hash(locking)));
const primaryWireBytes = primaryAsm.transactions[0].wireBytes;
const primaryLockingBytes = sum(primaryAsm.meta, (meta) => meta.lockingBytes);
const resourceInputs = primaryAsm.resourceChunks.map((chunk, index) => {
  const sourceFile = `_resource_${String(index).padStart(2, '0')}.cash`;
  const sourceBytes = new TextEncoder().encode(chunk.source);
  writeFileSync(join(GEN, sourceFile), chunk.source);
  return {
    index,
    label: primaryAsm.meta[index].label,
    sourceFile,
    sourceSha256: binToHex(sha256.hash(sourceBytes)),
    redeemSha256: binToHex(sha256.hash(chunk.redeem)),
    redeemBytes: chunk.redeem.length,
    compilerMode: chunk.compilerMode,
    argumentPushes: chunk.argumentPushes,
  };
});
const slopeWitnessMetadata = {
  bytesPerSlope: W,
  totalSlopeCount: GLV_SLOPE_LOCAL.slopeCount +
    GLV_SLOPE_CARRIERS.reduce((total, carrier) => total + carrier.slopeCount, 0),
  local: GLV_SLOPE_LOCAL,
  carriers: GLV_SLOPE_CARRIERS,
};
writeFileSync(join(GEN, 'resource_bounds_inputs.json'), JSON.stringify({
  version: 1,
  curve: 'BLS12-381',
  bchVm: 'BCH_2026',
  fixedCombWidth: GLV_FIXED_COMB_WIDTH,
  slopeWitness: slopeWitnessMetadata,
  inputs: resourceInputs,
}, null, 2));

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-intratx-residue-vectors.json'), JSON.stringify({
  description: 'One-transaction fixed-key BLS12-381 Groth16 quotient-torus verifier. ' +
    'The pairing equation is e(-A,B) * e(D,G2.BASE) = 1 with D = 5*alpha + 7*vk_x + 11*C. ' +
    'One width-six fixed-comb input assembles D, then ten affine-runtime-B Miller inputs complete ' +
    'the quotient verdict. Input zero transitively pins every successor P2SH32 program, exact ' +
    'input-position gates fix the eleven-input graph, OP_INPUTBYTECODE binds every handoff and the ' +
    'two carried slope slices, and hash256 pins the complete fixed-base table carried across three ' +
    'transaction inputs. The same locking graph verifies every canonical proof for this verification key. ' +
    'The deterministic benchmark fixtures use verification-key and proof points with known base-point ' +
    'scalars; this specializes and measures the verifier but does not claim external circuit-toolchain interoperability.',
  method: 'intra-tx-linked-residue', deployment: 'P2SH32', curve: 'BLS12-381',
  primaryFixture: '64/64+B=19G2',
  worstCaseFixture: worstCaseEntry[0],
  validFixtureCount: portfolio.length,
  rejectionFixtureCount: allInvalids.length,
  inputValidationFixtureCount: 3,
  numInputs: primaryAsm.meta.length,
  budgetPerInput: OP_BUDGET,
  serializedTransactionBytes: primaryWireBytes,
  scoreBytes: primaryWireBytes + primaryLockingBytes,
  minimumRelayFeeSatoshisAtOneSatPerByte: primaryWireBytes,
  totalBytes: sum(primaryAsm.meta, (meta) => meta.lockingBytes + meta.unlockingBytes),
  totalUnlockingBytes: sum(primaryAsm.meta, (meta) => meta.unlockingBytes),
  serializedInputOverheadBytes: PER_INPUT_OV * primaryAsm.meta.length,
  transactionFixedOverheadBytes: primaryAsm.transactions[0].wireBytes - primaryInputBytes,
  totalOperationCost: sum(primaryAsm.meta, (meta) => meta.operationCost),
  totalStandardOperationCost: sum(primaryAsm.meta, (meta) => meta.standardOperationCost),
  maxStepOperationCost: Math.max(...primaryAsm.meta.map((meta) => meta.operationCost)),
  maxStepStandardOperationCost: Math.max(...primaryAsm.meta.map((meta) => meta.standardOperationCost)),
  portfolioMaxima: {
    wireBytes: portfolioMaximum('wireBytes'),
    scoreBytes: portfolioMaximum('scoreBytes'),
    totalOperationCost: portfolioMaximum('totalOperationCost'),
    totalStandardOperationCost: portfolioMaximum('totalStandardOperationCost'),
    stepOperationCost: portfolioMaximum('maxStepOperationCost'),
    stepStandardOperationCost: portfolioMaximum('maxStepStandardOperationCost'),
    unlockingBytes: portfolioMaximum('maxUnlockingBytes'),
  },
  fixtureMetrics,
  fixedComb: {
    width: GLV_FIXED_COMB_WIDTH,
    iterations: Math.ceil(255 / GLV_FIXED_COMB_WIDTH),
    tableEntries: (1 << GLV_FIXED_COMB_WIDTH) - 1,
    tableBytes: GLV_TABLE_BYTES.length,
    tableHash256: binToHex(hash256(GLV_TABLE_BYTES)),
    carriers: GLV_TABLE_PARTS.map((part, index) => ({
      inputIndex: GLV_TABLE_CARRIER_INPUTS[index],
      millerOffset: GLV_TABLE_CARRIER_OFFSETS[index],
      length: part.length,
    })),
    slopeWitness: slopeWitnessMetadata,
    finalAdditionCoverage: {
      equalPointFixture: 'fixed-comb final-equal',
      accumulatorEqualsAddend: true,
      consensusVerified: asmFinalEqual.transactions.every(({ consensusVerified }) => consensusVerified),
      standardVerified: asmFinalEqual.transactions.every(({ standardVerified }) => standardVerified),
    },
  },
  graphBinding: {
    entryInputIndex: 0,
    exactInputCount: primaryAsm.meta.length,
    exactInputPositions: true,
    successorLockingBytecodeHash: 'sha256',
  },
  redeemScriptHash256,
  lockingBytecodeSha256,
  allFit: primaryAsm.fits, allAccept: primaryAsm.accepted,
  transactions: primaryAsm.transactions,
  steps: toSteps(primaryAsm),
  extraValidProofs: extraValidAsms.map(toSteps),
  identityProofTags: completenessRuns.map(({ tag }) => tag),
  worstCaseProof: toSteps(worstCaseEntry[1]),
  invalid: allInvalids.map((result) => result.run.steps),
  invalidInputs: [toSteps(offCurveA), toSteps(offSubgroupB), toSteps(plusPRange)],
}, null, 2));
console.error(`wrote groth16-bls12381-intratx-residue-vectors.json (${primaryAsm.meta.length} inputs)`);
