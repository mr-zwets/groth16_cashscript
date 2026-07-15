// Assemble the INTRA-TRANSACTION LINKED + RESIDUE verifier vectors for BN254.
//
// This is the residue-optimized cousin of build_vectors.mjs. Same single-transaction
// forward-checking mechanism (each chunk is an INPUT whose witness carries its incoming
// state as a raw byte blob, and it `require`s the next input's blob — read via
// tx.inputs[idx+1].unlockingBytecode — equals its recomputed output), but it consumes the
// RESIDUE chunk graph instead of the plain one:
//
//   fast-G2 endo subgroup check (ePrint 2022/348)          3 chunks, or 0 with FUSE_G2_ENDPOINT=1
//   GLV vk_x MSM (grouped 4-scalar ~128-bit Straus)        2 chunks
//   c^-(6x+2)-FUSED Miller + terminal residue verdict      manifest-selected chunk count
//
// Endpoint fusion validates canonical/on-curve proof coordinates at Miller genesis and enforces
// exact G2 subgroup membership in runtime B's post-processing. The standalone G2 stage is removed.
//
// Legacy mode links the c/cInv+w residue construction into one consensus-valid transaction;
// grouped mode instead partitions that graph into token-threaded standard transactions.
// MILLER_TORUS=1 carries one canonical six-limb quotient root, verifies the residue relation
// in Fp12*/Fp6*, and requires the committed and second-proof transactions to pass standard policy.
//
//   FUSE_G2_ENDPOINT=1 node build_vectors_residue.mjs
//     -> verifier/src/bch/groth16-intratx-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, BN_X, millerBatchOps, pairsFor, singlePairMiller, vk, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileFileBytecode, compileFileBytecodeSize, compileFileBytecodeRaw, ptLimbs,
  vkxPoint, le40, OP_DROP, TARGET_UNLOCK, OP_BUDGET, verifierPath, invalidG2Overrides, PT_CFG,
  assertG2StageManifest,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import {
  millerFusedOps, millerFusedAffineOps, residueTorusWitness, residueWitness, fp12limbsOf,
} from '../pairing/_residuemath.mjs';
import {
  GLV_LAMBDA, GLV_R, GLV_SPLIT_TABLE_HEX, VKXGLV_SPLIT_ITERS, glvDecomposeJoint,
  vkxGlvSplitStateAt, vkxGlvSplitZinv,
} from '../pairing/gen_vkx_glv.mjs';
import { transformChunk } from './transform.mjs';
import { GLV_GROUPED_BOUNDS, regenGlvSafe } from '../regen_vkx_windows.mjs';
import { infinityInstances } from './infinity_fixtures.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const FUSE_G2_ENDPOINT = process.env.FUSE_G2_ENDPOINT === '1';
const MILLER_AFFINE_G2 = process.env.MILLER_AFFINE_G2 === '1';
const MILLER_UNIT_LINES = process.env.MILLER_UNIT_LINES === '1';
const MILLER_TORUS = process.env.MILLER_TORUS === '1';
const PROJECTIVE_VKX = process.env.MILLER_PROJECTIVE_VKX === '1';
const NORMALIZED_PROOF_POINTS = process.env.MILLER_NORMALIZED_PROOF_POINTS === '1';
if (MILLER_AFFINE_G2 && !FUSE_G2_ENDPOINT) {
  throw new Error('MILLER_AFFINE_G2 requires FUSE_G2_ENDPOINT=1');
}
if (MILLER_UNIT_LINES && !MILLER_AFFINE_G2) {
  throw new Error('MILLER_UNIT_LINES requires MILLER_AFFINE_G2=1');
}
if (MILLER_TORUS && (!FUSE_G2_ENDPOINT || !MILLER_AFFINE_G2 || !MILLER_UNIT_LINES)) {
  throw new Error('MILLER_TORUS requires endpoint, affine, and unit-line modes');
}
if (PROJECTIVE_VKX && !MILLER_TORUS) {
  throw new Error('MILLER_PROJECTIVE_VKX requires quotient-torus mode');
}
if (NORMALIZED_PROOF_POINTS && (!MILLER_UNIT_LINES || !PROJECTIVE_VKX)) {
  throw new Error('MILLER_NORMALIZED_PROOF_POINTS requires unit lines and projective vk_x mode');
}
const ENDPOINT_VM_CASES = Number(process.env.ENDPOINT_VM_CASES ?? 1);
if (!Number.isInteger(ENDPOINT_VM_CASES) || ENDPOINT_VM_CASES < 1) {
  throw new Error('ENDPOINT_VM_CASES must be a positive integer');
}
// Regenerate the grouped 3x43 GLV schedule as two hash-free inputs, [0,21) and
// [21,43), before assembling. The proof-independent resource certificate covers
// both inputs and the complete linked transaction. See chunked/regen_vkx_windows.mjs.
// The final GLV input carries the table after its 228-byte state blob: PUSHDATA1(blob)
// takes 230 bytes, then the table's PUSHDATA2 header places table data at byte 233.
const GLV_COUNT = GLV_GROUPED_BOUNDS.length - 1;
const G2_COUNT = FUSE_G2_ENDPOINT ? 0 : 3;
const GLV_TABLE_SOURCE = { inputIndex: G2_COUNT + GLV_COUNT - 1, dataOffset: 233 };
regenGlvSafe(GEN, GLV_GROUPED_BOUNDS, true, GLV_TABLE_SOURCE, true, PROJECTIVE_VKX);
const PROBE = join(GEN, '_intratx_residue_probe.cash'); // transformed import-chunks compiled from here
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 32; // canonical BN254 field-element width (bytes)
const GLV_WITNESS_WIDTH = 17; // non-negative and <2^128; byte 17 carries the positive sign bit
const GLV_WIDTHS_BY_NAME = {
  k10: GLV_WITNESS_WIDTH, k20: GLV_WITNESS_WIDTH,
  k11: GLV_WITNESS_WIDTH, k21: GLV_WITNESS_WIDTH,
};
const GLV_STATE_WIDTHS = [
  W, W, W, W, W,
  GLV_WITNESS_WIDTH, GLV_WITNESS_WIDTH, GLV_WITNESS_WIDTH, GLV_WITNESS_WIDTH,
];
const GLV_GENESIS_WIDTHS = GLV_STATE_WIDTHS.slice(3);
import {
  hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash256, sha256,
  encodeLockingBytecodeP2sh32, encodeDataPush, encodeTransactionBch, createVirtualMachineBch2026,
} from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;
const GLV_TABLE_BYTES = hexToBin(GLV_SPLIT_TABLE_HEX.slice(2));

// Deploy each chunk as P2SH (same lever as build_vectors.mjs): the redeem rides in the
// scriptSig where it counts toward the op-cost budget ((41 + unlockingLen) * 800); the
// inBlob stays the FIRST scriptSig push (front offset preserved for sibling forward-checks).
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs, widths = limbs.map(() => W)) => Uint8Array.from(limbs.flatMap((l, i) =>
  [...le40(((BigInt(l) % P) + P) % P).slice(0, widths[i])]));
const widthsOf = (spec, side) => spec[`${side}Widths`] ?? spec[`${side}Limbs`].map(() => W);
const byteLengthOf = (spec, side) => widthsOf(spec, side).reduce((sum, width) => sum + width, 0);
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));

// ---- multi-input evaluation: build ONE tx from all inputs, evaluate at `index` ----
function verificationData(inputs) {
  if (inputs.length === 0) throw new Error('cannot build an empty verifier transaction');
  const transaction = {
    version: 2,
    inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })),
    outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS }],
    locktime: 0,
  };
  const requiredInputValue = TRANSACTION_OUTPUT_SATOSHIS +
    BigInt(encodeTransactionBch(transaction).length) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  const sourceOutputValue = (requiredInputValue + BigInt(inputs.length) - 1n) / BigInt(inputs.length);
  return {
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: sourceOutputValue })),
    transaction,
  };
}
function evalInput(inputs, index, vm = realVm) {
  const program = {
    inputIndex: index,
    ...verificationData(inputs),
  };
  const st = vm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// ---- proof instances (proof #0 committed, #1 minted under same VK, worst-case dense) ----
function parseProofUnlocking(hex) {
  const b = hexToBin(hex); const vals = []; let i = 0;
  while (i < b.length) {
    const op = b[i++];
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; }
  }
  const d = vals.reverse();
  return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] };
}
const mp = JSON.parse(readFileSync(verifierPath('src/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
// glvResourceProof supplies one full-valid asymmetric trace. The proof-independent
// event ceiling is certified separately by prove_vkx_glv_resource_bound.mjs.
const namedGlvProofs = ['glvDensityProof', 'glvResourceProof'].map((name) => {
  const fixture = mp[name];
  if (fixture === null || typeof fixture !== 'object' || typeof fixture.unlocking !== 'string') {
    throw new Error(`${name} must be a proof fixture with unlocking bytecode`);
  }
  if (!Array.isArray(fixture.glvScalars) || fixture.glvScalars.length !== 4 ||
      fixture.glvScalars.some((scalar) => typeof scalar !== 'string' || !/^(0|[1-9][0-9]*)$/.test(scalar))) {
    throw new Error(`${name}.glvScalars must contain four canonical decimal strings`);
  }
  const parsed = parseProofUnlocking(fixture.unlocking);
  const glvScalars = fixture.glvScalars.map(BigInt);
  const bound = 1n << 128n;
  if (glvScalars.some((scalar) => scalar < 0n || scalar >= bound)) {
    throw new Error(`${name}.glvScalars contains an out-of-range witness`);
  }
  const inputs = [parsed.in0, parsed.in1];
  if (inputs.some((input) => input < 0n || input >= GLV_R) ||
      (glvScalars[0] + glvScalars[1] * GLV_LAMBDA) % GLV_R !== inputs[0] ||
      (glvScalars[2] + glvScalars[3] * GLV_LAMBDA) % GLV_R !== inputs[1]) {
    throw new Error(`${name}.glvScalars does not reconstruct its canonical public inputs`);
  }
  return {
    proof: proofFromLimbs(
      parsed.Ax, parsed.Ay, parsed.Bxa, parsed.Bxb,
      parsed.Bya, parsed.Byb, parsed.Cx, parsed.Cy,
    ),
    inputs,
    glvScalars,
  };
});
const [glvDensityProof, glvResourceProof] = namedGlvProofs;
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: glvDensityProof,
  resource: glvResourceProof,
};

function millerPairsFor(inst) {
  const raw = pairsFor(inst.inputs, inst.proof, { msmOnly: PROJECTIVE_VKX });
  const bInfinity = raw[0].Q.equals(bn254.G2.Point.ZERO);
  if (!bInfinity) return { stage: raw, effective: raw };
  const stage = raw.map((pair, index) => index === 0
    ? { ...pair, Q: bn254.G2.Point.BASE }
    : pair);
  const effective = stage.map((pair, index) => index === 0
    ? { ...pair, P: bn254.G1.Point.ZERO }
    : pair);
  return { stage, effective };
}

// vk_x position inside the 34-limb Miller genesis inBlob: runtime points(10)+c(12)+cInv(12).
const dummy = pairsFor([1n, 1n], undefined, { msmOnly: PROJECTIVE_VKX });
const fixedMiller = PROJECTIVE_VKX
  ? bn254.fields.Fp12.mul(singlePairMiller(dummy[1]).f, singlePairMiller({ P: vk.ic[0], Q: vk.gamma }).f)
  : null;
const VKX_LIMB_OFFSET = NORMALIZED_PROOF_POINTS
  ? 8
  : ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(3, dummy[3].P.toAffine(), dummy[3].Q.toAffine()).length;
const PTL_LEN = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length; // 10
const MILLER_UNIT_NAMES = MILLER_UNIT_LINES
  ? NORMALIZED_PROOF_POINTS ? ['Pu2', 'Pv2'] : ['Pu0', 'Pv0', 'Pu2', 'Pv2', 'Pu3', 'Pv3']
  : [];
const MILLER_ROOT_NAMES = MILLER_TORUS
  ? Array.from({ length: 6 }, (_, i) => `u${i}`)
  : [
      ...Array.from({ length: 12 }, (_, i) => `c${i}`),
      ...Array.from({ length: 12 }, (_, i) => `ci${i}`),
    ];
const MILLER_IN_LIMBS = PTL_LEN + (PROJECTIVE_VKX ? 1 : 0) + MILLER_ROOT_NAMES.length + MILLER_UNIT_NAMES.length;
const MILLER_DYNAMIC_LIMBS = 16; // f(12) + affine runtime R0(4)
const MILLER_GENESIS_INPUT = G2_COUNT + GLV_COUNT;
const MILLER_GENESIS_NAMES = NORMALIZED_PROOF_POINTS
  ? [
      'Pu0', 'Pv0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu3', 'Pv3',
      'VkxX', 'VkxY', 'VkxZ', ...MILLER_ROOT_NAMES, 'Pu2', 'Pv2',
    ]
  : [
      'Px0', 'Py0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Px3', 'Py3',
      ...(PROJECTIVE_VKX ? ['VkxX', 'VkxY', 'VkxZ'] : ['Px2', 'Py2']),
      ...MILLER_ROOT_NAMES,
      ...MILLER_UNIT_NAMES,
    ];
const MILLER_STATIC_NAMES = [
  ...(MILLER_UNIT_LINES
    ? ['Pu0', 'Pv0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu2', 'Pv2', 'Pu3', 'Pv3']
    : ['Px0', 'Py0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Px2', 'Py2', 'Px3', 'Py3']),
  ...MILLER_ROOT_NAMES,
];
const MILLER_GENESIS_OFFSETS = new Map(MILLER_GENESIS_NAMES.map((name, i) => [name, i * W]));

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) — IDENTICAL to the grouped-residue
// build (chunked/grouped/build_vectors_residue.mjs); only the assembly below differs (single tx).
function specsG2check(inst, bad = {}) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.negate().toAffine(), Ca = pf.c.toAffine();
  const Bx = bad.Bx ?? Ba.x, By = bad.By ?? Ba.y;
  const Bpair = [[Bx.c0, Bx.c1], [By.c0, By.c1]];
  const tail = [bad.Ax ?? Aa.x, bad.Ay ?? Aa.y, Bx.c0, Bx.c1, By.c0, By.c1, bad.Cx ?? Ca.x, bad.Cy ?? Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  assertG2StageManifest(man, { linkedLayout: true });
  const zinv = g2checkFastZinv(Bpair); // [zinvA, zinvB] witnessed inverse of [x0]B.Z (last chunk only)
  return man.chunks.map((ch) => ({
    file: join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: ch.first ? tail : sLimbs(g2checkAccAt(Bpair, ch.lo)),
    outLimbs: ch.last ? [] : sLimbs(g2checkAccAt(Bpair, ch.hi)),
    extras: ch.last ? zinv : [], role: ch.last ? 'terminal' : 'within',
    label: `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' [x0]B-endo==psi(B)' : ''}`,
    checkpoint: ch.first ? 'validate-inputs' : undefined,
  }));
}
// GLV vk_x: 4-scalar Straus over {IC1, phiIC1, IC2, phiIC2}; state = R(3)+in0+in1+k10,k20,k11,k21
// (9 limbs). The genesis chunk binds the GLV witnesses to the public inputs (k1+k2*lambda==in).
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20, k11, k21] = inst.glvScalars ?? glvDecomposeJoint(in0, in1);
  const st = (X, Y, Z) => [X, Y, Z, in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx residue requires stage-bound GLV generation');
  if (man.sharedTable !== true) throw new Error('intratx residue requires shared-table GLV generation');
  if (man.grouped !== true) throw new Error('intratx residue requires grouped GLV generation');
  if ((man.projectiveOutput === true) !== PROJECTIVE_VKX) throw new Error('intratx residue GLV projective-output mode mismatch');
  return man.chunks.map((ch) => {
    const [X0, Y0, Z0] = vkxGlvSplitStateAt(k10, k20, k11, k21, ch.lo);
    const fullIn = st(X0, Y0, Z0);
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) {
      const finalState = vkxGlvSplitStateAt(k10, k20, k11, k21, ch.hi);
      let outLimbs = finalState;
      if (!PROJECTIVE_VKX) {
        const vkxAff = vkxPoint(inst.inputs).toAffine();
        outLimbs = [vkxAff.x, vkxAff.y];
      }
      return {
        file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
        outLimbs, outWidths: outLimbs.map(() => W),
        extras: [...(PROJECTIVE_VKX ? [] : [vkxGlvSplitZinv(k10, k20, k11, k21)]), GLV_TABLE_BYTES],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: outLimbs.length * W } : null,
        label: PROJECTIVE_VKX ? 'GLV MSM final -> bind projective state' : 'GLV vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    const [X1, Y1, Z1] = vkxGlvSplitStateAt(k10, k20, k11, k21, ch.hi);
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
      outLimbs: st(X1, Y1, Z1), outWidths: GLV_STATE_WIDTHS,
      extras: [], role: 'within',
      label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
// c^-(6x+2)-FUSED Miller (residue method). Quotient mode carries the finite
// root coordinate u; legacy mode carries c/cInv and consumes w at the tail.
function specsMillerFused(inst, root) {
  const { stage: stagePairs, effective: pairs } = millerPairsFor(inst);
  const trace = MILLER_AFFINE_G2
    ? millerFusedAffineOps(pairs, root.c, root.cInv, {
        unitLines: MILLER_UNIT_LINES,
        torusU: MILLER_TORUS ? root.u : null,
        fixedMiller,
      })
    : millerFusedOps(pairs, root.c, root.cInv, { fixedMiller });
  const { ops, states } = trace;
  const rawPtL = stagePairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const [k10, k20, k11, k21] = inst.glvScalars ?? glvDecomposeJoint(
    BigInt(inst.inputs[0]),
    BigInt(inst.inputs[1]),
  );
  const msmState = vkxGlvSplitStateAt(k10, k20, k11, k21, VKXGLV_SPLIT_ITERS);
  const msmYInv = bn254.fields.Fp.inv(msmState[1]);
  const msmZ2 = bn254.fields.Fp.sqr(msmState[2]);
  const msmUnit = [
    bn254.fields.Fp.neg(bn254.fields.Fp.mul(bn254.fields.Fp.mul(msmState[0], msmState[2]), msmYInv)),
    bn254.fields.Fp.neg(bn254.fields.Fp.mul(bn254.fields.Fp.mul(msmZ2, msmState[2]), msmYInv)),
  ];
  const ptL = PROJECTIVE_VKX
    ? [
        ...ptLimbs(0, pairs[0].P.toAffine(), pairs[0].Q.toAffine(), true),
        ...msmUnit,
        ...ptLimbs(3, pairs[3].P.toAffine(), pairs[3].Q.toAffine(), true),
      ]
    : pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine(), MILLER_UNIT_LINES));
  let invY = [];
  if (MILLER_UNIT_LINES && !NORMALIZED_PROOF_POINTS) {
    invY = PROJECTIVE_VKX
      ? [
          pairs[0].P.equals(bn254.G1.Point.ZERO) ? 0n : bn254.fields.Fp.inv(pairs[0].P.toAffine().y),
          msmYInv,
          pairs[3].P.equals(bn254.G1.Point.ZERO) ? 0n : bn254.fields.Fp.inv(pairs[3].P.toAffine().y),
        ]
      : pairs.filter((_, j) => PT_CFG[j].P).map((pair) =>
          pair.P.equals(bn254.G1.Point.ZERO) ? 0n : bn254.fields.Fp.inv(pair.P.toAffine().y));
  }
  const runtimeRLimbs = (R) => MILLER_AFFINE_G2
    ? [R.x.c0, R.x.c1, R.y.c0, R.y.c1]
    : r6limbs(R);
  const rootLimbs = MILLER_TORUS
    ? [root.u.c0.c0, root.u.c0.c1, root.u.c1.c0, root.u.c1.c1, root.u.c2.c0, root.u.c2.c1]
    : [...f12limbs(root.c), ...f12limbs(root.cInv)];
  const full = (s) => [...f12limbs(s.f), ...runtimeRLimbs(s.Rs[0]), ...ptL, ...rootLimbs];
  const genesisPts = NORMALIZED_PROOF_POINTS
    ? [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...msmState]
    : PROJECTIVE_VKX
      ? [...rawPtL.slice(0, 6), ...rawPtL.slice(8, 10), ...msmState]
      : [...rawPtL.slice(0, 6), ...rawPtL.slice(8, 10), ...rawPtL.slice(6, 8)];
  const genesisUnitPoints = MILLER_UNIT_LINES
    ? NORMALIZED_PROOF_POINTS ? msmUnit : [...ptL.slice(0, 2), ...ptL.slice(6, 10)]
    : [];
  const genesis = [...genesisPts, ...rootLimbs, ...genesisUnitPoints];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.linkedLayout !== true) {
    throw new Error('intratx residue requires MILLER_LINKED_LAYOUT=1 during Miller generation');
  }
  if (man.stageBound !== true) {
    throw new Error('intratx residue requires STAGE_BOUND_LAYOUT=1 during Miller generation');
  }
  if (man.covenantResidue !== true) {
    throw new Error('intratx residue requires COVENANT_RESIDUE_LAYOUT=1 during Miller generation');
  }
  if (man.endpointSubgroup !== FUSE_G2_ENDPOINT) {
    throw new Error(`Miller endpoint subgroup mode mismatch: generated=${man.endpointSubgroup} requested=${FUSE_G2_ENDPOINT}`);
  }
  if (man.affineG2 !== MILLER_AFFINE_G2) {
    throw new Error(`Miller affine-G2 mode mismatch: generated=${man.affineG2} requested=${MILLER_AFFINE_G2}`);
  }
  if (man.unitLines !== MILLER_UNIT_LINES) {
    throw new Error(`Miller unit-line mode mismatch: generated=${man.unitLines} requested=${MILLER_UNIT_LINES}`);
  }
  if (man.quotientTorus !== MILLER_TORUS) {
    throw new Error(`Miller quotient-torus mode mismatch: generated=${man.quotientTorus} requested=${MILLER_TORUS}`);
  }
  if ((man.projectiveVkx === true) !== PROJECTIVE_VKX) {
    throw new Error('Miller projective-vk_x mode mismatch');
  }
  if ((man.normalizedProofPoints === true) !== NORMALIZED_PROOF_POINTS) {
    throw new Error('Miller normalized-proof-point mode mismatch');
  }
  if (man.implicitInfinityB !== MILLER_UNIT_LINES) {
    throw new Error('Miller implicit B-infinity mode mismatch');
  }
  return man.chunks.map((ch) => {
    const slopes = ops.slice(ch.opLo, ch.opHi).flatMap((op) =>
      (op.affineSlopes ?? []).flatMap((slope) => [slope.c0, slope.c1]));
    return {
      file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs: ch.opLo === 0 ? genesis : full(states[ch.opLo]),
      outLimbs: ch.final ? [] : full(states[ch.opHi]),
      extras: [
        ...(ch.opLo === 0 ? invY : []),
        ...slopes,
        ...(ch.final && !MILLER_TORUS ? fp12limbsOf(root.w) : []),
      ],
      unitInvYCount: ch.opLo === 0 ? invY.length : 0,
      affineSlopeCount: slopes.length,
      role: ch.final ? 'terminal' : 'within',
      cmp: null,
      label: `fused-miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' + residue verdict' : ''}`,
      checkpoint: ch.final ? 'verify' : undefined,
    };
  });
}
function buildSpecs(inst, staticContextLockingHash) {
  const g2 = FUSE_G2_ENDPOINT ? [] : specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const { effective: pairs } = millerPairsFor(inst);
  const fRaw = MILLER_AFFINE_G2
    ? millerFusedAffineOps(
        pairs,
        bn254.fields.Fp12.ONE,
        bn254.fields.Fp12.ONE,
        { unitLines: MILLER_UNIT_LINES, fixedMiller },
      ).boundary
    : millerBatchOps(pairs).boundary;
  const root = MILLER_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw);
  const miller = specsMillerFused(inst, root);
  if (MILLER_AFFINE_G2) {
    if (g2.length !== 0 || miller.length === 0) {
      throw new Error('affine Miller static context requires fused G2 validation and a Miller stage');
    }
    miller.forEach((spec, i) => {
      spec.enforceExactInputLength = true;
      if (i > 0) {
        spec.inLimbs = spec.inLimbs.slice(0, MILLER_DYNAMIC_LIMBS);
        spec.externalParams = MILLER_STATIC_NAMES.map((name) => ({
          name,
          targetSpecIndex: MILLER_GENESIS_INPUT,
          targetOffset: MILLER_GENESIS_OFFSETS.get(name),
          width: W,
          targetLockingHash: staticContextLockingHash,
        }));
      }
      if (spec.role !== 'terminal') {
        spec.outLimbs = spec.outLimbs.slice(0, MILLER_DYNAMIC_LIMBS);
        spec.outputCount = MILLER_DYNAMIC_LIMBS;
      }
    });
  }
  if (!FUSE_G2_ENDPOINT) {
    const millerGenesisIndex = g2.length + vkx.length;
    g2[g2.length - 1].externalBindings = [
      // G2-final inBlob = R(6) || -A/B/C(8); Miller genesis starts with the same proof tuple.
      { targetSpecIndex: millerGenesisIndex, sourceOffset: 6 * W, targetOffset: 0, length: 8 * W },
    ];
  }
  return [...g2, ...vkx, ...miller];
}

// ---- assemble: transform+compile each chunk, build the single tx, tune pad, verify ----
// Forward-check config is derived from each chunk's role exactly like build_vectors.mjs:
//   within  -> forward the FULL output (cmpExpr null, equal in/out len)
//   cross   -> forward only the bound slice (spec.cmp)
//   stage-final / terminal -> no forward (null)
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map(); // key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // key -> 'resched' | 'raw'; fixed on the FIRST assembly so every
                                // instance shares identical lockings.
const specConfig = (specs, i) => {
  const s = specs[i];
  let forward = null;
  if (s.role === 'within') { const outLen = byteLengthOf(s, 'out'); forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  const externalBindings = (s.externalBindings ?? []).map((binding) => {
    const target = specs[binding.targetSpecIndex];
    if (!target) throw new Error(`external binding target ${binding.targetSpecIndex} is not a verifier input`);
    return {
      sourceOffset: binding.sourceOffset,
      targetInputIndex: binding.targetSpecIndex,
      targetFullInLen: byteLengthOf(target, 'in'),
      targetOffset: binding.targetOffset,
      length: binding.length,
    };
  });
  const externalParams = (s.externalParams ?? []).map((param) => {
    const target = specs[param.targetSpecIndex];
    if (!target) throw new Error(`external param target ${param.targetSpecIndex} is not a verifier input`);
    return {
      name: param.name,
      targetInputIndex: param.targetSpecIndex,
      targetFullInLen: byteLengthOf(target, 'in'),
      targetOffset: param.targetOffset,
      width: param.width,
      targetLockingHash: param.targetLockingHash,
    };
  });
  const key = `${s.file}|${s.role}|output=${s.outputCount ?? 'all'}|` +
    `exact=${s.enforceExactInputLength === true}|${JSON.stringify(forward)}|` +
    `${JSON.stringify(externalBindings)}|${JSON.stringify(externalParams)}`;
  return {
    key,
    forward,
    externalBindings,
    externalParams,
    outputCount: s.outputCount,
    enforceExactInputLength: s.enforceExactInputLength,
  };
};
function compileSpec(specs, i) {
  const s = specs[i];
  const {
    key, forward, externalBindings, externalParams, outputCount, enforceExactInputLength,
  } = specConfig(specs, i);
  let v = compileCache.get(key);
  if (!v) {
    // compile from a file (probe in generated/) so the chunk's relative library import resolves
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), {
      W, widthsByName: GLV_WIDTHS_BY_NAME, prime: PRIME, forward, externalBindings,
      externalParams, outputCount, enforceExactInputLength,
    }).src);
    const resched = s.file.includes('millerres_')
      ? compileFileBytecodeSize(PROBE)
      : compileFileBytecode(PROBE);
    const raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched;
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  // The later tuned-size A/B requires one successful full-budget VM pass. If the
  // rescheduled redeem cannot be pushed within that budget but the plain compile
  // can, select raw before the bootstrap pass; when both fit, leave selection to
  // the existing measured comparison below.
  if (!chosenCache.has(key) && P2SH && v.raw) {
    const argBytes = argBytesOf(s).length;
    const rescheduledFixedBytes = argBytes + encodeDataPush(v.resched).length;
    const rawFixedBytes = argBytes + encodeDataPush(v.raw).length;
    if (rescheduledFixedBytes > TARGET_UNLOCK && rawFixedBytes <= TARGET_UNLOCK) {
      chosenCache.set(key, 'raw');
    }
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
function argBytesOf(s) {
  // inBlob is the LAST declared param (pushed FIRST -> front of the unlocking, where siblings'
  // forward-checks read it); extras come before inBlob in the decl, pushed AFTER it in reverse.
  const parts = [pd(blob(s.inLimbs, widthsOf(s, 'in')))];
  for (const e of [...s.extras].reverse()) parts.push(e instanceof Uint8Array ? pd(e) : pushInt(e));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
function assemble(specs, expectRejected = false) {
  const redeems = specs.map((_, i) => compileSpec(specs, i)); // [OP_DROP, contract]
  const argB = specs.map(argBytesOf);     // [inBlob, extras...]
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + tailLen(i);
    const pad = padPush(0, Math.max(2, target - fixed));
    return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]);
  };
  // Start from the full unlocking budget so both consensus and standard-policy VMs can
  // run without a density error and report their complete op-cost before padding shrinks.
  // A forward check may return false until successor unlockings reach their tuned lengths.
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
  }

  // Per-chunk variant selection (RESCHEDULE only; decided once, first assembly): keep the
  // redeem with the smaller TUNED unlocking — see chunked/grouped/build_vectors_residue.mjs.
  if (RESCHED) {
    let switched = 0;
    for (let i = 0; i < specs.length; i++) {
      const { key } = specConfig(specs, i);
      if (chosenCache.has(key)) continue;
      const v = compileCache.get(key);
      if (!v.raw) { chosenCache.set(key, 'resched'); continue; }
      const rawRpush = encodeDataPush(v.raw);
      const rawFixed = argB[i].length + (P2SH ? rawRpush.length : 0);
      const rawUnlock = P2SH
        ? Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, TARGET_UNLOCK - rawFixed)), ...rawRpush])
        : Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, TARGET_UNLOCK - rawFixed))]);
      const probe = inputs.slice();
      probe[i] = { locking: P2SH ? p2shSpk(v.raw) : v.raw, unlocking: rawUnlock };
      const rawOp = evalInput(probe, i);
      const rawStandardOp = evalInput(probe, i, standardVm);
      const tR = tunedLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost));
      const tB = rawOp.accepted && rawStandardOp.accepted
        ? tunedLen(rawFixed, Math.max(rawOp.operationCost, rawStandardOp.operationCost))
        : Infinity;
      chosenCache.set(key, tB < tR ? 'raw' : 'resched');
      if (tB < tR) switched += 1;
    }
    if (switched) return assemble(specs, expectRejected); // reassemble with final choices (cached -> recurses once)
  }
  // Re-measure after each shrink: shorter successor unlockings make forward introspection
  // cheaper, which can safely expose another byte of density headroom in the predecessor.
  let targets = specs.map((_, i) => tunedLen(
    argB[i].length + tailLen(i),
    Math.max(op1[i].operationCost, standardOp1[i].operationCost),
  ));
  const minimumTargets = specs.map(() => 0);
  let op2;
  let standardOp2;
  while (true) {
    inputs = specs.map((_, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, targets[i]) }));
    op2 = specs.map((_, i) => evalInput(inputs, i));
    standardOp2 = specs.map((_, i) => evalInput(inputs, i, standardVm));
    if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
      let relaxed = false;
      targets = targets.map((target, i) => {
        const failures = [op2[i], standardOp2[i]].filter((outcome) => !outcome.accepted);
        if (failures.length === 0 || failures.some((outcome) => !outcome.error?.includes('operation cost density limit')) || target >= TARGET_UNLOCK) {
          return target;
        }
        minimumTargets[i] = target + 1;
        relaxed = true;
        return target + 1;
      });
      if (relaxed) continue;
      break;
    }
    const tightened = targets.map((target, i) => Math.max(
      minimumTargets[i],
      Math.min(target, tunedLen(argB[i].length + tailLen(i), Math.max(op2[i].operationCost, standardOp2[i].operationCost))),
    ));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
    const failures = [...op2, ...standardOp2]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => !outcome.accepted);
    throw new Error(`tightened input rejected during padding measurement: ${JSON.stringify(failures)}`);
  }
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint,
    lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length,
    redeemBytes: redeems[i].length, operationCost: op2[i].operationCost,
    accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
function pushBounds(unlocking, opcodeOffset = 0) {
  const op = unlocking[opcodeOffset];
  if (op <= 75) return { dataStart: opcodeOffset + 1, dataLen: op };
  if (op === 0x4c) return { dataStart: opcodeOffset + 2, dataLen: unlocking[opcodeOffset + 1] };
  if (op === 0x4d) return { dataStart: opcodeOffset + 3, dataLen: unlocking[opcodeOffset + 1] | (unlocking[opcodeOffset + 2] << 8) };
  throw new Error(`unsupported push opcode ${op}`);
}
function mutateInputBlob(inputs, inputIndex, byteOffset) {
  const mutated = inputs.slice();
  const unlocking = Uint8Array.from(mutated[inputIndex].unlocking);
  const { dataStart, dataLen } = pushBounds(unlocking);
  if (byteOffset < 0 || byteOffset >= dataLen) throw new Error(`mutation offset ${byteOffset} outside inBlob`);
  unlocking[dataStart + byteOffset] ^= 0x01;
  mutated[inputIndex] = { ...mutated[inputIndex], unlocking };
  return mutated;
}
function replaceInputBlobLimb(inputs, inputIndex, byteOffset, value) {
  const replaced = inputs.slice();
  const unlocking = Uint8Array.from(replaced[inputIndex].unlocking);
  const { dataStart, dataLen } = pushBounds(unlocking);
  if (byteOffset < 0 || byteOffset + W > dataLen) {
    throw new Error(`replacement offset ${byteOffset} outside inBlob`);
  }
  unlocking.set(le40(value).slice(0, W), dataStart + byteOffset);
  replaced[inputIndex] = { ...replaced[inputIndex], unlocking };
  return replaced;
}
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk uses); the
// predecessor's forward-check (and/or this chunk's own) then fails -> the run is rejected.
function invalidRun(asm, idx) {
  const { dataLen } = pushBounds(asm.inputs[idx].unlocking);
  const inputs = mutateInputBlob(asm.inputs, idx, Math.floor(dataLen / 2));
  const meta = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })), rejected: meta.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const maxOp = Math.max(...asm.meta.map((m) => m.operationCost));
  const totalOperationCost = sum(asm.meta, (m) => m.operationCost);
  const maxL = Math.max(...asm.meta.map((m) => m.lockingBytes)), maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  const data = verificationData(asm.inputs);
  const wireBytes = encodeTransactionBch(data.transaction).length;
  const consensusVerified = realVm.verify(data) === true;
  const standardVerified = standardVm.verify(data) === true;
  const feeSatoshis = data.sourceOutputs.reduce((total, output) => total + output.valueSatoshis, 0n) -
    data.transaction.outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
  const defaultMinRelayFeeVerified = feeSatoshis >=
    BigInt(wireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  if (asm.accepted && !consensusVerified) throw new Error(`${tag}: independently accepted inputs failed whole-transaction consensus verification`);
  if (standardVerified && !defaultMinRelayFeeVerified) throw new Error(`${tag}: standard transaction does not fund the default minimum relay fee`);
  console.error(`${tag}: ${asm.meta.length} inputs, accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} wireBytes=${wireBytes.toLocaleString()} totalOp=${totalOperationCost.toLocaleString()} maxOp=${maxOp.toLocaleString()} maxLock=${maxL} maxUnlock=${maxU} consensus=${consensusVerified} standard=${standardVerified} relayFee=${defaultMinRelayFeeVerified}`);
  if (process.env.DUMP_OPCOSTS) asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} redeem=${m.redeemBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
  return { wireBytes, consensusVerified, standardVerified, defaultMinRelayFeeVerified, totalOperationCost, maxStepOperationCost: maxOp };
};

// ===================== FULL GROTH16 (residue, single tx) =====================
let committedSpecs = buildSpecs(INSTANCES.committed);
let millerGenesisLockingHash;
if (MILLER_AFFINE_G2) {
  // Resolve the proof-independent genesis locking after redeem selection, then pin every
  // static-context reader to that exact UTXO script before producing the measured vectors.
  const carrierProbe = assemble(committedSpecs);
  millerGenesisLockingHash = binToHex(sha256.hash(carrierProbe.inputs[MILLER_GENESIS_INPUT].locking));
  committedSpecs = buildSpecs(INSTANCES.committed, millerGenesisLockingHash);
}
const proof1Specs = buildSpecs(INSTANCES.proof1, millerGenesisLockingHash);
const worstSpecs = buildSpecs(INSTANCES.worst, millerGenesisLockingHash);
const resourceSpecs = buildSpecs(INSTANCES.resource, millerGenesisLockingHash);
const full0 = assemble(committedSpecs);
const full0Transaction = report('groth16-intratx-residue committed', full0);
const millerGenesisIndex = G2_COUNT + GLV_COUNT;
const full1 = assemble(proof1Specs);
const fullWc = assemble(worstSpecs);
const fullResource = assemble(resourceSpecs);
const full1Transaction = report('groth16-intratx-residue proof#1', full1);
const fullWcTransaction = report('groth16-intratx-residue GLV-density proof', fullWc);
const fullResourceTransaction = report('groth16-intratx-residue GLV-resource fixture', fullResource);
const infinityRuns = Object.entries(infinityInstances).map(([name, instance]) => {
  const specs = buildSpecs(instance, millerGenesisLockingHash);
  const run = assemble(specs);
  const transaction = report(`groth16-intratx-residue ${name}`, run);
  return { name, instance, specs, run, transaction };
});
if (NORMALIZED_PROOF_POINTS) {
  const identityRun = infinityRuns.find(({ name }) => name === 'vkx-msm-infinity');
  if (identityRun === undefined) throw new Error('missing normalized vk_x identity fixture');
  const genesisLimbs = identityRun.specs[MILLER_GENESIS_INPUT].inLimbs;
  const expected = new Map([
    ['VkxX', 0n], ['VkxY', 1n], ['VkxZ', 0n], ['Pu2', 0n], ['Pv2', 0n],
  ]);
  for (const [name, value] of expected) {
    const index = MILLER_GENESIS_NAMES.indexOf(name);
    if (index < 0 || BigInt(genesisLimbs[index]) !== value) {
      throw new Error(`zero-input GLV fixture emitted unexpected ${name}`);
    }
  }
}
const infinityAlteredRuns = infinityRuns.map(({ name, instance, specs }) => {
  const alteredVkx = specsVkx({ ...instance, inputs: instance.alteredInputs }, true);
  const hybrid = assemble([...alteredVkx, ...specs.slice(GLV_COUNT)], true);
  if (hybrid.meta[GLV_COUNT - 1].accepted) {
    throw new Error(`${name} accepted an altered public input at the vk_x handoff`);
  }
  const unrelatedFailure = hybrid.meta.find((meta, index) => index !== GLV_COUNT - 1 && !meta.accepted);
  if (unrelatedFailure) {
    throw new Error(`${name} altered input also rejected at ${unrelatedFailure.label}`);
  }
  return { steps: toStepArr(hybrid), rejected: true };
});
const infinityMalformedRuns = [
  ['a-infinity', NORMALIZED_PROOF_POINTS ? 'Pu0' : 'Px0'],
  ['b-infinity', 'Q0xa'],
  ['c-infinity', NORMALIZED_PROOF_POINTS ? 'Pu3' : 'Px3'],
].map(([name, limbName]) => {
  const fixture = infinityRuns.find((candidate) => candidate.name === name);
  if (fixture === undefined) throw new Error(`missing ${name} fixture`);
  const byteOffset = MILLER_GENESIS_OFFSETS.get(limbName);
  if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${limbName}`);
  const inputs = replaceInputBlobLimb(fixture.run.inputs, millerGenesisIndex, byteOffset, 1n);
  if (evalInput(inputs, millerGenesisIndex).accepted || evalInput(inputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error(`${name} accepted a malformed infinity encoding`);
  }
  return { steps: toStepArr({ inputs, meta: fixture.run.meta }), rejected: true };
});
const densityGlv = fullWc.meta.slice(G2_COUNT, G2_COUNT + GLV_COUNT);
const resourceGlv = fullResource.meta.slice(G2_COUNT, G2_COUNT + GLV_COUNT);
if ([...densityGlv, ...resourceGlv].some((meta) =>
  !meta.accepted || meta.operationCost > OP_BUDGET || meta.unlockingBytes > TARGET_UNLOCK)) {
  throw new Error('named GLV density or resource fixture exceeds the BCH input budget');
}
console.error(`  GLV-density max op: ${Math.max(...densityGlv.map((meta) => meta.operationCost)).toLocaleString()}`);
console.error(`  GLV-resource max op: ${Math.max(...resourceGlv.map((meta) => meta.operationCost)).toLocaleString()}`);
let proofConsistency;
let proofMutations;
if (FUSE_G2_ENDPOINT) {
  const hybridSpecs = [
    ...committedSpecs.slice(0, GLV_COUNT),
    ...proof1Specs.slice(GLV_COUNT),
  ];
  const unboundHybridSpecs = hybridSpecs.map((spec, i) => i === GLV_COUNT - 1
    ? { ...spec, role: 'stage-final', cmp: null }
    : spec);
  const unboundHybrid = assemble(unboundHybridSpecs);
  if (!unboundHybrid.accepted) throw new Error('pre-binding proof0-GLV/proof1-Miller hybrid was not accepted');
  const boundHybrid = assemble(hybridSpecs, true);
  if (boundHybrid.meta[GLV_COUNT - 1].accepted) throw new Error('bound hybrid did not reject at GLV final');
  const unrelatedFailure = boundHybrid.meta.find((meta, i) => i !== GLV_COUNT - 1 && !meta.accepted);
  if (unrelatedFailure) throw new Error(`bound hybrid also rejected at ${unrelatedFailure.label}`);
  proofConsistency = { steps: toStepArr(boundHybrid), rejected: true };
  const proofMutationNames = NORMALIZED_PROOF_POINTS ? ['Q0xb', 'Pu3'] : ['Q0xb', 'Px3'];
  proofMutations = proofMutationNames.map((name) => {
    const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
    if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
    const inputs = mutateInputBlob(full0.inputs, millerGenesisIndex, byteOffset);
    if (evalInput(inputs, millerGenesisIndex).accepted) {
      throw new Error(`Miller genesis accepted mutated proof byte at ${byteOffset}`);
    }
    return { steps: toStepArr({ inputs, meta: full0.meta }), rejected: true };
  });
  console.error(
    `  proof consistency: unbound hybrid accepted=${unboundHybrid.accepted}; ` +
    `bound hybrid GLV-final rejected=${!boundHybrid.meta[GLV_COUNT - 1].accepted}; ` +
    `-A/B mutation rejected=${proofMutations[0].rejected}; C mutation rejected=${proofMutations[1].rejected}`,
  );
} else {
  const g2FinalIndex = committedSpecs.findIndex((spec) => (spec.externalBindings ?? []).length > 0);
  if (g2FinalIndex < 0) throw new Error('missing G2-final external bindings');
  const bindings = committedSpecs[g2FinalIndex].externalBindings;
  const hybridSpecs = [
    ...committedSpecs.slice(0, g2FinalIndex + 1),
    ...proof1Specs.slice(g2FinalIndex + 1),
  ];
  const unboundHybrid = assemble(hybridSpecs.map((spec) => ({ ...spec, externalBindings: [] })));
  if (!unboundHybrid.accepted) throw new Error('pre-binding proof0-G2/proof1-remainder hybrid was not accepted');
  const boundHybrid = assemble(hybridSpecs, true);
  if (boundHybrid.meta[g2FinalIndex].accepted) throw new Error('bound hybrid did not reject at G2 final');
  const unrelatedFailure = boundHybrid.meta.find((meta, i) => i !== g2FinalIndex && !meta.accepted);
  if (unrelatedFailure) throw new Error(`bound hybrid also rejected at ${unrelatedFailure.label}`);
  if (bindings.length !== 1) throw new Error('expected one contiguous proof binding');
  proofConsistency = { steps: toStepArr(boundHybrid), rejected: true };
  proofMutations = [3 * W, 7 * W].map((offset) => {
    const binding = bindings[0];
    const byteOffset = binding.targetOffset + offset;
    const inputs = mutateInputBlob(full0.inputs, binding.targetSpecIndex, byteOffset);
    if (evalInput(inputs, g2FinalIndex).accepted) {
      throw new Error(`G2 final accepted mutated bound region at ${binding.targetOffset}`);
    }
    return { steps: toStepArr({ inputs, meta: full0.meta }), rejected: true };
  });
  console.error(
    `  proof consistency: unbound hybrid accepted=${unboundHybrid.accepted}; ` +
    `bound hybrid G2-final rejected=${!boundHybrid.meta[g2FinalIndex].accepted}; ` +
    `-A/B mutation rejected=${proofMutations[0].rejected}; C mutation rejected=${proofMutations[1].rejected}`,
  );
}
const tableCarrierIndex = committedSpecs.findIndex((spec) => spec.extras.some((extra) => extra instanceof Uint8Array));
if (tableCarrierIndex < 0) throw new Error('missing shared GLV table carrier');
const tableInputs = full0.inputs.slice();
const tableUnlocking = Uint8Array.from(tableInputs[tableCarrierIndex].unlocking);
const carrierBlob = pushBounds(tableUnlocking);
const tablePush = pushBounds(tableUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
if (tablePush.dataLen !== GLV_TABLE_BYTES.length) throw new Error('shared GLV table push has unexpected length');
tableUnlocking[tablePush.dataStart + Math.floor(tablePush.dataLen / 2)] ^= 0x01;
tableInputs[tableCarrierIndex] = { ...tableInputs[tableCarrierIndex], unlocking: tableUnlocking };
if (evalInput(tableInputs, tableCarrierIndex).accepted) throw new Error('GLV carrier accepted a mutated shared table');
const tableMutation = { steps: toStepArr({ inputs: tableInputs, meta: full0.meta }), rejected: true };
const fullInvalid = [
  invalidRun(full0, 0),
  invalidRun(full0, Math.floor(full0.inputs.length / 2)),
  proofConsistency,
  ...proofMutations,
  tableMutation,
  ...infinityAlteredRuns,
  ...infinityMalformedRuns,
];
if (MILLER_AFFINE_G2) {
  const contextMutations = [
    ['-A/B', MILLER_UNIT_LINES ? 'Pu0' : 'Px0'],
    ['C', MILLER_UNIT_LINES ? 'Pu3' : 'Px3'],
    ['vk_x', MILLER_UNIT_LINES ? 'Pu2' : 'Px2'],
    ...(MILLER_TORUS ? [['residue root', 'u0']] : [['c', 'c0'], ['cInv', 'ci0']]),
  ].map(([label, name]) => {
    const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
    if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
    const inputs = mutateInputBlob(full0.inputs, MILLER_GENESIS_INPUT, byteOffset);
    let readerIndex = -1;
    for (let i = MILLER_GENESIS_INPUT + 1; i < committedSpecs.length; i++) {
      if (!evalInput(inputs, i).accepted && !evalInput(inputs, i, standardVm).accepted) {
        readerIndex = i;
        break;
      }
    }
    if (readerIndex < 0) {
      throw new Error(`Miller reader accepted mutated ${label} static context`);
    }
    return { steps: toStepArr({ inputs, meta: full0.meta }), rejected: true };
  });

  const lockingInputs = full0.inputs.map((input) => ({ ...input }));
  const locking = Uint8Array.from(lockingInputs[MILLER_GENESIS_INPUT].locking);
  locking[0] ^= 0x01;
  lockingInputs[MILLER_GENESIS_INPUT] = { ...lockingInputs[MILLER_GENESIS_INPUT], locking };
  const firstReaderIndex = MILLER_GENESIS_INPUT + 1;
  if (evalInput(lockingInputs, firstReaderIndex).accepted || evalInput(lockingInputs, firstReaderIndex, standardVm).accepted) {
    throw new Error('Miller reader accepted a redirected static-context carrier');
  }

  const seamInputIndex = MILLER_GENESIS_INPUT + 2;
  const seamInputs = mutateInputBlob(full0.inputs, seamInputIndex, 5 * W);
  if (evalInput(seamInputs, seamInputIndex - 1).accepted || evalInput(seamInputs, seamInputIndex - 1, standardVm).accepted) {
    throw new Error('Miller predecessor accepted a mutated dynamic-state seam');
  }

  const trailingInputIndex = MILLER_GENESIS_INPUT + 1;
  const trailingInputs = full0.inputs.slice();
  const baseUnlocking = trailingInputs[trailingInputIndex].unlocking;
  const inBlob = pushBounds(baseUnlocking);
  const longerInBlob = Uint8Array.from([
    ...baseUnlocking.slice(inBlob.dataStart, inBlob.dataStart + inBlob.dataLen),
    0,
  ]);
  trailingInputs[trailingInputIndex] = {
    ...trailingInputs[trailingInputIndex],
    unlocking: Uint8Array.from([
      ...pd(longerInBlob),
      ...baseUnlocking.slice(inBlob.dataStart + inBlob.dataLen),
    ]),
  };
  if (evalInput(trailingInputs, trailingInputIndex).accepted || evalInput(trailingInputs, trailingInputIndex, standardVm).accepted) {
    throw new Error('Miller reader accepted trailing bytes in dynamic state');
  }

  const torusMutations = [];
  if (MILLER_TORUS) {
    const rootIndex = MILLER_GENESIS_NAMES.indexOf('u0');
    const rootByteOffset = MILLER_GENESIS_OFFSETS.get('u0');
    if (rootIndex < 0 || rootByteOffset === undefined) throw new Error('missing torus root offset');
    const rootAliasInputs = full0.inputs.slice();
    const rootAliasUnlocking = Uint8Array.from(rootAliasInputs[MILLER_GENESIS_INPUT].unlocking);
    const rootAliasBlob = pushBounds(rootAliasUnlocking);
    const rootAlias = BigInt(committedSpecs[MILLER_GENESIS_INPUT].inLimbs[rootIndex]) + P;
    rootAliasUnlocking.set(le40(rootAlias).slice(0, W), rootAliasBlob.dataStart + rootByteOffset);
    rootAliasInputs[MILLER_GENESIS_INPUT] = {
      ...rootAliasInputs[MILLER_GENESIS_INPUT],
      unlocking: rootAliasUnlocking,
    };
    if (evalInput(rootAliasInputs, MILLER_GENESIS_INPUT).accepted ||
        evalInput(rootAliasInputs, MILLER_GENESIS_INPUT, standardVm).accepted) {
      throw new Error('Miller genesis accepted a noncanonical u+p residue root');
    }

    const terminalIndex = committedSpecs.findIndex((spec) => spec.role === 'terminal');
    if (terminalIndex < 0) throw new Error('missing torus terminal input');
    const zeroRepresentativeInputs = full0.inputs.slice();
    const zeroRepresentativeUnlocking = Uint8Array.from(zeroRepresentativeInputs[terminalIndex].unlocking);
    const terminalBlob = pushBounds(zeroRepresentativeUnlocking);
    if (terminalBlob.dataLen < 12 * W) throw new Error('torus terminal state is missing f');
    zeroRepresentativeUnlocking.fill(0, terminalBlob.dataStart, terminalBlob.dataStart + 12 * W);
    zeroRepresentativeInputs[terminalIndex] = {
      ...zeroRepresentativeInputs[terminalIndex],
      unlocking: zeroRepresentativeUnlocking,
    };
    if (evalInput(zeroRepresentativeInputs, terminalIndex).accepted ||
        evalInput(zeroRepresentativeInputs, terminalIndex, standardVm).accepted) {
      throw new Error('torus tail accepted the projective zero representative');
    }
    const wrongClassInputs = mutateInputBlob(full0.inputs, terminalIndex, 0);
    if (evalInput(wrongClassInputs, terminalIndex).accepted ||
        evalInput(wrongClassInputs, terminalIndex, standardVm).accepted) {
      throw new Error('torus tail accepted a wrong nonzero quotient class');
    }
    torusMutations.push(
      { steps: toStepArr({ inputs: rootAliasInputs, meta: full0.meta }), rejected: true },
      { steps: toStepArr({ inputs: zeroRepresentativeInputs, meta: full0.meta }), rejected: true },
      { steps: toStepArr({ inputs: wrongClassInputs, meta: full0.meta }), rejected: true },
    );
  }

  fullInvalid.push(
    ...contextMutations,
    { steps: toStepArr({ inputs: lockingInputs, meta: full0.meta }), rejected: true },
    { steps: toStepArr({ inputs: seamInputs, meta: full0.meta }), rejected: true },
    { steps: toStepArr({ inputs: trailingInputs, meta: full0.meta }), rejected: true },
    ...torusMutations,
  );
  console.error(`  static context mutations: -A/B, C, vk_x, ${MILLER_TORUS ? 'residue root, u+p alias, projective zero, wrong quotient class' : 'c, cInv'}, carrier locking, dynamic seam, and trailing state rejected`);
}
let endpointSpecIndex = -1;
if (FUSE_G2_ENDPOINT) {
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  const endpointPairs = pairsFor(INSTANCES.committed.inputs, proof);
  const trace = MILLER_AFFINE_G2
    ? millerFusedAffineOps(
        endpointPairs,
        bn254.fields.Fp12.ONE,
        bn254.fields.Fp12.ONE,
        { unitLines: MILLER_UNIT_LINES },
      )
    : millerFusedOps(endpointPairs, bn254.fields.Fp12.ONE, bn254.fields.Fp12.ONE);
  const endpointOp = trace.ops.findIndex((op) => op.t === 'pp' && op.j === 0);
  const endpointChunk = manifest.chunks.findIndex((chunk) => chunk.opLo <= endpointOp && endpointOp < chunk.opHi);
  if (endpointChunk < 0) throw new Error('missing fused Miller endpoint chunk');
  if (ENDPOINT_VM_CASES > 1 && manifest.chunks[endpointChunk].final) {
    throw new Error('extended endpoint VM cases require a cut after the runtime-B pp op');
  }
  endpointSpecIndex = GLV_COUNT + endpointChunk;
}

const invalidPointRuns = invalidG2Overrides(
  INSTANCES.committed.proof,
  FUSE_G2_ENDPOINT ? ENDPOINT_VM_CASES : 1,
).map((bad) => {
  if (!FUSE_G2_ENDPOINT) {
    const run = assemble(specsG2check(INSTANCES.committed, bad), true);
    if (run.accepted) throw new Error('isolated G2 validation accepted an invalid point');
    return run;
  }

  const baseNegA = proof.a.negate().toAffine();
  const baseB = proof.b.toAffine();
  const baseC = proof.c.toAffine();
  const badProof = {
    a: bn254.G1.Point.fromAffine({ x: bad.Ax ?? baseNegA.x, y: bad.Ay ?? baseNegA.y }).negate(),
    b: bn254.G2.Point.fromAffine({ x: bad.Bx ?? baseB.x, y: bad.By ?? baseB.y }),
    c: bn254.G1.Point.fromAffine({ x: bad.Cx ?? baseC.x, y: bad.Cy ?? baseC.y }),
  };
  const run = assemble(buildSpecs(
    { proof: badProof, inputs: INSTANCES.committed.inputs },
    millerGenesisLockingHash,
  ), true);
  const expectedFailure = bad.Bx === undefined ? millerGenesisIndex : endpointSpecIndex;
  if (run.meta[expectedFailure]?.accepted !== false) {
    throw new Error('fused Miller input validation accepted an invalid point');
  }
  const earlierFailure = run.meta.find((meta, i) => i < expectedFailure && !meta.accepted);
  if (earlierFailure) throw new Error(`invalid point rejected before its validation step at ${earlierFailure.label}`);
  return run;
});

const noncanonicalInputs = [];
if (FUSE_G2_ENDPOINT) {
  const noncanonicalNames = NORMALIZED_PROOF_POINTS ? ['Pu0', 'Q0xa', 'Pu2'] : ['Px0', 'Q0xa', 'Px3'];
  for (const name of noncanonicalNames) {
    const limbIndex = MILLER_GENESIS_NAMES.indexOf(name);
    if (limbIndex < 0) throw new Error(`missing Miller genesis limb ${name}`);
    const inputs = full0.inputs.slice();
    const unlocking = Uint8Array.from(inputs[millerGenesisIndex].unlocking);
    const inBlob = pushBounds(unlocking);
    const replacement = le40(BigInt(committedSpecs[millerGenesisIndex].inLimbs[limbIndex]) + P).slice(0, W);
    unlocking.set(replacement, inBlob.dataStart + limbIndex * W);
    inputs[millerGenesisIndex] = { ...inputs[millerGenesisIndex], unlocking };
    if (evalInput(inputs, millerGenesisIndex).accepted) {
      throw new Error(`Miller genesis accepted noncanonical proof limb ${name}`);
    }
    noncanonicalInputs.push(toStepArr({ inputs, meta: full0.meta }));
  }

  const endpointInputs = mutateInputBlob(full0.inputs, endpointSpecIndex, 12 * W);
  if (evalInput(endpointInputs, endpointSpecIndex).accepted) {
    throw new Error('fused Miller endpoint accepted a mutated R state');
  }
  fullInvalid.push({ steps: toStepArr({ inputs: endpointInputs, meta: full0.meta }), rejected: true });
}

if (MILLER_AFFINE_G2) {
  const slopeSpecIndex = committedSpecs.findIndex((spec) =>
    spec.role === 'within' && spec.affineSlopeCount > 0 && spec.extras.length === spec.affineSlopeCount);
  if (slopeSpecIndex < 0) throw new Error('missing non-final affine slope witness');
  const slopeSpec = committedSpecs[slopeSpecIndex];
  // Extras are pushed in reverse declaration order, so the first push after inBlob is the last
  // slope limb. Mutate that minimally encoded integer without touching the forward-bound inBlob.
  const originalSlope = BigInt(slopeSpec.extras[slopeSpec.affineSlopeCount - 1]);
  const wrongCanonicalSlope = originalSlope === P - 1n ? originalSlope - 1n : originalSlope + 1n;
  const baseUnlocking = full0.inputs[slopeSpecIndex].unlocking;
  const inBlobPush = pushBounds(baseUnlocking);
  const slopeOpcodeOffset = inBlobPush.dataStart + inBlobPush.dataLen;
  const slopePush = pushBounds(baseUnlocking, slopeOpcodeOffset);
  for (const [label, replacement] of [
    ['wrong canonical', pushInt(wrongCanonicalSlope)],
    ['noncanonical p', pushInt(P)],
  ]) {
    const inputs = full0.inputs.slice();
    const unlocking = Uint8Array.from([
      ...baseUnlocking.slice(0, slopeOpcodeOffset),
      ...replacement,
      ...baseUnlocking.slice(slopePush.dataStart + slopePush.dataLen),
    ]);
    inputs[slopeSpecIndex] = { ...inputs[slopeSpecIndex], unlocking };
    const outcomes = inputs.map((_, i) => evalInput(inputs, i));
    if (outcomes[slopeSpecIndex].accepted) throw new Error(`affine step accepted ${label} slope witness`);
    const unrelatedFailure = outcomes.find((outcome, i) => i !== slopeSpecIndex && !outcome.accepted);
    if (unrelatedFailure) throw new Error(`${label} slope mutation also rejected outside its affine step`);
    fullInvalid.push({ steps: toStepArr({ inputs, meta: full0.meta }), rejected: true });
  }
  console.error('  affine slope mutations: wrong canonical and noncanonical-p witnesses rejected at their step');
}

if (MILLER_UNIT_LINES && !NORMALIZED_PROOF_POINTS) {
  const inverseSpec = committedSpecs[millerGenesisIndex];
  if (inverseSpec.unitInvYCount !== 3) throw new Error('unit-line genesis must carry three inverse-Y witnesses');
  const baseUnlocking = full0.inputs[millerGenesisIndex].unlocking;
  const inBlobPush = pushBounds(baseUnlocking);
  const extraStart = inBlobPush.dataStart + inBlobPush.dataLen;
  const mutations = Array.from({ length: inverseSpec.unitInvYCount }, (_, invIndex) => {
    const value = BigInt(inverseSpec.extras[invIndex]);
    return [`wrong canonical inverse ${invIndex}`, invIndex, pushInt(value === P - 1n ? value - 1n : value + 1n)];
  });
  mutations.push(['noncanonical inverse p', 0, pushInt(P)]);
  for (const [label, invIndex, replacement] of mutations) {
    const physicalPushIndex = inverseSpec.extras.length - 1 - invIndex;
    let opcodeOffset = extraStart;
    for (let i = 0; i < physicalPushIndex; i++) {
      const current = pushBounds(baseUnlocking, opcodeOffset);
      opcodeOffset = current.dataStart + current.dataLen;
    }
    const inversePush = pushBounds(baseUnlocking, opcodeOffset);
    const inputs = full0.inputs.slice();
    const unlocking = Uint8Array.from([
      ...baseUnlocking.slice(0, opcodeOffset),
      ...replacement,
      ...baseUnlocking.slice(inversePush.dataStart + inversePush.dataLen),
    ]);
    inputs[millerGenesisIndex] = { ...inputs[millerGenesisIndex], unlocking };
    const consensusOutcomes = inputs.map((_, i) => evalInput(inputs, i));
    const standardOutcomes = inputs.map((_, i) => evalInput(inputs, i, standardVm));
    if (consensusOutcomes[millerGenesisIndex].accepted || standardOutcomes[millerGenesisIndex].accepted) {
      throw new Error(`unit-line genesis accepted ${label}`);
    }
    const unrelatedFailure = [...consensusOutcomes, ...standardOutcomes].find((outcome, i) =>
      i % inputs.length !== millerGenesisIndex && !outcome.accepted);
    if (unrelatedFailure) throw new Error(`${label} also rejected outside the unit-line genesis`);
    fullInvalid.push({ steps: toStepArr({ inputs, meta: full0.meta }), rejected: true });
  }
  console.error('  unit-line inverse mutations: three wrong canonical and one noncanonical-p witness rejected at genesis');
}

if (NORMALIZED_PROOF_POINTS) {
  const glvFinalIndex = G2_COUNT + GLV_COUNT - 1;
  for (const name of ['Pu2', 'Pv2']) {
    const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
    if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
    const inputs = mutateInputBlob(full0.inputs, millerGenesisIndex, byteOffset);
    const consensusGenesis = evalInput(inputs, millerGenesisIndex);
    const standardGenesis = evalInput(inputs, millerGenesisIndex, standardVm);
    if (consensusGenesis.accepted || standardGenesis.accepted) {
      throw new Error(`Miller genesis accepted mutated ${name} cross-multiplication hand-off`);
    }
    if (!evalInput(inputs, glvFinalIndex).accepted || !evalInput(inputs, glvFinalIndex, standardVm).accepted) {
      throw new Error(`mutated ${name} unexpectedly changed the projective GLV binding`);
    }
    fullInvalid.push({ steps: toStepArr({ inputs, meta: full0.meta }), rejected: true });
  }
  console.error('  normalized projective hand-off mutations: Pu2/Pv2 rejected by Miller cross multiplication');
}

if (FUSE_G2_ENDPOINT && ENDPOINT_VM_CASES > 1) {
  for (const scalar of [2n, 7n, BN_X]) {
    const scaledProof = {
      a: proof.a.multiply(bn254.fields.Fr.inv(scalar)),
      b: proof.b.multiply(scalar),
      c: proof.c,
    };
    const run = assemble(buildSpecs(
      { proof: scaledProof, inputs: INSTANCES.committed.inputs },
      millerGenesisLockingHash,
    ));
    if (!run.accepted || !run.fits) throw new Error(`subgroup-scaled valid pairing failed for scalar ${scalar}`);
  }

  const wrapX = P - 1n;
  const wrapY = bn254.fields.Fp.sqrt(2n);
  if ((wrapX ** 3n) % P !== P - 1n) throw new Error('G1 wraparound fixture does not exercise x^3+3 reduction');
  const wrapPoint = bn254.G1.Point.fromAffine({ x: wrapX, y: wrapY });
  wrapPoint.assertValidity();
  for (const wrapProof of [
    { a: wrapPoint.negate(), b: proof.b, c: proof.c },
    { a: proof.a, b: proof.b, c: wrapPoint },
  ]) {
    const run = assemble(buildSpecs(
      { proof: wrapProof, inputs: INSTANCES.committed.inputs },
      millerGenesisLockingHash,
    ), true);
    if (!run.meta[millerGenesisIndex].accepted) throw new Error('valid G1 wraparound point rejected at Miller genesis');
  }
  console.error(`  extended endpoint VM cases: ${ENDPOINT_VM_CASES} off-subgroup points, 3 subgroup scalings, 2 G1 wraparound points`);
}

const invalidInputs = [
  ...invalidPointRuns.slice(0, 4).map(toStepArr),
  ...noncanonicalInputs,
];
console.error(`  invalid runs rejected: ${fullInvalid.map((r) => r.rejected).join(',')}`);
console.error(`  invalid point runs rejected: ${invalidPointRuns.length}; serialized=${invalidInputs.length}`);
if (!full0.accepted || !full1.accepted || !fullWc.accepted || !fullResource.accepted ||
    !full0.fits || !full1.fits || !fullWc.fits || !fullResource.fits ||
    !full0Transaction.consensusVerified || !full1Transaction.consensusVerified ||
    !fullWcTransaction.consensusVerified || !fullResourceTransaction.consensusVerified ||
    infinityRuns.some(({ run, transaction }) =>
      !run.accepted || !run.fits || !transaction.consensusVerified) ||
    !fullInvalid.every((run) => run.rejected) || invalidInputs.length === 0) {
  throw new Error('valid, density, resource, or invalid fixture failed; refusing to write vectors');
}
if (MILLER_TORUS && (!full0Transaction.standardVerified || !full1Transaction.standardVerified ||
    !fullWcTransaction.standardVerified || !fullResourceTransaction.standardVerified ||
    !full0Transaction.defaultMinRelayFeeVerified || !full1Transaction.defaultMinRelayFeeVerified ||
    !fullWcTransaction.defaultMinRelayFeeVerified || !fullResourceTransaction.defaultMinRelayFeeVerified ||
    infinityRuns.some(({ transaction }) =>
      !transaction.standardVerified || !transaction.defaultMinRelayFeeVerified))) {
  throw new Error('a quotient-torus valid-proof transaction is not standard-policy valid at the default minimum relay fee; refusing to write vectors');
}

const millerInputCount = full0.inputs.length - G2_COUNT - GLV_COUNT;
const torusDescription = `The committed benchmark transaction is a standard-policy-valid, ${full0.inputs.length}-input BN254 Groth16 verifier. ${GLV_COUNT} grouped 3x43 GLV vk_x inputs feed ${millerInputCount} c^-(6x+2)-fused Miller inputs with e(alpha,beta) precomputed.${PROJECTIVE_VKX ? NORMALIZED_PROOF_POINTS ? ' The proof G1 points are committed directly as canonical (u,v)=(-x/y,-1/y), with (0,0) the identity; a B-at-infinity proof maps its neutral first pairing to P0=(0,0) and fixed Q0=G2.BASE. GLV hands its IC1/IC2 MSM to Miller as (X,Y,Z), e(IC0,gamma) joins the fixed Miller factor, and genesis uniquely binds Pu2/Pv2 by the branch-free equations Pu2*Y+X*Z=0 and Pv2*Y+Z^3=0. The reachable GLV accumulator always has Y nonzero, including its (0,1,0) identity.' : ' GLV hands its IC1/IC2 MSM to Miller as (X,Y,Z), e(IC0,gamma) joins the existing fixed Miller factor, and genesis derives the normalized unit-line coordinates directly; Z=0 maps to the pairing identity.' : ''} The Miller accumulator is evaluated in the quotient Fp12*/Fp6*: genesis carries the six canonical limbs of a finite [c]=[1+u*W] residue root, derives [c^-1]=[1-u*W], and pins that immutable root through every later input, where W is the quadratic-tower basis. The old residue-coset correction w lies in Fp6 and therefore disappears in this quotient. The terminal input checks the exact quotient relation [f*c^(p^2)]=[c^p*c^(p^3)] and explicitly rejects the projective zero representative. Runtime B is affine with canonical slope witnesses, normalized unit lines, and an exact endomorphism subgroup endpoint check. prove_vkx_glv_split.mjs proves grouped MSM equivalence and table correctness; prove_vkx_glv_resource_bound.mjs certifies the equal-point event ceiling. prove_projective_vkx.mjs proves the projective/unit-coordinate hand-off, the universal nonzero-Y invariant, and the canonical MSM identity. prove_miller_torus.mjs proves the quotient-kernel equivalence, finite-chart completeness, every projective transition, specialized Frobenius maps, and the terminal relation; the builder additionally exercises all nine finite/identity fixtures plus u+p alias, projective-zero, wrong-nonzero-quotient-class, static-context, seam, slope, cross-product, point, and proof-binding mutations.`;
const description = MILLER_TORUS
  ? torusDescription
  : FUSE_G2_ENDPOINT
  ? MILLER_AFFINE_G2
    ? MILLER_UNIT_LINES
      ? `INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction (${full0.inputs.length} inputs). ${GLV_COUNT} grouped 3x43 GLV vk_x inputs feed a c^-(6x+2)-fused batched Miller chain with e(alpha,beta) precomputed and a terminal witnessed-residue verdict. The Miller genesis requires canonical A/B/C coordinates, checks all three proof points on their curves, and binds canonical inverse-Y witnesses for the three runtime G1 points. Each G1 point is carried as (-x/y,-1/y), and every fixed line is normalized offline to c2=1, making the sparse multiplier's o0 coefficient one. Runtime B uses a four-limb affine accumulator; every tangent/chord carries a two-limb canonical slope witness, rejects a zero denominator, and checks the slope equation. These normalizations change the Miller value only by an Fp2 scale, which vanishes in final exponentiation. Exact G2 subgroup membership is fused into B's post-processing by requiring R+psi(B)-psi^2(B)=-psi^3(B). prove_miller_unit_lines.mjs proves the line-scale equivalence and all fixed-line denominators; unit_line_bound_analysis.mjs proves the specialized integer bounds; the affine and endpoint proof scripts retain their original completeness guarantees. Miller genesis at absolute input ${MILLER_GENESIS_INPUT} carries the immutable normalized proof points, vk_x, c, and cInv once; every later Miller input pins that locking, reads the static values by explicit genesis offsets, and forward-binds only its exact 512-byte f/R state.`
      : `INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction (${full0.inputs.length} inputs). ${GLV_COUNT} grouped 3x43 GLV vk_x inputs feed a c^-(6x+2)-fused batched Miller chain with e(alpha,beta) precomputed and a terminal witnessed-residue verdict. The Miller genesis requires canonical A/B/C coordinates and checks all three proof points on their curves. Runtime B uses a four-limb affine accumulator; every tangent/chord carries a two-limb canonical slope witness, rejects a zero denominator, and checks the slope equation before emitting a normalized line. The normalized line differs only by an Fp2 scale, which vanishes in final exponentiation. Exact G2 subgroup membership is fused into B's post-processing by requiring R+psi(B)-psi^2(B)=-psi^3(B). prove_miller_affine.mjs proves valid-subgroup completeness and line-scale equivalence; prove_miller_endpoint_subgroup.mjs proves the endpoint relation has exactly the r-torsion kernel on the full rational twist group. Miller genesis at absolute input ${MILLER_GENESIS_INPUT} carries the immutable proof points, vk_x, c, and cInv once; every later Miller input pins that locking, reads the static values by explicit genesis offsets, and forward-binds only its exact 512-byte f/R state.`
    : `INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction (${full0.inputs.length} inputs). ${GLV_COUNT} grouped 3x43 GLV vk_x inputs feed a c^-(6x+2)-fused batched Miller chain with e(alpha,beta) precomputed and a terminal witnessed-residue verdict. The Miller genesis requires canonical A/B/C coordinates, checks A and C on G1, and reuses runtime B's first doubling coefficients for its twist-curve equation. Exact G2 subgroup membership is fused into B's existing Miller post-processing: for R=[6x+2]B, the second-add line through R+psi(B) and -psi^2(B) must also contain psi^3(B), equivalent to R+psi(B)-psi^2(B)+psi^3(B)=O. prove_miller_endpoint_subgroup.mjs proves this condition has exactly the r-torsion kernel on the full rational twist group. The GLV result is cross-bound into Miller genesis and every later state is forward-bound with OP_INPUTBYTECODE.`
  : 'INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction. Same OP_INPUTBYTECODE forward-checking as bch-groth16-intratx (each chunk is an input whose witness carries its incoming state as a raw byte blob and require()s the next input\'s blob == its recomputed output — no NFT commitment, no hashing, arbitrary intermediate size), but it runs the residue-optimized chunk graph: 3 canonical-coordinate/on-curve/subgroup fast-G2 endomorphism chunks (ePrint 2022/348), 3 GLV vk_x chunks, and c^-(6x+2)-FUSED batched Miller chunks with e(alpha,beta) precomputed/skipped (ePrint 2024/640). The three GLV inputs share one hash-bound fixed lookup table carried by the final GLV input rather than embedding three copies. The final Miller chunk also performs the witnessed-residue verdict. The residue witness (c, cInv) threads through every Miller chunk; the terminal chunk checks c canonical, c*cInv==ONE, the exact w serialization in {1,w27,w27^2}, and fF*(w*c^q2)==(c*c^q2)^q. The G2 final chunk binds the proof-derived -A/B and C bytes into the fused-Miller genesis input, while the vk_x final chunk binds the GLV result into that same genesis; every later Miller state is forward-bound.';

writeFileSync(verifierPath('src/bch/groth16-intratx-residue-vectors.json'), JSON.stringify({
  description,
  method: 'intra-tx-linked-residue', deployment: 'P2SH32', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  serializedTransactionBytes: full0Transaction.wireBytes,
  consensusTransactionVerified: full0Transaction.consensusVerified,
  standardTransactionVerified: full0Transaction.standardVerified,
  defaultMinRelayFeeVerified: full0Transaction.defaultMinRelayFeeVerified,
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  extraValidProofTransactions: [
    {
      serializedTransactionBytes: full1Transaction.wireBytes,
      consensusTransactionVerified: full1Transaction.consensusVerified,
      standardTransactionVerified: full1Transaction.standardVerified,
      defaultMinRelayFeeVerified: full1Transaction.defaultMinRelayFeeVerified,
      totalOperationCost: full1Transaction.totalOperationCost,
      maxStepOperationCost: full1Transaction.maxStepOperationCost,
    },
    ...infinityRuns.map(({ name, transaction }) => ({
      name,
      serializedTransactionBytes: transaction.wireBytes,
      consensusTransactionVerified: transaction.consensusVerified,
      standardTransactionVerified: transaction.standardVerified,
      defaultMinRelayFeeVerified: transaction.defaultMinRelayFeeVerified,
      totalOperationCost: transaction.totalOperationCost,
      maxStepOperationCost: transaction.maxStepOperationCost,
    })),
  ],
  worstCaseTransaction: {
    serializedTransactionBytes: fullWcTransaction.wireBytes,
    consensusTransactionVerified: fullWcTransaction.consensusVerified,
    standardTransactionVerified: fullWcTransaction.standardVerified,
    defaultMinRelayFeeVerified: fullWcTransaction.defaultMinRelayFeeVerified,
    totalOperationCost: fullWcTransaction.totalOperationCost,
    maxStepOperationCost: fullWcTransaction.maxStepOperationCost,
  },
  resourceFixtureTransaction: {
    serializedTransactionBytes: fullResourceTransaction.wireBytes,
    consensusTransactionVerified: fullResourceTransaction.consensusVerified,
    standardTransactionVerified: fullResourceTransaction.standardVerified,
    defaultMinRelayFeeVerified: fullResourceTransaction.defaultMinRelayFeeVerified,
    totalOperationCost: fullResourceTransaction.totalOperationCost,
    maxStepOperationCost: fullResourceTransaction.maxStepOperationCost,
  },
  steps: toStepArr(full0),
  extraValidProofs: [
    toStepArr(full1),
    ...infinityRuns.map(({ run }) => toStepArr(run)),
  ],
  resourceFixtureProof: toStepArr(fullResource),
  worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
  invalidInputs,
}, null, 2));
console.error('wrote groth16-intratx-residue-vectors.json');
