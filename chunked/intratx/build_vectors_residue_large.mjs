// Assemble the INTRA-TX LINKED + QUOTIENT-TORUS verifier for BN254 with LARGE (100 kB) input
// scripts, targeting the PROPOSED bch-spec upgrade.
//
// This is build_vectors_residue.mjs's MILLER_TORUS cousin. The root fixes the exact input count,
// the terminal fixes its position, and the root pins the terminal locking program while binding
// the projective vk_x handoff through OP_INPUTBYTECODE. The quotient-torus graph evaluates a
// 128-position four-scalar GLV MSM and the
// c^-(6x+2)-fused Miller loop in Fp12*/Fp6*, with e(alpha,beta) and e(IC0,gamma) precomputed.
// Miller genesis validates canonical normalized proof coordinates, every supported identity
// encoding, the curve equations, and the exact runtime-B subgroup endpoint. The terminal checks
// [f*c^(p^2)]=[c^p*c^(p^3)] and rejects the [0:0] projective representative. The deployment
// difference is the proposed VM's per-input budget:
//
//   the bch-spec op-cost budget an input gets is (10000 + unlockingLen) * 800 and scripts may be
//   100,000 B. The current-BCH torus build sizes each chunk to a 10 kB unlocking (=> 8,032,800
//   op/input, 11 inputs). Here one 128-position GLV window and ONE unrolled Miller chunk
//   covering all 348 fused ops (verdict folded in) each fit their own fat input:
//     GLV vk_x MSM                       1 input   (one [0,128) window, baked table)
//     c^-(6x+2)-fused Miller + verdict   1 input   (terminal; ~63M op, op-bound)
//                                        --------
//                                        2 inputs  (ONE <100 kB transaction)
//
// Removing nine chunk boundaries also removes their forward-checks, state re-parses and per-chunk
// static-context reads, so total op-cost drops below the 11-input current-BCH build. The two-input
// layout keeps the GLV and Miller generators independent, and the vk_x hand-off remains byte-bound
// through OP_INPUTBYTECODE exactly like the current-BCH graph.
//
// NOTE: this leaves chunked/pairing/generated/ holding LARGE-budget chunks. Regenerate the
// current-BCH chunks before rebuilding a flagship build (generate_torus.mjs does it all):
//   VERIFIER_DIR=... node chunked/intratx/generate_torus.mjs
//
//   node build_vectors_residue_large.mjs  -> verifier/src/bch/groth16-intratx-residue-large-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, pairsFor, singlePairMiller, vk, proofFromLimbs, proof, vec, f12limbs,
  compileFileBytecode, compileFileBytecodeSize, compileFileBytecodeRaw, ptLimbs,
  le40, OP_DROP, verifierPath, invalidG2Overrides,
} from '../pairing/_millermath.mjs';
import { millerFusedAffineOps, residueTorusWitness } from '../pairing/_residuemath.mjs';
import {
  GLV_LAMBDA, GLV_R, glvDecompose, vkxGlvStateAt,
} from '../pairing/gen_vkx_glv.mjs';
import { transformChunk } from './transform.mjs';
import { regenGlvSafe } from '../regen_vkx_windows.mjs';
import { infinityInstances } from './infinity_fixtures.mjs';

// ---- LARGE per-input budget on the PROPOSED bch-spec VM (100 kB scripts) ----
// On bch-spec the op-cost budget an input gets is (densityControlBase 10,000 + unlockingLen)*800,
// so a 100 kB unlocking input gets (10000+100000)*800 = 88,000,000 op. maximumBytecodeLength is
// 100,000 B for BOTH locking and unlocking. (Current-BCH BCH_2026 caps scripts at 10 kB, so this
// build is only valid under the bch-spec upgrade.)
const DENSITY_BASE = 10_000;
const LARGE_UNLOCK = 100_000;
const LARGE_BUDGET = (DENSITY_BASE + LARGE_UNLOCK) * 800; // 88,000,000 (max, at a full 100 kB unlocking)
const opBudgetFor = (unlockingLen) => (DENSITY_BASE + unlockingLen) * 800; // exact per-input budget

const here = dirname(fileURLToPath(import.meta.url));
const PAIR = join(here, '..', 'pairing');
const GEN = join(PAIR, 'generated');
const { Fp, Fp12 } = bn254.fields;
const PROJECTIVE_VKX = true;
const NORMALIZED_PROOF_POINTS = true;
const RAW_B_INFINITY = true;

// ---- regenerate the two variable-length stages at the 100 kB budget ----
// The fused-Miller op count is proof-independent (fixed ATE loop), so the whole loop is ONE
// explicit terminal cut. gen_miller_residue.mjs re-measures the chunk on the real bch-spec VM
// (BCH_VM=spec) and the assembly below re-verifies every fixture on it.
const TORUS_OPS = millerFusedAffineOps(
  pairsFor(vec.publicInputs.map(BigInt)), Fp12.ONE, Fp12.ONE, { unitLines: true },
).ops.length;
const GEN_ENV = {
  ...process.env,
  FUSE_G2_ENDPOINT: '1', MILLER_AFFINE_G2: '1', MILLER_UNIT_LINES: '1', MILLER_TORUS: '1',
  MILLER_PROJECTIVE_VKX: '1', MILLER_NORMALIZED_PROOF_POINTS: '1', MILLER_RAW_B_INFINITY: '1',
  STAGE_BOUND_LAYOUT: '1', COVENANT_RESIDUE_LAYOUT: '1', MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: String(TORUS_OPS), // ONE chunk [0,TORUS_OPS) with the verdict fused in
  BCH_VM: 'spec', TARGET_UNLOCK: String(LARGE_UNLOCK),
  OP_COST_TARGET: '86000000', BYTE_BUDGET: '95000',
};
console.error(`\n== regenerating gen_miller_residue.mjs (quotient torus) as ONE chunk [0,${TORUS_OPS}) at the 100 kB budget ==`);
execFileSync(process.execPath, [join(PAIR, 'gen_miller_residue.mjs')], { env: GEN_ENV, stdio: 'inherit' });
console.error('\n== regenerating GLV vk_x as ONE stage-bound window [0,128) ==');
const GLV_COUNT = 1;
regenGlvSafe(GEN, [0, 128], true, null, false, PROJECTIVE_VKX);

const PROBE = join(GEN, '_intratx_residue_large_probe.cash'); // transformed import-chunks compiled from here
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
  encodeLockingBytecodeP2sh32, encodeDataPush, encodeTransactionBch, createVirtualMachineBchSpec,
} from '@bitauth/libauth';
const realVm = createVirtualMachineBchSpec(false); // PROPOSED bch-spec VM (100 kB scripts, 88M-op inputs)
const standardVm = createVirtualMachineBchSpec(true);
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;

// Deploy each chunk as P2SH (same lever as the flagship build): the redeem rides in the scriptSig
// where it counts toward the op-cost budget ((10000 + unlockingLen) * 800); the inBlob stays the
// FIRST scriptSig push (front offset preserved for sibling forward-checks).
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
  // header size: 1 (<=75), 2 (PUSHDATA1 <=255), 3 (PUSHDATA2 <=65535), 5 (PUSHDATA4). Pick N so
  // encodeDataPush emits exactly `budget` bytes (header + N) — at 100 kB the header is 5, not 3.
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget <= 65538 ? budget - 3 : budget - 5;
  return encodeDataPush(new Uint8Array(N));
};
// minimal total unlocking length whose spec budget (10000+len)*800 covers opCost.
const tunedLen = (argLen, opCost) => Math.min(LARGE_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - DENSITY_BASE));

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
  const program = { inputIndex: index, ...verificationData(inputs) };
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
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: { proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] },
};

function millerPairsFor(inst) {
  const raw = pairsFor(inst.inputs, inst.proof, { msmOnly: PROJECTIVE_VKX });
  const bInfinity = raw[0].Q.equals(bn254.G2.Point.ZERO);
  const rawB = raw[0].Q.toAffine();
  if (!bInfinity) return { stage: raw, effective: raw, rawB };
  const mapped = raw.map((pair, index) => index === 0
    ? { ...pair, Q: bn254.G2.Point.BASE }
    : pair);
  const effective = mapped.map((pair, index) => index === 0
    ? { ...pair, P: bn254.G1.Point.ZERO }
    : pair);
  return { stage: mapped, effective, rawB };
}

// GLV returns IC1/IC2's MSM projectively. Miller binds all three limbs, folds
// e(IC0,gamma) into the fixed factor, and authenticates raw/effective B identity data.
const dummy = pairsFor([1n, 1n], undefined, { msmOnly: PROJECTIVE_VKX });
const fixedMiller = Fp12.mul(
  singlePairMiller(dummy[1]).f,
  singlePairMiller({ P: vk.ic[0], Q: vk.gamma }).f,
);
const VKX_LIMB_OFFSET = 8;
const PTL_LEN = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;
const MILLER_ROOT_NAMES = Array.from({ length: 6 }, (_, i) => `u${i}`);
const MILLER_UNIT_NAMES = ['Pu2', 'Pv2'];
const MILLER_IN_LIMBS = PTL_LEN + 1 + 6 + MILLER_ROOT_NAMES.length + MILLER_UNIT_NAMES.length;
const MILLER_GENESIS_INPUT = GLV_COUNT;
const MILLER_GENESIS_NAMES = [
  'Pu0', 'Pv0', 'Q0xa', 'Q0xb', 'Q0ya', 'Q0yb', 'Pu3', 'Pv3',
  'VkxX', 'VkxY', 'VkxZ',
  'effectivePu0', 'effectivePv0', 'rawBxa', 'rawBxb', 'rawBya', 'rawByb',
  ...MILLER_ROOT_NAMES, 'Pu2', 'Pv2',
];
const MILLER_GENESIS_OFFSETS = new Map(MILLER_GENESIS_NAMES.map((name, i) => [name, i * W]));

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) — the quotient-torus Miller layout of
// build_vectors_residue.mjs plus the byte-smaller 128-position GLV schedule for 100 kB inputs. ----
// GLV vk_x: 4-scalar Straus over {IC1, phiIC1, IC2, phiIC2}; ONE stage-bound loop window whose
// genesis binds the GLV witnesses to the public inputs (k1+k2*lambda==in mod r, 0<=k<2^128) and
// whose final epilogue asserts the affine vk_x and cross-binds it into the Miller genesis.
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20, k11, k21] = inst.glvScalars ?? [...glvDecompose(in0), ...glvDecompose(in1)];
  const st = (X, Y, Z) => [X, Y, Z, in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx residue-large requires stage-bound GLV generation');
  if (man.sharedTable !== false) throw new Error('intratx residue-large requires a baked GLV table');
  if (man.grouped === true) throw new Error('intratx residue-large requires the 128-position GLV schedule');
  if (man.projectiveOutput !== true) throw new Error('intratx residue-large requires projective GLV output');
  return man.chunks.map((ch) => {
    const [X0, Y0, Z0] = vkxGlvStateAt(k10, k20, k11, k21, ch.lo);
    const fullIn = st(X0, Y0, Z0);
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) {
      const outLimbs = vkxGlvStateAt(k10, k20, k11, k21, ch.hi);
      return {
        file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
        outLimbs, outWidths: outLimbs.map(() => W),
        extras: [],
        enforceExactInputLength: true,
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: outLimbs.length * W } : null,
        label: 'GLV MSM -> bind projective state', checkpoint: 'vk_x',
      };
    }
    const [X1, Y1, Z1] = vkxGlvStateAt(k10, k20, k11, k21, ch.hi);
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
      outLimbs: st(X1, Y1, Z1), outWidths: GLV_STATE_WIDTHS,
      enforceExactInputLength: true,
      extras: [], role: 'within',
      label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
// c^-(6x+2)-FUSED Miller, quotient-torus mode: ONE terminal chunk covering the whole loop. The
// genesis prologue validates canonical A/B/C coordinates, on-curve membership, canonical
// inverse-Y witnesses (unit lines) and range-gates the six-limb torus root u; the endpoint psi
// relation proves exact G2 subgroup membership; the fused tail checks the cross-multiplied
// quotient relation [f*c^(p^2)]=[c^p*c^(p^3)] and rejects the projective zero representative.
function specsMillerFused(inst, root) {
  const { stage: stagePairs, effective: pairs, rawB } = millerPairsFor(inst);
  const trace = millerFusedAffineOps(pairs, root.c, root.cInv, {
    unitLines: true,
    torusU: root.u,
    fixedMiller,
  });
  const { ops, states } = trace;
  const stageUnitPtL = stagePairs.flatMap((p, j) =>
    ptLimbs(j, p.P.toAffine(), p.Q.toAffine(), true));
  const effectiveUnitPtL = pairs.flatMap((p, j) =>
    ptLimbs(j, p.P.toAffine(), p.Q.toAffine(), true));
  const [k10, k20, k11, k21] = inst.glvScalars ?? [
    ...glvDecompose(BigInt(inst.inputs[0])),
    ...glvDecompose(BigInt(inst.inputs[1])),
  ];
  const msmState = vkxGlvStateAt(k10, k20, k11, k21, 128);
  const msmYInv = Fp.inv(msmState[1]);
  const msmZ2 = Fp.sqr(msmState[2]);
  const msmUnit = [
    Fp.neg(Fp.mul(Fp.mul(msmState[0], msmState[2]), msmYInv)),
    Fp.neg(Fp.mul(Fp.mul(msmZ2, msmState[2]), msmYInv)),
  ];
  const ptL = [
    ...effectiveUnitPtL.slice(0, 6),
    ...msmUnit,
    ...stageUnitPtL.slice(8, 10),
  ];
  const rootLimbs = [root.u.c0.c0, root.u.c0.c1, root.u.c1.c0, root.u.c1.c1, root.u.c2.c0, root.u.c2.c1];
  const full = (s) => [...f12limbs(s.f), s.Rs[0].x.c0, s.Rs[0].x.c1, s.Rs[0].y.c0, s.Rs[0].y.c1, ...ptL, ...rootLimbs];
  const genesis = [
    ...stageUnitPtL.slice(0, 6),
    ...stageUnitPtL.slice(8, 10),
    ...msmState,
    ...effectiveUnitPtL.slice(0, 2),
    rawB.x.c0, rawB.x.c1, rawB.y.c0, rawB.y.c1,
    ...rootLimbs,
    ...msmUnit,
  ];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  for (const [flag, name] of [
    [man.linkedLayout, 'MILLER_LINKED_LAYOUT'], [man.stageBound, 'STAGE_BOUND_LAYOUT'],
    [man.covenantResidue, 'COVENANT_RESIDUE_LAYOUT'], [man.endpointSubgroup, 'FUSE_G2_ENDPOINT'],
    [man.affineG2, 'MILLER_AFFINE_G2'], [man.unitLines, 'MILLER_UNIT_LINES'], [man.quotientTorus, 'MILLER_TORUS'],
  ]) {
    if (flag !== true) throw new Error(`intratx residue-large requires ${name}=1 during Miller generation`);
  }
  if (man.projectiveVkx !== true) throw new Error('intratx residue-large requires projective vk_x');
  if (man.normalizedProofPoints !== true) throw new Error('intratx residue-large requires normalized proof points');
  if (man.rawBInfinity !== true) throw new Error('intratx residue-large requires raw B identity handling');
  if (man.bInfinityFlag === true) throw new Error('intratx residue-large must derive B identity from raw coordinates');
  if (man.implicitInfinityB !== true) throw new Error('intratx residue-large requires implicit B identity semantics');
  if (man.numOps !== ops.length) throw new Error('Miller manifest op count does not match the trace');
  return man.chunks.map((ch) => {
    const slopes = ops.slice(ch.opLo, ch.opHi).flatMap((op) =>
      (op.affineSlopes ?? []).flatMap((slope) => [slope.c0, slope.c1]));
    return {
      file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs: ch.opLo === 0 ? genesis : full(states[ch.opLo]),
      outLimbs: ch.final ? [] : full(states[ch.opHi]),
      extras: slopes,
      unitInvYCount: 0,
      affineSlopeCount: slopes.length,
      role: ch.final ? 'terminal' : 'within',
      enforceExactInputLength: true,
      cmp: null,
      label: `fused-miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' + torus residue verdict' : ''}`,
      checkpoint: ch.final ? 'verify' : undefined,
    };
  });
}
function buildSpecs(inst) {
  const vkx = specsVkx(inst, true);
  const { effective: pairs } = millerPairsFor(inst);
  const fRaw = millerFusedAffineOps(
    pairs,
    Fp12.ONE,
    Fp12.ONE,
    { unitLines: true, fixedMiller },
  ).boundary;
  const root = residueTorusWitness(fRaw);
  const miller = specsMillerFused(inst, root); // torus verdict fused into miller's final chunk
  return [...vkx, ...miller];
}

// The single-chunk layout cannot inject a forged f into the terminal verdict (f is computed
// in-contract from the genesis witness), so assert the emitted source still carries the
// projective-zero guard and the cross-multiplied quotient relation as compensating evidence.
{
  const finalSrc = readFileSync(join(GEN, 'millerres_00.cash'), 'utf8');
  // The terminal uses short signed inline Frobenius^2 coefficients, so pin the emitted operations
  // and all six quotient guards rather than depending on the generic helper's source spelling.
  const zeroGuard = `require(${Array.from({ length: 12 }, (_, i) => `tailLhs${i} != 0`).join(' || ')});`;
  if (!finalSrc.includes(zeroGuard)) {
    throw new Error('terminal Miller chunk is missing the [0:0] projective-zero rejection');
  }
  const quotientGuards = Array.from(
    { length: 6 },
    (_, i) => `require((tailCrossL${i} - tailCrossR${i}) % tailP == 0);`,
  );
  if (
    !finalSrc.includes('= torusFrob1(') ||
    !finalSrc.includes('int tailU2_0 =') ||
    !finalSrc.includes('int tailU3_0 =') ||
    !finalSrc.includes('= fp6MulRaw(tailU1_0') ||
    !finalSrc.includes('= fp6MulRaw(tailLhs0') ||
    !finalSrc.includes('= fp6MulRaw(tailLhs6') ||
    quotientGuards.some((guard) => !finalSrc.includes(guard))
  ) {
    throw new Error('terminal Miller chunk is missing the cross-multiplied quotient relation');
  }
}

// ---- assemble: transform+compile each chunk, build the single tx, tune pad, verify ----
// Forward-check config is derived from each chunk's role exactly like build_vectors_residue.mjs:
//   within  -> forward the FULL output (cmpExpr null, equal in/out len)
//   cross   -> forward only the bound slice (spec.cmp)
//   stage-final / terminal -> no forward (null)
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map(); // key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // key -> 'resched' | 'raw'; fixed on the FIRST assembly so every
                                // instance shares identical lockings.
const specConfig = (specs, i, nextLockingHash) => {
  const s = specs[i];
  let forward = null;
  if (s.role === 'within') { const outLen = byteLengthOf(s, 'out'); forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  if (forward !== null && nextLockingHash !== undefined) {
    forward = { ...forward, nextLockingHash };
  }
  const expectedInputIndex = i === 0 ? undefined : i;
  const expectedInputCount = i === 0 ? specs.length : undefined;
  const key = `${s.file}|${s.role}|exact=${s.enforceExactInputLength === true}|` +
    `${JSON.stringify(forward)}|layout=${expectedInputIndex}/${expectedInputCount}`;
  return {
    key,
    forward,
    enforceExactInputLength: s.enforceExactInputLength,
    expectedInputIndex,
    expectedInputCount,
  };
};
function compileSpec(specs, i, config = specConfig(specs, i)) {
  const s = specs[i];
  const {
    key, forward, enforceExactInputLength, expectedInputIndex, expectedInputCount,
  } = config;
  let v = compileCache.get(key);
  if (!v) {
    // compile from a file (probe in generated/) so the chunk's relative library import resolves
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), {
      W, widthsByName: GLV_WIDTHS_BY_NAME, prime: PRIME, forward, enforceExactInputLength,
      expectedInputIndex, expectedInputCount,
    }).src);
    const resched = s.file.includes('millerres_')
      ? compileFileBytecodeSize(PROBE)
      : compileFileBytecode(PROBE);
    const raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched;
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
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
  const configs = specs.map((_, i) => specConfig(specs, i));
  const redeems = new Array(specs.length);
  const lockings = new Array(specs.length);
  for (let i = specs.length - 1; i >= 0; i--) {
    if (configs[i].forward !== null) {
      if (lockings[i + 1] === undefined) throw new Error(`input ${i} has no successor locking program`);
      configs[i] = specConfig(specs, i, binToHex(sha256.hash(lockings[i + 1])));
    }
    redeems[i] = compileSpec(specs, i, configs[i]);
    lockings[i] = P2SH ? p2shSpk(redeems[i]) : redeems[i];
  }
  const argB = specs.map(argBytesOf);     // [inBlob, extras...]
  const rpush = redeems.map((r) => encodeDataPush(r));
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + tailLen(i);
    const pad = padPush(0, Math.max(2, target - fixed));
    return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]);
  };
  // Start from the full unlocking budget so both consensus and standard-policy VMs can
  // run without a density error and report their complete op-cost before padding shrinks.
  let inputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, LARGE_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
  }

  // Per-chunk variant selection (RESCHEDULE only; decided once, first assembly): keep the
  // redeem with the smaller TUNED unlocking.
  if (RESCHED) {
    let switched = 0;
    for (let i = 0; i < specs.length; i++) {
      const { key } = configs[i];
      if (chosenCache.has(key)) continue;
      const v = compileCache.get(key);
      if (!v.raw) { chosenCache.set(key, 'resched'); continue; }
      const rawRpush = encodeDataPush(v.raw);
      const rawFixed = argB[i].length + (P2SH ? rawRpush.length : 0);
      const rawUnlock = P2SH
        ? Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, LARGE_UNLOCK - rawFixed)), ...rawRpush])
        : Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, LARGE_UNLOCK - rawFixed))]);
      const probe = inputs.slice();
      probe[i] = { locking: P2SH ? p2shSpk(v.raw) : v.raw, unlocking: rawUnlock };
      const rawOp = evalInput(probe, i);
      const rawStandardOp = evalInput(probe, i, standardVm);
      const tR = op1[i].accepted && standardOp1[i].accepted
        ? tunedLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost))
        : Infinity;
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
    inputs = specs.map((_, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, targets[i]) }));
    op2 = specs.map((_, i) => evalInput(inputs, i));
    standardOp2 = specs.map((_, i) => evalInput(inputs, i, standardVm));
    if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
      let relaxed = false;
      targets = targets.map((target, i) => {
        const failures = [op2[i], standardOp2[i]].filter((outcome) => !outcome.accepted);
        if (failures.length === 0 || failures.some((outcome) => !outcome.error?.includes('operation cost density limit')) || target >= LARGE_UNLOCK) {
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
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  // spec caps: locking/unlocking each <= 100 kB; op-cost <= the input's own (10000+unlockingLen)*800.
  const fits = meta.every((m) => m.lockingBytes <= LARGE_UNLOCK && m.unlockingBytes <= LARGE_UNLOCK && m.operationCost <= opBudgetFor(m.unlockingBytes)) && accepted;
  return { inputs, meta, redeems, fits, accepted };
}

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({
  label: asm.meta[i]?.label ?? `transaction-graph input ${i}`,
  locking: binToHex(inp.locking),
  unlocking: binToHex(inp.unlocking),
  checkpoint: asm.meta[i]?.checkpoint,
}));
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
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk uses); the chunk's
// own validation (and/or a sibling's cross-check) then fails -> the run is rejected.
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
  asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
  return { wireBytes, consensusVerified, standardVerified, defaultMinRelayFeeVerified, totalOperationCost, maxStepOperationCost: maxOp };
};

// ===================== FULL GROTH16 (quotient torus, single tx, 100 kB inputs) =====================
const committedSpecs = buildSpecs(INSTANCES.committed);
const proof1Specs = buildSpecs(INSTANCES.proof1);
const worstSpecs = buildSpecs(INSTANCES.worst);
const full0 = assemble(committedSpecs);
const full0Transaction = report('groth16-intratx-residue-large committed', full0);
const millerGenesisIndex = MILLER_GENESIS_INPUT;

// The benchmark's dense proof is not the GLV density worst case: its four decomposition
// witnesses have unrelated bit gaps. Exercise the absolute case explicitly (all 128 bits set
// in all four bounded witnesses) so the loop window cannot silently exceed the input budget.
const denseScalar = (1n << 128n) - 1n;
const denseInput = (denseScalar + denseScalar * GLV_LAMBDA) % GLV_R;
const densitySpecs = committedSpecs.slice();
densitySpecs.splice(0, GLV_COUNT, ...specsVkx({
  inputs: [denseInput, denseInput],
  glvScalars: [denseScalar, denseScalar, denseScalar, denseScalar],
}, true));
const denseVkx = vkxGlvStateAt(
  denseScalar,
  denseScalar,
  denseScalar,
  denseScalar,
  128,
);
const millerGenesis = densitySpecs[millerGenesisIndex];
const millerIn = millerGenesis.inLimbs.slice();
millerIn.splice(VKX_LIMB_OFFSET, 3, ...denseVkx);
densitySpecs[millerGenesisIndex] = { ...millerGenesis, inLimbs: millerIn };
const densityGlv = assemble(densitySpecs, true).meta.slice(0, GLV_COUNT);
if (densityGlv.some((meta) => !meta.accepted || meta.operationCost > opBudgetFor(meta.unlockingBytes) || meta.unlockingBytes > LARGE_UNLOCK)) {
  throw new Error('max-density GLV window exceeds the bch-spec input budget');
}
console.error(`  max-density GLV max op: ${Math.max(...densityGlv.map((meta) => meta.operationCost)).toLocaleString()}`);

const full1 = assemble(proof1Specs);
const fullWc = assemble(worstSpecs);
const full1Transaction = report('groth16-intratx-residue-large proof#1', full1);
const fullWcTransaction = report('groth16-intratx-residue-large worst-case', fullWc);
const infinityRuns = Object.entries(infinityInstances).map(([name, instance]) => {
  const specs = buildSpecs(instance);
  const run = assemble(specs);
  const transaction = report(`groth16-intratx-residue-large ${name}`, run);
  return { name, instance, specs, run, transaction };
});
{
  const identityRun = infinityRuns.find(({ name }) => name === 'vkx-msm-infinity');
  if (identityRun === undefined) throw new Error('missing normalized vk_x identity fixture');
  const genesisLimbs = identityRun.specs[MILLER_GENESIS_INPUT].inLimbs;
  for (const [name, value] of new Map([
    ['VkxX', 0n], ['VkxY', 1n], ['VkxZ', 0n], ['Pu2', 0n], ['Pv2', 0n],
  ])) {
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
  if (unrelatedFailure) throw new Error(`${name} altered input also rejected at ${unrelatedFailure.label}`);
  return { steps: toStepArr(hybrid), rejected: true };
});
const infinityMalformedRuns = [
  ['a-infinity', 'Pu0'],
  ['b-infinity', 'Q0xa'],
  ['c-infinity', 'Pu3'],
].map(([name, limbName]) => {
  const fixture = infinityRuns.find((candidate) => candidate.name === name);
  if (fixture === undefined) throw new Error(`missing ${name} fixture`);
  const byteOffset = MILLER_GENESIS_OFFSETS.get(limbName);
  if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${limbName}`);
  const inputs = replaceInputBlobLimb(fixture.run.inputs, millerGenesisIndex, byteOffset, 1n);
  if (evalInput(inputs, millerGenesisIndex).accepted ||
      evalInput(inputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error(`${name} accepted a malformed identity encoding`);
  }
  return { steps: toStepArr({ inputs, meta: fixture.run.meta }), rejected: true };
});
const bInfinityRun = infinityRuns.find(({ name }) => name === 'b-infinity');
if (bInfinityRun === undefined) throw new Error('missing B-identity fixture');
const base = bn254.G2.Point.BASE.toAffine();
let finiteBaseInputs = bInfinityRun.run.inputs;
for (const [name, value] of [
  ['rawBxa', base.x.c0], ['rawBxb', base.x.c1],
  ['rawBya', base.y.c0], ['rawByb', base.y.c1],
]) {
  const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
  if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
  finiteBaseInputs = replaceInputBlobLimb(finiteBaseInputs, millerGenesisIndex, byteOffset, value);
}
if (evalInput(finiteBaseInputs, millerGenesisIndex).accepted ||
    evalInput(finiteBaseInputs, millerGenesisIndex, standardVm).accepted) {
  throw new Error('finite B=G2.BASE selected the B-identity Miller representation');
}
const finiteBaseIdentitySelection = {
  steps: toStepArr({ inputs: finiteBaseInputs, meta: bInfinityRun.run.meta }),
  rejected: true,
};

// ---- cross-proof seam: GLV(proof0 inputs) + Miller(proof1) must be rejected by the binding ----
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
const proofConsistency = { steps: toStepArr(boundHybrid), rejected: true };
const proofMutations = ['Q0xb', 'Pu3', 'Pu0', 'rawBxa'].map((name) => {
  const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
  if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
  const inputs = mutateInputBlob(full0.inputs, millerGenesisIndex, byteOffset);
  if (evalInput(inputs, millerGenesisIndex).accepted ||
      evalInput(inputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error(`Miller genesis accepted mutated proof byte at ${byteOffset}`);
  }
  return { steps: toStepArr({ inputs, meta: full0.meta }), rejected: true };
});
console.error(
  `  proof consistency: unbound hybrid accepted=${unboundHybrid.accepted}; ` +
  `bound hybrid GLV-final rejected=${!boundHybrid.meta[GLV_COUNT - 1].accepted}; ` +
  `-A/B mutation rejected=${proofMutations[0].rejected}; C mutation rejected=${proofMutations[1].rejected}`,
);
const fullInvalid = [
  invalidRun(full0, 0),
  invalidRun(full0, millerGenesisIndex),
  proofConsistency,
  ...proofMutations,
  ...infinityAlteredRuns,
  ...infinityMalformedRuns,
  finiteBaseIdentitySelection,
];

// Exact graph size/position plus the root's successor-program pin must reject any alternate
// transaction graph, even when the state bytes themselves are copied from an accepting run.
const extraInputGraph = [...full0.inputs, full0.inputs[full0.inputs.length - 1]];
const missingInputGraph = full0.inputs.slice(0, -1);
const reorderedInputGraph = full0.inputs.slice();
[reorderedInputGraph[0], reorderedInputGraph[1]] = [reorderedInputGraph[1], reorderedInputGraph[0]];
for (const [label, inputs] of [
  ['extra input', extraInputGraph],
  ['missing input', missingInputGraph],
  ['reordered inputs', reorderedInputGraph],
]) {
  if (evalInput(inputs, 0).accepted || evalInput(inputs, 0, standardVm).accepted) {
    throw new Error(`transaction graph accepted ${label}`);
  }
  fullInvalid.push({ steps: toStepArr({ inputs, meta: [] }), rejected: true });
}
const redirectedSuccessor = full0.inputs.map((input) => ({ ...input }));
const redirectedLocking = Uint8Array.from(redirectedSuccessor[1].locking);
redirectedLocking[redirectedLocking.length - 1] ^= 0x01;
redirectedSuccessor[1] = { ...redirectedSuccessor[1], locking: redirectedLocking };
if (evalInput(redirectedSuccessor, 0).accepted || evalInput(redirectedSuccessor, 0, standardVm).accepted) {
  throw new Error('root accepted a redirected successor program');
}
fullInvalid.push({ steps: toStepArr({ inputs: redirectedSuccessor, meta: [] }), rejected: true });

for (const name of ['Pu2', 'Pv2']) {
  const byteOffset = MILLER_GENESIS_OFFSETS.get(name);
  if (byteOffset === undefined) throw new Error(`missing Miller genesis offset for ${name}`);
  const inputs = mutateInputBlob(full0.inputs, millerGenesisIndex, byteOffset);
  if (evalInput(inputs, millerGenesisIndex).accepted ||
      evalInput(inputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error(`Miller genesis accepted mutated ${name} cross-multiplication handoff`);
  }
  if (!evalInput(inputs, GLV_COUNT - 1).accepted ||
      !evalInput(inputs, GLV_COUNT - 1, standardVm).accepted) {
    throw new Error(`mutated ${name} unexpectedly changed the projective GLV binding`);
  }
  fullInvalid.push({ steps: toStepArr({ inputs, meta: full0.meta }), rejected: true });
}

// ---- torus-root mutations at the genesis-terminal input ----
{
  const rootByteOffset = MILLER_GENESIS_OFFSETS.get('u0');
  // u+p alias of the canonical residue root: rejected by the genesis range gate.
  const rootAliasInputs = full0.inputs.slice();
  const rootAliasUnlocking = Uint8Array.from(rootAliasInputs[millerGenesisIndex].unlocking);
  const rootAliasBlob = pushBounds(rootAliasUnlocking);
  const rootAlias = BigInt(committedSpecs[millerGenesisIndex].inLimbs[MILLER_GENESIS_NAMES.indexOf('u0')]) + P;
  rootAliasUnlocking.set(le40(rootAlias).slice(0, W), rootAliasBlob.dataStart + rootByteOffset);
  rootAliasInputs[millerGenesisIndex] = { ...rootAliasInputs[millerGenesisIndex], unlocking: rootAliasUnlocking };
  if (evalInput(rootAliasInputs, millerGenesisIndex).accepted ||
      evalInput(rootAliasInputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error('Miller genesis accepted a noncanonical u+p residue root');
  }
  // Wrong nonzero quotient class: flip one canonical root bit; the terminal relation fails.
  const wrongClassInputs = mutateInputBlob(full0.inputs, millerGenesisIndex, rootByteOffset);
  if (evalInput(wrongClassInputs, millerGenesisIndex).accepted ||
      evalInput(wrongClassInputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error('torus verdict accepted a wrong nonzero quotient class');
  }
  // Zero root ([c]=[1]): every c-fold degenerates to the identity, so the terminal
  // cross-multiplication demands the raw Miller value lie in Fp6 — it does not.
  const zeroRootInputs = full0.inputs.slice();
  const zeroRootUnlocking = Uint8Array.from(zeroRootInputs[millerGenesisIndex].unlocking);
  const zeroRootBlob = pushBounds(zeroRootUnlocking);
  zeroRootUnlocking.fill(0, zeroRootBlob.dataStart + rootByteOffset, zeroRootBlob.dataStart + rootByteOffset + 6 * W);
  zeroRootInputs[millerGenesisIndex] = { ...zeroRootInputs[millerGenesisIndex], unlocking: zeroRootUnlocking };
  if (evalInput(zeroRootInputs, millerGenesisIndex).accepted ||
      evalInput(zeroRootInputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error('torus verdict accepted the degenerate zero residue root');
  }
  fullInvalid.push(
    { steps: toStepArr({ inputs: rootAliasInputs, meta: full0.meta }), rejected: true },
    { steps: toStepArr({ inputs: wrongClassInputs, meta: full0.meta }), rejected: true },
    { steps: toStepArr({ inputs: zeroRootInputs, meta: full0.meta }), rejected: true },
  );
  console.error('  torus root mutations: u+p alias, wrong quotient class, and zero root rejected');
}

// ---- trailing bytes in the genesis blob: rejected by enforceExactInputLength ----
{
  const trailingInputs = full0.inputs.slice();
  const baseUnlocking = trailingInputs[millerGenesisIndex].unlocking;
  const inBlob = pushBounds(baseUnlocking);
  const longerInBlob = Uint8Array.from([
    ...baseUnlocking.slice(inBlob.dataStart, inBlob.dataStart + inBlob.dataLen),
    0,
  ]);
  trailingInputs[millerGenesisIndex] = {
    ...trailingInputs[millerGenesisIndex],
    unlocking: Uint8Array.from([
      ...pd(longerInBlob),
      ...baseUnlocking.slice(inBlob.dataStart + inBlob.dataLen),
    ]),
  };
  if (evalInput(trailingInputs, millerGenesisIndex).accepted || evalInput(trailingInputs, millerGenesisIndex, standardVm).accepted) {
    throw new Error('Miller genesis accepted trailing bytes in its input blob');
  }
  fullInvalid.push({ steps: toStepArr({ inputs: trailingInputs, meta: full0.meta }), rejected: true });
  console.error('  trailing genesis-blob bytes rejected');
}

// ---- affine slope witness mutations (extras ride after the genesis inBlob) ----
{
  const spec = committedSpecs[millerGenesisIndex];
  if (spec.affineSlopeCount <= 0) throw new Error('missing affine slope witnesses');
  // Extras are pushed in reverse declaration order, so the FIRST push after inBlob is the
  // last slope limb. Mutate that minimally encoded integer without touching the bound inBlob.
  const originalSlope = BigInt(spec.extras[spec.extras.length - 1]);
  const wrongCanonicalSlope = originalSlope === P - 1n ? originalSlope - 1n : originalSlope + 1n;
  const baseUnlocking = full0.inputs[millerGenesisIndex].unlocking;
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
    inputs[millerGenesisIndex] = { ...inputs[millerGenesisIndex], unlocking };
    if (evalInput(inputs, millerGenesisIndex).accepted || evalInput(inputs, millerGenesisIndex, standardVm).accepted) {
      throw new Error(`affine step accepted ${label} slope witness`);
    }
    fullInvalid.push({ steps: toStepArr({ inputs, meta: full0.meta }), rejected: true });
  }
  console.error('  affine slope mutations: wrong canonical and noncanonical-p witnesses rejected');
}

// ---- isolated invalid points (off-curve A/C/B + off-subgroup B): full-tx runs that must be
// rejected at their validation step (genesis canonical/on-curve checks, or the fused psi
// endpoint subgroup relation inside the same Miller input). ----
const invalidPointRuns = invalidG2Overrides(INSTANCES.committed.proof, 1).map((bad) => {
  const baseNegA = proof.a.negate().toAffine();
  const baseB = proof.b.toAffine();
  const baseC = proof.c.toAffine();
  const badProof = {
    a: bn254.G1.Point.fromAffine({ x: bad.Ax ?? baseNegA.x, y: bad.Ay ?? baseNegA.y }).negate(),
    b: bn254.G2.Point.fromAffine({ x: bad.Bx ?? baseB.x, y: bad.By ?? baseB.y }),
    c: bn254.G1.Point.fromAffine({ x: bad.Cx ?? baseC.x, y: bad.Cy ?? baseC.y }),
  };
  const run = assemble(buildSpecs({ proof: badProof, inputs: INSTANCES.committed.inputs }), true);
  if (run.meta[millerGenesisIndex]?.accepted !== false) {
    throw new Error('fused Miller input validation accepted an invalid point');
  }
  const earlierFailure = run.meta.find((meta, i) => i < millerGenesisIndex && !meta.accepted);
  if (earlierFailure) throw new Error(`invalid point rejected before its validation step at ${earlierFailure.label}`);
  return run;
});

// ---- noncanonical (limb+p) proof coordinates at genesis ----
const noncanonicalInputs = [];
for (const limbIndex of [0, 2, 6]) {
  const inputs = full0.inputs.slice();
  const unlocking = Uint8Array.from(inputs[millerGenesisIndex].unlocking);
  const inBlob = pushBounds(unlocking);
  const replacement = le40(BigInt(committedSpecs[millerGenesisIndex].inLimbs[limbIndex]) + P).slice(0, W);
  unlocking.set(replacement, inBlob.dataStart + limbIndex * W);
  inputs[millerGenesisIndex] = { ...inputs[millerGenesisIndex], unlocking };
  if (evalInput(inputs, millerGenesisIndex).accepted) {
    throw new Error(`Miller genesis accepted noncanonical proof limb ${limbIndex}`);
  }
  noncanonicalInputs.push(toStepArr({ inputs, meta: full0.meta }));
}

const invalidInputs = [
  ...invalidPointRuns.map(toStepArr),
  ...noncanonicalInputs,
];
console.error(`  invalid runs rejected: ${fullInvalid.map((r) => r.rejected).join(',')}`);
console.error(`  invalid point runs rejected: ${invalidPointRuns.length}; serialized invalidInputs=${invalidInputs.length}`);
if (!full0.accepted || !full1.accepted || !fullWc.accepted ||
    !full0.fits || !full1.fits || !fullWc.fits ||
    !full0Transaction.consensusVerified || !full1Transaction.consensusVerified || !fullWcTransaction.consensusVerified ||
    !full0Transaction.standardVerified || !full1Transaction.standardVerified || !fullWcTransaction.standardVerified ||
    !full0Transaction.defaultMinRelayFeeVerified || !full1Transaction.defaultMinRelayFeeVerified ||
    !fullWcTransaction.defaultMinRelayFeeVerified ||
    infinityRuns.some(({ run, transaction }) =>
      !run.accepted || !run.fits || !transaction.consensusVerified || !transaction.standardVerified ||
      !transaction.defaultMinRelayFeeVerified) ||
    !fullInvalid.every((run) => run.rejected) || invalidInputs.length === 0) {
  throw new Error('valid, worst-case, or invalid fixture failed; refusing to write vectors');
}

const committedLockings = full0.inputs.map((input) => binToHex(input.locking));
for (const [name, run] of [
  ['proof#1', full1],
  ['worst case', fullWc],
  ...infinityRuns.map(({ name, run }) => [name, run]),
]) {
  const lockings = run.inputs.map((input) => binToHex(input.locking));
  if (JSON.stringify(lockings) !== JSON.stringify(committedLockings)) {
    throw new Error(`${name} changed the verifier locking graph`);
  }
}

const description = [
  `INTRA-TRANSACTION LINKED + QUOTIENT-TORUS full BN254 Groth16 verifier in one ${full0.inputs.length}-input transaction targeting the proposed bch-spec VM.`,
  `One 128-position four-scalar GLV input computes the runtime IC1/IC2 MSM projectively; one unrolled ${TORUS_OPS}-operation Miller input completes the verifier and quotient-torus verdict.`,
  'The Miller input folds the fixed e(alpha,beta) and e(IC0,gamma) factors, binds the projective MSM by cross multiplication, validates canonical normalized A/C and raw B encodings, supports every A/B/C identity combination, and enforces the exact runtime-B subgroup endpoint.',
  'The terminal checks [f*c^(p^2)]=[c^p*c^(p^3)] and rejects the projective zero representative.',
  'The root fixes the exact input count, the terminal fixes its position, and the root SHA-256-pins the terminal locking program; OP_INPUTBYTECODE binds the projective handoff, and both input blobs have exact widths.',
  'Both inputs satisfy the proposed VM script and length-derived operation budgets, and every accepting fixture passes its standard-policy VM with a default-minimum-fee-funded deterministic template.',
  'This artifact requires the proposed bch-spec upgrade because current BCH limits scripts to 10,000 bytes.',
  'The bytecode evaluates the complete four-pair equation for runtime proof points and two runtime public inputs without using the prescribed key\'s published scalar relations to collapse the statement.',
  'The checkpoint key is synthetic and publishes setup and IC scalars, so the result establishes complete-equation execution and proposed-VM resource validity for that key, not circuit knowledge, secure public-input-vector binding, arbitrary-key verification, or independent-setup interoperability.',
].join(' ');

writeFileSync(verifierPath('src/bch/groth16-intratx-residue-large-vectors.json'), JSON.stringify({
  description,
  method: 'intra-tx-linked-residue-large', deployment: 'P2SH32', numInputs: full0.inputs.length, budgetPerInput: LARGE_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  serializedTransactionBytes: full0Transaction.wireBytes,
  consensusTransactionVerified: full0Transaction.consensusVerified,
  standardTransactionVerified: full0Transaction.standardVerified,
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  extraValidProofTransactions: [
    {
      serializedTransactionBytes: full1Transaction.wireBytes,
      consensusTransactionVerified: full1Transaction.consensusVerified,
      standardTransactionVerified: full1Transaction.standardVerified,
      totalOperationCost: full1Transaction.totalOperationCost,
      maxStepOperationCost: full1Transaction.maxStepOperationCost,
    },
    ...infinityRuns.map(({ name, transaction }) => ({
      name,
      serializedTransactionBytes: transaction.wireBytes,
      consensusTransactionVerified: transaction.consensusVerified,
      standardTransactionVerified: transaction.standardVerified,
      totalOperationCost: transaction.totalOperationCost,
      maxStepOperationCost: transaction.maxStepOperationCost,
    })),
  ],
  worstCaseTransaction: {
    serializedTransactionBytes: fullWcTransaction.wireBytes,
    consensusTransactionVerified: fullWcTransaction.consensusVerified,
    standardTransactionVerified: fullWcTransaction.standardVerified,
    totalOperationCost: fullWcTransaction.totalOperationCost,
    maxStepOperationCost: fullWcTransaction.maxStepOperationCost,
  },
  steps: toStepArr(full0),
  extraValidProofs: [toStepArr(full1), ...infinityRuns.map(({ run }) => toStepArr(run))],
  worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
  invalidInputs,
}, null, 2));
console.error('\nwrote groth16-intratx-residue-large-vectors.json');
console.error('NOTE: generated/ now holds 100 kB-budget chunks. Regenerate the current-BCH chunks before rebuilding a flagship build:');
console.error('  VERIFIER_DIR=... node chunked/intratx/generate_torus.mjs');
