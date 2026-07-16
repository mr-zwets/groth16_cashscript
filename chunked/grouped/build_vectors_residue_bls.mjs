// GROUPED + RESIDUE verifier vectors for BLS12-381 — the residue-optimized chunk graph packed
// into a handful of standard (<100,000 B) transactions. The BLS counterpart of
// chunked/grouped/build_vectors_residue.mjs (BN254), and the residue analog of
// build_vectors_bls.mjs (this reuses that file's grouping/assembly machinery verbatim; only the
// per-stage chunk graph changes).
//
// Chunk graph (vs the plain BLS grouped's g2check -> vk_x -> 4-pair Miller -> final exp):
//   GLV vk_x (4-scalar 128-bit Straus, baked table)                -> 5 chunks
//   c^-|x|-FUSED prepared-VK batched Miller (e(a,b) baked, cmul1),
//     with G2 validation fused into its first/last chunks           -> 29 chunks
//   witnessed-residue tail: w in Fp6* + fF*w==frob(c,1)            -> 1 chunk
//                                                                     ---------
//                                                                     35 inputs
// The hard-part final exponentiation (Hayashida-Scott, 23 chunks in the plain build) collapses to
// the residue tail. c,cInv thread through every fused-Miller chunk as constant witness; w enters
// the terminal tail as an uncommitted witness and is checked there (see gen_finalexp_residue).
//
//   node build_vectors_residue_bls.mjs -> verifier/src/bch/groth16-bls12381-grouped-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  B_IDENTITY_SUBSTITUTE, millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs, unitG1, PT_CFG,
  compileBytecode, commitBinExact, CATEGORY, le48Exact, P, OP_DROP, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileBytecodeRaw, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import {
  millerFusedOps, millerFusedTorusOps, residueTorusWitness, residueWitness,
} from '../bls12-381/_residuemath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, vkxGlvYinv, vkxGlvUnit, GLV_TABLE_HEX,
  GLV_SHARED_AUDITED_BOUNDS, regenGlvSharedAudited,
} from '../bls12-381/gen_vkx_glv.mjs';
import { LINKED_HIGH_COST_INPUTS, LINKED_RESIDUE_NAMESPACE } from '../bls12-381/_residue_linked_plan.mjs';
import { transformChunk, headerSize } from '../intratx/transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
const GEN = join(here, '..', 'bls12-381', 'generated', LINKED_RESIDUE_NAMESPACE);
const W = 48; // BLS12-381 limb width
const UNIT_G1 = process.env.BLS_UNIT_G1 === '1';
if (QUOTIENT_TORUS && !UNIT_G1) {
  throw new Error('the grouped quotient-torus build requires identity-complete G1 coordinates');
}
const PRIME = P.toString();
import {
  hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32,
  encodeDataPush, encodeTransactionBch, createVirtualMachineBch2026,
} from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));

// SHARED GLV TABLE: the 1,440-byte Straus table rides ONCE in the final GLV input (right after its
// 9-limb inBlob push); the four sibling GLV inputs read that exact slice via input-bytecode
// introspection and the carrier pins it with hash256. The GLV chunks lead the graph and the packer
// blocks cuts inside the span, so the carrier's transaction-local index equals its graph index.
const GLV_COUNT = GLV_SHARED_AUDITED_BOUNDS.length - 1;
const GLV_STATE_BYTES = 9 * W; // rX,rY,rZ,in0,in1,k10,k20,k11,k21
regenGlvSharedAudited(GEN, {
  inputIndex: GLV_COUNT - 1,
  dataOffset: headerSize(GLV_STATE_BYTES) + GLV_STATE_BYTES + headerSize(GLV_TABLE_BYTES.length),
}, true);

const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((limb) => [...le48Exact(limb)]));
const commitOf = (limbs) => commitBinExact(limbs.map(BigInt));
const limbsEqual = (a, b) => a.length === b.length && a.every((x, i) => BigInt(x) === BigInt(b[i]));

const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));
const OP_RETURN = Uint8Array.from([0x6a]);

// ---- per-group evaluation: one token-carrying tx for the group, evaluate input `index` ----
function tokenOf(t) {
  return t ? { amount: 0n, category: CATEGORY, nft: { capability: t.cap, commitment: t.commit } } : undefined;
}
function groupVerificationData(inputs, gm) {
  if (inputs.length === 0) throw new Error('cannot build an empty verifier transaction group');
  const transaction = {
    version: 2,
    inputs: inputs.map((inp, n) => ({
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: n,
      sequenceNumber: 0,
      unlockingBytecode: inp.unlocking,
    })),
    outputs: gm.outToken
      ? [{ lockingBytecode: gm.outLocking, valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS, token: tokenOf(gm.outToken) }]
      : [{ lockingBytecode: OP_RETURN, valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS }],
    locktime: 0,
  };
  const requiredSourceSatoshis = TRANSACTION_OUTPUT_SATOSHIS +
    BigInt(encodeTransactionBch(transaction).length) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  const perInputSatoshis = requiredSourceSatoshis / BigInt(inputs.length);
  const remainder = requiredSourceSatoshis % BigInt(inputs.length);
  return {
    sourceOutputs: inputs.map((inp, n) => ({
      lockingBytecode: inp.locking,
      valueSatoshis: perInputSatoshis + (BigInt(n) < remainder ? 1n : 0n),
      token: tokenOf(gm.inputTokens?.[n] ?? (n === 0 ? gm.inToken : null)),
    })),
    transaction,
  };
}
function evalGroup(inputs, index, gm, vm = realVm) {
  const st = vm.evaluate({ inputIndex: index, ...groupVerificationData(inputs, gm) });
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
const mkInstance = (inputs) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);
  const A = mod(3n * 5n + vx * 7n + 13n * 11n);
  return { inputs, proof: { a: G1.BASE.multiply(A), b: proof.b, c: proof.c } };
};
const INSTANCES = { committed: { inputs: PUBLIC_INPUTS, proof }, proof1: mkInstance([135208n, 67633n]), stress: mkInstance(LINKED_HIGH_COST_INPUTS) };
const kZeroInputs = [1n, mod((mod(-15n * invR(7n)) - 6n) * invR(6n))];
const identityInstance = (tag) => {
  const identities = new Set(tag);
  const needsKZero = identities.has('C') && (identities.has('A') || identities.has('B'));
  const inputs = needsKZero ? kZeroInputs : PUBLIC_INPUTS.map(BigInt);
  const vx = mod(2n + 4n * inputs[0] + 6n * inputs[1]);
  const k = mod(15n + 7n * vx);
  let a = identities.has('A') ? 0n : 1n;
  const b = identities.has('B') ? 0n : 1n;
  let c = identities.has('C') ? 0n : 13n;
  if (a !== 0n && b !== 0n) a = mod(k + 11n * c);
  else if (c !== 0n) c = mod(-k * invR(11n));
  if (mod(-a * b + k + 11n * c) !== 0n) throw new Error(`invalid identity fixture equation: ${tag}`);
  return { inputs, proof: { a: g1(a), b: g2(b), c: g1(c) }, identityTag: tag };
};
const IDENTITY_INSTANCES = ['A', 'B', 'C', 'AB', 'AC', 'BC', 'ABC'].map(identityInstance);
const MSM_IDENTITY_INSTANCE = (() => {
  const inputs = [1n, Rord - 1n];
  if (!computeVkx(inputs).is0()) throw new Error('runtime MSM identity fixture does not produce infinity');
  const vx = 0n, c = 13n, a = mod(15n + 7n * vx + 11n * c);
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
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const pointLimbs = (pair, j) => {
  const out = [];
  if (PT_CFG[j].P) {
    const point = UNIT_G1 ? unitG1(pair.P) : pair.P.toAffine();
    out.push(...(UNIT_G1 ? [point.u, point.v] : [point.x, point.y]));
  }
  if (PT_CFG[j].Q) {
    const q = pair.Q.toAffine();
    out.push(q.x.c0, q.x.c1, q.y.c0, q.y.c1);
  }
  return out;
};
const effectivePairsFor = (inst) => {
  const pairs = pairsFor(inst.inputs, inst.proof);
  if (!UNIT_G1 || !inst.proof.b.is0()) return pairs;
  return pairs.map((pair, j) => j === 0 ? { ...pair, P: G1.ZERO, Q: B_IDENTITY_SUBSTITUTE } : pair);
};
const ptLof = (inst) => pairsFor(inst.inputs, inst.proof).flatMap(pointLimbs);
const ROOT_LIMBS = QUOTIENT_TORUS ? 6 : 24;
const VKX_LIMB_OFFSET = ROOT_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length;
const MILLER_IN_LIMBS = ptLof(INSTANCES.committed).length + ROOT_LIMBS;
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]

// ---- per-stage specs ----------------------------------------------------------------
const uLimbs = (u) => [u.c0.c0, u.c0.c1, u.c1.c0, u.c1.c1, u.c2.c0, u.c2.c1];
const stateLimbsR = (s) => [
  ...f12limbs(s.f),
  ...r6limbs(s.Rs[0]),
  ...(QUOTIENT_TORUS ? uLimbs(s.u) : [...f12limbs(s.c), ...f12limbs(s.cInv)]),
];
const withPtsR = (limbs, ptL) => [...limbs.slice(0, 18), ...ptL, ...limbs.slice(18)]; // insert ptL after f+R_B

// g2check is no longer a standalone stage — the on-curve checks + G2 subgroup test are fused into
// the first/last fused-Miller chunks (see gen_miller_residue.mjs), reusing R_B = [|x|]B.
function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const scal = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('grouped BLS residue requires stage-bound GLV generation');
  if (man.sharedTable !== true) throw new Error('grouped BLS residue requires shared-table GLV generation');
  return man.chunks.map((ch) => {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scal];
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: UNIT_G1 ? vkxGlvUnit(k10, k20, k11, k21) : [vkxAff.x, vkxAff.y],
      extras: [UNIT_G1 ? vkxGlvYinv(k10, k20, k11, k21) : vkxGlvZinv(k10, k20, k11, k21), GLV_TABLE_BYTES], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
      label: 'GLV vk_x final -> assemble vk_x', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scal], extras: [], role: 'within', label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMillerResidue(inst, c, cInv, u = null, bad = {}) {
  const originalPairs = pairsFor(inst.inputs, inst.proof);
  const pairs = effectivePairsFor(inst);
  const { states, boundary } = QUOTIENT_TORUS
    ? millerFusedTorusOps(pairs, c, cInv, u, { unitLines: UNIT_G1 })
    : millerFusedOps(pairs, c, cInv, { unitLines: UNIT_G1 });
  const ptL = pairs.flatMap(pointLimbs);
  const originalPtL = originalPairs.flatMap(pointLimbs);
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('grouped BLS residue requires stage-bound Miller generation');
  if (man.unitG1Lines !== UNIT_G1) throw new Error('grouped BLS residue Miller coordinate mode does not match the generated manifest');
  if ((man.quotientTorus === true) !== QUOTIENT_TORUS ||
    (man.terminalFused === true) !== QUOTIENT_TORUS) {
    throw new Error('grouped BLS residue arithmetic mode does not match the generated manifest');
  }
  const genesisPts = [...originalPtL.slice(2, 6), ...originalPtL.slice(0, 2), ...originalPtL.slice(6)];
  if (bad.Ax !== undefined) genesisPts[4] = bad.Ax;
  if (bad.Ay !== undefined) genesisPts[5] = bad.Ay;
  if (bad.Cy !== undefined) genesisPts[9] = bad.Cy;
  const genesis = QUOTIENT_TORUS
    ? [...uLimbs(u), ...genesisPts]
    : [...f12limbs(cInv), ...f12limbs(c), ...genesisPts];
  const specs = man.chunks.map((ch) => {
    const inLimbs = ch.opLo === 0 ? genesis : withPtsR(stateLimbsR(states[ch.opLo]), ptL);
    if (ch.final) {
      if (QUOTIENT_TORUS) {
        if (ch.terminalFused !== true || ch.outgoing !== null) {
          throw new Error('grouped quotient-torus final Miller chunk is not terminal');
        }
        return {
          file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
          inLimbs, outLimbs: [], extras: [], role: 'terminal',
          label: `miller ops[${ch.opLo},${ch.opHi}) + quotient verdict`, checkpoint: 'verify',
        };
      }
      const s = states[ch.opHi];
      return {
        file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [...f12limbs(s.f), ...f12limbs(s.c), ...f12limbs(s.cInv)], extras: [], role: 'cross',
        cmp: { cmpExpr: 'outBlob', nextFullInLen: TAIL_HANDOFF_LIMBS * W, skip: 0, cmpLen: TAIL_HANDOFF_LIMBS * W },
        label: `miller ops[${ch.opLo},${ch.opHi}) -> boundary fF`, checkpoint: 'miller-boundary',
      };
    }
    return { file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: withPtsR(stateLimbsR(states[ch.opHi]), ptL), extras: [], role: 'within', label: `miller ops[${ch.opLo},${ch.opHi})${ch.idx === 0 ? ' + validate inputs (on-curve A/B/C)' : ''}`, checkpoint: ch.idx === 0 ? 'validate-inputs' : undefined };
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
    throw new Error('grouped BLS residue requires the one-chunk Fp6 tail');
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
  const vkx = specsVkxGlv(inst);
  const pairs = effectivePairsFor(inst);
  const { boundary: fRaw } = millerBatchOps(pairs, { unitLines: UNIT_G1 });
  const root = QUOTIENT_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw);
  const { c, cInv, w, u } = root;
  const { specs: miller, boundary: fF } = specsMillerResidue(inst, c, cInv, u);
  if (QUOTIENT_TORUS) return [...vkx, ...miller];
  const tail = specsResidueTail(fF, c, cInv, w);
  return [...vkx, ...miller, ...tail];
}

// ---- grouping (identical logic to build_vectors_bls.mjs) -----------------------------
const PER_INPUT_OV = 43;
// Cuts are BLOCKED inside the shared-table span [0, carrier]: the sibling GLV inputs read the
// carrier's unlocking via tx.inputs[GLV_COUNT-1], so all GLV chunks must share one group tx with
// the carrier at that transaction-local index (group 0 always starts at graph index 0).
const blockedCut = (i) => i < GLV_COUNT - 1;
function packGroups(specs, sz, target) {
  const allowed = (i) => i < specs.length - 1 && !blockedCut(i) && specs[i].outLimbs.length > 0 && limbsEqual(specs[i].outLimbs, specs[i + 1].inLimbs);
  const groups = []; let start = 0;
  while (start < specs.length) {
    let acc = 0, lastAllowed = -1, end = specs.length - 1;
    for (let i = start; i < specs.length; i++) {
      acc += sz[i] + PER_INPUT_OV;
      if (acc > target && lastAllowed >= start) { end = lastAllowed; break; }
      if (allowed(i)) lastAllowed = i;
    }
    groups.push([start, end]); start = end + 1;
  }
  return groups;
}
function groupedCfg(specs, i, lo, hi, groupIdx, G) {
  const isFirst = i === lo, isLast = i === hi;
  const covInHash = isFirst && groupIdx > 0;
  const epilogueMode = isLast && groupIdx < G - 1 ? 'covout' : undefined;
  let forward = null;
  if (!epilogueMode && specs[i].role !== 'terminal') {
    if (specs[i].role === 'within') { const outLen = specs[i].outLimbs.length * W; forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
    else if (specs[i].role === 'cross') forward = specs[i].cmp;
  }
  return {
    covInHash,
    epilogueMode,
    forward,
    expectedInputCount: isFirst ? hi - lo + 1 : undefined,
    expectedInputIndex: isFirst ? 0 : undefined,
    tokenThreadMode: isFirst && hi > lo ? (groupIdx === G - 1 ? 'burn' : 'continue') : undefined,
    enforceExactInputLength: true,
  };
}

const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map();
const PROBE = join(GEN, '_grouped_residue_probe.cash');
const cfgKey = (spec, cfg) => `${spec.file}|${cfg.covInHash ? 'ci' : ''}|${cfg.epilogueMode ?? ''}|${cfg.nextLockingHash ?? ''}|${cfg.nextLockingBytecode ?? ''}|${cfg.expectedInputCount ?? ''}|${cfg.expectedInputIndex ?? ''}|${cfg.tokenThreadMode ?? ''}|${cfg.enforceExactInputLength ? 'exact' : ''}|${JSON.stringify(cfg.forward)}`;
function compileChunk(spec, cfg) {
  const key = cfgKey(spec, cfg);
  let v = compileCache.get(key);
  if (!v) {
    const t = transformChunk(readFileSync(spec.file, 'utf8'), {
      W, prime: PRIME, forward: cfg.forward, covInHash: cfg.covInHash,
      epilogueMode: cfg.epilogueMode, nextLockingHash: cfg.nextLockingHash,
      nextLockingBytecode: cfg.nextLockingBytecode,
      expectedInputCount: cfg.expectedInputCount, expectedInputIndex: cfg.expectedInputIndex,
      tokenThreadMode: cfg.tokenThreadMode,
      enforceExactInputLength: cfg.enforceExactInputLength,
    });
    let resched, raw;
    if (/^import\s/m.test(t.src)) { writeFileSync(PROBE, t.src); resched = compileFileBytecode(PROBE); raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched; }
    else { resched = compileBytecode(t.src); raw = RESCHED ? compileBytecodeRaw(t.src) : resched; }
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41) : Infinity);
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs))];
  for (const e of [...spec.extras].reverse()) parts.push(e instanceof Uint8Array ? pd(e) : pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

function assembleGrouped(specs, groups, expectRejected = false) {
  const G = groups.length;
  const cfgs = specs.map((_, i) => {
    const gi = groups.findIndex(([lo, hi]) => i >= lo && i <= hi);
    return { ...groupedCfg(specs, i, groups[gi][0], groups[gi][1], gi, G), group: gi };
  });
  // Compile groups from tail to head so each nonterminal group's last contract can
  // embed the already-known hash of the successor group's first P2SH32 locking.
  const redeems = new Array(specs.length), lockings = new Array(specs.length);
  for (let gi = G - 1; gi >= 0; gi--) {
    const [lo, hi] = groups[gi];
    for (let i = hi; i >= lo; i--) {
      if (cfgs[i].epilogueMode === 'covout') {
        cfgs[i].nextLockingBytecode = binToHex(lockings[groups[gi + 1][0]]);
      }
      if (cfgs[i].forward) {
        if (!lockings[i + 1]) throw new Error(`missing successor locking for graph edge ${i} -> ${i + 1}`);
        cfgs[i].forward = { ...cfgs[i].forward, nextLockingBytecode: binToHex(lockings[i + 1]) };
      }
      redeems[i] = compileChunk(specs[i], cfgs[i]);
      lockings[i] = p2shSpk(redeems[i]);
    }
  }
  const rpush = redeems.map((r) => encodeDataPush(r));
  const argB = specs.map(argBytesOf);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + rpush[i].length;
    const pad = padPush(0, Math.max(2, target - fixed));
    return Uint8Array.from([...argB[i], ...pad, ...rpush[i]]);
  };

  const gmeta = groups.map(([lo, hi], gi) => {
    const inToken = gi === 0
      ? { cap: 'mutable', commit: new Uint8Array(0) }
      : { cap: 'mutable', commit: commitOf(specs[lo].inLimbs) };
    const outToken = gi === G - 1 ? null : { cap: 'mutable', commit: commitOf(specs[hi].outLimbs) };
    return { lo, hi, inToken, outToken, outLocking: null };
  });
  for (let gi = 0; gi < G - 1; gi++) gmeta[gi].outLocking = lockings[groups[gi + 1][0]];
  let handoffsMatch = true;
  for (let gi = 0; gi < G - 1; gi++) {
    const a = binToHex(gmeta[gi].outToken.commit), b = binToHex(gmeta[gi + 1].inToken.commit);
    if (a !== b) {
      handoffsMatch = false;
      if (!expectRejected) throw new Error(`group ${gi} hand-off mismatch: ${a} != ${b}`);
    }
  }

  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) op1[lo + k] = evalGroup(ins, k, gmeta[gi]); });
  const standardOp1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) standardOp1[lo + k] = evalGroup(ins, k, gmeta[gi], standardVm); });
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
      const gi = cfgs[i].group, lo = groups[gi][0];
      const rawRpush = encodeDataPush(v.raw);
      const rawFixed = argB[i].length + rawRpush.length;
      const rawUnlock = Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, TARGET_UNLOCK - rawFixed)), ...rawRpush]);
      const rawInputs = allInputs.slice(lo, groups[gi][1] + 1);
      rawInputs[i - lo] = { locking: p2shSpk(v.raw), unlocking: rawUnlock };
      const rawOp = evalGroup(rawInputs, i - lo, gmeta[gi]);
      const rawStandardOp = evalGroup(rawInputs, i - lo, gmeta[gi], standardVm);
      const tR = effLen(argB[i].length + rpush[i].length, Math.max(op1[i].operationCost, standardOp1[i].operationCost), op1[i].accepted && standardOp1[i].accepted);
      const tB = effLen(rawFixed, Math.max(rawOp.operationCost, rawStandardOp.operationCost), rawOp.accepted && rawStandardOp.accepted);
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assembleGrouped(specs, groups, expectRejected);
  }
  const op2 = [];
  let standardOp2;
  let targets = specs.map((_, i) => tunedLen(argB[i].length + rpush[i].length, Math.max(op1[i].operationCost, standardOp1[i].operationCost)));
  while (true) {
    for (let i = 0; i < specs.length; i++) allInputs[i].unlocking = mkUnlock(i, targets[i]);
    standardOp2 = [];
    groups.forEach(([lo, hi], gi) => {
      const ins = allInputs.slice(lo, hi + 1);
      for (let k = 0; k <= hi - lo; k++) {
        op2[lo + k] = evalGroup(ins, k, gmeta[gi]);
        standardOp2[lo + k] = evalGroup(ins, k, gmeta[gi], standardVm);
      }
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
    throw new Error('tightened input rejected during padding measurement');
  }

  const meta = specs.map((s, i) => ({
    label: s.label, checkpoint: s.checkpoint, group: cfgs[i].group,
    lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
    operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error,
  }));
  const accepted = handoffsMatch && op2.every((o) => o.accepted);
  if (expectRejected && accepted) throw new Error('invalid grouped residue fixture unexpectedly accepted');
  const groupBytes = groups.map(([lo, hi], gi) => {
    let b = 8 + 1 + 1;
    for (let i = lo; i <= hi; i++) b += allInputs[i].unlocking.length + PER_INPUT_OV;
    b += gmeta[gi].outToken
      ? 8 + 1 + (1 + 32 + 1 + 1 + 32) + gmeta[gi].outLocking.length
      : 8 + 1 + 1;
    return b;
  });
  const groupTransactions = groups.map(([lo, hi], gi) => {
    const data = groupVerificationData(allInputs.slice(lo, hi + 1), gmeta[gi]);
    const wireBytes = encodeTransactionBch(data.transaction).length;
    if (wireBytes !== groupBytes[gi]) {
      throw new Error(`group ${gi} serialized as ${wireBytes} bytes, modeled as ${groupBytes[gi]}`);
    }
    const feeSatoshis = data.sourceOutputs.reduce((total, output) => total + output.valueSatoshis, 0n) -
      data.transaction.outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
    return {
      wireBytes,
      consensusVerified: realVm.verify(data) === true,
      standardVerified: standardVm.verify(data) === true,
      defaultMinRelayFeeVerified: feeSatoshis ===
        BigInt(wireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE,
    };
  });
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) &&
    accepted && groupTransactions.every((tx) =>
      tx.wireBytes <= 100000 && tx.consensusVerified && tx.standardVerified && tx.defaultMinRelayFeeVerified);
  return { inputs: allInputs, meta, gmeta, groups, groupBytes, groupTransactions, fits, accepted };
}

const toStep = (asm, i) => ({ label: asm.meta[i].label, locking: binToHex(asm.inputs[i].locking), unlocking: binToHex(asm.inputs[i].unlocking), checkpoint: asm.meta[i].checkpoint, group: asm.meta[i].group });
const toRun = (asm) => ({
  steps: asm.inputs.map((_, i) => toStep(asm, i)),
  groups: asm.gmeta.map((g) => ({
    lo: g.lo, hi: g.hi,
    inToken: g.inToken ? { capability: g.inToken.cap, commitment: binToHex(g.inToken.commit) } : null,
    inputTokens: g.inputTokens?.map((token) => token
      ? { capability: token.cap, commitment: binToHex(token.commit) }
      : null),
    outToken: g.outToken ? { capability: g.outToken.cap, commitment: binToHex(g.outToken.commit) } : null,
    outLocking: g.outLocking ? binToHex(g.outLocking) : null,
  })),
});

function invalidRun(specs, groups, idx) {
  const asm = assembleGrouped(specs, groups);
  asm.inputs[idx] = { ...asm.inputs[idx], unlocking: (() => {
    const u = Uint8Array.from(asm.inputs[idx].unlocking);
    const op = u[0];
    const dataStart = op <= 75 ? 1 : op === 0x4c ? 2 : 3;
    const dataLen = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8);
    u[dataStart + Math.floor(dataLen / 2)] ^= 0x01;
    return u;
  })() };
  const res = [];
  groups.forEach(([lo, hi], gi) => { const ins = asm.inputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) res[lo + k] = evalGroup(ins, k, asm.gmeta[gi]); });
  return { run: toRun(asm), rejected: res.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const transactionMetadata = (asm) => ({
  groupBytes: asm.groupTransactions.map((tx) => tx.wireBytes),
  minimumRelayFeeSatoshisAtOneSatPerByte: asm.groupTransactions.map((tx) => tx.wireBytes),
  consensusTransactionsVerified: asm.groupTransactions.map((tx) => tx.consensusVerified),
  standardTransactionsVerified: asm.groupTransactions.map((tx) => tx.standardVerified),
  defaultMinimumRelayFeeVerified: asm.groupTransactions.map((tx) => tx.defaultMinRelayFeeVerified),
  totalBytes: sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(asm.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...asm.meta.map((m) => m.operationCost)),
  maxUnlockingBytes: Math.max(...asm.meta.map((m) => m.unlockingBytes), 0),
});
const report = (tag, asm) => {
  console.error(`${tag}: ${asm.meta.length} inputs / ${asm.groups.length} groups, accepted=${asm.accepted} fits=${asm.fits}`);
  console.error(`  groups (chunks): ${asm.groups.map(([lo, hi]) => hi - lo + 1).join(',')}  group bytes: ${asm.groupBytes.map((b) => b.toLocaleString()).join(', ')}`);
  console.error(`  totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()} maxUnlock=${Math.max(...asm.meta.map((m) => m.unlockingBytes))}`);
  console.error(`  whole tx: consensus=${asm.groupTransactions.map((tx) => tx.consensusVerified).join(',')} standard=${asm.groupTransactions.map((tx) => tx.standardVerified).join(',')} relayFee=${asm.groupTransactions.map((tx) => tx.defaultMinRelayFeeVerified).join(',')}`);
  asm.meta.filter((m) => !m.accepted).slice(0, 6).forEach((m) => console.error(`  !! non-accepting: g${m.group} ${m.label} :: op=${m.operationCost.toLocaleString()} err=${m.error}`));
};

// ===================== build =====================
const TARGET_GROUP_BYTES = Number(process.env.TARGET_GROUP_BYTES ?? 90000);
if (!Number.isSafeInteger(TARGET_GROUP_BYTES) || TARGET_GROUP_BYTES <= 0 || TARGET_GROUP_BYTES > 100000) {
  throw new Error(`invalid TARGET_GROUP_BYTES: ${TARGET_GROUP_BYTES}`);
}
console.error('building residue specs (residueWitness per instance ~seconds)...');
const cSpecs = buildSpecs(INSTANCES.committed);
const p1Specs = buildSpecs(INSTANCES.proof1);
const stressSpecs = buildSpecs(INSTANCES.stress);
function requireStageGenesis(specs, inst, label) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  if (!limbsEqual(specs[0].inLimbs, [in0, in1, k10, k20, k11, k21])) {
    throw new Error(`${label} GLV genesis still exposes accumulator state`);
  }
  const pairs = pairsFor(inst.inputs, inst.proof);
  const ptL = pairs.flatMap(pointLimbs);
  const expectedPoints = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
  if (specs[GLV_COUNT].inLimbs.length !== MILLER_IN_LIMBS ||
    !limbsEqual(specs[GLV_COUNT].inLimbs.slice(ROOT_LIMBS, ROOT_LIMBS + 10), expectedPoints)) {
    throw new Error(`${label} Miller genesis still exposes f/R_B state or misorders proof points`);
  }
}
[
  ['committed', cSpecs, INSTANCES.committed],
  ['proof#1', p1Specs, INSTANCES.proof1],
  ['stress', stressSpecs, INSTANCES.stress],
].forEach(([label, specs, inst]) => requireStageGenesis(specs, inst, label));
function sizeEstimate(specs) {
  const provisional = packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES);
  return assembleGrouped(specs, provisional).meta.map((m) => m.unlockingBytes);
}
const cSizes = sizeEstimate(cSpecs), p1Sizes = sizeEstimate(p1Specs), stressSizes = sizeEstimate(stressSpecs);
const packSizes = cSizes.map((s, i) => Math.max(s, p1Sizes[i], stressSizes[i]));
const GROUPS = packGroups(cSpecs, packSizes, TARGET_GROUP_BYTES);

const asmCommitted = assembleGrouped(cSpecs, GROUPS);
report('groth16-bls-grouped-residue committed', asmCommitted);
const asmProof1 = assembleGrouped(p1Specs, GROUPS);
report('groth16-bls-grouped-residue proof#1', asmProof1);
const asmStress = assembleGrouped(stressSpecs, GROUPS);
report('groth16-bls-grouped-residue all-position stress', asmStress);
const completenessInstances = [...IDENTITY_INSTANCES, MSM_IDENTITY_INSTANCE];
const completenessRuns = completenessInstances.map((inst) => {
  if (!pairingEquationAccepts(inst)) throw new Error(`${inst.identityTag} fixture does not satisfy the pairing equation`);
  const specs = buildSpecs(inst);
  requireStageGenesis(specs, inst, `${inst.identityTag} identity`);
  const asm = assembleGrouped(specs, GROUPS);
  report(`groth16-bls-grouped-residue ${inst.identityTag} identity`, asm);
  if (!asm.accepted || !asm.fits) throw new Error(`${inst.identityTag} identity fixture did not pass as a standard grouped verifier`);
  return { tag: inst.identityTag, specs, asm };
});

for (const [label, otherSpecs] of [['proof#1', p1Specs], ['stress', stressSpecs]]) {
  const hybridSpecs = [...cSpecs.slice(0, GLV_COUNT), ...otherSpecs.slice(GLV_COUNT)];
  const unboundSpecs = hybridSpecs.map((spec, i) => i === GLV_COUNT - 1 ? { ...spec, role: 'stage-final', cmp: null } : spec);
  const unbound = assembleGrouped(unboundSpecs, GROUPS);
  if (!unbound.accepted) throw new Error(`${label} unbound valid-fixture hybrid was not accepted`);
  const boundInputs = [...asmCommitted.inputs.slice(0, GLV_COUNT), ...unbound.inputs.slice(GLV_COUNT)];
  const outcomes = [];
  GROUPS.forEach(([lo, hi], gi) => {
    const inputs = boundInputs.slice(lo, hi + 1);
    for (let i = lo; i <= hi; i++) outcomes[i] = evalGroup(inputs, i - lo, unbound.gmeta[gi]);
  });
  if (outcomes[GLV_COUNT - 1].accepted) throw new Error(`${label} hybrid did not reject at the vk_x boundary`);
  const unrelated = outcomes.find((outcome, i) => i !== GLV_COUNT - 1 && !outcome.accepted);
  if (unrelated) throw new Error(`${label} hybrid also rejected outside the vk_x boundary`);
}
console.error('  stage genesis layouts and proof#1/stress vk_x boundaries verified');

if (GROUPS[0][0] !== 0 || GROUPS[0][1] < GLV_COUNT - 1) {
  throw new Error(`shared GLV table span [0,${GLV_COUNT - 1}] not contained in group 0: ${JSON.stringify(GROUPS[0])}`);
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
const tableCarrierIndex = GLV_COUNT - 1;
const tableInputs = asmCommitted.inputs.slice();
const tableUnlocking = Uint8Array.from(tableInputs[tableCarrierIndex].unlocking);
const carrierBlob = pushBounds(tableUnlocking);
const tablePush = pushBounds(tableUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
if (tablePush.dataLen !== GLV_TABLE_BYTES.length) throw new Error('shared GLV table push has unexpected length');
tableUnlocking[tablePush.dataStart + Math.floor(tablePush.dataLen / 2)] ^= 0x01;
tableInputs[tableCarrierIndex] = { ...tableInputs[tableCarrierIndex], unlocking: tableUnlocking };
const tableGroupInputs = tableInputs.slice(GROUPS[0][0], GROUPS[0][1] + 1);
if (evalGroup(tableGroupInputs, tableCarrierIndex, asmCommitted.gmeta[0]).accepted) {
  throw new Error('GLV carrier accepted a mutated shared table');
}
const tableMutation = { run: toRun({ ...asmCommitted, inputs: tableInputs }), rejected: true };
console.error('  shared GLV table mutation rejected at carrier');

// A group hand-off binds the actual successor P2SH32 locking as well as its state hash.
const changedLockAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((group) => ({ ...group })) };
const changedLockGroup = changedLockAsm.gmeta.find((group) => group.outLocking !== null);
if (!changedLockGroup) throw new Error('missing grouped hand-off fixture');
changedLockGroup.outLocking = Uint8Array.from(changedLockGroup.outLocking);
changedLockGroup.outLocking[changedLockGroup.outLocking.length - 1] ^= 0x01;
const changedLockInputs = changedLockAsm.inputs.slice(changedLockGroup.lo, changedLockGroup.hi + 1);
const changedLockOutcomes = Array.from(
  { length: changedLockGroup.hi - changedLockGroup.lo + 1 },
  (_, index) => evalGroup(changedLockInputs, index, changedLockGroup),
);
const handoffIndex = changedLockGroup.hi - changedLockGroup.lo;
if (changedLockOutcomes[handoffIndex].accepted) throw new Error('changed successor locking was accepted');
const unrelatedLockFailure = changedLockOutcomes.find((outcome, index) => index !== handoffIndex && !outcome.accepted);
if (unrelatedLockFailure) throw new Error('changed successor locking also failed outside the hand-off input');
const changedSuccessorLock = { run: toRun(changedLockAsm), rejected: true };
console.error('  changed successor locking rejected at group hand-off');

// The carried token must retain its mutable capability across every group hand-off.
const changedCapabilityAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((group) => ({
  ...group,
  outToken: group.outToken ? { ...group.outToken } : null,
})) };
const changedCapabilityGroup = changedCapabilityAsm.gmeta.find((group) => group.outToken?.cap === 'mutable');
if (!changedCapabilityGroup) throw new Error('missing mutable grouped hand-off fixture');
changedCapabilityGroup.outToken.cap = 'none';
const changedCapabilityInputs = changedCapabilityAsm.inputs.slice(
  changedCapabilityGroup.lo,
  changedCapabilityGroup.hi + 1,
);
const changedCapabilityOutcomes = Array.from(
  { length: changedCapabilityGroup.hi - changedCapabilityGroup.lo + 1 },
  (_, index) => evalGroup(changedCapabilityInputs, index, changedCapabilityGroup),
);
const capabilityHandoffIndex = changedCapabilityGroup.hi - changedCapabilityGroup.lo;
if (changedCapabilityOutcomes[capabilityHandoffIndex].accepted) {
  throw new Error('changed output token capability was accepted');
}
const unrelatedCapabilityFailure = changedCapabilityOutcomes.find(
  (outcome, index) => index !== capabilityHandoffIndex && !outcome.accepted,
);
if (unrelatedCapabilityFailure) {
  throw new Error('changed output token capability also failed outside the hand-off input');
}
const changedCapability = { run: toRun(changedCapabilityAsm), rejected: true };
console.error('  mutable-to-none capability change rejected at group hand-off');

// A same-category NFT on an existing sibling input must not be able to enter the state thread.
const siblingTokenAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((group) => ({ ...group })) };
const siblingTokenGroup = siblingTokenAsm.gmeta[0];
const siblingTokenLocalIndex = 1;
siblingTokenGroup.inputTokens = Array.from(
  { length: siblingTokenGroup.hi - siblingTokenGroup.lo + 1 },
  (_, index) => index === siblingTokenLocalIndex
    ? { cap: 'mutable', commit: Uint8Array.of(1) }
    : null,
);
const siblingTokenInputs = siblingTokenAsm.inputs.slice(siblingTokenGroup.lo, siblingTokenGroup.hi + 1);
const siblingTokenOutcomes = siblingTokenInputs.map((_, index) =>
  evalGroup(siblingTokenInputs, index, siblingTokenGroup));
if (siblingTokenOutcomes[0].accepted) throw new Error('same-category sibling token was accepted');
const unrelatedSiblingTokenFailure = siblingTokenOutcomes.find(
  (outcome, index) => index !== 0 && !outcome.accepted,
);
if (unrelatedSiblingTokenFailure) {
  throw new Error('same-category sibling token also failed outside the group root');
}
const siblingTokenInjection = { run: toRun(siblingTokenAsm), rejected: true };
console.error('  same-category sibling token rejected at group root');

// Capability continuity alone is insufficient: the carried NFT must be mutable, not minting.
const mintingThreadAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((group) => ({
  ...group,
  inToken: group.inToken ? { ...group.inToken } : null,
  outToken: group.outToken ? { ...group.outToken } : null,
})) };
const mintingThreadGroup = mintingThreadAsm.gmeta.find((group) => group.outToken !== null);
if (!mintingThreadGroup) throw new Error('missing nonterminal token-thread fixture');
mintingThreadGroup.inToken.cap = 'minting';
mintingThreadGroup.outToken.cap = 'minting';
const mintingThreadInputs = mintingThreadAsm.inputs.slice(mintingThreadGroup.lo, mintingThreadGroup.hi + 1);
const mintingThreadOutcomes = mintingThreadInputs.map((_, index) =>
  evalGroup(mintingThreadInputs, index, mintingThreadGroup));
if (mintingThreadOutcomes[0].accepted) throw new Error('minting token thread was accepted');
if (mintingThreadOutcomes.some((outcome, index) => index !== 0 && !outcome.accepted)) {
  throw new Error('minting token thread also failed outside the group root');
}
const mintingThread = { run: toRun(mintingThreadAsm), rejected: true };
console.error('  minting input/output thread rejected at group root');

// The terminal group spends the last mutable state NFT and must not recreate it.
const retainedTerminalTokenAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((group) => ({ ...group })) };
const retainedTerminalTokenGroup = retainedTerminalTokenAsm.gmeta.at(-1);
if (!retainedTerminalTokenGroup || retainedTerminalTokenGroup.outToken !== null) {
  throw new Error('missing terminal token-burn fixture');
}
retainedTerminalTokenGroup.outToken = {
  cap: 'mutable',
  commit: Uint8Array.from(retainedTerminalTokenGroup.inToken.commit),
};
retainedTerminalTokenGroup.outLocking = OP_RETURN;
const retainedTerminalTokenInputs = retainedTerminalTokenAsm.inputs.slice(
  retainedTerminalTokenGroup.lo,
  retainedTerminalTokenGroup.hi + 1,
);
const retainedTerminalTokenOutcomes = retainedTerminalTokenInputs.map((_, index) =>
  evalGroup(retainedTerminalTokenInputs, index, retainedTerminalTokenGroup));
if (retainedTerminalTokenOutcomes[0].accepted) throw new Error('retained terminal thread token was accepted');
if (retainedTerminalTokenOutcomes.some((outcome, index) => index !== 0 && !outcome.accepted)) {
  throw new Error('retained terminal thread token also failed outside the group root');
}
const retainedTerminalToken = { run: toRun(retainedTerminalTokenAsm), rejected: true };
console.error('  retained terminal thread token rejected at group root');

// Every in-transaction edge pins the successor program, and every group root fixes
// both its transaction-local position and the exact number of group inputs.
let representativeWithinGroupLock = null;
let pinnedWithinGroupEdges = 0;
GROUPS.forEach(([lo, hi], groupIndex) => {
  const groupInputs = asmCommitted.inputs.slice(lo, hi + 1);
  for (let index = 0; index < groupInputs.length - 1; index++) {
    const changed = groupInputs.map((input) => ({ ...input }));
    const successorLocking = Uint8Array.from(changed[index + 1].locking);
    successorLocking[successorLocking.length - 1] ^= 0x01;
    changed[index + 1] = { ...changed[index + 1], locking: successorLocking };
    if (evalGroup(changed, index, asmCommitted.gmeta[groupIndex]).accepted) {
      throw new Error(`changed in-group successor locking was accepted at edge ${lo + index} -> ${lo + index + 1}`);
    }
    if (representativeWithinGroupLock === null) {
      const allInputs = asmCommitted.inputs.slice();
      allInputs[lo + index + 1] = changed[index + 1];
      representativeWithinGroupLock = { run: toRun({ ...asmCommitted, inputs: allInputs }), rejected: true };
    }
    pinnedWithinGroupEdges += 1;
  }

  const extraInput = { ...groupInputs[groupInputs.length - 1] };
  if (evalGroup([...groupInputs, extraInput], 0, asmCommitted.gmeta[groupIndex]).accepted) {
    throw new Error(`group ${groupIndex} root accepted an extra transaction input`);
  }
  if (groupInputs.length > 1) {
    const shifted = [groupInputs[1], groupInputs[0], ...groupInputs.slice(2)];
    if (evalGroup(shifted, 1, asmCommitted.gmeta[groupIndex]).accepted) {
      throw new Error(`group ${groupIndex} root accepted transaction-local index 1`);
    }
  }
});
if (representativeWithinGroupLock === null) throw new Error('missing in-group successor edge fixture');
console.error(`  ${pinnedWithinGroupEdges} in-group successor locks and ${GROUPS.length} exact group layouts verified`);

const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1;
const invalids = [
  invalidRun(cSpecs, GROUPS, Math.floor(cSpecs.length / 2)),
  invalidRun(cSpecs, GROUPS, firstBoundary),
  tableMutation,
  changedSuccessorLock,
  changedCapability,
  siblingTokenInjection,
  mintingThread,
  retainedTerminalToken,
  representativeWithinGroupLock,
];
function changedSpecRun(specs, index, mutate, label) {
  const changed = specs.map((spec) => ({ ...spec, inLimbs: [...spec.inLimbs], outLimbs: [...spec.outLimbs], extras: [...spec.extras] }));
  mutate(changed[index]);
  const asm = assembleGrouped(changed, GROUPS, true);
  if (asm.accepted) throw new Error(`${label} was accepted`);
  return { run: toRun(asm), rejected: true };
}
const yInvMutation = changedSpecRun(cSpecs, GLV_COUNT - 1, (spec) => {
  spec.extras[0] = BigInt(spec.extras[0]) + 1n;
}, 'changed GLV Y inverse');
const alteredIdentityInput = changedSpecRun(completenessRuns.find(({ tag }) => tag === 'A').specs, 0, (spec) => {
  spec.inLimbs[0] = BigInt(spec.inLimbs[0]) + 1n;
}, 'altered public input on identity proof');
const normalizedHandoffMutation = changedSpecRun(cSpecs, GLV_COUNT, (spec) => {
  const vkxOffset = ROOT_LIMBS + 6;
  spec.inLimbs[vkxOffset] = (BigInt(spec.inLimbs[vkxOffset]) + 1n) % P;
}, 'changed normalized vk_x handoff');

// Isolate the fused A on-curve and B subgroup checks from the residue verdict.
const committedPairs = pairsFor(INSTANCES.committed.inputs, INSTANCES.committed.proof);
const { boundary: committedRawBoundary } = millerBatchOps(committedPairs, { unitLines: UNIT_G1 });
const committedRoot = QUOTIENT_TORUS
  ? residueTorusWitness(committedRawBoundary)
  : residueWitness(committedRawBoundary);
const { c: committedC, cInv: committedCInv, u: committedU = null } = committedRoot;
const isolated = (specs) => assembleGrouped(specs, packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES), true);
const negA = proof.a.negate().toAffine();
const firstMiller = specsMillerResidue(
  INSTANCES.committed, committedC, committedCInv, committedU, { Ay: (negA.y + 1n) % P },
).specs[0];
firstMiller.role = 'stage-final'; firstMiller.cmp = null;
const offCurveA = isolated([firstMiller]);
const finiteC = proof.c.toAffine();
const offCurveCFirstMiller = specsMillerResidue(
  INSTANCES.committed, committedC, committedCInv, committedU, { Cy: (finiteC.y + 1n) % P },
).specs[0];
offCurveCFirstMiller.role = 'stage-final'; offCurveCFirstMiller.cmp = null;
const offCurveC = isolated([offCurveCFirstMiller]);
if (offCurveC.meta[0].accepted) throw new Error('finite off-curve C passed grouped-residue Miller input validation');
const plusPFirstMiller = specsMillerResidue(
  INSTANCES.committed, committedC, committedCInv, committedU, { Ax: negA.x + P },
).specs[0];
plusPFirstMiller.role = 'stage-final'; plusPFirstMiller.cmp = null;
const plusPRange = isolated([plusPFirstMiller]);
if (plusPRange.meta[0].accepted) throw new Error('+P proof encoding passed grouped-residue Miller input validation');
const twistB = F2.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2.create({ c0: i, c1: 0n });
  const rhs = F2.add(F2.mul(F2.sqr(x), x), twistB);
  let y; try { y = F2.sqrt(rhs); } catch { continue; }
  if (!F2.eql(F2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; }
}
if (!offSub) throw new Error('failed to construct off-subgroup B grouped-residue fixture');
const offSubInst = {
  inputs: INSTANCES.committed.inputs,
  proof: { ...INSTANCES.committed.proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const offSubSpecs = specsMillerResidue(offSubInst, committedC, committedCInv, committedU).specs;
offSubSpecs[offSubSpecs.length - 1].role = 'stage-final';
offSubSpecs[offSubSpecs.length - 1].cmp = null;
const offSubgroupB = isolated(offSubSpecs);
const semanticInvalids = [offCurveA, offCurveC, offSubgroupB, plusPRange]
  .map((asm) => ({ run: toRun(asm), rejected: !asm.accepted }));

function rangeInvalid(spec, location, value, label) {
  const candidate = { ...spec, extras: [...spec.extras], role: 'stage-final', cmp: null, label };
  if (location.extra !== undefined) candidate.extras[location.extra] = value;
  const asm = assembleGrouped([candidate], [[0, 0]], location.extra !== undefined);
  if (location.limb !== undefined) {
    const unlocking = Uint8Array.from(asm.inputs[0].unlocking);
    const pushed = pushBounds(unlocking);
    if (pushed.dataLen !== candidate.inLimbs.length * W) throw new Error(`${label} has an unexpected input blob length`);
    const encoded = le48Exact(value < 0n ? -value : value);
    if (value < 0n) encoded[W - 1] |= 0x80;
    unlocking.set(encoded, pushed.dataStart + location.limb * W);
    asm.inputs[0] = { ...asm.inputs[0], unlocking };
  }
  const consensusOutcome = evalGroup(asm.inputs, 0, asm.gmeta[0]);
  const standardOutcome = evalGroup(asm.inputs, 0, asm.gmeta[0], standardVm);
  if (consensusOutcome.accepted || standardOutcome.accepted) {
    throw new Error(`${label} passed a residue witness range gate`);
  }
  return { run: toRun(asm), rejected: true };
}

const firstRangeMiller = cSpecs[GLV_COUNT];
const firstRangeTail = cSpecs.find((spec) => spec.file.includes('finalexpres_'));
if (!firstRangeMiller || (!QUOTIENT_TORUS && !firstRangeTail)) {
  throw new Error('missing residue witness range fixture stage');
}
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
const torusInvalids = [];
if (QUOTIENT_TORUS) {
  const terminalSpec = cSpecs[cSpecs.length - 1];
  const terminalInvalid = (mutate, label) => {
    const inLimbs = terminalSpec.inLimbs.slice();
    mutate(inLimbs);
    const asm = assembleGrouped([{ ...terminalSpec, inLimbs, label }], [[0, 0]], true);
    if (asm.accepted) throw new Error(`${label} passed the quotient terminal`);
    return { run: toRun(asm), rejected: true };
  };
  torusInvalids.push(
    terminalInvalid((limbs) => {
      for (let i = 0; i < 12; i++) limbs[i] = 0n;
    }, 'reject projective zero quotient state'),
    terminalInvalid((limbs) => {
      limbs[0] = (BigInt(limbs[0]) + 1n) % P;
    }, 'reject wrong nonzero quotient class'),
    terminalInvalid((limbs) => {
      const rootOffset = limbs.length - 6;
      limbs[rootOffset] = (BigInt(limbs[rootOffset]) + 1n) % P;
    }, 'reject wrong quotient root'),
  );
}
const aIdentityFirst = completenessRuns.find(({ tag }) => tag === 'A').specs[GLV_COUNT];
const bIdentityFirst = completenessRuns.find(({ tag }) => tag === 'B').specs[GLV_COUNT];
const cIdentityFirst = completenessRuns.find(({ tag }) => tag === 'C').specs[GLV_COUNT];
const identityEncodingInvalids = [
  rangeInvalid(aIdentityFirst, { limb: ROOT_LIMBS + 4 }, 1n, 'reject malformed A identity'),
  rangeInvalid(cIdentityFirst, { limb: ROOT_LIMBS + 8 }, 1n, 'reject malformed C identity'),
  rangeInvalid(bIdentityFirst, { limb: ROOT_LIMBS }, 1n, 'reject partial-zero B identity'),
  rangeInvalid(aIdentityFirst, { limb: ROOT_LIMBS + 4 }, P, 'reject non-canonical A identity'),
  rangeInvalid(bIdentityFirst, { limb: ROOT_LIMBS }, P, 'reject non-canonical B identity'),
  rangeInvalid(
    bIdentityFirst,
    { limb: ROOT_LIMBS + 5 },
    (BigInt(bIdentityFirst.inLimbs[ROOT_LIMBS + 5]) + 1n) % P,
    'validate A even when B is identity',
  ),
];
const allInvalids = [
  ...invalids, yInvMutation, alteredIdentityInput, normalizedHandoffMutation,
  ...semanticInvalids, ...rangeInvalids, ...torusInvalids, ...identityEncodingInvalids,
];
console.error(`  invalid runs rejected: ${allInvalids.map((r) => r.rejected).join(',')}`);
if (!asmCommitted.fits || !asmProof1.fits || !asmStress.fits || !allInvalids.every((r) => r.rejected)) {
  console.error('!! a run failed -- NOT writing vectors'); process.exit(1);
}

const extraValidAsms = [asmProof1, ...completenessRuns.map(({ asm }) => asm)];
const observedValidAsms = [asmCommitted, ...extraValidAsms, asmStress];
const observedValidMetadata = observedValidAsms.map(transactionMetadata);
const observedValidFixtureEnvelope = {
  scriptBytes: Math.max(...observedValidMetadata.map((meta) => meta.totalBytes)),
  serializedTransactionBytes: Math.max(...observedValidMetadata.map((meta) =>
    sum(meta.groupBytes, (bytes) => bytes))),
  largestSingleTransactionBytes: Math.max(...observedValidMetadata.flatMap((meta) => meta.groupBytes)),
  totalOperationCost: Math.max(...observedValidMetadata.map((meta) => meta.totalOperationCost)),
  maxStepOperationCost: Math.max(...observedValidMetadata.map((meta) => meta.maxStepOperationCost)),
  maxUnlockingBytes: Math.max(...observedValidMetadata.map((meta) => meta.maxUnlockingBytes)),
};
const description = QUOTIENT_TORUS
  ? 'GROUPED + QUOTIENT-TORUS BLS12-381 Groth16 verifier: 34 inputs packed into current-policy standard transactions. ' +
    'The graph is five shared-table GLV vk_x chunks followed by 29 input-validation-fused Miller chunks; the final Miller input executes the quotient terminal. ' +
    'The immutable six-limb root represents the finite class [c]=[1+u*W] in Fp12*/Fp6*, and the terminal checks the exact projective Frobenius relation while excluding [0:0]. ' +
    'Every in-group program pins its immediate successor locking and state; every group root fixes input index zero and the exact transaction input count. ' +
    'Across groups, a CashToken NFT commitment and pinned successor P2SH32 locking bind the state and program. One fixed locking graph verifies every proof for the VK.'
  : 'GROUPED + RESIDUE BLS12-381 Groth16 verifier: 35 inputs packed into four standard transactions. ' +
    'The graph is five shared-table GLV vk_x chunks, 29 input-validation-fused prepared Miller chunks, and one terminal residue chunk. ' +
    'The terminal checks c*cInv==1 and fF*w==frob(c,1), with w supplied directly as six Fp6 limbs and its Fp12 upper half fixed to zero; ' +
    'p^6-1 divides (p^12-1)/r, and the terminal equations exclude zero. Every in-group program pins its immediate successor locking and state; ' +
    'every group root fixes input index zero and the exact transaction input count. Across groups, a CashToken NFT commitment and pinned successor P2SH32 locking bind the state. One fixed locking graph verifies every proof for the VK.';

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-grouped-residue-vectors.json'), JSON.stringify({
  description,
  method: QUOTIENT_TORUS ? 'grouped-quotient-torus' : 'grouped-residue',
  deployment: 'P2SH32', curve: 'BLS12-381', category: binToHex(CATEGORY),
  numInputs: asmCommitted.meta.length, numGroups: GROUPS.length, budgetPerInput: OP_BUDGET,
  groupSizes: GROUPS.map(([lo, hi]) => hi - lo + 1),
  ...transactionMetadata(asmCommitted),
  allFit: asmCommitted.fits, allAccept: asmCommitted.accepted,
  valid: toRun(asmCommitted),
  extraValidProofs: [toRun(asmProof1), ...completenessRuns.map(({ asm }) => toRun(asm))],
  extraValidProofTransactions: extraValidAsms.map(transactionMetadata),
  identityProofTags: completenessRuns.map(({ tag }) => tag),
  worstCaseProof: toRun(asmStress),
  worstCaseTransaction: transactionMetadata(asmStress),
  observedValidFixtureEnvelope,
  invalid: allInvalids.map((r) => r.run),
  invalidInputs: [toRun(offCurveA), toRun(offCurveC), toRun(offSubgroupB), toRun(plusPRange)],
}, null, 2));
console.error(`wrote groth16-bls12381-grouped-residue-vectors.json (${GROUPS.length} groups, ${asmCommitted.meta.length} inputs)`);
