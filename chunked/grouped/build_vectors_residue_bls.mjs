// GROUPED + RESIDUE verifier vectors for BLS12-381 — the residue-optimized chunk graph packed
// into a handful of standard (<100,000 B) transactions. The BLS counterpart of
// chunked/grouped/build_vectors_residue.mjs (BN254), and the residue analog of
// build_vectors_bls.mjs (this reuses that file's grouping/assembly machinery verbatim; only the
// per-stage chunk graph changes).
//
// Chunk graph (vs the plain BLS grouped's g2check -> vk_x -> 4-pair Miller -> final exp):
//   GLV vk_x (4-scalar 128-bit Straus, baked table)                -> 5 chunks
//   c^-|x|-FUSED prepared-VK batched Miller (e(a,b) baked, cmul1),
//     with G2 validation fused into its first/last chunks           -> 30 chunks
//   witnessed-residue tail: ((w^|x|)*w)^9 walk + fF*w==frob(c,1)   -> 6 chunks
//                                                                     ---------
//                                                                     41 inputs
// The hard-part final exponentiation (Hayashida-Scott, 23 chunks in the plain build) collapses to
// the residue tail. c,cInv thread through every fused-Miller chunk as constant witness; w enters
// the tail as an uncommitted witness and is re-derived/checked there (see gen_finalexp_residue).
//
//   node build_vectors_residue_bls.mjs -> verifier/src/bch/groth16-bls12381-grouped-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs,
  compileBytecode, commitBin, CATEGORY, le48, P, OP_DROP, TARGET_UNLOCK, OP_BUDGET,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileBytecodeRaw, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { residueWitness, millerFusedOps } from '../bls12-381/_residuemath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, GLV_TABLE_HEX,
  GLV_ALL_POSITIONS_INPUTS, GLV_SHARED_SAFE_BOUNDS, regenGlvSharedSafe,
} from '../bls12-381/gen_vkx_glv.mjs';
import { residueWalkT } from '../bls12-381/gen_finalexp_residue.mjs';
import { transformChunk, headerSize } from '../intratx/transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const W = 48; // BLS12-381 limb width
const PRIME = P.toString();
import { hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));

// SHARED GLV TABLE: the 1,440-byte Straus table rides ONCE in the final GLV input (right after its
// 9-limb inBlob push); the four sibling GLV inputs read that exact slice via input-bytecode
// introspection and the carrier pins it with hash256. The GLV chunks lead the graph and the packer
// blocks cuts inside the span, so the carrier's transaction-local index equals its graph index.
const GLV_COUNT = GLV_SHARED_SAFE_BOUNDS.length - 1;
const GLV_STATE_BYTES = 9 * W; // rX,rY,rZ,in0,in1,k10,k20,k11,k21
regenGlvSharedSafe(GEN, {
  inputIndex: GLV_COUNT - 1,
  dataOffset: headerSize(GLV_STATE_BYTES) + GLV_STATE_BYTES + headerSize(GLV_TABLE_BYTES.length),
});

const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le48(((BigInt(l) % P) + P) % P)]));
const commitOf = (limbs) => commitBin(limbs.map(BigInt));
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
function evalGroup(inputs, index, gm, vm = realVm) {
  const st = vm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((inp, n) => ({ lockingBytecode: inp.locking, valueSatoshis: 1000n, token: n === 0 ? tokenOf(gm.inToken) : undefined })),
    transaction: {
      version: 2,
      inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
      outputs: gm.outToken
        ? [{ lockingBytecode: gm.outLocking, valueSatoshis: 1000n, token: tokenOf(gm.outToken) }]
        : [{ lockingBytecode: OP_RETURN, valueSatoshis: 1000n }],
      locktime: 0,
    },
  });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// ---- instances: #0 committed, #1 distinct (same VK; only A and vk_x change) ----
const G1 = bls12_381.G1.Point;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);
  const A = mod(3n * 5n + vx * 7n + 13n * 11n);
  return { inputs, proof: { a: G1.BASE.multiply(A), b: proof.b, c: proof.c } };
};
const INSTANCES = { committed: { inputs: PUBLIC_INPUTS, proof }, proof1: mkInstance([135208n, 67633n]), allPositions: mkInstance(GLV_ALL_POSITIONS_INPUTS) };

// ---- residue chunk-graph layout constants ----
// fused-Miller state = f(12) + R_B(6) + runtime points(10) + c(12) + cInv(12) = 52 limbs.
// runtime points ptL = pair0 (-A.x,-A.y, Bxa,Bxb,Bya,Byb) + pair2 (vkxX,vkxY) + pair3 (Cx,Cy).
const MILLER_STATE_LIMBS = 12 + 6; // f + R_B
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const ptLof = (inst) => { const pr = pairsFor(inst.inputs, inst.proof); return pr.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())); };
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length; // vk_x = pair2 P, at 18+6 = 24
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + ptLof(INSTANCES.committed).length; // 18 + 10 = 52
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]

// ---- per-stage specs ----------------------------------------------------------------
const stateLimbsR = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 42
const withPtsR = (limbs, ptL) => [...limbs.slice(0, 18), ...ptL, ...limbs.slice(18)]; // insert ptL after f+R_B

// g2check is no longer a standalone stage — the on-curve checks + G2 subgroup test are fused into
// the first/last fused-Miller chunks (see gen_miller_residue.mjs), reusing R_B = [|x|]B.
function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const scal = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.sharedTable !== true) throw new Error('grouped BLS residue requires shared-table GLV generation');
  return man.chunks.map((ch) => {
    const inLimbs = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scal];
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxGlvZinv(k10, k20, k11, k21), GLV_TABLE_BYTES], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
      label: 'GLV vk_x final -> assemble vk_x', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scal], extras: [], role: 'within', label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMillerResidue(inst, c, cInv) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  const specs = man.chunks.map((ch) => {
    const inLimbs = withPtsR(stateLimbsR(states[ch.opLo]), ptL);
    if (ch.final) {
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
  const fFl = f12limbs(fF), cl = f12limbs(c), cil = f12limbs(cInv), wl = f12limbs(w);
  const commit36 = [...fFl, ...cl, ...cil];
  const state5At = (upto) => [...fFl, ...cl, ...cil, ...wl, ...f12limbs(residueWalkT(w, upto))];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexpres.json'), 'utf8'));
  return man.chunks.map((ch) => {
    if (ch.role === 'walk') {
      const first = ch.lo === 0;
      return {
        file: join(GEN, `finalexpres_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs: first ? commit36 : state5At(ch.lo), outLimbs: state5At(ch.hi), extras: first ? wl : [],
        role: 'within', label: `residue walk[${ch.lo},${ch.hi})`, checkpoint: first ? 'residue-witness' : undefined,
      };
    }
    return {
      file: join(GEN, `finalexpres_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs: state5At(63), outLimbs: [], extras: [], role: 'terminal',
      label: 'residue finalize -> verdict', checkpoint: 'verify',
    };
  });
}
function buildSpecs(inst) {
  // g2check is no longer a standalone stage: its on-curve checks + G2 subgroup test are fused into
  // the first/last fused-Miller chunks (the Miller loop already walks R_B = [|x|]B). See
  // gen_miller_residue.mjs. This drops ~3 chunks / ~28 KB of op-cost-bought padding.
  const vkx = specsVkxGlv(inst);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const { specs: miller, boundary: fF } = specsMillerResidue(inst, c, cInv);
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
  return { covInHash, epilogueMode, forward };
}

const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map();
const PROBE = join(GEN, '_grouped_residue_probe.cash');
const cfgKey = (spec, cfg) => `${spec.file}|${cfg.covInHash ? 'ci' : ''}|${cfg.epilogueMode ?? ''}|${JSON.stringify(cfg.forward)}`;
function compileChunk(spec, cfg) {
  const key = cfgKey(spec, cfg);
  let v = compileCache.get(key);
  if (!v) {
    const t = transformChunk(readFileSync(spec.file, 'utf8'), { W, prime: PRIME, forward: cfg.forward, covInHash: cfg.covInHash, epilogueMode: cfg.epilogueMode });
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

function assembleGrouped(specs, groups) {
  const G = groups.length;
  const cfgs = specs.map((_, i) => {
    const gi = groups.findIndex(([lo, hi]) => i >= lo && i <= hi);
    return { ...groupedCfg(specs, i, groups[gi][0], groups[gi][1], gi, G), group: gi };
  });
  const redeems = specs.map((s, i) => compileChunk(s, cfgs[i]));
  const lockings = redeems.map((r) => p2shSpk(r));
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
  for (let gi = 0; gi < G - 1; gi++) {
    const a = binToHex(gmeta[gi].outToken.commit), b = binToHex(gmeta[gi + 1].inToken.commit);
    if (a !== b) throw new Error(`group ${gi} hand-off mismatch: ${a} != ${b}`);
  }

  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) op1[lo + k] = evalGroup(ins, k, gmeta[gi]); });
  const standardOp1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) standardOp1[lo + k] = evalGroup(ins, k, gmeta[gi], standardVm); });
  if ([...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
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
    if (switched) return assembleGrouped(specs, groups);
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
    if (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted)) break;
    const tightened = targets.map((target, i) => Math.min(target, tunedLen(
      argB[i].length + rpush[i].length,
      Math.max(op2[i].operationCost, standardOp2[i].operationCost),
    )));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted)) {
    throw new Error('tightened input rejected during padding measurement');
  }

  const meta = specs.map((s, i) => ({
    label: s.label, checkpoint: s.checkpoint, group: cfgs[i].group,
    lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
    operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error,
  }));
  const accepted = op2.every((o) => o.accepted);
  const groupBytes = groups.map(([lo, hi], gi) => {
    let b = 8 + 1 + 1;
    for (let i = lo; i <= hi; i++) b += allInputs[i].unlocking.length + PER_INPUT_OV;
    b += gmeta[gi].outToken ? 8 + 3 + (1 + 32 + 1 + 1 + 32) : 8 + 1 + 1;
    return b;
  });
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted && groupBytes.every((b) => b <= 100000);
  return { inputs: allInputs, meta, gmeta, groups, groupBytes, fits, accepted };
}

const toStep = (asm, i) => ({ label: asm.meta[i].label, locking: binToHex(asm.inputs[i].locking), unlocking: binToHex(asm.inputs[i].unlocking), checkpoint: asm.meta[i].checkpoint, group: asm.meta[i].group });
const toRun = (asm) => ({
  steps: asm.inputs.map((_, i) => toStep(asm, i)),
  groups: asm.gmeta.map((g) => ({
    lo: g.lo, hi: g.hi,
    inToken: g.inToken ? { capability: g.inToken.cap, commitment: binToHex(g.inToken.commit) } : null,
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
const report = (tag, asm) => {
  console.error(`${tag}: ${asm.meta.length} inputs / ${asm.groups.length} groups, accepted=${asm.accepted} fits=${asm.fits}`);
  console.error(`  groups (chunks): ${asm.groups.map(([lo, hi]) => hi - lo + 1).join(',')}  group bytes: ${asm.groupBytes.map((b) => b.toLocaleString()).join(', ')}`);
  console.error(`  totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()} maxUnlock=${Math.max(...asm.meta.map((m) => m.unlockingBytes))}`);
  asm.meta.filter((m) => !m.accepted).slice(0, 6).forEach((m) => console.error(`  !! non-accepting: g${m.group} ${m.label} :: op=${m.operationCost.toLocaleString()} err=${m.error}`));
};

// ===================== build =====================
const TARGET_GROUP_BYTES = 84000;
console.error('building residue specs (residueWitness per instance ~seconds)...');
const cSpecs = buildSpecs(INSTANCES.committed);
const p1Specs = buildSpecs(INSTANCES.proof1);
const allPositionSpecs = buildSpecs(INSTANCES.allPositions);
function sizeEstimate(specs) {
  const provisional = packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES);
  return assembleGrouped(specs, provisional).meta.map((m) => m.unlockingBytes);
}
const cSizes = sizeEstimate(cSpecs), p1Sizes = sizeEstimate(p1Specs), allPositionSizes = sizeEstimate(allPositionSpecs);
const packSizes = cSizes.map((s, i) => Math.max(s, p1Sizes[i], allPositionSizes[i]));
const GROUPS = packGroups(cSpecs, packSizes, TARGET_GROUP_BYTES);

const asmCommitted = assembleGrouped(cSpecs, GROUPS);
report('groth16-bls-grouped-residue committed', asmCommitted);
const asmProof1 = assembleGrouped(p1Specs, GROUPS);
report('groth16-bls-grouped-residue proof#1', asmProof1);
const asmAllPositions = assembleGrouped(allPositionSpecs, GROUPS);
report('groth16-bls-grouped-residue all-positions', asmAllPositions);

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

const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1;
const invalids = [invalidRun(cSpecs, GROUPS, Math.floor(cSpecs.length / 2)), invalidRun(cSpecs, GROUPS, firstBoundary), tableMutation];
console.error(`  invalid runs rejected: ${invalids.map((r) => r.rejected).join(',')}`);
if (!asmCommitted.accepted || !asmProof1.accepted || !asmAllPositions.fits || !invalids.every((r) => r.rejected)) {
  console.error('!! a run failed -- NOT writing vectors'); process.exit(1);
}

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-bls12381-grouped-residue-vectors.json', JSON.stringify({
  description: 'GROUPED + RESIDUE BLS12-381 Groth16 verifier: the residue-optimized chunk graph (G2 validation fused into the Miller stage; 5-chunk GLV 4-scalar vk_x MSM; c^-|x|-FUSED prepared-VK batched Miller with e(alpha,beta) baked and only e(-A,B) running on-chain G2 arithmetic; witnessed-residue final-exp tail collapsing the Hayashida-Scott hard part to a ((w^|x|)*w)^9 mu_(27A) walk + fF*w==frob(c,1) verdict) packed into five STANDARD (<100,000 B) transactions. The five GLV inputs share one hash-bound fixed lookup table carried by the final GLV input rather than embedding five copies. Within each group tx the chunks forward-check each other via OP_INPUTBYTECODE; across groups the running state rides a CashToken NFT commitment. The residue witness (c, cInv) threads through every fused-Miller chunk; w enters the tail as an uncommitted witness. One fixed set of lockings verifies any proof for the VK. Deployed P2SH32.',
  method: 'grouped-residue', deployment: 'P2SH32', curve: 'BLS12-381', category: binToHex(CATEGORY),
  numInputs: asmCommitted.meta.length, numGroups: GROUPS.length, budgetPerInput: OP_BUDGET,
  groupSizes: GROUPS.map(([lo, hi]) => hi - lo + 1),
  groupBytes: asmCommitted.groupBytes,
  totalBytes: sum(asmCommitted.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(asmCommitted.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...asmCommitted.meta.map((m) => m.operationCost)),
  allFit: asmCommitted.fits, allAccept: asmCommitted.accepted,
  valid: toRun(asmCommitted),
  extraValidProofs: [toRun(asmProof1)],
  worstCaseProof: toRun(asmAllPositions),
  invalid: invalids.map((r) => r.run),
}, null, 2));
console.error(`wrote groth16-bls12381-grouped-residue-vectors.json (${GROUPS.length} groups, ${asmCommitted.meta.length} inputs)`);
