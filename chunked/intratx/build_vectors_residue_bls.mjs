// INTRA-TRANSACTION LINKED + RESIDUE verifier vectors for BLS12-381 — the BLS counterpart of
// build_vectors_residue.mjs (BN254) and the intra-tx cousin of the grouped-residue BLS build
// (chunked/grouped/build_vectors_residue_bls.mjs).
//
// Same single-transaction forward-checking mechanism as build_vectors_bls.mjs (each chunk is an
// INPUT whose witness carries its incoming state as a raw 48-byte-limb blob and require()s the
// next input's blob — read via tx.inputs[idx+1].unlockingBytecode — equals its recomputed output;
// no NFT commitment, no hashing, arbitrary intermediate size), but it consumes an optimized
// residue graph instead of the plain one. The default path remains the 35-input Fp6-tail graph:
//
//   GLV vk_x MSM (4-scalar ~128-bit Straus, baked table)              5 chunks
//   c^-|x|-FUSED batched Miller, e(alpha,beta) baked (cmul1); the G2   29 chunks
//     on-curve + subgroup check is FUSED in (first/last chunks reuse R_B=[|x|]B)
//   witnessed-residue final-exp TAIL: w in Fp6* + terminal relation    1 chunk
//                                                                     ---------
//                                                                     35 inputs
//
// With BLS_QUOTIENT_TORUS=1, the generated Miller windows instead carry the six-limb finite class
// [c]=[1+u*W] in Fp12*/Fp6*. The final Miller input performs the projective terminal check, so
// the correction w and separate tail disappear. The one-command frontier path pins this linked
// affine-G1 schedule; the grouped quotient path is separately pinned and the default Fp6-tail path
// remains unchanged. The opt-in generator proves the quotient construction before this builder
// writes its vector. One fixed set of
// lockings verifies any proof for the VK in either mode.
//
//   node build_vectors_residue_bls.mjs -> verifier/src/bch/groth16-bls12381-intratx-residue-vectors.json
//   VERIFIER_DIR=/path/to/verifier pnpm vectors:intratx:torus:bls  # quotient frontier
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs,
  le48Exact, P, OP_DROP, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import {
  millerFusedOps, millerFusedTorusOps, residueTorusWitness, residueWitness,
} from '../bls12-381/_residuemath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, GLV_TABLE_HEX,
  GLV_SHARED_AUDITED_BOUNDS, regenGlvSharedAudited,
} from '../bls12-381/gen_vkx_glv.mjs';
import {
  LINKED_HIGH_COST_INPUTS, LINKED_RESIDUE_NAMESPACE, LINKED_TORUS_GLV_BOUNDS,
} from '../bls12-381/_residue_linked_plan.mjs';
import { transformChunk, headerSize } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const QUOTIENT_TORUS = process.env.BLS_QUOTIENT_TORUS === '1';
const GEN = join(here, '..', 'bls12-381', 'generated', LINKED_RESIDUE_NAMESPACE);
const PROBE = join(GEN, '_intratx_residue_bls_probe.cash'); // transformed import-chunks compiled from here
const W = 48; // BLS12-381 limb width (bytes)
const PRIME = P.toString();
import {
  hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32,
  encodeDataPush, encodeTransactionBch, createVirtualMachineBch2026,
} from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE = 1n;
const TRANSACTION_OUTPUT_SATOSHIS = 1000n;
const OP_RETURN = Uint8Array.from([0x6a]);
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));
const GLV_BOUNDS = QUOTIENT_TORUS ? LINKED_TORUS_GLV_BOUNDS : GLV_SHARED_AUDITED_BOUNDS;
const GLV_COUNT = GLV_BOUNDS.length - 1;

// SHARED GLV TABLE: the 1,440-byte Straus table rides ONCE in the final GLV input (right after its
// 9-limb inBlob push); the four sibling GLV inputs read that exact slice via input-bytecode
// introspection and the carrier pins it with hash256.
{
  const GLV_STATE_BYTES = 9 * W; // rX,rY,rZ,in0,in1,k10,k20,k11,k21
  regenGlvSharedAudited(GEN, {
    inputIndex: GLV_COUNT - 1,
    dataOffset: headerSize(GLV_STATE_BYTES) + GLV_STATE_BYTES + headerSize(GLV_TABLE_BYTES.length),
  }, true, false, GLV_BOUNDS);
}

// Deploy as P2SH so the ~4-5 KB redeem (in the scriptSig) counts toward the op-cost budget and
// offsets the pad (~30% smaller on-chain than bare). See build_vectors_bls.mjs.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((limb) => [...le48Exact(limb)]));
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));

// ---- multi-input evaluation: build ONE exactly funded tx, evaluate at `index` ----
function verificationData(inputs) {
  if (inputs.length === 0) throw new Error('cannot build an empty verifier transaction');
  const transaction = {
    version: 2,
    inputs: inputs.map((i, n) => ({
      outpointTransactionHash: new Uint8Array(32), outpointIndex: n,
      sequenceNumber: 0, unlockingBytecode: i.unlocking,
    })),
    outputs: [{ lockingBytecode: OP_RETURN, valueSatoshis: TRANSACTION_OUTPUT_SATOSHIS }],
    locktime: 0,
  };
  const feeSatoshis = BigInt(encodeTransactionBch(transaction).length) *
    DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE;
  const totalInputSatoshis = TRANSACTION_OUTPUT_SATOSHIS + feeSatoshis;
  const perInputSatoshis = totalInputSatoshis / BigInt(inputs.length);
  const remainder = totalInputSatoshis % BigInt(inputs.length);
  return {
    sourceOutputs: inputs.map((i, n) => ({
      lockingBytecode: i.locking,
      valueSatoshis: perInputSatoshis + (BigInt(n) < remainder ? 1n : 0n),
    })),
    transaction,
  };
}
function evalInput(inputs, index, vm = realVm) {
  const st = vm.evaluate({ inputIndex: index, ...verificationData(inputs) });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// ---- instances: #0 committed, #1 distinct (same VK; only A and vk_x change) ----
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point, F2 = bls12_381.fields.Fp2;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);
  const A = mod(3n * 5n + vx * 7n + 13n * 11n);
  return { inputs, proof: { a: G1.BASE.multiply(A), b: proof.b, c: proof.c } };
};
const INSTANCES = { committed: { inputs: PUBLIC_INPUTS, proof }, proof1: mkInstance([135208n, 67633n]), stress: mkInstance(LINKED_HIGH_COST_INPUTS) };

// ---- residue chunk-graph layout constants (identical to grouped/build_vectors_residue_bls.mjs) ----
// Stage-bound Miller genesis carries the residue root plus ten runtime-point limbs. Quotient
// mode uses u(6), while the legacy path uses cInv+c(24). f and R_B are derived in-contract.
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const ptLof = (inst) => { const pr = pairsFor(inst.inputs, inst.proof); return pr.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())); };
const ROOT_LIMBS = QUOTIENT_TORUS ? 6 : 24;
const VKX_LIMB_OFFSET = ROOT_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length;
const MILLER_IN_LIMBS = ptLof(INSTANCES.committed).length + ROOT_LIMBS;
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]

// ---- per-stage specs (inLimbs/outLimbs/extras/role) — same graph as the grouped-residue BLS
// build; only the assembly below differs (single tx, forward-checks, no token). ----
const uLimbs = (u) => [u.c0.c0, u.c0.c1, u.c1.c0, u.c1.c1, u.c2.c0, u.c2.c1];
const stateLimbsR = (s) => [
  ...f12limbs(s.f), ...r6limbs(s.Rs[0]),
  ...(QUOTIENT_TORUS ? uLimbs(s.u) : [...f12limbs(s.c), ...f12limbs(s.cInv)]),
];
const withPtsR = (limbs, ptL) => [...limbs.slice(0, 18), ...ptL, ...limbs.slice(18)]; // insert ptL after f+R_B

function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const scal = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx BLS residue requires stage-bound GLV generation');
  if (man.sharedTable !== true) throw new Error('intratx BLS residue requires shared-table GLV generation');
  return man.chunks.map((ch) => {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scal];
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxGlvZinv(k10, k20, k11, k21), GLV_TABLE_BYTES], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
      label: 'GLV vk_x final -> assemble vk_x', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scal], extras: [], role: 'within', label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMillerResidue(inst, c, cInv, u = null, bad = {}) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = QUOTIENT_TORUS
    ? millerFusedTorusOps(pairs, c, cInv, u)
    : millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx BLS residue requires stage-bound Miller generation');
  if ((man.quotientTorus === true) !== QUOTIENT_TORUS ||
    (man.terminalFused === true) !== QUOTIENT_TORUS) {
    throw new Error('BLS residue Miller mode does not match the generated manifest');
  }
  const genesisPts = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
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
          throw new Error('quotient-torus final Miller chunk is not terminal');
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
    throw new Error('linked BLS residue requires the one-chunk Fp6 tail');
  }
  return [{
    file: join(GEN, 'finalexpres_00.cash'), inLimbs: commit36, outLimbs: [], extras: wl, role: 'terminal',
    label: 'residue Fp6 verdict', checkpoint: 'verify',
  }];
}
function buildSpecs(inst) {
  // g2check is fused into the first/last fused-Miller chunks (see gen_miller_residue.mjs), so the
  // graph is vk_x -> Miller (with on-curve + subgroup checks) -> residue tail.
  const vkx = specsVkxGlv(inst);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const root = QUOTIENT_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw);
  const { c, cInv, w, u } = root;
  const { specs: miller, boundary: fF } = specsMillerResidue(inst, c, cInv, u);
  if (QUOTIENT_TORUS) return [...vkx, ...miller];
  const tail = specsResidueTail(fF, c, cInv, w);
  return [...vkx, ...miller, ...tail];
}

// ---- assemble: transform+compile each chunk, build the single tx, tune pad, verify ----
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map(); // key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // key -> 'resched' | 'raw'; fixed on the FIRST assembly so every
                                // instance shares identical lockings.
const specKey = (s) => {
  let forward = null;
  if (s.role === 'within') { const outLen = s.outLimbs.length * W; forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  return { key: `${s.file}|${s.role}|${JSON.stringify(forward)}`, forward };
};
function compileSpec(s) {
  const { key, forward } = specKey(s);
  let v = compileCache.get(key);
  if (!v) {
    // compile from a file (probe in generated/) so the chunk's relative library import resolves
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward }).src);
    const resched = compileFileBytecode(PROBE);
    const raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched;
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) }; // [OP_DROP, contract] — OP_DROP discards the pad
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
// effective unlocking length a chunk needs, UNCAPPED (BLS redeems run close to the 10,000 B script
// caps, so an over-cap fixed part must lose the comparison rather than saturate); Infinity when the
// variant does not even accept.
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41) : Infinity);
function argBytesOf(s) {
  // inBlob is the LAST declared param (pushed FIRST -> front of the unlocking, where siblings'
  // forward-checks read it); extras come before inBlob in the decl, pushed AFTER it in reverse.
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(e instanceof Uint8Array ? pd(e) : pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
function assemble(specs, expectRejected = false) {
  const redeems = specs.map(compileSpec); // [OP_DROP, contract]
  const argB = specs.map(argBytesOf);     // [inBlob, extras...]
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => { const pad = padPush(0, Math.max(2, target - (argB[i].length + tailLen(i)))); return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]); };
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));
  // With stack rescheduling enabled, a candidate may exceed a byte/op limit while its raw
  // compilation still fits. Let the selector below compare both variants before failing.
  if (!expectRejected && !RESCHED && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
  }

  // Per-chunk variant selection (RESCHEDULE only; decided once, first assembly): keep whichever
  // redeem needs the smaller effective unlocking (uncapped effLen; Infinity on non-accept).
  if (RESCHED) {
    let switched = 0;
    for (let i = 0; i < specs.length; i++) {
      const { key } = specKey(specs[i]);
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
      const tR = effLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost), op1[i].accepted && standardOp1[i].accepted);
      const tB = effLen(rawFixed, Math.max(rawOp.operationCost, rawStandardOp.operationCost), rawOp.accepted && rawStandardOp.accepted);
      // both variants failing usually means a NEIGHBOUR is oversized (the forward-check pushes the
      // successor's whole unlocking) — defer this chunk's decision to the reassembly.
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assemble(specs, expectRejected); // reassemble with final choices (cached -> recurses once)
  }
  let targets = specs.map((_, i) => tunedLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost)));
  let op2;
  let standardOp2;
  while (true) {
    inputs = specs.map((_, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, targets[i]) }));
    op2 = specs.map((_, i) => evalInput(inputs, i));
    standardOp2 = specs.map((_, i) => evalInput(inputs, i, standardVm));
    if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) break;
    const tightened = targets.map((target, i) => Math.min(target, tunedLen(
      argB[i].length + tailLen(i),
      Math.max(op2[i].operationCost, standardOp2[i].operationCost),
    )));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
    throw new Error('tightened input rejected during padding measurement');
  }
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  const standardAccepted = standardOp2.every((o) => o.accepted);
  if (expectRejected && (accepted || standardAccepted)) {
    throw new Error('invalid intra-transaction residue fixture unexpectedly accepted by a BCH VM');
  }
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted && standardAccepted;
  return { inputs, meta, fits, accepted, standardAccepted };
}
const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk uses); the
// predecessor's forward-check (and/or this chunk's own) then fails -> the run is rejected.
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => { const u = Uint8Array.from(inp.unlocking); const op = u[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : 3; const dl = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8); u[ds + Math.floor(dl / 2)] ^= 0x01; return u; })() } : inp));
  const consensus = inputs.map((_, i) => evalInput(inputs, i));
  const standard = inputs.map((_, i) => evalInput(inputs, i, standardVm));
  return {
    steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })),
    rejected: consensus.some((outcome) => !outcome.accepted) && standard.some((outcome) => !outcome.accepted),
  };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const transactionMetadata = (asm) => {
  const data = verificationData(asm.inputs);
  const wireBytes = encodeTransactionBch(data.transaction).length;
  const feeSatoshis = data.sourceOutputs.reduce((total, output) => total + output.valueSatoshis, 0n) -
    data.transaction.outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
  const consensusVerified = asm.inputs.every((_, i) => evalInput(asm.inputs, i).accepted);
  const standardScriptsVerified = asm.inputs.every((_, i) => evalInput(asm.inputs, i, standardVm).accepted);
  const standardTransactionSizeVerified = wireBytes <= 100000;
  return {
    wireBytes,
    consensusVerified,
    standardScriptsVerified,
    standardTransactionSizeVerified,
    standardTransactionVerified: standardScriptsVerified && standardTransactionSizeVerified,
    defaultMinRelayFeeVerified: feeSatoshis ===
      BigInt(wireBytes) * DEFAULT_MIN_RELAY_FEE_SATOSHIS_PER_BYTE,
  };
};
const report = (tag, asm) => {
  const tx = transactionMetadata(asm);
  const bad = asm.meta.find((m) => !m.accepted);
  console.error(`${tag}: ${asm.meta.length} inputs accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} wireBytes=${tx.wireBytes.toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()} consensus=${tx.consensusVerified} standardScripts=${tx.standardScriptsVerified} standardSize=${tx.standardTransactionSizeVerified} relayFee=${tx.defaultMinRelayFeeVerified}`);
  if (process.env.DUMP_OPCOSTS) asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
  return tx;
};

// ===================== FULL GROTH16 (residue, single tx) =====================
const committedSpecs = buildSpecs(INSTANCES.committed);
const proof1Specs = buildSpecs(INSTANCES.proof1);
const stressSpecs = buildSpecs(INSTANCES.stress);
const limbsEqual = (a, b) => a.length === b.length && a.every((x, i) => BigInt(x) === BigInt(b[i]));
function requireStageGenesis(specs, inst, label) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  if (!limbsEqual(specs[0].inLimbs, [in0, in1, k10, k20, k11, k21])) {
    throw new Error(`${label} GLV genesis still exposes accumulator state`);
  }
  const pairs = pairsFor(inst.inputs, inst.proof);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const expectedPoints = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
  if (specs[GLV_COUNT].inLimbs.length !== MILLER_IN_LIMBS ||
    !limbsEqual(specs[GLV_COUNT].inLimbs.slice(ROOT_LIMBS, ROOT_LIMBS + 10), expectedPoints)) {
    throw new Error(`${label} Miller genesis still exposes f/R_B state or misorders proof points`);
  }
}
[
  ['committed', committedSpecs, INSTANCES.committed],
  ['proof#1', proof1Specs, INSTANCES.proof1],
  ['stress', stressSpecs, INSTANCES.stress],
].forEach(([label, specs, inst]) => requireStageGenesis(specs, inst, label));

const full0 = assemble(committedSpecs);
const full0Transaction = report('groth16-bls12381-intratx-residue committed', full0);
const full1 = assemble(proof1Specs);
const full1Transaction = report('groth16-bls12381-intratx-residue proof#1', full1);
const fullStress = assemble(stressSpecs);
const fullStressTransaction = report('groth16-bls12381-intratx-residue all-position stress', fullStress);
for (const [label, otherSpecs, otherRun] of [['proof#1', proof1Specs, full1], ['stress', stressSpecs, fullStress]]) {
  const hybridSpecs = [...committedSpecs.slice(0, GLV_COUNT), ...otherSpecs.slice(GLV_COUNT)];
  const unboundSpecs = hybridSpecs.map((spec, i) => i === GLV_COUNT - 1 ? { ...spec, role: 'stage-final', cmp: null } : spec);
  const unbound = assemble(unboundSpecs);
  if (!unbound.accepted || !unbound.standardAccepted) {
    throw new Error(`${label} unbound valid-fixture hybrid was not accepted by both BCH VMs`);
  }
  const boundInputs = [...full0.inputs.slice(0, GLV_COUNT), ...otherRun.inputs.slice(GLV_COUNT)];
  for (const [vmLabel, vm] of [['consensus', realVm], ['standard', standardVm]]) {
    const outcomes = boundInputs.map((_, i) => evalInput(boundInputs, i, vm));
    if (outcomes[GLV_COUNT - 1].accepted) {
      throw new Error(`${label} hybrid did not reject at the vk_x boundary on the ${vmLabel} VM`);
    }
    const unrelated = outcomes.find((outcome, i) => i !== GLV_COUNT - 1 && !outcome.accepted);
    if (unrelated) throw new Error(`${label} hybrid also rejected outside the vk_x boundary on the ${vmLabel} VM`);
  }
}
console.error('  stage genesis layouts and proof#1/stress vk_x boundaries verified');
// shared-table fixture: flip a middle byte of the carried GLV table -> the carrier's hash256
// pin must reject (the four sibling readers consume that exact slice).
function pushBounds(unlocking, opcodeOffset = 0) {
  const op = unlocking[opcodeOffset];
  if (op <= 75) return { dataStart: opcodeOffset + 1, dataLen: op };
  if (op === 0x4c) return { dataStart: opcodeOffset + 2, dataLen: unlocking[opcodeOffset + 1] };
  if (op === 0x4d) return { dataStart: opcodeOffset + 3, dataLen: unlocking[opcodeOffset + 1] | (unlocking[opcodeOffset + 2] << 8) };
  throw new Error(`unsupported push opcode ${op}`);
}
const tableCarrierIndex = full0.meta.findIndex((m) => m.label === 'GLV vk_x final -> assemble vk_x');
if (tableCarrierIndex < 0) throw new Error('missing shared GLV table carrier');
const tableInputs = full0.inputs.slice();
const tableUnlocking = Uint8Array.from(tableInputs[tableCarrierIndex].unlocking);
const carrierBlob = pushBounds(tableUnlocking);
const tablePush = pushBounds(tableUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
if (tablePush.dataLen !== GLV_TABLE_BYTES.length) throw new Error('shared GLV table push has unexpected length');
tableUnlocking[tablePush.dataStart + Math.floor(tablePush.dataLen / 2)] ^= 0x01;
tableInputs[tableCarrierIndex] = { ...tableInputs[tableCarrierIndex], unlocking: tableUnlocking };
if (evalInput(tableInputs, tableCarrierIndex).accepted || evalInput(tableInputs, tableCarrierIndex, standardVm).accepted) {
  throw new Error('GLV carrier accepted a mutated shared table on a BCH VM');
}
const tableMutation = { steps: toStepArr({ inputs: tableInputs, meta: full0.meta }), rejected: true };
console.error('  shared GLV table mutation rejected at carrier');

const fInv = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2)), tableMutation];

// Isolate the two fused point-validation checks from the later residue verdict. The first Miller
// chunk rejects an off-curve A immediately; the full Miller-only trace reaches the final guarded
// psi(B)==[-x]B check for an on-curve point outside the order-r subgroup.
const committedPairs = pairsFor(INSTANCES.committed.inputs, INSTANCES.committed.proof);
const { boundary: committedRawBoundary } = millerBatchOps(committedPairs);
const committedRoot = QUOTIENT_TORUS
  ? residueTorusWitness(committedRawBoundary)
  : residueWitness(committedRawBoundary);
const { c: committedC, cInv: committedCInv, u: committedU } = committedRoot;
const negA = proof.a.negate().toAffine();
const firstMiller = specsMillerResidue(
  INSTANCES.committed, committedC, committedCInv, committedU,
  { Ay: (negA.y + 1n) % P },
).specs[0];
firstMiller.role = 'stage-final'; firstMiller.cmp = null;
const offCurveA = assemble([firstMiller], true);
const plusPFirstMiller = specsMillerResidue(
  INSTANCES.committed, committedC, committedCInv, committedU,
  { Ax: negA.x + P },
).specs[0];
plusPFirstMiller.role = 'stage-final'; plusPFirstMiller.cmp = null;
const plusPRange = assemble([plusPFirstMiller], true);
if (plusPRange.meta[0].accepted) throw new Error('+P proof encoding passed residue Miller input validation');
const twistB = F2.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2.create({ c0: i, c1: 0n });
  const rhs = F2.add(F2.mul(F2.sqr(x), x), twistB);
  let y; try { y = F2.sqrt(rhs); } catch { continue; }
  if (!F2.eql(F2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; }
}
if (!offSub) throw new Error('failed to construct off-subgroup B residue fixture');
const offSubInst = {
  inputs: INSTANCES.committed.inputs,
  proof: { ...INSTANCES.committed.proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const offSubSpecs = specsMillerResidue(offSubInst, committedC, committedCInv, committedU).specs;
offSubSpecs[offSubSpecs.length - 1].role = 'stage-final';
offSubSpecs[offSubSpecs.length - 1].cmp = null;
const offSubgroupB = assemble(offSubSpecs, true);
const semanticRuns = [offCurveA, offSubgroupB, plusPRange].map((asm) => ({ steps: toStepArr(asm), rejected: !asm.accepted }));

function rangeInvalid(spec, location, value, label) {
  const candidate = { ...spec, extras: [...spec.extras], role: 'stage-final', cmp: null, label };
  if (location.extra !== undefined) candidate.extras[location.extra] = value;
  const asm = assemble([candidate], location.extra !== undefined);
  if (location.limb !== undefined) {
    const unlocking = Uint8Array.from(asm.inputs[0].unlocking);
    const pushed = pushBounds(unlocking);
    if (pushed.dataLen !== candidate.inLimbs.length * W) throw new Error(`${label} has an unexpected input blob length`);
    const encoded = le48Exact(value < 0n ? -value : value);
    if (value < 0n) encoded[W - 1] |= 0x80;
    unlocking.set(encoded, pushed.dataStart + location.limb * W);
    asm.inputs[0] = { ...asm.inputs[0], unlocking };
  }
  const consensusOutcome = evalInput(asm.inputs, 0);
  const standardOutcome = evalInput(asm.inputs, 0, standardVm);
  if (consensusOutcome.accepted || standardOutcome.accepted) {
    throw new Error(`${label} passed a residue witness range gate`);
  }
  return { steps: toStepArr(asm), rejected: true };
}

const firstRangeMiller = committedSpecs[GLV_COUNT];
const firstRangeTail = committedSpecs.find((spec) => spec.file.includes('finalexpres_'));
if (!firstRangeMiller || (!QUOTIENT_TORUS && !firstRangeTail)) {
  throw new Error('missing residue witness range fixture stage');
}
const rangeRuns = QUOTIENT_TORUS
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

const torusRuns = [];
if (QUOTIENT_TORUS) {
  const terminalSpec = committedSpecs[committedSpecs.length - 1];
  const terminalInvalid = (mutate, label) => {
    const inLimbs = terminalSpec.inLimbs.slice();
    mutate(inLimbs);
    const candidate = { ...terminalSpec, inLimbs, label };
    const asm = assemble([candidate], true);
    if (asm.accepted) throw new Error(`${label} passed the quotient terminal`);
    return { steps: toStepArr(asm), rejected: true };
  };
  torusRuns.push(
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

const allInvalid = [...fInv, ...semanticRuns, ...rangeRuns, ...torusRuns];
console.error(`  invalid runs rejected: ${allInvalid.map((r) => r.rejected).join(',')}`);
const validTransactions = [full0Transaction, full1Transaction, fullStressTransaction];
if (!full0.fits || !full1.fits || !fullStress.fits || !allInvalid.every((r) => r.rejected) ||
  validTransactions.some((tx) => !tx.consensusVerified || !tx.standardScriptsVerified ||
    tx.standardTransactionSizeVerified || tx.standardTransactionVerified ||
    !tx.defaultMinRelayFeeVerified)) {
  console.error('!! a run failed the consensus/standard dual-VM gates -- NOT writing vectors');
  process.exit(1);
}

const millerInputCount = committedSpecs.length - GLV_COUNT;
const description = QUOTIENT_TORUS
  ? `INTRA-TRANSACTION LINKED + QUOTIENT-TORUS RESIDUE full BLS12-381 Groth16 verifier in one current-BCH consensus-valid transaction. Its ${full0.inputs.length}-input graph is ${GLV_COUNT} shared-table GLV vk_x chunks followed by ${millerInputCount} input-validation-fused prepared Miller chunks; the final Miller input also executes the terminal verdict. ` +
    'The bytecode evaluates e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) = 1 for runtime A/B/C and two runtime public inputs. The fixed e(alpha,beta) Miller value and fixed-G2 gamma/delta lines are ordinary verification-key preparation; the construction retains all four terms and does not use the fixture\'s published setup-scalar relations to collapse the equation. ' +
    'The Miller accumulator lives in Fp12*/Fp6*, and the immutable six-limb canonical u represents the finite residue-root class [c]=[1+u*W], with inverse [1-u*W]. ' +
    'Because gcd(p+|x|,p^6+1)=r, the lambda-power image is exactly the final-exponent kernel in the quotient; the legacy correction w is in Fp6 and disappears. ' +
    'The terminal checks [fF]=[frob(c,1)] by a projective cross-product and explicitly rejects [0:0]. ' +
    'Canonical A/C encodings are checked on-curve; non-identity B is canonical, on-curve, and checked in the exact G2 subgroup. A/C cofactor components pair trivially with their order-r G2 partners, so unique G1 subgroup encodings are not claimed. ' +
    `OP_INPUTBYTECODE binds every state, the residue root, and both stage seams without hashing. The exactly funded committed spend is ${full0Transaction.wireBytes} bytes and every input passes current BCH consensus and standard script policy; the complete transaction is non-standard only because it exceeds 100,000 bytes. Deployed P2SH32. ` +
    'The prescribed key is a synthetic fixture with published setup and IC scalars, so this artifact establishes complete-equation execution and BCH resource validity for that key, not circuit knowledge, application-level public-input binding, arbitrary-key support, or independent-setup interoperability.'
  : 'INTRA-TRANSACTION LINKED + RESIDUE full BLS12-381 Groth16 verifier in one transaction. ' +
    'Its 35-input graph is five shared-table GLV vk_x chunks, 29 input-validation-fused prepared Miller chunks, and one terminal residue chunk. ' +
    'The terminal checks c*cInv==1 and fF*w==frob(c,1), with w supplied directly as six Fp6 limbs and its Fp12 upper half fixed to zero. ' +
    'This is sound because p^6-1 divides (p^12-1)/r; the terminal equations exclude zero. ' +
    'OP_INPUTBYTECODE binds every intra-transaction handoff without hashing, and the vk_x and Miller stage seams bind the proof-specific state. Deployed P2SH32.';

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-intratx-residue-vectors.json'), JSON.stringify({
  description,
  method: 'intra-tx-linked-residue', deployment: 'P2SH32', curve: 'BLS12-381', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  serializedTransactionBytes: full0Transaction.wireBytes,
  consensusTransactionVerified: full0Transaction.consensusVerified,
  standardScriptsVerified: full0Transaction.standardScriptsVerified,
  standardTransactionSizeVerified: full0Transaction.standardTransactionSizeVerified,
  standardTransactionVerified: full0Transaction.standardTransactionVerified,
  minimumRelayFeeSatoshisAtOneSatPerByte: full0Transaction.wireBytes,
  defaultMinRelayFeeVerified: full0Transaction.defaultMinRelayFeeVerified,
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0),
  extraValidProofs: [toStepArr(full1)],
  extraValidProofTransactions: [{
    serializedTransactionBytes: full1Transaction.wireBytes,
    consensusTransactionVerified: full1Transaction.consensusVerified,
    standardScriptsVerified: full1Transaction.standardScriptsVerified,
    standardTransactionSizeVerified: full1Transaction.standardTransactionSizeVerified,
    standardTransactionVerified: full1Transaction.standardTransactionVerified,
    defaultMinRelayFeeVerified: full1Transaction.defaultMinRelayFeeVerified,
  }],
  worstCaseProof: toStepArr(fullStress),
  worstCaseTransaction: {
    serializedTransactionBytes: fullStressTransaction.wireBytes,
    consensusTransactionVerified: fullStressTransaction.consensusVerified,
    standardScriptsVerified: fullStressTransaction.standardScriptsVerified,
    standardTransactionSizeVerified: fullStressTransaction.standardTransactionSizeVerified,
    standardTransactionVerified: fullStressTransaction.standardTransactionVerified,
    defaultMinRelayFeeVerified: fullStressTransaction.defaultMinRelayFeeVerified,
  },
  invalid: allInvalid.map((r) => r.steps),
  invalidInputs: [toStepArr(offCurveA), toStepArr(offSubgroupB), toStepArr(plusPRange)],
}, null, 2));
console.error('wrote groth16-bls12381-intratx-residue-vectors.json');
