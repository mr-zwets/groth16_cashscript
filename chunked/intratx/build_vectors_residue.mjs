// Assemble the INTRA-TRANSACTION LINKED + RESIDUE verifier vectors for BN254.
//
// This is the residue-optimized cousin of build_vectors.mjs. Same single-transaction
// forward-checking mechanism (each chunk is an INPUT whose witness carries its incoming
// state as a raw byte blob, and it `require`s the next input's blob — read via
// tx.inputs[idx+1].unlockingBytecode — equals its recomputed output), but it consumes the
// RESIDUE chunk graph instead of the plain one:
//
//   fast-G2 endo subgroup check (ePrint 2022/348)          3 chunks, or 0 with FUSE_G2_ENDPOINT=1
//   GLV vk_x MSM (4-scalar ~128-bit Straus)                3 chunks
//   c^-(6x+2)-FUSED Miller + terminal residue verdict      manifest-selected chunk count
//
// Endpoint fusion validates canonical/on-curve proof coordinates at Miller genesis and reuses
// runtime B's post-processing line to enforce exact G2 subgroup membership. The selected current-
// BCH graph is 3 GLV + 14 Miller inputs; the standalone G2 stage is removed.
//
// Outside endpoint-fusion mode, the chunk math is reused verbatim by the grouped-residue build;
// only the assembly differs:
// grouped partitions the chain into token-threaded standard txs, this links the whole chain
// into ONE non-standard (<1 MB) tx via OP_INPUTBYTECODE forward-checks. The residue witness
// (c, cInv) threads through every fused-Miller chunk; the terminal Miller chunk checks
// c*cInv==ONE, c canonical, the exact w encoding in {1,w27,w27^2}, and the residue verdict.
//
//   FUSE_G2_ENDPOINT=1 node build_vectors_residue.mjs
//     -> verifier/src/bch/groth16-intratx-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, BN_X, millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileFileBytecode, compileFileBytecodeRaw, ptLimbs,
  vkxPoint, le40, OP_DROP, TARGET_UNLOCK, OP_BUDGET, verifierPath, invalidG2Overrides,
  assertG2StageManifest,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import { millerFusedOps, residueWitness, fp12limbsOf } from '../pairing/_residuemath.mjs';
import { GLV_LAMBDA, GLV_R, GLV_TABLE_HEX, glvDecompose, vkxGlvStateAt, vkxGlvZinv } from '../pairing/gen_vkx_glv.mjs';
import { transformChunk } from './transform.mjs';
import { GLV_SAFE_BOUNDS, regenGlvSafe } from '../regen_vkx_windows.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const FUSE_G2_ENDPOINT = process.env.FUSE_G2_ENDPOINT === '1';
const ENDPOINT_VM_CASES = Number(process.env.ENDPOINT_VM_CASES ?? 1);
if (!Number.isInteger(ENDPOINT_VM_CASES) || ENDPOINT_VM_CASES < 1) {
  throw new Error('ENDPOINT_VM_CASES must be a positive integer');
}
// Re-plan the GLV vk_x windows to the hash-free SAFE floor (3 chunks, max-density-validated)
// before assembling — the covenant-planned manifest_vkxglv (4 chunks) under-fills this
// hash-free deployment. See chunked/regen_vkx_windows.mjs.
// The final GLV input carries the table after its 228-byte state blob: PUSHDATA1(blob)
// takes 230 bytes, then the table's PUSHDATA2 header places table data at byte 233.
const GLV_COUNT = GLV_SAFE_BOUNDS.length - 1;
const G2_COUNT = FUSE_G2_ENDPOINT ? 0 : 3;
const GLV_TABLE_SOURCE = { inputIndex: G2_COUNT + GLV_COUNT - 1, dataOffset: 233 };
regenGlvSafe(GEN, GLV_SAFE_BOUNDS, true, GLV_TABLE_SOURCE);
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
import { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));

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
function evalInput(inputs, index, vm = realVm) {
  const program = {
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })),
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
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
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: { proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] },
};

// vk_x position inside the 34-limb Miller genesis inBlob: runtime points(10)+c(12)+cInv(12).
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(3, dummy[3].P.toAffine(), dummy[3].Q.toAffine()).length;
const PTL_LEN = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length; // 10
const MILLER_IN_LIMBS = PTL_LEN + 24;

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
  const [k10, k20, k11, k21] = inst.glvScalars ?? [...glvDecompose(in0), ...glvDecompose(in1)];
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const st = (X, Y, Z) => [X, Y, Z, in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx residue requires stage-bound GLV generation');
  if (man.sharedTable !== true) throw new Error('intratx residue requires shared-table GLV generation');
  return man.chunks.map((ch) => {
    const [X0, Y0, Z0] = vkxGlvStateAt(k10, k20, k11, k21, ch.lo);
    const fullIn = st(X0, Y0, Z0);
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) {
      return {
        file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
        outLimbs: [vkxAff.x, vkxAff.y], outWidths: [W, W],
        extras: [vkxGlvZinv(k10, k20, k11, k21), GLV_TABLE_BYTES],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'GLV vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    const [X1, Y1, Z1] = vkxGlvStateAt(k10, k20, k11, k21, ch.hi);
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
      outLimbs: st(X1, Y1, Z1), outWidths: GLV_STATE_WIDTHS,
      extras: [], role: 'within',
      label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
// c^-(6x+2)-FUSED miller (residue method). The final Miller chunk also consumes w and
// performs the residue verdict, so there is no separate terminal input or state hand-off.
function specsMillerFused(inst, c, cInv, w) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states } = millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const full = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...ptL, ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 52
  const genesisPts = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];
  const genesis = [...genesisPts, ...f12limbs(c), ...f12limbs(cInv)];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.linkedLayout !== true) {
    throw new Error('intratx residue requires MILLER_LINKED_LAYOUT=1 during Miller generation');
  }
  if (man.stageBound !== true) {
    throw new Error('intratx residue requires STAGE_BOUND_LAYOUT=1 during Miller generation');
  }
  if (man.endpointSubgroup !== FUSE_G2_ENDPOINT) {
    throw new Error(`Miller endpoint subgroup mode mismatch: generated=${man.endpointSubgroup} requested=${FUSE_G2_ENDPOINT}`);
  }
  return man.chunks.map((ch) => ({
    file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: ch.opLo === 0 ? genesis : full(states[ch.opLo]),
    outLimbs: ch.final ? [] : full(states[ch.opHi]),
    extras: ch.final ? fp12limbsOf(w) : [],
    role: ch.final ? 'terminal' : 'within',
    cmp: null,
    label: `fused-miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' + residue verdict' : ''}`,
    checkpoint: ch.final ? 'verify' : undefined,
  }));
}
function buildSpecs(inst) {
  const g2 = FUSE_G2_ENDPOINT ? [] : specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const miller = specsMillerFused(inst, c, cInv, w);
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
  const key = `${s.file}|${s.role}|${JSON.stringify(forward)}|${JSON.stringify(externalBindings)}`;
  return { key, forward, externalBindings };
};
function compileSpec(specs, i) {
  const s = specs[i];
  const { key, forward, externalBindings } = specConfig(specs, i);
  let v = compileCache.get(key);
  if (!v) {
    // compile from a file (probe in generated/) so the chunk's relative library import resolves
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), {
      W, widthsByName: GLV_WIDTHS_BY_NAME, prime: PRIME, forward, externalBindings,
    }).src);
    const resched = compileFileBytecode(PROBE);
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
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
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
  const maxL = Math.max(...asm.meta.map((m) => m.lockingBytes)), maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  console.error(`${tag}: ${asm.meta.length} inputs, accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${maxOp.toLocaleString()} maxLock=${maxL} maxUnlock=${maxU}`);
  if (process.env.DUMP_OPCOSTS) asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== FULL GROTH16 (residue, single tx) =====================
const committedSpecs = buildSpecs(INSTANCES.committed);
const proof1Specs = buildSpecs(INSTANCES.proof1);
const worstSpecs = buildSpecs(INSTANCES.worst);
const full0 = assemble(committedSpecs);
report('groth16-intratx-residue committed', full0);
// The benchmark's dense proof is not the GLV density worst case: its four decomposition
// witnesses have unrelated bit gaps. Exercise the absolute case explicitly (all 128 bits set
// in all four bounded witnesses) so a window replan cannot silently exceed the input budget.
const denseScalar = (1n << 128n) - 1n;
const denseInput = (denseScalar + denseScalar * GLV_LAMBDA) % GLV_R;
const densitySpecs = committedSpecs.slice();
densitySpecs.splice(G2_COUNT, GLV_COUNT, ...specsVkx({
  inputs: [denseInput, denseInput],
  glvScalars: [denseScalar, denseScalar, denseScalar, denseScalar],
}, true));
const denseVkx = vkxPoint([denseInput, denseInput]).toAffine();
const millerGenesisIndex = G2_COUNT + GLV_COUNT;
const millerGenesis = densitySpecs[millerGenesisIndex];
const millerIn = millerGenesis.inLimbs.slice();
millerIn.splice(VKX_LIMB_OFFSET, 2, denseVkx.x, denseVkx.y);
densitySpecs[millerGenesisIndex] = { ...millerGenesis, inLimbs: millerIn };
const densityGlv = assemble(densitySpecs, true).meta.slice(G2_COUNT, G2_COUNT + GLV_COUNT);
if (densityGlv.some((meta) => !meta.accepted || meta.operationCost > OP_BUDGET || meta.unlockingBytes > TARGET_UNLOCK)) {
  throw new Error('max-density GLV window exceeds the BCH input budget');
}
console.error(`  max-density GLV max op: ${Math.max(...densityGlv.map((meta) => meta.operationCost)).toLocaleString()}`);
if (process.env.DUMP_OPCOSTS) console.error(`  max-density GLV ops: ${densityGlv.map((meta) => meta.operationCost.toLocaleString()).join(', ')}`);
const full1 = assemble(proof1Specs);
const fullWc = assemble(worstSpecs);
report('groth16-intratx-residue proof#1', full1);
report('groth16-intratx-residue worst-case', fullWc);
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
  proofMutations = [3 * W, 7 * W].map((byteOffset) => {
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
];
let endpointSpecIndex = -1;
if (FUSE_G2_ENDPOINT) {
  const manifest = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  const trace = millerFusedOps(
    pairsFor(INSTANCES.committed.inputs, proof),
    bn254.fields.Fp12.ONE,
    bn254.fields.Fp12.ONE,
  );
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
  const run = assemble(buildSpecs({ proof: badProof, inputs: INSTANCES.committed.inputs }), true);
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

  const endpointInputs = mutateInputBlob(full0.inputs, endpointSpecIndex, 12 * W);
  if (evalInput(endpointInputs, endpointSpecIndex).accepted) {
    throw new Error('fused Miller endpoint accepted a mutated R state');
  }
  fullInvalid.push({ steps: toStepArr({ inputs: endpointInputs, meta: full0.meta }), rejected: true });
}

if (FUSE_G2_ENDPOINT && ENDPOINT_VM_CASES > 1) {
  for (const scalar of [2n, 7n, BN_X]) {
    const scaledProof = {
      a: proof.a.multiply(bn254.fields.Fr.inv(scalar)),
      b: proof.b.multiply(scalar),
      c: proof.c,
    };
    const run = assemble(buildSpecs({ proof: scaledProof, inputs: INSTANCES.committed.inputs }));
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
    const run = assemble(buildSpecs({ proof: wrapProof, inputs: INSTANCES.committed.inputs }), true);
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
if (!full0.fits || !full1.fits || !fullWc.fits || !fullInvalid.every((run) => run.rejected) || invalidInputs.length === 0) {
  throw new Error('valid, worst-case, or invalid fixture failed; refusing to write vectors');
}

const description = FUSE_G2_ENDPOINT
  ? `INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction (${full0.inputs.length} inputs). Three GLV vk_x inputs feed a c^-(6x+2)-fused batched Miller chain with e(alpha,beta) precomputed and a terminal witnessed-residue verdict. The Miller genesis requires canonical A/B/C coordinates, checks A and C on G1, and reuses runtime B's first doubling coefficients for its twist-curve equation. Exact G2 subgroup membership is fused into B's existing Miller post-processing: for R=[6x+2]B, the second-add line through R+psi(B) and -psi^2(B) must also contain psi^3(B), equivalent to R+psi(B)-psi^2(B)+psi^3(B)=O. prove_miller_endpoint_subgroup.mjs proves this condition has exactly the r-torsion kernel on the full rational twist group. The GLV result is cross-bound into Miller genesis and every later state is forward-bound with OP_INPUTBYTECODE.`
  : 'INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction. Same OP_INPUTBYTECODE forward-checking as bch-groth16-intratx (each chunk is an input whose witness carries its incoming state as a raw byte blob and require()s the next input\'s blob == its recomputed output — no NFT commitment, no hashing, arbitrary intermediate size), but it runs the residue-optimized chunk graph: 3 canonical-coordinate/on-curve/subgroup fast-G2 endomorphism chunks (ePrint 2022/348), 3 GLV vk_x chunks, and c^-(6x+2)-FUSED batched Miller chunks with e(alpha,beta) precomputed/skipped (ePrint 2024/640). The three GLV inputs share one hash-bound fixed lookup table carried by the final GLV input rather than embedding three copies. The final Miller chunk also performs the witnessed-residue verdict. The residue witness (c, cInv) threads through every Miller chunk; the terminal chunk checks c canonical, c*cInv==ONE, the exact w serialization in {1,w27,w27^2}, and fF*(w*c^q2)==(c*c^q2)^q. The G2 final chunk binds the proof-derived -A/B and C bytes into the fused-Miller genesis input, while the vk_x final chunk binds the GLV result into that same genesis; every later Miller state is forward-bound.';

writeFileSync(verifierPath('src/bch/groth16-intratx-residue-vectors.json'), JSON.stringify({
  description,
  method: 'intra-tx-linked-residue', deployment: 'P2SH32', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
  invalidInputs,
}, null, 2));
console.error('wrote groth16-intratx-residue-vectors.json');
