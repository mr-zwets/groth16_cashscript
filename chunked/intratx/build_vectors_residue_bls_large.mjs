// INTRA-TX LINKED + RESIDUE verifier for BLS12-381 with LARGE (100 kB) input scripts, targeting
// the PROPOSED bch-spec upgrade. The BLS counterpart of build_vectors_residue_large.mjs (BN254)
// and the large-script cousin of build_vectors_residue_bls.mjs (the 10 kB current-BCH build).
//
// IDENTICAL mechanism (each chunk is an INPUT whose witness carries its incoming state as a raw
// 48-byte-limb blob and require()s the next input's blob — read via tx.inputs[idx+1].unlockingBytecode
// — equals its recomputed output; no NFT commitment, no hashing) and IDENTICAL residue chunk graph
// (GLV vk_x MSM / c^-|x|-FUSED batched Miller with e(alpha,beta) baked and the G2 on-curve+subgroup
// check fused in / witnessed-residue mu_27A final-exp tail). The ONLY difference is the per-input
// budget:
//
//   the BCH op-cost budget an input gets is (densityControlBase + unlockingLen) * 800. The flagship
//   BLS residue build sizes each chunk to a 10 kB unlocking under BCH_2026 (base 41 => 8,032,800
//   op/input, 39 inputs). Here we size to a 100 kB unlocking under bch-spec (base 10,000 =>
//   88,000,000 op/input, ~11x), collapsing the same verifier into a HANDFUL of fat inputs,
//   one per stage floor:
//     GLV vk_x MSM             1 input
//     c^-|x|-fused Miller       3 inputs   (op-bound; the on-curve+subgroup check stays fused in)
//     witnessed-residue tail    1 input   (mu_27A ((w^|x|)*w)^9 walk + finalize)
//                              ---------
//                               5 inputs   (still ONE non-standard <1 MB tx)
//
// The verifier arithmetic is unchanged; fewer state boundaries also remove repeated checks and
// padding. Each 100 kB input exceeds standard relay policy, so the tx is
// mine-direct — but the single-tx intratx bundle is already non-standard, so nothing new is given
// up. The chunks are regenerated at startup at the 100 kB budget by re-running the three BLS stage
// generators with big OP_COST_TARGET / BYTE_BUDGET / TARGET_UNLOCK env.
//
// NOTE: this leaves chunked/bls12-381/generated/ holding LARGE-budget chunks. Before rebuilding a
// flagship (10 kB) BLS build, regenerate the default-budget chunks:
//   node chunked/bls12-381/gen_vkx_glv.mjs && node chunked/bls12-381/gen_miller_residue.mjs && node chunked/bls12-381/gen_finalexp_residue.mjs
//
//   node build_vectors_residue_bls_large.mjs -> verifier/src/bch/groth16-bls12381-intratx-residue-large-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs, le48Exact, P, OP_DROP, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { residueWitness, millerFusedOps } from '../bls12-381/_residuemath.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv, GLV_HIGH_COST_INPUTS } from '../bls12-381/gen_vkx_glv.mjs';
import { residueWalkT } from '../bls12-381/gen_finalexp_residue.mjs';
import { transformChunk } from './transform.mjs';

// ---- LARGE per-input budget on the PROPOSED bch-spec VM (100 kB scripts) ----
// On bch-spec the op-cost budget an input gets is (densityControlBase 10,000 + unlockingLen)*800,
// so a 100 kB unlocking input gets (10000+100000)*800 = 88,000,000 op. maximumBytecodeLength is
// 100,000 B for BOTH locking and unlocking. (Current-BCH BCH_2026 caps scripts at 10 kB, so this
// build is only valid under the bch-spec upgrade; the whole tx is <=1 MB, non-standard/mine-direct.)
const DENSITY_BASE = 10_000;
const LARGE_UNLOCK = 100_000;
const LARGE_BUDGET = (DENSITY_BASE + LARGE_UNLOCK) * 800; // 88,000,000 (max, at a full 100 kB unlocking)
const opBudgetFor = (unlockingLen) => (DENSITY_BASE + unlockingLen) * 800; // exact per-input budget

const here = dirname(fileURLToPath(import.meta.url));
const BLS = join(here, '..', 'bls12-381');
const GEN = join(BLS, 'generated');
const PROBE = join(GEN, '_intratx_residue_bls_large_probe.cash'); // transformed import-chunks compiled from here
const W = 48; // BLS12-381 limb width (bytes)
const PRIME = P.toString();

// Regenerate the three variable-length stages at the 100 kB budget. The generators read the budget
// from env (BCH_VM=spec => densityControlBase 10,000 + spec VM; TARGET_UNLOCK sets the pad target;
// OP_COST_TARGET / BYTE_BUDGET cap each chunk). The greedy planners collapse 42 chunks into a
// handful of fat ones (vk_x 1, Miller ~3, tail ~2). BYTE_BUDGET stays under the 100 kB script cap.
const GEN_ENV = { ...process.env, BCH_VM: 'spec', TARGET_UNLOCK: String(LARGE_UNLOCK), OP_COST_TARGET: '86000000', BYTE_BUDGET: '95000', STAGE_BOUND_LAYOUT: '1' };
console.error('\n== regenerating gen_vkx_glv.mjs at 100 kB budget ==');
execFileSync(process.execPath, [join(BLS, 'gen_vkx_glv.mjs')], { env: GEN_ENV, stdio: 'inherit' });
console.error('\n== regenerating gen_miller_residue.mjs at 100 kB budget ==');
execFileSync(process.execPath, [join(BLS, 'gen_miller_residue.mjs')], { env: GEN_ENV, stdio: 'inherit' });
console.error('\n== regenerating gen_finalexp_residue.mjs at 100 kB budget (FUSE_FINAL -> finalize folded into the last walk chunk) ==');
execFileSync(process.execPath, [join(BLS, 'gen_finalexp_residue.mjs')], { env: { ...GEN_ENV, FUSE_FINAL: '1' }, stdio: 'inherit' });

import { binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, numberToBinUint16LE, numberToBinUint32LE, createVirtualMachineBchSpec } from '@bitauth/libauth';
const realVm = createVirtualMachineBchSpec(false); // PROPOSED bch-spec VM (100 kB scripts, 88M-op inputs)
const standardVm = createVirtualMachineBchSpec(true);

// Deploy each chunk as P2SH (same lever as the flagship build): the redeem rides in the scriptSig
// where it counts toward the op-cost budget ((10000 + unlockingLen) * 800); the inBlob stays the
// FIRST scriptSig push (front offset preserved for sibling forward-checks).
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((limb) => [...le48Exact(limb)]));
// Zero-pad the unlocking to exactly `budget` bytes using the MINIMAL push encoding (the consensus
// VM rejects non-minimal pushes). Header is 1 B (<=75), 2 B (PUSHDATA1 <=255), 3 B (PUSHDATA2
// <=65535), 5 B (PUSHDATA4) — pick N so encodeDataPush emits exactly `budget` bytes. At 100 kB the
// header is 5, not 3; for a small tuned pad it drops to 1/2 (this is why hand-built PUSHDATA2 fails).
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget <= 65538 ? budget - 3 : budget - 5;
  return encodeDataPush(new Uint8Array(N));
};
// minimal total unlocking length whose spec budget (10000+len)*800 covers opCost.
const tunedLen = (argLen, opCost) => Math.min(LARGE_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - DENSITY_BASE));

// ---- multi-input evaluation: build ONE tx from all inputs, evaluate at `index` ----
function evalInput(inputs, index, vm = realVm) {
  const st = vm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: 1000n })),
    transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })), outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }], locktime: 0 },
  });
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
const INSTANCES = { committed: { inputs: PUBLIC_INPUTS, proof }, proof1: mkInstance([135208n, 67633n]), stress: mkInstance(GLV_HIGH_COST_INPUTS) };

// ---- residue chunk-graph layout constants (identical to build_vectors_residue_bls.mjs) ----
// Stage-bound Miller genesis = cInv(12) + c(12) + runtime points(10) = 34 limbs.
// f=cInv and R_B=B are derived in-contract; later Miller states still carry all 52 limbs.
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const ptLof = (inst) => { const pr = pairsFor(inst.inputs, inst.proof); return pr.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())); };
const VKX_LIMB_OFFSET = 24 + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length;
const MILLER_IN_LIMBS = ptLof(INSTANCES.committed).length + 24;
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]
const GLV_COUNT = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8')).numChunks;

// ---- per-stage specs (inLimbs/outLimbs/extras/role) — same graph as build_vectors_residue_bls.mjs;
// only the assembly below differs (100 kB inputs, spec VM). ----
const stateLimbsR = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 42
const withPtsR = (limbs, ptL) => [...limbs.slice(0, 18), ...ptL, ...limbs.slice(18)]; // insert ptL after f+R_B

function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const scal = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx BLS residue-large requires stage-bound GLV generation');
  return man.chunks.map((ch) => {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scal];
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxGlvZinv(k10, k20, k11, k21)], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
      label: 'GLV vk_x final -> assemble vk_x', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scal], extras: [], role: 'within', label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMillerResidue(inst, c, cInv, bad = {}) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('intratx BLS residue-large requires stage-bound Miller generation');
  const genesisPts = [...ptL.slice(2, 6), ...ptL.slice(0, 2), ...ptL.slice(6)];
  if (bad.Ax !== undefined) genesisPts[4] = bad.Ax;
  if (bad.Ay !== undefined) genesisPts[5] = bad.Ay;
  if (bad.Cy !== undefined) genesisPts[9] = bad.Cy;
  const genesis = [...f12limbs(cInv), ...f12limbs(c), ...genesisPts];
  const specs = man.chunks.map((ch) => {
    const inLimbs = ch.opLo === 0 ? genesis : withPtsR(stateLimbsR(states[ch.opLo]), ptL);
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
      if (ch.fused) {
        // FUSE_FINAL: the last walk chunk also runs the finalize verdict inline and is TERMINAL
        // (no forward hand-off); the separate finalize input is gone. w is the witness extra.
        return {
          file: join(GEN, `finalexpres_${String(ch.idx).padStart(2, '0')}.cash`),
          inLimbs: first ? commit36 : state5At(ch.lo), outLimbs: [], extras: first ? wl : [], role: 'terminal',
          label: `residue walk+finalize[${ch.lo},${ch.hi}) -> verdict`, checkpoint: 'verify',
        };
      }
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
  // g2check is fused into the first/last fused-Miller chunks (see gen_miller_residue.mjs), so the
  // graph is vk_x -> Miller (with on-curve + subgroup checks) -> residue tail.
  const vkx = specsVkxGlv(inst);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const { specs: miller, boundary: fF } = specsMillerResidue(inst, c, cInv);
  const tail = specsResidueTail(fF, c, cInv, w);
  return [...vkx, ...miller, ...tail];
}

// ---- assemble: transform+compile each chunk, build the single tx, tune pad, verify ----
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map();
const chosenCache = new Map();
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
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward }).src);
    const resched = compileFileBytecode(PROBE);
    const raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched;
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
// effective unlocking length a chunk needs, UNCAPPED; Infinity when the variant does not accept.
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - DENSITY_BASE) : Infinity);
function argBytesOf(s) {
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
function assemble(specs, expectRejected = false) {
  const redeems = specs.map(compileSpec);
  const argB = specs.map(argBytesOf);
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => { const pad = padPush(0, Math.max(2, target - (argB[i].length + tailLen(i)))); return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]); };
  // pass 1: full unlocking -> max budget so the real VM accepts and reports true op-cost
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, LARGE_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    throw new Error('full-budget input errored during padding measurement');
  }

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
        ? Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, LARGE_UNLOCK - rawFixed)), ...rawRpush])
        : Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, LARGE_UNLOCK - rawFixed))]);
      const probe = inputs.slice();
      probe[i] = { locking: P2SH ? p2shSpk(v.raw) : v.raw, unlocking: rawUnlock };
      const rawOp = evalInput(probe, i);
      const rawStandardOp = evalInput(probe, i, standardVm);
      const tR = effLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost), op1[i].accepted && standardOp1[i].accepted);
      const tB = effLen(rawFixed, Math.max(rawOp.operationCost, rawStandardOp.operationCost), rawOp.accepted && rawStandardOp.accepted);
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assemble(specs, expectRejected);
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
  if (expectRejected && accepted) throw new Error('invalid large-script residue fixture unexpectedly accepted');
  // spec caps: locking/unlocking each <= 100 kB; op-cost <= the input's own (10000+unlockingLen)*800.
  const fits = meta.every((m) => m.lockingBytes <= LARGE_UNLOCK && m.unlockingBytes <= LARGE_UNLOCK && m.operationCost <= opBudgetFor(m.unlockingBytes)) && accepted;
  return { inputs, meta, fits, accepted };
}
const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => { const u = Uint8Array.from(inp.unlocking); const op = u[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : op === 0x4d ? 3 : 5; const dl = op <= 75 ? op : op === 0x4c ? u[1] : op === 0x4d ? u[1] | (u[2] << 8) : u[1] | (u[2] << 8) | (u[3] << 16) | (u[4] << 24); u[ds + Math.floor(dl / 2)] ^= 0x01; return u; })() } : inp));
  const meta = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })), rejected: meta.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const maxOp = Math.max(...asm.meta.map((m) => m.operationCost));
  const maxL = Math.max(...asm.meta.map((m) => m.lockingBytes)), maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  console.error(`${tag}: ${asm.meta.length} inputs accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${maxOp.toLocaleString()} maxLock=${maxL} maxUnlock=${maxU}`);
  asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== FULL GROTH16 (residue, single tx, 100 kB inputs) =====================
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
  if (specs[GLV_COUNT].inLimbs.length !== MILLER_IN_LIMBS || !limbsEqual(specs[GLV_COUNT].inLimbs.slice(24, 34), expectedPoints)) {
    throw new Error(`${label} Miller genesis still exposes f/R_B state or misorders proof points`);
  }
}
[
  ['committed', committedSpecs, INSTANCES.committed],
  ['proof#1', proof1Specs, INSTANCES.proof1],
  ['stress', stressSpecs, INSTANCES.stress],
].forEach(([label, specs, inst]) => requireStageGenesis(specs, inst, label));

const full0 = assemble(committedSpecs);
report('groth16-bls12381-intratx-residue-large committed', full0);
const full1 = assemble(proof1Specs);
report('groth16-bls12381-intratx-residue-large proof#1', full1);
const fullStress = assemble(stressSpecs);
report('groth16-bls12381-intratx-residue-large all-position stress', fullStress);
for (const [label, otherSpecs, otherRun] of [['proof#1', proof1Specs, full1], ['stress', stressSpecs, fullStress]]) {
  const hybridSpecs = [...committedSpecs.slice(0, GLV_COUNT), ...otherSpecs.slice(GLV_COUNT)];
  const unboundSpecs = hybridSpecs.map((spec, i) => i === GLV_COUNT - 1 ? { ...spec, role: 'stage-final', cmp: null } : spec);
  if (!assemble(unboundSpecs).accepted) throw new Error(`${label} unbound valid-fixture hybrid was not accepted`);
  const boundInputs = [...full0.inputs.slice(0, GLV_COUNT), ...otherRun.inputs.slice(GLV_COUNT)];
  const outcomes = boundInputs.map((_, i) => evalInput(boundInputs, i));
  if (outcomes[GLV_COUNT - 1].accepted) throw new Error(`${label} hybrid did not reject at the vk_x boundary`);
  const unrelated = outcomes.find((outcome, i) => i !== GLV_COUNT - 1 && !outcome.accepted);
  if (unrelated) throw new Error(`${label} hybrid also rejected outside the vk_x boundary`);
}
console.error('  stage genesis layouts and proof#1/stress vk_x boundaries verified');
const fInv = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];

// Point-validation fixtures use only the fused Miller stage, so rejection cannot be attributed to
// the later residue verdict. The first chunk checks A on-curve; the final chunk checks B subgroup.
const committedPairs = pairsFor(INSTANCES.committed.inputs, INSTANCES.committed.proof);
const { boundary: committedRawBoundary } = millerBatchOps(committedPairs);
const { c: committedC, cInv: committedCInv } = residueWitness(committedRawBoundary);
const negA = proof.a.negate().toAffine();
const firstMiller = specsMillerResidue(INSTANCES.committed, committedC, committedCInv, { Ay: (negA.y + 1n) % P }).specs[0];
firstMiller.role = 'stage-final'; firstMiller.cmp = null;
const offCurveA = assemble([firstMiller], true);
const plusPFirstMiller = specsMillerResidue(INSTANCES.committed, committedC, committedCInv, { Ax: negA.x + P }).specs[0];
plusPFirstMiller.role = 'stage-final'; plusPFirstMiller.cmp = null;
const plusPRange = assemble([plusPFirstMiller], true);
if (plusPRange.meta[0].accepted) throw new Error('+P proof encoding passed large-script residue Miller input validation');
const twistB = F2.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2.create({ c0: i, c1: 0n });
  const rhs = F2.add(F2.mul(F2.sqr(x), x), twistB);
  let y; try { y = F2.sqrt(rhs); } catch { continue; }
  if (!F2.eql(F2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; }
}
if (!offSub) throw new Error('failed to construct off-subgroup B large-script residue fixture');
const offSubInst = {
  inputs: INSTANCES.committed.inputs,
  proof: { ...INSTANCES.committed.proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const offSubSpecs = specsMillerResidue(offSubInst, committedC, committedCInv).specs;
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
    const op = unlocking[0];
    if (op > 75 && op !== 0x4c && op !== 0x4d && op !== 0x4e) throw new Error(`${label} has an unsupported input push`);
    const dataStart = op <= 75 ? 1 : op === 0x4c ? 2 : op === 0x4d ? 3 : 5;
    const dataLen = op <= 75 ? op : op === 0x4c ? unlocking[1] : op === 0x4d
      ? unlocking[1] | (unlocking[2] << 8)
      : unlocking[1] | (unlocking[2] << 8) | (unlocking[3] << 16) | (unlocking[4] << 24);
    if (dataLen !== candidate.inLimbs.length * W) throw new Error(`${label} has an unexpected input blob length`);
    const encoded = le48Exact(value < 0n ? -value : value);
    if (value < 0n) encoded[W - 1] |= 0x80;
    unlocking.set(encoded, dataStart + location.limb * W);
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
if (!firstRangeMiller || !firstRangeTail) throw new Error('missing residue witness range fixture stage');
const rangeRuns = [
  rangeInvalid(firstRangeMiller, { limb: 0 }, -1n, 'reject negative cInv limb'),
  rangeInvalid(firstRangeMiller, { limb: 0 }, P, 'reject cInv limb at P'),
  rangeInvalid(firstRangeMiller, { limb: 12 }, -1n, 'reject negative c limb'),
  rangeInvalid(firstRangeMiller, { limb: 12 }, P, 'reject c limb at P'),
  rangeInvalid(firstRangeTail, { extra: 0 }, -1n, 'reject negative w limb'),
  rangeInvalid(firstRangeTail, { extra: 0 }, P, 'reject w limb at P'),
];
const allInvalid = [...fInv, ...semanticRuns, ...rangeRuns];
console.error(`  invalid runs rejected: ${allInvalid.map((r) => r.rejected).join(',')}`);
if (!full0.accepted || !full1.accepted || !fullStress.fits || !allInvalid.every((r) => r.rejected)) { console.error('!! a run failed -- NOT writing vectors'); process.exit(1); }

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-intratx-residue-large-vectors.json'), JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED + RESIDUE full BLS12-381 Groth16 verifier in ONE transaction with LARGE (100 kB) input scripts, targeting the PROPOSED bch-spec upgrade. Identical mechanism and residue chunk graph to bch-groth16-bls12381-intratx-residue (OP_INPUTBYTECODE forward-checking, no NFT commitment, no hashing; GLV vk_x MSM + c^-|x|-FUSED batched Miller with e(alpha,beta) baked and the G2 on-curve+prime-order-subgroup validation fused into the first/last Miller chunks + witnessed-residue mu_27A final-exp tail), but each chunk is sized to a 100 kB unlocking instead of 10 kB. On bch-spec the op-cost budget an input receives is (10000 + unlockingLen) * 800, so a 100 kB input gets 88,000,000 op (~11x the 8,032,800 of a current-BCH 10 kB input); the current-BCH plan therefore collapses from 39 inputs to 5 (GLV vk_x 1, c^-|x|-fused Miller 3, witnessed-residue walk+finalize 1). The verifier arithmetic is unchanged, while fewer state boundaries remove repeated checks and padding. Every input fits its own bch-spec input budget (op-cost <= 88,000,000, scripts <= 100,000 B) and the whole verifier is ONE non-standard (<1 MB) transaction; the residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in the tail, w enters the tail as an uncommitted witness. NOT valid on current BCH (BCH_2026 caps scripts at 10,000 B). Deployed as P2SH32 so each chunk redeem rides in the scriptSig where it counts toward the op-cost budget.',
  method: 'intra-tx-linked-residue-large', deployment: 'P2SH32', curve: 'BLS12-381', numInputs: full0.inputs.length, budgetPerInput: LARGE_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullStress),
  invalid: allInvalid.map((r) => r.steps),
  invalidInputs: [toStepArr(offCurveA), toStepArr(offSubgroupB), toStepArr(plusPRange)],
}, null, 2));
console.error('\nwrote groth16-bls12381-intratx-residue-large-vectors.json');
console.error('NOTE: generated/ now holds 100 kB-budget chunks. Regenerate the default-budget chunks before rebuilding a flagship 10 kB build:');
console.error('  node chunked/bls12-381/gen_vkx_glv.mjs && node chunked/bls12-381/gen_miller_residue.mjs && node chunked/bls12-381/gen_finalexp_residue.mjs');
