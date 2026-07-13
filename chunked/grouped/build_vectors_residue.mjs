// Assemble the GROUPED verifier vectors for BN254 — a hybrid of the intra-tx linked
// method (chunked/intratx) and the covenant NFT hand-off (chunked/pairing).
//
// MOTIVATION. The multi-tx covenant (bch-groth16-chunked / -covenant) is 54 SEQUENTIAL
// transactions, one chunk each — a 54-deep unconfirmed chain that exceeds BCH's default
// mempool ancestor/descendant limit (50). The single-tx intra-tx bundle (bch-groth16-
// intratx) is one ~0.5 MB transaction — fine at consensus but NON-standard (> 100,000 B,
// must be mined directly). GROUPED packs the same 54 chunks into ~6 STANDARD transactions
// of < 100,000 B each: comfortably under the chain limit AND relayable under standard policy.
//
// MECHANISM. Within one group transaction the chunks bind each other exactly as in the
// intra-tx method — each chunk FORWARD-checks its successor's incoming blob via
// tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE). An input cannot spend an output
// created by its OWN transaction, so the cross-GROUP hand-off instead rides a CashToken NFT
// commitment (exactly the covenant method): a group's LAST chunk commits hash256(outBlob)
// to tx.outputs[0]'s NFT (covout), and the NEXT group's FIRST chunk binds its inBlob to the
// spent token via require(tx.inputs[0].nftCommitment == hash256(inBlob)) (covInHash). The
// token thread chains all groups in order (group k+1 spends group k's token), so no group
// can be skipped or reordered. Group boundaries are placed ONLY at within-stage links that
// carry the full state (outLimbs[i] == inLimbs[i+1]) — never at a stage seam — so every
// hand-off is a full-state commitment and the stage-internal cross/terminal links stay
// inside a single group, preserving the intra-tx binding bit-for-bit.
//
// Reuses the validated chunk MATH from chunked/pairing/generated/*.cash verbatim (the same
// files the covenant and intra-tx builds consume); transform.mjs only swaps prologue/epilogue.
//
//   node build_vectors.mjs   -> verifier/src/bch/groth16-grouped-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, bn254, millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileBytecode, compileFileBytecode, ptLimbs, PT_CFG,
  compileBytecodeRaw, compileFileBytecodeRaw,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace, le40, CATEGORY,
  OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import { millerFusedOps, residueWitness, fp12limbsOf } from '../pairing/_residuemath.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv } from '../pairing/gen_vkx_glv.mjs';
import { transformChunk, headerSize } from '../intratx/transform.mjs';

import { GLV_SAFE_BOUNDS, regenGlvSafe } from '../regen_vkx_windows.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
// Re-plan the GLV vk_x windows to the hash-free SAFE floor (4 chunks, max-density-validated);
// vk_x within-chunks are never at a group seam, so they run hash-free like intratx. See
// chunked/regen_vkx_windows.mjs.
regenGlvSafe(GEN, GLV_SAFE_BOUNDS, true);
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

// Deploy each chunk as P2SH (same as intra-tx): the redeem rides in the scriptSig where it
// counts toward the op-cost budget; the inBlob stays the FIRST scriptSig push (front offset
// preserved for sibling forward-checks); the redeem is the LAST push.
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs, widths = limbs.map(() => W)) => Uint8Array.from(limbs.flatMap((l, i) =>
  [...le40(((BigInt(l) % P) + P) % P).slice(0, widths[i])]));
// NFT commitment a covout chunk produces / a covInHash chunk checks == in-VM hash256(blob(limbs)).
const commitOf = (limbs, widths) => hash256(blob(limbs, widths));
const limbsEqual = (a, b) => a.length === b.length && a.every((x, i) => BigInt(x) === BigInt(b[i]));
const widthsEqual = (a, b) => a.length === b.length && a.every((width, i) => width === b[i]);
const widthsOf = (spec, side) => spec[`${side}Widths`] ?? spec[`${side}Limbs`].map(() => W);
const byteLengthOf = (spec, side) => widthsOf(spec, side).reduce((sum, width) => sum + width, 0);

const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

// OP_RETURN output (keeps the terminal group's tx well-formed; the verdict chunk ignores it)
const OP_RETURN = Uint8Array.from([0x6a]);

// ---- per-group evaluation: build ONE token-carrying tx for the group, evaluate input `index`.
// input[0] optionally spends the incoming-state token (covInHash binds it); output[0]
// optionally carries the outgoing-state token (covout commits it). Other inputs are plain.
function tokenOf(t) {
  return t ? { amount: 0n, category: CATEGORY, nft: { capability: t.cap, commitment: t.commit } } : undefined;
}
function evalGroup(inputs, index, gm) {
  const program = {
    inputIndex: index,
    sourceOutputs: inputs.map((inp, n) => ({
      lockingBytecode: inp.locking, valueSatoshis: 1000n,
      token: n === 0 ? tokenOf(gm.inToken) : undefined,
    })),
    transaction: {
      version: 2,
      inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
      outputs: gm.outToken
        ? [{ lockingBytecode: gm.outLocking, valueSatoshis: 1000n, token: tokenOf(gm.outToken) }]
        : [{ lockingBytecode: OP_RETURN, valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null, stackLen: st.stack.length, topHex: top ? binToHex(top) : '' };
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

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) for one instance ----
// ALIGNED with chunked/pairing/build_vectors.mjs (the current, working covenant build) so the
// GROUPED chain reuses the exact same ordered chunk graph (g2check -> vk_x -> batched Miller ->
// final exponentiation), roles and cross-stage cmp configs. The only difference is how the
// chain is partitioned into transactions (see assembleGrouped below). Prepared-VK Miller carries
// only the runtime pair's R0, so the state is f(12)+R0(6), NOT four R's.
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.negate().toAffine(), Ca = pf.c.toAffine();
  const Bpair = [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const tail = [Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  if (man.linkedLayout !== true) {
    throw new Error('grouped residue requires G2_LINKED_LAYOUT=1 during G2 generation');
  }
  if (man.stageBound !== true) {
    throw new Error('grouped residue requires STAGE_BOUND_LAYOUT=1 during G2 generation');
  }
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
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const st = (X, Y, Z) => [X, Y, Z, in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  if (man.stageBound !== true) throw new Error('grouped residue requires stage-bound GLV generation');
  return man.chunks.map((ch) => {
    const [X0, Y0, Z0] = vkxGlvStateAt(k10, k20, k11, k21, ch.lo);
    const fullIn = st(X0, Y0, Z0);
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) {
      return {
        file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
        outLimbs: [vkxAff.x, vkxAff.y], outWidths: [W, W], extras: [vkxGlvZinv(k10, k20, k11, k21)],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'GLV vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    const [X1, Y1, Z1] = vkxGlvStateAt(k10, k20, k11, k21, ch.hi);
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, inWidths: ch.first ? GLV_GENESIS_WIDTHS : GLV_STATE_WIDTHS,
      outLimbs: st(X1, Y1, Z1), outWidths: GLV_STATE_WIDTHS, extras: [], role: 'within',
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
    throw new Error('grouped residue requires MILLER_LINKED_LAYOUT=1 during Miller generation');
  }
  if (man.stageBound !== true) {
    throw new Error('grouped residue requires STAGE_BOUND_LAYOUT=1 during Miller generation');
  }
  return man.chunks.map((ch) => ({
    file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: ch.opLo === 0 ? genesis : full(states[ch.opLo]),
    outLimbs: ch.final ? [] : full(states[ch.opHi]),
    extras: ch.final ? fp12limbsOf(w) : [], role: ch.final ? 'terminal' : 'within',
    cmp: null,
    label: `fused-miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' + residue verdict' : ''}`,
    checkpoint: ch.final ? 'verify' : undefined,
  }));
}
function buildSpecs(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const miller = specsMillerFused(inst, c, cInv, w);
  const millerGenesisIndex = g2.length + vkx.length;
  g2[g2.length - 1].externalBindings = [
    // G2-final inBlob = R(6) || -A/B/C(8); Miller genesis starts with the same proof tuple.
    { targetSpecIndex: millerGenesisIndex, sourceOffset: 6 * W, targetOffset: 0, length: 8 * W },
  ];
  return [...g2, ...vkx, ...miller];
}

// ---- grouping: partition the ordered chunk list into transactions -------------------
// A cut between chunk i and i+1 is allowed ONLY where the full state crosses unchanged
// (outLimbs[i] == inLimbs[i+1], both non-empty) — i.e. a within-stage link. Stage seams
// (cross / terminal / genesis) carry no full-state hand-off, so they stay inside one group.
const PER_INPUT_OV = 43; // outpoint(36) + sequence(4) + script-length varint(~3)

// grouped role of chunk i in group [lo,hi] (groupIdx of G groups)
function groupedCfg(specs, i, lo, hi, groupIdx, G) {
  const isFirst = i === lo, isLast = i === hi;
  const covInHash = isFirst && groupIdx > 0;
  const epilogueMode = isLast && groupIdx < G - 1 ? 'covout' : undefined;
  let forward = null;
  if (!epilogueMode && specs[i].role !== 'terminal') {
    if (specs[i].role === 'within') { const outLen = byteLengthOf(specs[i], 'out'); forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
    else if (specs[i].role === 'cross') forward = specs[i].cmp;
  }
  const externalBindings = (specs[i].externalBindings ?? []).map((binding) => {
    const target = specs[binding.targetSpecIndex];
    if (!target) throw new Error(`external binding target ${binding.targetSpecIndex} is not a verifier input`);
    if (binding.targetSpecIndex < lo || binding.targetSpecIndex > hi) {
      throw new Error(`external binding target ${binding.targetSpecIndex} is outside group ${groupIdx}`);
    }
    return {
      sourceOffset: binding.sourceOffset,
      targetInputIndex: binding.targetSpecIndex - lo,
      targetFullInLen: byteLengthOf(target, 'in'),
      targetOffset: binding.targetOffset,
      length: binding.length,
    };
  });
  return { covInHash, epilogueMode, forward, externalBindings };
}

const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map(); // cfg key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // cfg key -> 'resched' | 'raw'; fixed on the FIRST assembly (worst-case
                                // sizing pass) so every instance shares identical lockings.
// chunks that `import` the shared singleton library must be compiled FROM A FILE so the
// relative import resolves; we write the transformed source to a probe inside generated/.
const PROBE = join(GEN, '_grouped_probe.cash');
const cfgKey = (spec, cfg) => [
  spec.file,
  cfg.covInHash ? 'ci' : '',
  cfg.epilogueMode ?? '',
  JSON.stringify(cfg.forward),
  JSON.stringify(cfg.externalBindings),
].join('|');
function compileChunk(spec, cfg) {
  const key = cfgKey(spec, cfg);
  let v = compileCache.get(key);
  if (!v) {
    const t = transformChunk(readFileSync(spec.file, 'utf8'), {
      W,
      widthsByName: GLV_WIDTHS_BY_NAME,
      prime: PRIME,
      forward: cfg.forward,
      covInHash: cfg.covInHash,
      epilogueMode: cfg.epilogueMode,
      externalBindings: cfg.externalBindings,
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
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs, widthsOf(spec, 'in')))];
  for (const e of [...spec.extras].reverse()) parts.push(pushInt(e));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

// ---- assemble a full run for one instance against a FIXED group partition ----
// `groups` is the [lo,hi] partition (computed once, shared by all instances so the lockings
// match). Returns inputs/meta plus per-group token metadata for the harness.
function assembleGrouped(specs, groups) {
  const G = groups.length;
  // role/cfg per chunk
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

  // token metadata per group (in/out NFT commitments; the genesis group mints, the terminal burns)
  const gmeta = groups.map(([lo, hi], gi) => {
    // All groups thread a MUTABLE NFT (cap byte 0x01). The genesis group's first chunk has no
    // covInHash, so its incoming commitment is irrelevant (a placeholder) — but it must still be
    // mutable so covout's `outputs[0].tokenCategory == inputs[0].tokenCategory` (capability-tagged)
    // holds. The thread is mutable->mutable across every boundary; the terminal group burns it.
    const inToken = gi === 0
      ? { cap: 'mutable', commit: new Uint8Array(0) }
      : { cap: 'mutable', commit: commitOf(specs[lo].inLimbs, widthsOf(specs[lo], 'in')) };
    const outToken = gi === G - 1 ? null : {
      cap: 'mutable', commit: commitOf(specs[hi].outLimbs, widthsOf(specs[hi], 'out')),
    };
    return { lo, hi, inToken, outToken, outLocking: null };
  });
  // outLocking = next group's first chunk locking (where the perpetuated token rests)
  for (let gi = 0; gi < G - 1; gi++) gmeta[gi].outLocking = lockings[groups[gi + 1][0]];
  // sanity: the committed out-hash of group k equals the in-hash group k+1 will check
  for (let gi = 0; gi < G - 1; gi++) {
    const a = binToHex(gmeta[gi].outToken.commit), b = binToHex(gmeta[gi + 1].inToken.commit);
    if (a !== b) throw new Error(`group ${gi} hand-off mismatch: ${a} != ${b}`);
  }

  // tune each chunk's pad against its measured op-cost (within its own group's tx)
  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const perGroupInputs = groups.map(([lo, hi]) => allInputs.slice(lo, hi + 1));
  const op1 = [];
  groups.forEach(([lo, hi], gi) => { for (let k = 0; k <= hi - lo; k++) op1[lo + k] = evalGroup(perGroupInputs[gi], k, gmeta[gi]); });

  // Per-chunk variant selection (RESCHEDULE only; decided once, on the first assembly):
  // keep whichever redeem yields the smaller TUNED unlocking. Op-cost-bound chunks favor
  // the rescheduled redeem (padding shrinks with the meter); small chunks whose unlocking
  // is arg+redeem-bound favor the byte-smaller cashc redeem. A chunk's measured op-cost
  // is independent of sibling redeems (forward-checks read only the argument front), so
  // the raw variant can be probed by swapping input i alone.
  if (RESCHED) {
    let switched = 0;
    for (let i = 0; i < specs.length; i++) {
      const key = cfgKey(specs[i], cfgs[i]);
      if (chosenCache.has(key)) continue;
      const v = compileCache.get(key);
      if (!v.raw) { chosenCache.set(key, 'resched'); continue; }
      const gi = cfgs[i].group, lo = groups[gi][0];
      const rawRpush = encodeDataPush(v.raw);
      const rawUnlock = Uint8Array.from([...argB[i], ...padPush(0, Math.max(2, TARGET_UNLOCK - (argB[i].length + rawRpush.length))), ...rawRpush]);
      const rawInputs = perGroupInputs[gi].slice();
      rawInputs[i - lo] = { locking: p2shSpk(v.raw), unlocking: rawUnlock };
      const rawOp = evalGroup(rawInputs, i - lo, gmeta[gi]);
      const tR = tunedLen(argB[i].length + rpush[i].length, op1[i].operationCost);
      const tB = rawOp.accepted ? tunedLen(argB[i].length + rawRpush.length, rawOp.operationCost) : Infinity;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    // a switch invalidates the lockings/op-costs computed above; reassemble with the now-
    // complete chosenCache (deterministic -> recurses at most once).
    if (switched) return assembleGrouped(specs, groups);
  }
  // pass 2: shrink each pad to just cover its op-cost
  for (let i = 0; i < specs.length; i++) allInputs[i].unlocking = mkUnlock(i, tunedLen(argB[i].length + rpush[i].length, op1[i].operationCost));
  const perGroupInputs2 = groups.map(([lo, hi]) => allInputs.slice(lo, hi + 1));
  const op2 = [];
  groups.forEach(([lo, hi], gi) => { for (let k = 0; k <= hi - lo; k++) op2[lo + k] = evalGroup(perGroupInputs2[gi], k, gmeta[gi]); });

  const meta = specs.map((s, i) => ({
    label: s.label, checkpoint: s.checkpoint, group: cfgs[i].group,
    lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
    operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error,
    stackLen: op2[i].stackLen, topHex: op2[i].topHex,
  }));
  const accepted = op2.every((o) => o.accepted);
  const groupBytes = groups.map(([lo, hi], gi) => {
    let b = 8 + 1 + 1; // version+locktime envelope + in-count varint + out-count varint (small)
    for (let i = lo; i <= hi; i++) b += allInputs[i].unlocking.length + PER_INPUT_OV;
    b += gmeta[gi].outToken ? 8 + 3 + (1 + 32 + 1 + 1 + 32) : 8 + 1 + 1; // token output prefix or OP_RETURN
    return b;
  });
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted && groupBytes.every((b) => b <= 100000);
  return { inputs: allInputs, meta, gmeta, groups, groupBytes, fits, accepted };
}

// ---- emit shape: each run carries its steps + per-group token config -----------------
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

function firstPushBounds(unlocking) {
  const op = unlocking[0];
  if (op <= 75) return { dataStart: 1, dataLen: op };
  if (op === 0x4c) return { dataStart: 2, dataLen: unlocking[1] };
  if (op === 0x4d) return { dataStart: 3, dataLen: unlocking[1] | (unlocking[2] << 8) };
  throw new Error(`unsupported first push opcode ${op}`);
}
function mutateInputBlob(inputs, inputIndex, byteOffset) {
  const mutated = inputs.slice();
  const unlocking = Uint8Array.from(mutated[inputIndex].unlocking);
  const { dataStart, dataLen } = firstPushBounds(unlocking);
  if (byteOffset < 0 || byteOffset >= dataLen) throw new Error(`mutation offset ${byteOffset} outside inBlob`);
  unlocking[dataStart + byteOffset] ^= 0x01;
  mutated[inputIndex] = { ...mutated[inputIndex], unlocking };
  return mutated;
}

// corrupt a middle chunk's inBlob -> its predecessor's forward-check (same group) OR its
// covInHash (group boundary) fails; either way the run is rejected.
function invalidRun(specs, groups, idx) {
  const asm = assembleGrouped(specs, groups);
  const { dataLen } = firstPushBounds(asm.inputs[idx].unlocking);
  asm.inputs = mutateInputBlob(asm.inputs, idx, Math.floor(dataLen / 2));
  const perGroup = groups.map(([lo, hi]) => asm.inputs.slice(lo, hi + 1));
  const res = [];
  groups.forEach(([lo, hi], gi) => { for (let k = 0; k <= hi - lo; k++) res[lo + k] = evalGroup(perGroup[gi], k, asm.gmeta[gi]); });
  return { run: toRun(asm), rejected: res.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const maxOp = Math.max(...asm.meta.map((m) => m.operationCost));
  const maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  console.error(`${tag}: ${asm.meta.length} inputs / ${asm.groups.length} groups, accepted=${asm.accepted} fits=${asm.fits}`);
  console.error(`  groups (chunks): ${asm.groups.map(([lo, hi]) => hi - lo + 1).join(',')}  group bytes: ${asm.groupBytes.map((b) => b.toLocaleString()).join(', ')}`);
  console.error(`  totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${maxOp.toLocaleString()} maxUnlock=${maxU}`);
  if (process.env.DUMP_OPCOSTS) asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  asm.meta.filter((m) => !m.accepted).slice(0, 4).forEach((m) => console.error(`  !! non-accepting: g${m.group} ${m.label} :: op=${m.operationCost.toLocaleString()} stackLen=${m.stackLen} top=${m.topHex} err=${m.error}`));
  const over = asm.meta.filter((m) => m.operationCost > OP_BUDGET);
  if (over.length) console.error(`  !! over-budget: ${over.map((m) => `${m.label}(${m.operationCost.toLocaleString()})`).join(', ')}`);
};

// ===================== build =====================
// Exact boundary compilation across all 276 legal three-group partitions selected the
// balanced 9/9/9 split while preserving standardness for committed, proof #1, and worst-case.
const wcSpecs = buildSpecs(INSTANCES.worst);
const GROUP_CUTS = [8, 17];
if (!GROUP_CUTS.every((i) =>
  i < wcSpecs.length - 1 &&
  wcSpecs[i].outLimbs.length > 0 &&
  limbsEqual(wcSpecs[i].outLimbs, wcSpecs[i + 1].inLimbs) &&
  widthsEqual(widthsOf(wcSpecs[i], 'out'), widthsOf(wcSpecs[i + 1], 'in'))
)) {
  throw new Error('measured grouped-residue boundary no longer carries full state');
}
const GROUPS = [[0, GROUP_CUTS[0]], [GROUP_CUTS[0] + 1, GROUP_CUTS[1]], [GROUP_CUTS[1] + 1, wcSpecs.length - 1]];

const committedSpecs = buildSpecs(INSTANCES.committed);
const proof1Specs = buildSpecs(INSTANCES.proof1);
const asmCommitted = assembleGrouped(committedSpecs, GROUPS);
report('groth16-grouped committed', asmCommitted);
const asmProof1 = assembleGrouped(proof1Specs, GROUPS);
report('groth16-grouped proof#1', asmProof1);
const asmWorst = assembleGrouped(wcSpecs, GROUPS);
report('groth16-grouped worst-case', asmWorst);

// invalid runs: corrupt a chunk that is a group's FIRST (covInHash boundary) and a generic middle one
const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1; // first chunk of group 1 (a covInHash chunk)
const g2FinalIndex = committedSpecs.findIndex((spec) => (spec.externalBindings ?? []).length > 0);
if (g2FinalIndex < 0) throw new Error('missing G2-final external bindings');
const bindings = committedSpecs[g2FinalIndex].externalBindings;
const hybridSpecs = [
  ...committedSpecs.slice(0, g2FinalIndex + 1),
  ...proof1Specs.slice(g2FinalIndex + 1),
];
const unboundHybrid = assembleGrouped(hybridSpecs.map((spec) => ({ ...spec, externalBindings: [] })), GROUPS);
if (!unboundHybrid.accepted) throw new Error('pre-binding proof0-G2/proof1-remainder hybrid was not accepted');
const boundHybrid = assembleGrouped(hybridSpecs, GROUPS);
if (boundHybrid.meta[g2FinalIndex].accepted) throw new Error('bound hybrid did not reject at G2 final');
const unrelatedFailure = boundHybrid.meta.find((meta, i) => i !== g2FinalIndex && !meta.accepted);
if (unrelatedFailure) throw new Error(`bound hybrid also rejected at ${unrelatedFailure.label}`);
if (bindings.length !== 1) throw new Error('expected one contiguous proof binding');
const bindingMutations = [3 * W, 7 * W].map((offset) => {
  const binding = bindings[0];
  const byteOffset = binding.targetOffset + offset;
  const inputs = mutateInputBlob(asmCommitted.inputs, binding.targetSpecIndex, byteOffset);
  const [groupLo, groupHi] = GROUPS[asmCommitted.meta[g2FinalIndex].group];
  const groupInputs = inputs.slice(groupLo, groupHi + 1);
  if (evalGroup(groupInputs, g2FinalIndex - groupLo, asmCommitted.gmeta[asmCommitted.meta[g2FinalIndex].group]).accepted) {
    throw new Error(`G2 final accepted mutated bound region at ${binding.targetOffset}`);
  }
  return { run: toRun({ ...asmCommitted, inputs }), rejected: true };
});
console.error(
  `  proof consistency: unbound hybrid accepted=${unboundHybrid.accepted}; ` +
  `bound hybrid G2-final rejected=${!boundHybrid.meta[g2FinalIndex].accepted}; ` +
  `-A/B mutation rejected=${bindingMutations[0].rejected}; C mutation rejected=${bindingMutations[1].rejected}`,
);
const invalids = [
  invalidRun(committedSpecs, GROUPS, Math.floor(committedSpecs.length / 2)),
  invalidRun(committedSpecs, GROUPS, firstBoundary),
  { run: toRun(boundHybrid), rejected: true },
  ...bindingMutations,
];
console.error(`  invalid runs rejected: ${invalids.map((r) => r.rejected).join(',')}`);

writeFileSync(verifierPath('src/bch/groth16-grouped-residue-vectors.json'), JSON.stringify({
  description: 'GROUPED + RESIDUE BN254 Groth16 verifier: 3 fast-G2 endomorphism chunks (ePrint 2022/348), 4 GLV vk_x chunks, and 20 c^-(6x+2)-FUSED batched Miller chunks (ePrint 2024/640) packed into 3 STANDARD (<100,000 B) transactions. The final Miller chunk also performs the witnessed-residue verdict, eliminating a separate tail input. Within each group tx the chunks forward-check each other via OP_INPUTBYTECODE; across groups the running state rides a CashToken NFT commitment. The G2 final chunk binds the proof-derived -A/B and C bytes into the Miller genesis input, while the GLV final chunk binds vk_x into that same genesis. The residue witness (c, cInv) threads through every Miller chunk; the terminal chunk checks c canonical, c*cInv==ONE, the exact w serialization in {1,w27,w27^2}, and fF*(w*c^q2)==(c*c^q2)^q. One fixed set of lockings verifies any proof for the VK.',
  method: 'grouped-residue', deployment: 'P2SH32', category: binToHex(CATEGORY),
  numInputs: asmCommitted.meta.length, numGroups: GROUPS.length, budgetPerInput: OP_BUDGET,
  groupSizes: GROUPS.map(([lo, hi]) => hi - lo + 1),
  groupBytes: asmCommitted.groupBytes,
  worstCaseGroupBytes: asmWorst.groupBytes,
  totalBytes: sum(asmCommitted.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(asmCommitted.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...asmCommitted.meta.map((m) => m.operationCost)),
  allFit: asmCommitted.fits, allAccept: asmCommitted.accepted,
  valid: toRun(asmCommitted),
  extraValidProofs: [toRun(asmProof1)],
  worstCaseProof: toRun(asmWorst),
  invalid: invalids.map((r) => r.run),
}, null, 2));
console.error(`wrote groth16-grouped-residue-vectors.json (${GROUPS.length} groups, ${asmCommitted.meta.length} inputs)`);
