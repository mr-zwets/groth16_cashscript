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
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace, le40, CATEGORY, commitBin,
  OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import { millerFusedOps, residueWitness, fp12limbsOf } from '../pairing/_residuemath.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv } from '../pairing/gen_vkx_glv.mjs';
import { transformChunk, headerSize } from '../intratx/transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 40; // BN254 limb width (bytes)
import { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);

// Deploy each chunk as P2SH (same as intra-tx): the redeem rides in the scriptSig where it
// counts toward the op-cost budget; the inBlob stays the FIRST scriptSig push (front offset
// preserved for sibling forward-checks); the redeem is the LAST push.
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le40(((BigInt(l) % P) + P) % P)]));
// NFT commitment a covout chunk produces / a covInHash chunk checks == in-VM hash256(blob(limbs)).
// limbs here are reduced (< P), so commitBin's le40 concat equals blob(limbs).
const commitOf = (limbs) => commitBin(limbs);
const limbsEqual = (a, b) => a.length === b.length && a.every((x, i) => BigInt(x) === BigInt(b[i]));

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
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: { proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] },
};

// vk_x position inside the FUSED miller genesis inBlob. The fused layout is
// f(12)+R0(6)+pts(10)+c(12)+cInv(12) = 52 limbs; vk_x (pair2 P) sits at the SAME offset as the
// non-fused build (after f+R0+pair0 pts) since c,cInv are appended at the END.
const MILLER_STATE_LIMBS = 12 + 6; // f(12) + R0(6)
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const PTL_LEN = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length; // 10
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + PTL_LEN + 24; // + c(12) + cInv(12) = 52 (fused)
const TAIL_IN_LIMBS = 12 + 12 + 12; // [fF, c, cInv] hand-off from the fused miller's final chunk

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) for one instance ----
// ALIGNED with chunked/pairing/build_vectors.mjs (the current, working covenant build) so the
// GROUPED chain reuses the exact same ordered chunk graph (g2check -> vk_x -> batched Miller ->
// final exponentiation), roles and cross-stage cmp configs. The only difference is how the
// chain is partitioned into transactions (see assembleGrouped below). Prepared-VK Miller carries
// only the runtime pair's R0, so the state is f(12)+R0(6), NOT four R's.
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bpair = [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const tail = [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Aa.x, Aa.y, Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  const zinv = g2checkFastZinv(Bpair); // [zinvA, zinvB] witnessed inverse of [x0]B.Z (last chunk only)
  return man.chunks.map((ch) => ({
    file: join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: sLimbs(g2checkAccAt(Bpair, ch.lo)),
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
  return man.chunks.map((ch) => {
    const [X0, Y0, Z0] = vkxGlvStateAt(k10, k20, k11, k21, ch.lo);
    const inLimbs = st(X0, Y0, Z0);
    if (ch.final) {
      return {
        file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxGlvZinv(k10, k20, k11, k21)],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'GLV vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    const [X1, Y1, Z1] = vkxGlvStateAt(k10, k20, k11, k21, ch.hi);
    return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, outLimbs: st(X1, Y1, Z1), extras: [], role: 'within',
      label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
// c^-(6x+2)-FUSED miller (residue method). State f(12)+R0(6)+pts(10)+c(12)+cInv(12) = 52; the
// FINAL chunk hands off only [fF, c, cInv] (36) to the residue tail. c,cInv are the (constant)
// residue witness, carried through every chunk and re-checked in the tail (c*cInv==ONE).
function specsMillerFused(inst, c, cInv) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const full = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...ptL, ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 52
  const handoff = (s) => [...f12limbs(s.f), ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 36 -> tail
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: full(states[ch.opLo]),
    outLimbs: ch.final ? handoff(states[ch.opHi]) : full(states[ch.opHi]),
    extras: [], role: ch.final ? 'cross' : 'within',
    cmp: ch.final ? { cmpExpr: 'outBlob', nextFullInLen: TAIL_IN_LIMBS * W, skip: 0, cmpLen: TAIL_IN_LIMBS * W } : null,
    label: `fused-miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' =boundary*c^-(6x+2)' : ''}`,
    checkpoint: ch.final ? 'miller-boundary' : undefined,
  }));
  return { specs, boundary };
}
// witnessed-residue final-exp TAIL — ONE chunk. inBlob = [fF, c, cInv] (36); w is a witness extra.
function specsResidueTail(fF, c, cInv, w) {
  return [{
    file: join(GEN, 'finalexpres_00.cash'),
    inLimbs: [...fp12limbsOf(fF), ...fp12limbsOf(c), ...fp12limbsOf(cInv)],
    outLimbs: [], extras: fp12limbsOf(w), role: 'terminal',
    label: 'residue-tail fF*w*c^q2==c^q*c^q3 verdict', checkpoint: 'verify',
  }];
}
function buildSpecs(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const { specs: miller, boundary: fF } = specsMillerFused(inst, c, cInv);
  const tail = specsResidueTail(fF, c, cInv, w);
  return [...g2, ...vkx, ...miller, ...tail];
}

// ---- grouping: partition the ordered chunk list into transactions -------------------
// A cut between chunk i and i+1 is allowed ONLY where the full state crosses unchanged
// (outLimbs[i] == inLimbs[i+1], both non-empty) — i.e. a within-stage link. Stage seams
// (cross / terminal / genesis) carry no full-state hand-off, so they stay inside one group.
const PER_INPUT_OV = 43; // outpoint(36) + sequence(4) + script-length varint(~3)
function packGroups(specs, sz, target) {
  const allowed = (i) => i < specs.length - 1 && specs[i].outLimbs.length > 0 && limbsEqual(specs[i].outLimbs, specs[i + 1].inLimbs);
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

// grouped role of chunk i in group [lo,hi] (groupIdx of G groups)
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
const compileCache = new Map(); // cfg key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // cfg key -> 'resched' | 'raw'; fixed on the FIRST assembly (worst-case
                                // sizing pass) so every instance shares identical lockings.
// chunks that `import` the shared singleton library must be compiled FROM A FILE so the
// relative import resolves; we write the transformed source to a probe inside generated/.
const PROBE = join(GEN, '_grouped_probe.cash');
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
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs))];
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
      : { cap: 'mutable', commit: commitOf(specs[lo].inLimbs) };
    const outToken = gi === G - 1 ? null : { cap: 'mutable', commit: commitOf(specs[hi].outLimbs) };
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

// corrupt a middle chunk's inBlob -> its predecessor's forward-check (same group) OR its
// covInHash (group boundary) fails; either way the run is rejected.
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
// Compute the group partition ONCE from the WORST-CASE instance (largest pads) so every
// instance fits and all instances share the SAME lockings (group roles are identical).
const TARGET_GROUP_BYTES = 99000; // GLV-shrunk verifier packs into 3 standard txs (<100KB each)
const wcSpecs = buildSpecs(INSTANCES.worst);
// size estimate for packing: assemble worst-case in a single trivial partition to size pads,
// then pack. We size with a conservative per-chunk ceiling first to avoid the chicken/egg of
// roles affecting size: assemble once with a naive 1-group-per-chunk-free guess is overkill,
// so instead pack using the worst-case unlocking sizes from a full single-group assembly.
function sizeEstimate(specs) {
  // assemble with everything in one group is invalid (cross-tx token), so size each chunk's
  // unlocking via the intra-tx pad rule using its op-cost measured in a tiny 2-input probe is
  // also heavy. Simplest robust proxy: tune against TARGET then measure — do a provisional
  // pack with a generous target, assemble, then read true sizes and repack.
  const provisional = packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES);
  const a = assembleGrouped(specs, provisional);
  return a.meta.map((m) => m.unlockingBytes);
}
const wcSizes = sizeEstimate(wcSpecs);
const GROUPS = packGroups(wcSpecs, wcSizes, TARGET_GROUP_BYTES);

const asmCommitted = assembleGrouped(buildSpecs(INSTANCES.committed), GROUPS);
report('groth16-grouped committed', asmCommitted);
const asmProof1 = assembleGrouped(buildSpecs(INSTANCES.proof1), GROUPS);
report('groth16-grouped proof#1', asmProof1);
const asmWorst = assembleGrouped(wcSpecs, GROUPS);
report('groth16-grouped worst-case', asmWorst);

// invalid runs: corrupt a chunk that is a group's FIRST (covInHash boundary) and a generic middle one
const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1; // first chunk of group 1 (a covInHash chunk)
const cSpecs = buildSpecs(INSTANCES.committed);
const invalids = [invalidRun(cSpecs, GROUPS, Math.floor(cSpecs.length / 2)), invalidRun(cSpecs, GROUPS, firstBoundary)];
console.error(`  invalid runs rejected: ${invalids.map((r) => r.rejected).join(',')}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-grouped-residue-vectors.json', JSON.stringify({
  description: 'GROUPED + RESIDUE BN254 Groth16 verifier: the residue-optimized chunk graph (fast-G2 endo subgroup check, ePrint 2022/348, 4 chunks; vk_x MSM; c^-(6x+2)-FUSED batched Miller, ePrint 2024/640; witnessed-residue final-exp TAIL collapsing the hard part to 1 chunk) packed into a handful of STANDARD (<100,000 B) transactions. Within each group tx the chunks forward-check each other via OP_INPUTBYTECODE; across groups the running state rides a CashToken NFT commitment. The residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in the tail (c*cInv==ONE, c canonical, w in {1,w27,w27^2}); the verdict is fF*w*c^q2 == c^q*c^q3. One fixed set of lockings verifies any proof for the VK.',
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
