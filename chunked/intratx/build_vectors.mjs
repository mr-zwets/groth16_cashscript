// Assemble the INTRA-TRANSACTION LINKED verifier vectors for BN254.
//
// The whole chunked Groth16 computation becomes the INPUTS of ONE transaction. Each
// chunk takes its incoming state as a raw byte blob in its witness, recomputes the
// outgoing state, and FORWARD-checks its successor: it `require`s the next input's
// incoming blob (read via tx.inputs[idx+1].unlockingBytecode) equals its own output.
// No NFT-commitment hand-off, no hashing, no 128-byte limit — and it all fits one
// (non-standard, <1MB) transaction instead of 44 sequential transactions.
//
// Reuses the validated chunk MATH from chunked/pairing/generated/*.cash verbatim
// (the same files the covenant build consumes); transform.mjs only swaps the
// covIn/covOut prologue/epilogue for split-in / rebuild-out + forward-check.
//
//   node build_vectors.mjs        -> verifier/src/bch/{pairing,groth16}-intratx-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, bn254, preparedMillerOps, assertPreparedMillerManifest, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileFileBytecode, compileFileBytecodeRaw, ptLimbs, PT_CFG,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace, le40,
  OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import { transformChunk, headerSize } from './transform.mjs';
import { regenShamirSafe } from '../regen_vkx_windows.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
// Re-plan the Shamir vk_x windows to the hash-free SAFE floor (6 chunks) into a PRIVATE
// namespace (manifest_vkxplain / vkxplain_NN.cash) so the covenant build keeps its 8-window
// manifest_vkx. specsVkx below reads the private files. See chunked/regen_vkx_windows.mjs.
regenShamirSafe(GEN);
const PROBE = join(GEN, '_intratx_probe.cash'); // transformed import-chunks compiled from here
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 40; // BN254 limb width (bytes)
import { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);

// Deploy each chunk as P2SH: the ~4-5 KB redeem script (the field-tower prologue +
// chunk body) lives in the scriptSig, where it COUNTS toward the op-cost budget
// ((41 + unlockingLen) * 800) — so it does double duty (code AND budget) instead of
// sitting in the locking (which contributes nothing to the budget) alongside an
// equal-sized dead pad. Measured ~30% smaller on-chain than the bare-script model.
// P2SH is compatible with the forward-check: the inBlob stays the FIRST push of the
// scriptSig (siblings read it at a fixed front offset); the redeem is the LAST push.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL

// ---- push helpers (libauth encodeDataPush does the minimal length-prefix; we keep the
// numeric-opcode minimal forms — OP_0/OP_1..16/OP_1NEGATE — which encodeDataPush omits) ----
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le40(((BigInt(l) % P) + P) % P)]));
// trailing all-zero pad that buys op-cost budget (libauth-minimal push; the consensus VM
// rejects a non-minimal push, so a light chunk needing <256 pad bytes must not use
// PUSHDATA2). The pad sits at the END of the unlocking, so its size never shifts the front
// inBlob a sibling's forward-check reads.
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
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: { proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] },
};

// vk_x position inside the STAGE-BOUND Miller genesis inBlob (computed, not hardcoded).
// The genesis carries only the runtime points, proof tuple first: [-A/B(6), C(2), vk_x(2)];
// f and R0 are derived in-contract, so no state limbs precede the points.
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(3, dummy[3].P.toAffine(), dummy[3].Q.toAffine()).length;
const MILLER_IN_LIMBS = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) for one instance ----
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])]; // prepared-VK: only the runtime pair's R0

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.negate().toAffine(), Ca = pf.c.toAffine();
  const Bpair = [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const tail = [Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  if (man.stageBound !== true) {
    throw new Error('intratx requires STAGE_BOUND_LAYOUT=1 during G2 generation');
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
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs;
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxplain.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const inLimbs = [...inAcc, in0, in1];
    if (ch.final) {
      return {
        file: join(GEN, `vkxplain_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxFinalZinv(in0, in1)],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    return {
      file: join(GEN, `vkxplain_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, outLimbs: [...vkxStateAt(in0, in1, ch.hi), in0, in1], extras: [], role: 'within',
      label: `vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
function specsMiller(inst, crossToFinalexp) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const trace = preparedMillerOps(pairs);
  const { states, boundary } = trace;
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  // STAGE-BOUND genesis: proof tuple first (-A/B, C), then vk_x; f/R0 derived in-contract.
  const genesisPts = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  assertPreparedMillerManifest(man, trace);
  if (man.stageBound !== true) {
    throw new Error('intratx requires STAGE_BOUND_LAYOUT=1 during Miller generation');
  }
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: ch.opLo === 0 ? genesisPts : [...stateLimbs(states[ch.opLo]), ...ptL],
    outLimbs: [...stateLimbs(states[ch.opHi]), ...ptL],
    extras: [], role: ch.final ? (crossToFinalexp ? 'cross' : 'stage-final') : 'within',
    cmp: ch.final && crossToFinalexp ? { cmpExpr: 'outBlob.split(480)[0]', nextFullInLen: 12 * W, skip: 0, cmpLen: 12 * W } : null,
    label: `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' =boundary' : ''}`,
    checkpoint: ch.final ? 'miller-boundary' : undefined,
  }));
  return { specs, boundary };
}
function specsFinalexp(boundaryVal) {
  const tr = finalexpTrace(boundaryVal);
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  return man.chunks.map((ch) => ({
    file: join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: liveLimbs(ch.opLo), outLimbs: ch.final ? [] : liveLimbs(ch.opHi),
    extras: [], role: ch.final ? 'terminal' : 'within',
    label: `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`,
    checkpoint: ch.final ? 'verify' : undefined,
  }));
}

// ---- assemble: transform+compile each chunk, build the tx, tune pad, verify ----
const RESCHED = process.env.RESCHEDULE !== 'off';
const compileCache = new Map(); // key -> {resched, raw?} full redeems (raw only when RESCHEDULE differs)
const chosenCache = new Map();  // key -> 'resched' | 'raw'; fixed on the FIRST assembly so every
                                // instance shares identical lockings.
const specConfig = (specs, i) => {
  const s = specs[i];
  let forward = null;
  if (s.role === 'within') { const outLen = s.outLimbs.length * W; forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  // 'stage-final' and 'terminal' -> forward = null
  const externalBindings = (s.externalBindings ?? []).map((binding) => {
    const target = specs[binding.targetSpecIndex];
    if (!target) throw new Error(`external binding target ${binding.targetSpecIndex} is not a verifier input`);
    return {
      sourceOffset: binding.sourceOffset,
      targetInputIndex: binding.targetSpecIndex,
      targetFullInLen: target.inLimbs.length * W,
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
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward, externalBindings }).src);
    const resched = compileFileBytecode(PROBE);
    const raw = RESCHED ? compileFileBytecodeRaw(PROBE) : resched;
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) }; // [OP_DROP, contract] — OP_DROP discards the pad
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
function argBytesOf(s) {
  // inBlob is the LAST declared param (so it is pushed FIRST -> the front of the
  // unlocking bytecode, where siblings' forward-checks read it). The extra params
  // come before inBlob in the declaration, so they are pushed AFTER it in REVERSE
  // declaration order (param0 ends up on top of stack).
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(e));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
// Build the full input set for a run; tune each input's pad against its measured
// op-cost. The pad is the trailing all-zero push that buys op-cost budget; it never
// shifts the FRONT inBlob, so it cannot disturb any sibling's forward-check.
//
// P2SH (default): locking = OP_HASH256 <h> OP_EQUAL (35 B); unlocking = [inBlob,
//   extras, pad, push(redeem)] — the redeem ([OP_DROP, contract]) is the last push,
//   and it counts toward the budget, so the pad shrinks by ~the redeem length.
// bare (INTRATX_BARE=1): locking = redeem; unlocking = [inBlob, extras, pad] — the
//   redeem does not count toward the budget, so the pad must buy the whole budget.
// Both: the front of the unlocking is [inBlob, extras...], identical, so the
// forward-check offsets are the same in either model.
function assemble(specs, expectRejected = false) {
  const redeems = specs.map((_, i) => compileSpec(specs, i)); // [OP_DROP, contract]
  const argB = specs.map(argBytesOf);     // [inBlob, extras...]
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  // total unlocking length given a pad-push of `padTotal` bytes
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + tailLen(i);
    const pad = padPush(0, Math.max(2, target - fixed)); // pad sized to fill `target`
    return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]);
  };
  // pass 1: full unlocking -> max budget so the real VM accepts and reports true op-cost
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));

  // Per-chunk variant selection (RESCHEDULE only; decided once, first assembly): keep the
  // redeem with the smaller TUNED unlocking — see build_vectors_residue.mjs.
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
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    throw new Error('chosen full-budget input errored during padding measurement');
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
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}

function buildFullSpecs(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const { specs: miller, boundary } = specsMiller(inst, true);
  const fe = specsFinalexp(boundary);
  const millerGenesisIndex = g2.length + vkx.length;
  g2[g2.length - 1].externalBindings = [
    // G2-final inBlob = R(6) || -A/B/C(8); Miller genesis starts with the same proof tuple.
    { targetSpecIndex: millerGenesisIndex, sourceOffset: (g2.length === 1 ? 0 : 6) * W, targetOffset: 0, length: 8 * W },
  ];
  return [...g2, ...vkx, ...miller, ...fe];
}
function buildPairing(inst) {
  const { specs } = specsMiller(inst, false); // miller-final = stage-final (boundary milestone)
  return assemble(specs);
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
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk actually
// uses — flipping the genesis accumulator's leading infinity-limb would be a no-op).
// Both the predecessor's forward-check (out != this input's blob) and this chunk's own
// forward-check (recomputed out != successor's blob) then fail -> the run is rejected.
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => {
    const u = Uint8Array.from(inp.unlocking);
    // parse the leading inBlob push to find its data length, flip a middle data byte
    const op = u[0];
    const dataStart = op <= 75 ? 1 : op === 0x4c ? 2 : 3;
    const dataLen = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8);
    u[dataStart + Math.floor(dataLen / 2)] ^= 0x01;
    return u;
  })() } : inp));
  const meta = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })), rejected: meta.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const maxOp = Math.max(...asm.meta.map((m) => m.operationCost));
  const maxL = Math.max(...asm.meta.map((m) => m.lockingBytes)), maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  console.error(`${tag}: ${asm.meta.length} inputs, accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${maxOp.toLocaleString()} maxLock=${maxL} maxUnlock=${maxU}`);
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== PAIRING (Miller boundary, single tx) =====================
const pair0 = buildPairing(INSTANCES.committed);
report('pairing committed', pair0);
const pair1 = buildPairing(INSTANCES.proof1);
const pairWc = buildPairing(INSTANCES.worst);
report('pairing proof#1', pair1);
const pairInvalid = [invalidRun(pair0, 0), invalidRun(pair0, Math.floor(pair0.inputs.length / 2))];
console.error(`  pairing invalid runs rejected: ${pairInvalid.map((r) => r.rejected).join(',')}`);

if (!pair0.fits || !pair1.fits || !pairWc.fits || !pairInvalid.every((run) => run.rejected)) {
  throw new Error('pairing valid, worst-case, or invalid fixture failed; refusing to write vectors');
}

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-intratx-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED BN254 Groth16 pairing to the Miller boundary. A prepared batched loop shares each fp12Sqr across the three runtime-dependent pairs; the fixed e(alpha,beta) pair is omitted and its precomputed raw Miller value is multiplied into f once at the end. Its chunks are the INPUTS of ONE transaction; each takes its incoming Fp12+G2 state as a raw byte blob and FORWARD-checks its successor via OP_INPUTBYTECODE. No NFT hand-off, hashing, or 128-byte state limit. Reuses the same validated chunk math as bch-pairing-chunked.',
  method: 'intra-tx-linked', deployment: 'P2SH32', numInputs: pair0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(pair0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(pair0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...pair0.meta.map((m) => m.operationCost)),
  allFit: pair0.fits, allAccept: pair0.accepted,
  steps: toStepArr(pair0), extraValidProofs: [toStepArr(pair1)], worstCaseProof: toStepArr(pairWc),
  invalid: pairInvalid.map((r) => r.steps),
}, null, 2));
console.error('wrote pairing-intratx-vectors.json');

// ===================== FULL GROTH16 (single tx) =====================
const committedSpecs = buildFullSpecs(INSTANCES.committed);
const proof1Specs = buildFullSpecs(INSTANCES.proof1);
const worstSpecs = buildFullSpecs(INSTANCES.worst);
const full0 = assemble(committedSpecs);
report('groth16 committed', full0);
const full1 = assemble(proof1Specs);
const fullWc = assemble(worstSpecs);
report('groth16 proof#1', full1);
// ---- cross-stage staple fixtures: prove the G2->Miller binding closes the splice hole ----
const g2FinalIndex = committedSpecs.findIndex((spec) => (spec.externalBindings ?? []).length > 0);
if (g2FinalIndex < 0) throw new Error('missing G2-final external bindings');
const bindings = committedSpecs[g2FinalIndex].externalBindings;
if (bindings.length !== 1) throw new Error('expected one contiguous proof binding');
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
const bindingMutations = [1 * W, 3 * W, 7 * W].map((offset) => {
  const binding = bindings[0];
  const byteOffset = binding.targetOffset + offset;
  const inputs = mutateInputBlob(full0.inputs, binding.targetSpecIndex, byteOffset);
  if (evalInput(inputs, g2FinalIndex).accepted) {
    throw new Error(`G2 final accepted mutated bound region at ${byteOffset}`);
  }
  return { steps: toStepArr({ inputs, meta: full0.meta }), rejected: true };
});
console.error(
  `  proof consistency: unbound hybrid accepted=${unboundHybrid.accepted}; ` +
  `bound hybrid G2-final rejected=${!boundHybrid.meta[g2FinalIndex].accepted}; ` +
  `-A/B/C mutations rejected=${bindingMutations.map((m) => m.rejected).join(',')}`,
);
const fullInvalid = [
  invalidRun(full0, 0),
  invalidRun(full0, Math.floor(full0.inputs.length / 2)),
  { steps: toStepArr(boundHybrid), rejected: true },
  ...bindingMutations,
];
console.error(`  groth16 invalid runs rejected: ${fullInvalid.map((r) => r.rejected).join(',')}`);
if (!full0.fits || !full1.fits || !fullWc.fits || !fullInvalid.every((run) => run.rejected)) {
  throw new Error('Groth16 valid, worst-case, or invalid fixture failed; refusing to write vectors');
}

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-intratx-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED full BN254 Groth16 verifier in ONE transaction: validate G2 inputs -> vk_x -> prepared batched Miller (fixed e(alpha,beta) raw Miller value precomputed and multiplied once) -> final exponentiation -> assert product==1. State passes as raw byte blobs through OP_INPUTBYTECODE forward-checks, not NFT commitments. All stages bind one proof tuple: Miller derives f=1 and R0=B in-contract; G2 validation binds -A/B/C into Miller genesis; vk_x binds its result into that genesis; and the Miller boundary binds into final exponentiation. Reuses the validated bch-groth16-chunked math.',
  method: 'intra-tx-linked', deployment: 'P2SH32', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
}, null, 2));
console.error('wrote groth16-intratx-vectors.json');
