// INTRA-TRANSACTION LINKED + RESIDUE verifier vectors for BLS12-381 — the BLS counterpart of
// build_vectors_residue.mjs (BN254) and the intra-tx cousin of the grouped-residue BLS build
// (chunked/grouped/build_vectors_residue_bls.mjs).
//
// Same single-transaction forward-checking mechanism as build_vectors_bls.mjs (each chunk is an
// INPUT whose witness carries its incoming state as a raw 48-byte-limb blob and require()s the
// next input's blob — read via tx.inputs[idx+1].unlockingBytecode — equals its recomputed output;
// no NFT commitment, no hashing, arbitrary intermediate size), but it consumes the RESIDUE chunk
// graph instead of the plain one:
//
//   GLV vk_x MSM (4-scalar ~128-bit Straus, baked table)              6 chunks
//   c^-|x|-FUSED batched Miller, e(alpha,beta) baked (cmul1); the G2   30 chunks
//     on-curve + subgroup check is FUSED in (first/last chunks reuse R_B=[|x|]B)
//   witnessed-residue final-exp TAIL: mu_27A ((w^|x|)*w)^9 walk        6 chunks (5 walk + finalize)
//                                                                     ---------
//                                                                     42 inputs
//
// The chunk MATH is reused VERBATIM from the same generated/*.cash the grouped-residue BLS build
// consumes — only the assembly differs (one non-standard <1 MB tx vs token-threaded standard txs).
// The residue witness (c, cInv) threads through every fused-Miller chunk; w enters the tail as an
// uncommitted witness. One fixed set of lockings verifies any proof for the VK.
//
//   node build_vectors_residue_bls.mjs -> verifier/src/bch/groth16-bls12381-intratx-residue-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs,
  le48, P, OP_DROP, TARGET_UNLOCK, OP_BUDGET,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { residueWitness, millerFusedOps } from '../bls12-381/_residuemath.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv } from '../bls12-381/gen_vkx_glv.mjs';
import { residueWalkT } from '../bls12-381/gen_finalexp_residue.mjs';
import { transformChunk } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const PROBE = join(GEN, '_intratx_residue_bls_probe.cash'); // transformed import-chunks compiled from here
const W = 48; // BLS12-381 limb width (bytes)
const PRIME = P.toString();
import { binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);

// Deploy as P2SH so the ~4-5 KB redeem (in the scriptSig) counts toward the op-cost budget and
// offsets the pad (~30% smaller on-chain than bare). See build_vectors_bls.mjs.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le48(((BigInt(l) % P) + P) % P)]));
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

// ---- multi-input evaluation: build ONE tx from all inputs, evaluate at `index` ----
function evalInput(inputs, index) {
  const st = realVm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: 1000n })),
    transaction: { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })), outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }], locktime: 0 },
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
const INSTANCES = { committed: { inputs: PUBLIC_INPUTS, proof }, proof1: mkInstance([135208n, 67633n]) };

// ---- residue chunk-graph layout constants (identical to grouped/build_vectors_residue_bls.mjs) ----
// fused-Miller state = f(12) + R_B(6) + runtime points(10) + c(12) + cInv(12) = 52 limbs.
const MILLER_STATE_LIMBS = 12 + 6; // f + R_B
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const ptLof = (inst) => { const pr = pairsFor(inst.inputs, inst.proof); return pr.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())); };
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length; // vk_x = pair2 P, at 18+6 = 24
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + ptLof(INSTANCES.committed).length; // 18 + 10 = 52
const TAIL_HANDOFF_LIMBS = 36; // [fF, c, cInv]

// ---- per-stage specs (inLimbs/outLimbs/extras/role) — same graph as the grouped-residue BLS
// build; only the assembly below differs (single tx, forward-checks, no token). ----
const stateLimbsR = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 42
const withPtsR = (limbs, ptL) => [...limbs.slice(0, 18), ...ptL, ...limbs.slice(18)]; // insert ptL after f+R_B

function specsVkxGlv(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const scal = [in0, in1, k10, k20, k11, k21];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglv.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inLimbs = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scal];
    if (ch.final) return {
      file: join(GEN, `vkxglv_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxGlvZinv(k10, k20, k11, k21)], role: 'cross',
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
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41 + 96) : Infinity);
function argBytesOf(s) {
  // inBlob is the LAST declared param (pushed FIRST -> front of the unlocking, where siblings'
  // forward-checks read it); extras come before inBlob in the decl, pushed AFTER it in reverse.
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
function assemble(specs) {
  const redeems = specs.map(compileSpec); // [OP_DROP, contract]
  const argB = specs.map(argBytesOf);     // [inBlob, extras...]
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => { const pad = padPush(0, Math.max(2, target - (argB[i].length + tailLen(i)))); return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]); };
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));

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
      const tR = effLen(argB[i].length + tailLen(i), op1[i].operationCost, op1[i].accepted);
      const tB = effLen(rawFixed, rawOp.operationCost, rawOp.accepted);
      // both variants failing usually means a NEIGHBOUR is oversized (the forward-check pushes the
      // successor's whole unlocking) — defer this chunk's decision to the reassembly.
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assemble(specs); // reassemble with final choices (cached -> recurses once)
  }
  inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, tunedLen(argB[i].length + tailLen(i), op1[i].operationCost)) }));
  const op2 = specs.map((_, i) => evalInput(inputs, i));
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}
function buildFull(inst) { return assemble(buildSpecs(inst)); }

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk uses); the
// predecessor's forward-check (and/or this chunk's own) then fails -> the run is rejected.
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => { const u = Uint8Array.from(inp.unlocking); const op = u[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : 3; const dl = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8); u[ds + Math.floor(dl / 2)] ^= 0x01; return u; })() } : inp));
  const meta = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })), rejected: meta.some((m) => !m.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const bad = asm.meta.find((m) => !m.accepted);
  console.error(`${tag}: ${asm.meta.length} inputs accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()}`);
  if (process.env.DUMP_OPCOSTS) asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== FULL GROTH16 (residue, single tx) =====================
const full0 = buildFull(INSTANCES.committed);
report('groth16-bls12381-intratx-residue committed', full0);
const full1 = buildFull(INSTANCES.proof1);
report('groth16-bls12381-intratx-residue proof#1', full1);
const fInv = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];
console.error(`  invalid runs rejected: ${fInv.map((r) => r.rejected).join(',')}`);
if (!full0.accepted || !full1.accepted || !fInv.every((r) => r.rejected)) { console.error('!! a run failed -- NOT writing vectors'); process.exit(1); }

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-bls12381-intratx-residue-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED + RESIDUE full BLS12-381 Groth16 verifier in ONE transaction. Same OP_INPUTBYTECODE forward-checking as bch-groth16-bls12381-intratx (each chunk is an input whose witness carries its incoming state as a raw 48-byte-limb blob and require()s the next input\'s blob == its recomputed output — no NFT commitment, no hashing, arbitrary intermediate size), but it runs the residue-optimized chunk graph: GLV vk_x MSM (6 chunks), c^-|x|-FUSED batched Miller with e(alpha,beta) baked and only e(-A,B) running on-chain G2 arithmetic (30 chunks; the G2 on-curve + prime-order-subgroup validation is FUSED into the first/last Miller chunks, reusing the running R_B=[|x|]B the loop already walks), and a witnessed-residue final-exp TAIL collapsing the Hayashida-Scott hard part to a mu_27A ((w^|x|)*w)^9 walk + fF*w==frob(c,1) verdict (6 chunks). The residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in the tail; w enters the tail as an uncommitted witness. Cross-stage soundness links are bound where layouts allow: vk_x final binds the vk_x point into the fused-Miller genesis input, and the fused-Miller boundary [fF,c,cInv] is bound into the residue tail. Reuses the same validated chunk math as bch-groth16-bls12381-grouped-residue. Deployed P2SH32.',
  method: 'intra-tx-linked-residue', deployment: 'P2SH32', curve: 'BLS12-381', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)],
  invalid: fInv.map((r) => r.steps),
}, null, 2));
console.error('wrote groth16-bls12381-intratx-residue-vectors.json');
