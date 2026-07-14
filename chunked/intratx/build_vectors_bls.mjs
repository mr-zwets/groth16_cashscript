// INTRA-TRANSACTION LINKED verifier vectors for BLS12-381 — the BLS counterpart of
// build_vectors.mjs. Same idea: the whole chunked computation is the INPUTS of ONE
// transaction; each chunk takes its incoming state as a raw byte blob and forward-
// checks its successor via OP_INPUTBYTECODE (no NFT commitment, no hashing).
//
// BLS specifics vs BN254: 48-byte limbs; no G2-subgroup prologue stage; the final
// exponentiation's easy-part inverse f^-1 rides as an UNCOMMITTED witness (extra args
// after the inBlob); the Miller boundary is the conjugated f. Reuses the validated
// chunk math from chunked/bls12-381/generated/*.cash (same files the covenant build
// consumes); transform.mjs only swaps the covIn/covOut for split-in / forward-check.
//
//   node build_vectors_bls.mjs -> verifier/src/bch/{pairing,groth16}-bls12381-intratx-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace,
  le48, P, OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, vk, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { vkxStateAt, vkxFinalZinv, computeVkx, compileFileBytecode, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { transformChunk } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const PROBE = join(GEN, '_intratx_probe.cash'); // transformed import-chunks compiled from here
const W = 48; // BLS12-381 limb width
const PRIME = P.toString();
import { binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);

// Deploy as P2SH so the ~4-5 KB redeem (in the scriptSig) counts toward the op-cost
// budget and offsets the pad (~30% smaller on-chain than bare). See build_vectors.mjs.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

// libauth encodeDataPush does the minimal length-prefix; pushInt keeps the numeric-opcode
// minimal forms (OP_0/OP_1..16/OP_1NEGATE) that encodeDataPush omits.
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le48(((BigInt(l) % P) + P) % P)]));
// trailing all-zero pad (libauth-minimal push). Pad sits at the END, never shifting the front inBlob.
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));

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
const G1 = bls12_381.G1.Point;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);
  const A = mod(3n * 5n + vx * 7n + 13n * 11n);
  return { inputs, proof: { a: G1.BASE.multiply(A), b: proof.b, c: proof.c } };
};
// Both valid scalars set bits 0..253, exercising every add branch in the 11 main vk_x windows.
const DENSE_INPUTS = [(1n << 254n) - 1n, (1n << 254n) - 1n];
const INSTANCES = {
  committed: { inputs: PUBLIC_INPUTS, proof },
  proof1: mkInstance([135208n, 67633n]),
  dense: mkInstance(DENSE_INPUTS),
};

// vk_x position in the Miller genesis inBlob (stateLimbs=36, then ptL; pair2's P at
// ptL offset = pairs 0+1 lengths). Same PT_CFG as BN254.
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const MILLER_STATE_LIMBS = 12 + 4 * 6;
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;

// ---- per-stage specs ----
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inLimbs = [...vkxStateAt(in0, in1, ch.lo), in0, in1];
    if (ch.final) return {
      file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxFinalZinv(in0, in1)],
      role: crossToMiller ? 'cross' : 'stage-final',
      cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
      label: 'vk_x final -> assemble vk_x', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxStateAt(in0, in1, ch.hi), in0, in1], extras: [], role: 'within', label: `vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMiller(inst) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { ops, states, finalF } = millerBatchOps(pairs);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const finalLimbs = [...f12limbs(finalF), ...states[ops.length].Rs.flatMap(r6limbs), ...ptL];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: [...stateLimbs(states[ch.opLo]), ...ptL],
    outLimbs: ch.final ? finalLimbs : [...stateLimbs(states[ch.opHi]), ...ptL],
    extras: [], role: 'cross', // every Miller boundary feeds final-exp here
    cmp: ch.final ? { cmpExpr: `outBlob.split(${12 * W})[0]`, nextFullInLen: 12 * W, skip: 0, cmpLen: 12 * W } : null,
    label: `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' +conj=boundary' : ''}`,
    checkpoint: ch.final ? 'miller-boundary' : undefined,
  }));
  // non-final miller chunks are plain within-stage links
  specs.forEach((s, i) => { if (!man.chunks[i].final) { s.role = 'within'; s.cmp = null; } });
  return { specs, boundary: finalF };
}
function specsFinalexp(boundaryVal) {
  const tr = finalexpTrace(boundaryVal);
  if (!Fp12.eql(tr.result, Fp12.ONE)) throw new Error('finalExp(boundary) != ONE');
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const witnesses = [];
    for (let i = ch.opLo; i < ch.opHi; i++) if (tr.ops[i].op === 'inv') witnesses.push(...tr.limbs12(tr.ops[i].id));
    return {
      file: join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs: liveLimbs(ch.opLo), outLimbs: ch.final ? [] : liveLimbs(ch.opHi),
      extras: witnesses, role: ch.final ? 'terminal' : 'within',
      label: `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`,
      checkpoint: ch.final ? 'verify' : undefined,
    };
  });
}

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
    v = { resched: Uint8Array.from([OP_DROP, ...resched]) };
    if (RESCHED && binToHex(raw) !== binToHex(resched)) v.raw = Uint8Array.from([OP_DROP, ...raw]);
    compileCache.set(key, v);
  }
  return (chosenCache.get(key) === 'raw' && v.raw) ? v.raw : v.resched;
}
// effective unlocking length a chunk needs, UNCAPPED (BLS redeems run close to the 10,000 B
// script caps, so an over-cap fixed part must lose the comparison rather than saturate at
// TARGET_UNLOCK); Infinity when the variant does not even accept.
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41) : Infinity);
function argBytesOf(s) {
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(e));
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
  const standardOp1 = specs.map((_, i) => evalInput(inputs, i, standardVm));

  // Per-chunk variant selection (first assembly only): keep whichever redeem needs the
  // smaller effective unlocking. BLS chunks run close to the 10,000 B script caps, so a
  // byte-fatter rescheduled redeem can overflow where the plain one fits — the uncapped
  // effLen (Infinity on non-accept) makes the plain variant win those.
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
      // both variants failing usually means a NEIGHBOUR is oversized (the forward-check
      // pushes the successor's whole unlocking) — defer this chunk's decision to the
      // reassembly, where the neighbour's switch has taken effect
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assemble(specs); // reassemble with final choices (cached -> recurses once)
  }
  if ([...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`chosen full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
  }
  let targets = specs.map((_, i) => tunedLen(argB[i].length + tailLen(i), Math.max(op1[i].operationCost, standardOp1[i].operationCost)));
  let op2;
  let standardOp2;
  while (true) {
    inputs = specs.map((_, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, targets[i]) }));
    op2 = specs.map((_, i) => evalInput(inputs, i));
    standardOp2 = specs.map((_, i) => evalInput(inputs, i, standardVm));
    if (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted)) break;
    const tightened = targets.map((target, i) => Math.min(target, tunedLen(
      argB[i].length + tailLen(i),
      Math.max(op2[i].operationCost, standardOp2[i].operationCost),
    )));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted)) {
    throw new Error('tightened input rejected during padding measurement');
  }
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}
function buildPairing(inst) { const { specs, boundary } = specsMiller(inst); return assemble([...specs, ...specsFinalexp(boundary)]); }
function buildFull(inst) { const { specs, boundary } = specsMiller(inst); return assemble([...specsVkx(inst, true), ...specs, ...specsFinalexp(boundary)]); }

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => { const u = Uint8Array.from(inp.unlocking); const op = u[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : 3; const dl = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8); u[ds + Math.floor(dl / 2)] ^= 0x01; return u; })() } : inp));
  const meta = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint })), rejected: meta.some((m) => !m.accepted) };
}
const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const bad = asm.meta.find((m) => !m.accepted);
  console.error(`${tag}: ${asm.meta.length} inputs accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()}`);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};
const meta = (asm) => ({ method: 'intra-tx-linked', deployment: 'P2SH32', curve: 'BLS12-381', numInputs: asm.inputs.length, budgetPerInput: OP_BUDGET, totalBytes: sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes), totalOperationCost: sum(asm.meta, (m) => m.operationCost), maxStepOperationCost: Math.max(...asm.meta.map((m) => m.operationCost)), allFit: asm.fits, allAccept: asm.accepted });

const OUT = 'C:/Users/mathi/Desktop/verifier/src/bch';
// pairing (miller + final exp -> verdict) single tx
const pair0 = buildPairing(INSTANCES.committed); report('pairing committed', pair0);
const pair1 = buildPairing(INSTANCES.proof1); report('pairing proof#1', pair1);
const pairDense = buildPairing(INSTANCES.dense); report('pairing max-density', pairDense);
const pInv = [invalidRun(pair0, 0), invalidRun(pair0, Math.floor(pair0.inputs.length / 2))];
console.error(`  pairing invalid rejected: ${pInv.map((r) => r.rejected).join(',')}`);
if (!pair0.accepted || !pair1.accepted || !pairDense.fits || !pInv.every((r) => r.rejected)) { console.error('!! pairing run failed -- NOT writing vectors'); process.exit(1); }
writeFileSync(`${OUT}/pairing-bls12381-intratx-vectors.json`, JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED BLS12-381 Groth16 pairing (batched 4-pair Miller -> final exponentiation -> verdict==1) as the INPUTS of ONE transaction. State passed as raw 48-byte-limb blobs via sibling-input introspection (OP_INPUTBYTECODE forward-checks); the easy-part inverse is an uncommitted witness. No NFT commitment, no hashing. Same chunk math as bch-pairing-bls12381-chunked.',
  ...meta(pair0), steps: toStepArr(pair0), extraValidProofs: [toStepArr(pair1)], worstCaseProof: toStepArr(pairDense), invalid: pInv.map((r) => r.steps),
}, null, 2));
console.error('wrote pairing-bls12381-intratx-vectors.json');

// full groth16 (vkx + miller + final exp) single tx
const full0 = buildFull(INSTANCES.committed); report('groth16 committed', full0);
const full1 = buildFull(INSTANCES.proof1); report('groth16 proof#1', full1);
const fullDense = buildFull(INSTANCES.dense); report('groth16 max-density', fullDense);
const fInv = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];
console.error(`  groth16 invalid rejected: ${fInv.map((r) => r.rejected).join(',')}`);
if (!full0.accepted || !full1.accepted || !fullDense.fits || !fInv.every((r) => r.rejected)) { console.error('!! groth16 run failed -- NOT writing vectors'); process.exit(1); }
writeFileSync(`${OUT}/groth16-bls12381-intratx-vectors.json`, JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED full BLS12-381 Groth16 verifier in ONE transaction: vk_x -> batched 4-pair Miller -> final exponentiation -> assert verdict==1, as the inputs of a single tx. State passed as raw 48-byte-limb blobs through sibling-input introspection (OP_INPUTBYTECODE forward-checks), not NFT commitments. vk_x is bound into the Miller genesis input and the Miller boundary into the final-exp genesis input. Same chunk math as bch-groth16-bls12381-chunked.',
  ...meta(full0), steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullDense), invalid: fInv.map((r) => r.steps),
}, null, 2));
console.error('wrote groth16-bls12381-intratx-vectors.json');
