// INTRA-TRANSACTION LINKED verifier vectors for BLS12-381 — the BLS counterpart of
// build_vectors.mjs. Same idea: the whole chunked computation is the INPUTS of ONE
// transaction; each chunk takes its incoming state as a raw byte blob and forward-
// checks its successor via OP_INPUTBYTECODE (no NFT commitment, no hashing).
//
// BLS specifics vs BN254: 48-byte limbs; the full verifier fuses input validation into
// its Miller loop; the pairing-only milestone intentionally does not validate inputs. The final
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
  Fp12, millerPreparedOps, assertPreparedMillerManifest, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace,
  le48Exact, P, OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { computeVkx, compileFileBytecode, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import {
  glvDecompose, vkxGlvStateAt, vkxGlvZinv, GLV_TABLE_HEX,
  GLV_HIGH_COST_INPUTS, GLV_SHARED_AUDITED_BOUNDS, regenGlvSharedAudited,
} from '../bls12-381/gen_vkx_glv.mjs';
import { transformChunk, headerSize } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const PROBE = join(GEN, '_intratx_probe.cash'); // transformed import-chunks compiled from here
const W = 48; // BLS12-381 limb width
const PRIME = P.toString();
import { hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);
const GLV_TABLE_BYTES = hexToBin(GLV_TABLE_HEX.slice(2));
const GLV_COUNT = GLV_SHARED_AUDITED_BOUNDS.length - 1;
const GLV_STATE_BYTES = 9 * W;
regenGlvSharedAudited(GEN, {
  inputIndex: GLV_COUNT - 1,
  dataOffset: headerSize(GLV_STATE_BYTES) + GLV_STATE_BYTES + headerSize(GLV_TABLE_BYTES.length),
}, true, true);

// Deploy as P2SH so the ~4-5 KB redeem (in the scriptSig) counts toward the op-cost
// budget and offsets the pad (~30% smaller on-chain than bare). See build_vectors.mjs.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

// libauth encodeDataPush does the minimal length-prefix; pushInt keeps the numeric-opcode
// minimal forms (OP_0/OP_1..16/OP_1NEGATE) that encodeDataPush omits.
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((limb) => [...le48Exact(limb)]));
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

// ---- instances: #0 committed, #1 distinct A/B/C/vk_x under the same VK ----
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;
const Fr = bls12_381.fields.Fr;
const Rord = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % Rord) + Rord) % Rord;
const mkInstance = (inputs, bS = 1n, cS = 13n) => {
  const [s0, s1] = inputs.map(BigInt);
  const vx = mod(2n + s0 * 4n + s1 * 6n);
  const rhs = mod(3n * 5n + vx * 7n + cS * 11n);
  const A = Fr.mul(rhs, Fr.inv(bS));
  return { inputs, proof: { a: G1.BASE.multiply(A), b: G2.BASE.multiply(bS), c: G1.BASE.multiply(cS) } };
};
const INSTANCES = {
  committed: { inputs: PUBLIC_INPUTS, proof },
  proof1: mkInstance([135208n, 67633n], 17n, 19n),
  pairingDense: mkInstance([(1n << 254n) - 1n, (1n << 254n) - 1n]),
  dense: mkInstance(GLV_HIGH_COST_INPUTS),
};

// ---- per-stage specs ----
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const F2 = bls12_381.fields.Fp2;
const sameLimbs = (a, b) => a.length === b.length && a.every((v, i) => BigInt(v) === BigInt(b[i]));
const stageLimbs = (inst, bad = {}) => {
  const A = inst.proof.a.negate().toAffine(), B = inst.proof.b.toAffine(), C = inst.proof.c.toAffine();
  const vkx = computeVkx(inst.inputs.map(BigInt)).toAffine();
  return [
    bad.Ax ?? A.x, bad.Ay ?? A.y,
    bad.Bx?.c0 ?? B.x.c0, bad.Bx?.c1 ?? B.x.c1,
    bad.By?.c0 ?? B.y.c0, bad.By?.c1 ?? B.y.c1,
    bad.Cx ?? C.x, bad.Cy ?? C.y,
    bad.vkxX ?? vkx.x, bad.vkxY ?? vkx.y,
  ];
};

function specsVkx(inst, bad = {}) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const [k10, k20] = glvDecompose(in0), [k11, k21] = glvDecompose(in1);
  const scalars = [in0, in1, k10, k20, k11, k21];
  const stage = stageLimbs(inst, bad);
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxglvfull.json'), 'utf8'));
  if (man.stageBound !== true || man.fullStageBound !== true || man.sharedTable !== true || man.numChunks !== GLV_COUNT) {
    throw new Error('full GLV vk_x manifest is not the stage-bound shared-table layout');
  }
  return man.chunks.map((ch) => {
    const fullIn = [...vkxGlvStateAt(k10, k20, k11, k21, ch.lo), ...scalars];
    const inLimbs = ch.first ? fullIn.slice(3) : fullIn;
    if (ch.final) return {
      file: join(GEN, `vkxglvfull_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: stage, extras: [vkxGlvZinv(k10, k20, k11, k21), ...stage.slice(0, 8), GLV_TABLE_BYTES],
      role: 'within', label: 'GLV vk_x final -> bind (-A,B,C,vk_x)', checkpoint: 'vk_x',
    };
    return {
      file: join(GEN, `vkxglvfull_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [...vkxGlvStateAt(k10, k20, k11, k21, ch.hi), ...scalars], extras: [],
      role: 'within', label: `GLV vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}

function specsMiller(inst, validated = false, bad = {}) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const trace = millerPreparedOps(pairs);
  const { ops, states, finalF } = trace;
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const traceStage = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];
  if (!sameLimbs(traceStage, stageLimbs(inst))) throw new Error('Miller genesis layout mismatch');
  const stage = stageLimbs(inst, bad);
  const prefix = validated ? 'millerfull' : 'miller';
  const man = JSON.parse(readFileSync(join(GEN, `manifest_${prefix}.json`), 'utf8'));
  if (man.inputValidationFused !== validated) throw new Error(`${prefix} input-validation mode mismatch`);
  assertPreparedMillerManifest(man, trace, { checkReferenceBoundary: inst === INSTANCES.committed });
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `${prefix}_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: ch.opLo === 0 ? stage : [...stateLimbs(states[ch.opLo]), ...ptL],
    outLimbs: ch.final ? f12limbs(finalF) : [...stateLimbs(states[ch.opHi]), ...ptL],
    extras: [], role: 'within',
    label: `${validated ? 'validated ' : ''}miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' +subgroup+conj=boundary' : ''}`,
    checkpoint: ch.opLo === 0 && validated ? 'validate-inputs' : ch.final ? 'miller-boundary' : undefined,
  }));
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
    writeFileSync(PROBE, transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward, enforceExactInputLength: true }).src);
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
    if (switched) return assemble(specs, expectRejected); // reassemble with final choices (cached -> recurses once)
  }
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
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
  if (expectRejected && accepted) throw new Error('invalid intra-transaction fixture unexpectedly accepted');
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}
function buildPairing(inst) { const { specs, boundary } = specsMiller(inst); return assemble([...specs, ...specsFinalexp(boundary)]); }
function buildFullSpecs(inst) {
  const { specs: miller, boundary } = specsMiller(inst, true);
  return [...specsVkx(inst), ...miller, ...specsFinalexp(boundary)];
}
function buildFull(inst) { return assemble(buildFullSpecs(inst)); }

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
function pushBounds(unlocking, opcodeOffset = 0) {
  const op = unlocking[opcodeOffset];
  if (op <= 75) return { dataStart: opcodeOffset + 1, dataLen: op };
  if (op === 0x4c) return { dataStart: opcodeOffset + 2, dataLen: unlocking[opcodeOffset + 1] };
  if (op === 0x4d) return { dataStart: opcodeOffset + 3, dataLen: unlocking[opcodeOffset + 1] | (unlocking[opcodeOffset + 2] << 8) };
  throw new Error(`unsupported inBlob push opcode ${op}`);
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
function invalidInputsRun(asm, inputs) {
  const outcomes = inputs.map((_, i) => evalInput(inputs, i));
  return { steps: toStepArr({ inputs, meta: asm.meta }), rejected: outcomes.some((outcome) => !outcome.accepted) };
}
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => { const u = Uint8Array.from(inp.unlocking); const op = u[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : 3; const dl = op <= 75 ? op : op === 0x4c ? u[1] : u[1] | (u[2] << 8); u[ds + Math.floor(dl / 2)] ^= 0x01; return u; })() } : inp));
  return invalidInputsRun(asm, inputs);
}
const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const bad = asm.meta.find((m) => !m.accepted);
  console.error(`${tag}: ${asm.meta.length} inputs accepted=${asm.accepted} fits=${asm.fits} | totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${Math.max(...asm.meta.map((m) => m.operationCost)).toLocaleString()}`);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};
const meta = (asm) => ({ method: 'intra-tx-linked', deployment: 'P2SH32', curve: 'BLS12-381', numInputs: asm.inputs.length, budgetPerInput: OP_BUDGET, totalBytes: sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes), totalOperationCost: sum(asm.meta, (m) => m.operationCost), maxStepOperationCost: Math.max(...asm.meta.map((m) => m.operationCost)), allFit: asm.fits, allAccept: asm.accepted });

// pairing (miller + final exp -> verdict) single tx
const pair0 = buildPairing(INSTANCES.committed); report('pairing committed', pair0);
const pair1 = buildPairing(INSTANCES.proof1); report('pairing proof#1', pair1);
const pairDense = buildPairing(INSTANCES.pairingDense); report('pairing max-density', pairDense);
const pInv = [invalidRun(pair0, 0), invalidRun(pair0, Math.floor(pair0.inputs.length / 2))];
console.error(`  pairing invalid rejected: ${pInv.map((r) => r.rejected).join(',')}`);
if (!pair0.fits || !pair1.fits || !pairDense.fits || !pInv.every((r) => r.rejected)) {
  throw new Error('pairing valid, dense, or invalid fixture failed; refusing to write vectors');
}
writeFileSync(verifierPath('src', 'bch', 'pairing-bls12381-intratx-vectors.json'), JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED BLS12-381 Groth16 pairing (prepared-VK Miller product -> final exponentiation -> verdict==1) as the INPUTS of ONE transaction. Pairing-only intentionally does not validate G1/G2 inputs; the full Groth16 track does. Miller genesis accepts exactly (-A,B,C,vk_x), derives f=1 and R_B=B, and each chunk forward-checks its entire successor state via OP_INPUTBYTECODE. Fixed gamma/delta lines and e(alpha,beta) are manifest-bound VK constants. The easy-part inverse is an uncommitted verified witness; no NFT commitment or state hashing is used.',
  ...meta(pair0), steps: toStepArr(pair0), extraValidProofs: [toStepArr(pair1)], worstCaseProof: toStepArr(pairDense), invalid: pInv.map((r) => r.steps),
}, null, 2));
console.error('wrote pairing-bls12381-intratx-vectors.json');

// full groth16 (vkx + input-validated miller + final exp) single tx
const full0Specs = buildFullSpecs(INSTANCES.committed);
const full1Specs = buildFullSpecs(INSTANCES.proof1);
const fullDenseSpecs = buildFullSpecs(INSTANCES.dense);
if (full0Specs[0].inLimbs.length !== 6 || !sameLimbs(full0Specs[GLV_COUNT - 1].outLimbs, full0Specs[GLV_COUNT].inLimbs)) {
  throw new Error('GLV genesis or exact (-A,B,C,vk_x) seam is not stage-bound');
}
const full0 = assemble(full0Specs); report('groth16 committed', full0);
const full1 = assemble(full1Specs); report('groth16 proof#1', full1);
const fullDense = assemble(fullDenseSpecs); report('groth16 max-density', fullDense);
const fInv = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];

// Semantic input-validation fixtures isolate the fused checks from the later pairing verdict.
const negA = proof.a.negate().toAffine(), C = proof.c.toAffine();
const isolatedFirstMiller = (bad, forgedPrefix = []) => {
  const first = specsMiller(INSTANCES.committed, true, bad).specs[0];
  first.role = 'stage-final';
  if (forgedPrefix.length > 0) first.inLimbs = [...forgedPrefix, ...first.inLimbs];
  return assemble([first], true);
};
const offCurveA = isolatedFirstMiller({ Ay: (negA.y + 1n) % P });
const plusPBad = { Ax: negA.x + P };
const plusPVkx = specsVkx(INSTANCES.committed, plusPBad);
const plusPFirstMiller = specsMiller(INSTANCES.committed, true, plusPBad).specs[0];
plusPFirstMiller.role = 'stage-final';
const plusPRange = assemble([plusPVkx[plusPVkx.length - 1], plusPFirstMiller], true);
if (!plusPRange.meta[0].accepted || plusPRange.meta[1].accepted) {
  throw new Error('+P proof encoding did not cross the GLV seam and reject at Miller input validation');
}
const offCurveC = isolatedFirstMiller({ Cy: (C.y + 1n) % P });
const twistB = F2.create({ c0: 4n, c1: 4n });
let offSub = null;
for (let i = 1n; i < 800n && !offSub; i++) {
  const x = F2.create({ c0: i, c1: 0n });
  const rhs = F2.add(F2.mul(F2.sqr(x), x), twistB);
  let y; try { y = F2.sqrt(rhs); } catch { continue; }
  if (!F2.eql(F2.sqr(y), rhs)) continue;
  try { G2.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; }
}
if (!offSub) throw new Error('failed to construct off-subgroup B fixture');
const offSubInst = {
  inputs: INSTANCES.committed.inputs,
  proof: { ...INSTANCES.committed.proof, b: G2.fromAffine({ x: offSub.x, y: offSub.y }) },
};
const offSubSpecs = specsMiller(offSubInst, true).specs;
offSubSpecs[offSubSpecs.length - 1].role = 'stage-final';
const offSubgroupB = assemble(offSubSpecs, true);

// The validated Miller genesis accepts exactly ten stage limbs and derives f/R_B.
const forgedState = isolatedFirstMiller({}, Array.from({ length: 18 }, (_, i) => BigInt(i + 1)));

const badRangeSpecs = buildFullSpecs(INSTANCES.committed);
const badRangeGenesis = [...badRangeSpecs[0].inLimbs]; badRangeGenesis[0] = Rord;
badRangeSpecs[0] = { ...badRangeSpecs[0], inLimbs: badRangeGenesis };
const outOfRange = assemble(badRangeSpecs, true);
const oversizedSpecs = buildFullSpecs(INSTANCES.committed);
const oversizedGenesis = [...oversizedSpecs[0].inLimbs]; oversizedGenesis[2] = 1n << 128n;
oversizedSpecs[0] = { ...oversizedSpecs[0], inLimbs: oversizedGenesis };
const oversizedGlv = assemble(oversizedSpecs, true);
const incongruentSpecs = buildFullSpecs(INSTANCES.committed);
const incongruentGenesis = [...incongruentSpecs[0].inLimbs]; incongruentGenesis[2] += 1n;
incongruentSpecs[0] = { ...incongruentSpecs[0], inLimbs: incongruentGenesis };
const incongruentGlv = assemble(incongruentSpecs, true);

const tableInputs = full0.inputs.slice();
const tableUnlocking = Uint8Array.from(tableInputs[GLV_COUNT - 1].unlocking);
const carrierBlob = pushBounds(tableUnlocking);
const tablePush = pushBounds(tableUnlocking, carrierBlob.dataStart + carrierBlob.dataLen);
if (tablePush.dataLen !== GLV_TABLE_BYTES.length) throw new Error('shared GLV table push has unexpected length');
tableUnlocking[tablePush.dataStart + Math.floor(tablePush.dataLen / 2)] ^= 0x01;
tableInputs[GLV_COUNT - 1] = { ...tableInputs[GLV_COUNT - 1], unlocking: tableUnlocking };
const tableMutation = invalidInputsRun(full0, tableInputs);
if (!tableMutation.rejected || evalInput(tableInputs, GLV_COUNT - 1).accepted) throw new Error('mutated shared GLV table was accepted');

const vkxCount = specsVkx(INSTANCES.committed).length;
const millerGenesisIndex = vkxCount;
const hybrid = assemble([...full0Specs.slice(0, millerGenesisIndex), ...full1Specs.slice(millerGenesisIndex)], true);
if (hybrid.meta[millerGenesisIndex - 1].accepted) throw new Error('proof splice did not reject at the exact vk_x -> Miller seam');
const bindingMutations = [1 * W, 3 * W, 7 * W].map((offset) => {
  const run = invalidInputsRun(full0, mutateInputBlob(full0.inputs, millerGenesisIndex, offset));
  if (!run.rejected) throw new Error(`bound -A/B/C mutation at ${offset} was accepted`);
  return run;
});

const semanticInvalid = [offCurveA, offSubgroupB, plusPRange, offCurveC, forgedState, outOfRange, oversizedGlv, incongruentGlv];
const semanticRuns = semanticInvalid.map((asm) => ({ steps: toStepArr(asm), rejected: !asm.accepted }));
const proofBindingInvalid = [{ steps: toStepArr(hybrid), rejected: !hybrid.accepted }, ...bindingMutations];
const allInvalid = [...fInv, tableMutation, ...semanticRuns, ...proofBindingInvalid];
console.error(`  groth16 semantic/binding invalid rejected: ${allInvalid.map((r) => r.rejected).join(',')}`);
if (!full0.fits || !full1.fits || !fullDense.fits || !allInvalid.every((r) => r.rejected)) {
  throw new Error('Groth16 valid, dense, or invalid fixture failed; refusing to write vectors');
}
writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-intratx-vectors.json'), JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED full BLS12-381 Groth16 verifier in ONE transaction: canonical-range-checked five-chunk GLV vk_x with one hash-bound shared VK table -> exact (-A,B,C,vk_x) state -> input-validated prepared-VK Miller product -> final exponentiation -> verdict. The first Miller chunk checks A/C and B on-curve; the final Miller chunk reuses its running R_B=[|x|]B for the guarded psi(B)==[-x]B subgroup check. Miller derives f=1 and R_B=B. Every adjacent input checks the entire next-stage blob, including all stage seams; exact blob lengths reject legacy caller-supplied f/R layouts. Fixed gamma/delta lines and e(alpha,beta) are manifest-bound VK constants. Negative cases cover the shared table, GLV decomposition bounds/congruence, off-curve, off-subgroup, forged-state, scalar-range, proof-splice, and A/B/C mutations.',
  ...meta(full0), steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullDense),
  invalid: allInvalid.map((r) => r.steps),
  invalidInputs: [toStepArr(offCurveA), toStepArr(offSubgroupB), toStepArr(plusPRange)],
}, null, 2));
console.error('wrote groth16-bls12381-intratx-vectors.json');
