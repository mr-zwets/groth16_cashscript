// GROUPED verifier vectors for BLS12-381 — the BLS counterpart of build_vectors.mjs.
// Same hybrid: the chunked computation is packed into a HANDFUL of standard (<100,000 B)
// transactions; WITHIN a group tx the inputs forward-check via OP_INPUTBYTECODE (intra-tx),
// ACROSS groups the running state rides a CashToken NFT commitment (covenant). The token
// thread chains all groups in order; boundaries sit only at within-stage full-state links.
//
// BLS specifics vs BN254: 48-byte limbs; the prepared-VK Miller carries only the runtime B
// walk, so the state is f(12)+R_B(6); the final exponentiation's easy-part
// inverses ride as UNCOMMITTED witnesses (extra args after the inBlob); the Miller boundary
// is the conjugated f. The chunk graph (vk_x -> input-validated batched Miller -> final exp)
// uses exact whole-state seams; the full Miller namespace is shared with the covenant build.
//
//   node build_vectors_bls.mjs -> verifier/src/bch/groth16-bls12381-grouped-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, millerPreparedOps, assertPreparedMillerManifest, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace,
  compileBytecode, commitBin, CATEGORY, le48, P, OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET, verifierPath,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { vkxStateAt, vkxFinalZinv, computeVkx, compileFileBytecode, compileBytecodeRaw, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { transformChunk } from '../intratx/transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const W = 48; // BLS12-381 limb width
const PRIME = P.toString();
import { hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);
const standardVm = createVirtualMachineBch2026(true);

const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le48(((BigInt(l) % P) + P) % P)]));
const commitOf = (limbs) => commitBin(limbs.map(BigInt)); // == in-VM hash256(blob(limbs))
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
// Both valid scalars set bits 0..253, exercising every add branch in the 11 main vk_x windows.
const DENSE_INPUTS = [(1n << 254n) - 1n, (1n << 254n) - 1n];
const INSTANCES = {
  committed: { inputs: PUBLIC_INPUTS, proof },
  proof1: mkInstance([135208n, 67633n], 17n, 19n),
  dense: mkInstance(DENSE_INPUTS),
};

// ---- per-stage specs ----
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const F2 = bls12_381.fields.Fp2;
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
  const stage = stageLimbs(inst, bad);
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkxfull.json'), 'utf8'));
  if (man.genesisDerived !== true || man.fullStageBound !== true) throw new Error('full vk_x manifest is not stage-bound');
  return man.chunks.map((ch) => {
    const inLimbs = ch.lo === 0 ? [in0, in1] : [...vkxStateAt(in0, in1, ch.lo), in0, in1];
    if (ch.final) return {
      file: join(GEN, `vkxfull_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: stage, extras: [vkxFinalZinv(in0, in1), ...stage.slice(0, 8)], role: 'within',
      label: 'vk_x final -> bind (-A,B,C,vk_x)', checkpoint: 'vk_x',
    };
    return { file: join(GEN, `vkxfull_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs: [...vkxStateAt(in0, in1, ch.hi), in0, in1], extras: [], role: 'within', label: `vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined };
  });
}
function specsMiller(inst, validated = false, bad = {}) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const trace = millerPreparedOps(pairs);
  const { ops, states, finalF } = trace;
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const traceStage = [...ptL.slice(0, 6), ...ptL.slice(8, 10), ...ptL.slice(6, 8)];
  if (!limbsEqual(traceStage, stageLimbs(inst))) throw new Error('Miller genesis layout mismatch');
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
function buildSpecs(inst) {
  const vkx = specsVkx(inst);
  const { specs: miller, boundary } = specsMiller(inst, true);
  const fe = specsFinalexp(boundary);
  return [...vkx, ...miller, ...fe];
}

// ---- grouping (identical logic to the BN254 build) ----------------------------------
const PER_INPUT_OV = 43;
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
const chosenCache = new Map();  // cfg key -> 'resched' | 'raw'; fixed on the FIRST assembly so every
                                // instance shares identical lockings.
const PROBE = join(GEN, '_grouped_probe.cash');
const cfgKey = (spec, cfg) => `${spec.file}|${cfg.covInHash ? 'ci' : ''}|${cfg.epilogueMode ?? ''}|${cfg.nextLockingHash ?? ''}|${JSON.stringify(cfg.forward)}`;
function compileChunk(spec, cfg) {
  const key = cfgKey(spec, cfg);
  let v = compileCache.get(key);
  if (!v) {
    const t = transformChunk(readFileSync(spec.file, 'utf8'), {
      W, prime: PRIME, forward: cfg.forward, covInHash: cfg.covInHash,
      epilogueMode: cfg.epilogueMode, nextLockingHash: cfg.nextLockingHash,
      enforceExactInputLength: true,
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
// effective unlocking length a chunk needs, UNCAPPED (BLS redeems run close to the 10,000 B
// script caps, so an over-cap fixed part must lose the comparison rather than saturate);
// Infinity when the variant does not even accept.
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41) : Infinity);
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs))];
  for (const e of [...spec.extras].reverse()) parts.push(pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

function assembleGrouped(specs, groups, expectRejected = false) {
  const G = groups.length;
  const cfgs = specs.map((_, i) => {
    const gi = groups.findIndex(([lo, hi]) => i >= lo && i <= hi);
    return { ...groupedCfg(specs, i, groups[gi][0], groups[gi][1], gi, G), group: gi };
  });
  // Compile groups from tail to head. Each nonterminal group's last contract embeds the
  // hash of the already-known first locking of the successor group.
  const redeems = new Array(specs.length), lockings = new Array(specs.length);
  for (let gi = G - 1; gi >= 0; gi--) {
    const [lo, hi] = groups[gi];
    for (let i = lo; i <= hi; i++) {
      if (cfgs[i].epilogueMode === 'covout') cfgs[i].nextLockingHash = binToHex(hash256(lockings[groups[gi + 1][0]]));
      redeems[i] = compileChunk(specs[i], cfgs[i]);
      lockings[i] = p2shSpk(redeems[i]);
    }
  }
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
  let handoffsMatch = true;
  for (let gi = 0; gi < G - 1; gi++) {
    const a = binToHex(gmeta[gi].outToken.commit), b = binToHex(gmeta[gi + 1].inToken.commit);
    if (a !== b) {
      handoffsMatch = false;
      if (!expectRejected) throw new Error(`group ${gi} hand-off mismatch: ${a} != ${b}`);
    }
  }

  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) op1[lo + k] = evalGroup(ins, k, gmeta[gi]); });
  const standardOp1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) standardOp1[lo + k] = evalGroup(ins, k, gmeta[gi], standardVm); });

  // Per-chunk variant selection (first assembly only): keep whichever redeem needs the
  // smaller effective unlocking — BLS chunks run close to the 10,000 B caps, so a
  // byte-fatter rescheduled redeem can overflow where the plain one fits.
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
      // both failing usually means a NEIGHBOUR is oversized (forward-checks push the
      // successor's whole unlocking) — defer to the reassembly
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assembleGrouped(specs, groups, expectRejected); // reassemble with final choices (cached -> recurses)
  }
  if (!expectRejected && [...op1, ...standardOp1].some((outcome) => outcome.error !== null)) {
    const failures = [...op1, ...standardOp1]
      .map((outcome, i) => ({ vm: i < specs.length ? 'consensus' : 'standard', index: i % specs.length, ...outcome }))
      .filter((outcome) => outcome.error !== null);
    throw new Error(`chosen full-budget input errored during padding measurement: ${JSON.stringify(failures)}`);
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
    if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) break;
    const tightened = targets.map((target, i) => Math.min(target, tunedLen(
      argB[i].length + rpush[i].length,
      Math.max(op2[i].operationCost, standardOp2[i].operationCost),
    )));
    if (tightened.every((target, i) => target === targets[i])) break;
    targets = tightened;
  }
  if (!expectRejected && (op2.some((outcome) => !outcome.accepted) || standardOp2.some((outcome) => !outcome.accepted))) {
    throw new Error('tightened input rejected during padding measurement');
  }

  const meta = specs.map((s, i) => ({
    label: s.label, checkpoint: s.checkpoint, group: cfgs[i].group,
    lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
    operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error,
  }));
  const accepted = handoffsMatch && op2.every((o) => o.accepted);
  if (expectRejected && accepted) throw new Error('invalid grouped fixture unexpectedly accepted');
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

function pushBounds(unlocking) {
  const op = unlocking[0];
  if (op <= 75) return { dataStart: 1, dataLen: op };
  if (op === 0x4c) return { dataStart: 2, dataLen: unlocking[1] };
  if (op === 0x4d) return { dataStart: 3, dataLen: unlocking[1] | (unlocking[2] << 8) };
  throw new Error(`unsupported inBlob push opcode ${op}`);
}
function evaluateMutated(asm) {
  const outcomes = [];
  asm.groups.forEach(([lo, hi], gi) => {
    const inputs = asm.inputs.slice(lo, hi + 1);
    for (let k = 0; k <= hi - lo; k++) outcomes[lo + k] = evalGroup(inputs, k, asm.gmeta[gi]);
  });
  return { run: toRun(asm), rejected: outcomes.some((outcome) => !outcome.accepted) };
}
function mutateGroupedInput(asm, inputIndex, byteOffset) {
  const mutated = { ...asm, inputs: asm.inputs.slice() };
  const unlocking = Uint8Array.from(mutated.inputs[inputIndex].unlocking);
  const { dataStart, dataLen } = pushBounds(unlocking);
  if (byteOffset < 0 || byteOffset >= dataLen) throw new Error(`mutation offset ${byteOffset} outside inBlob`);
  unlocking[dataStart + byteOffset] ^= 0x01;
  mutated.inputs[inputIndex] = { ...mutated.inputs[inputIndex], unlocking };
  return evaluateMutated(mutated);
}

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
  asm.meta.filter((m) => !m.accepted).slice(0, 4).forEach((m) => console.error(`  !! non-accepting: g${m.group} ${m.label} :: op=${m.operationCost.toLocaleString()} err=${m.error}`));
};

// ===================== build =====================
// Pack once using the largest per-chunk size across both ordinary proofs and the dense vk_x case;
// the partition (hence the lockings) is shared by every proof and leaves at least 3,430 bytes
// below the 100,000-byte policy cap across the measured runs.
const TARGET_GROUP_BYTES = 97000;
const cSpecs = buildSpecs(INSTANCES.committed);
const p1Specs = buildSpecs(INSTANCES.proof1);
const denseSpecs = buildSpecs(INSTANCES.dense);
function sizeEstimate(specs) {
  const provisional = packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES);
  return assembleGrouped(specs, provisional).meta.map((m) => m.unlockingBytes);
}
const cSizes = sizeEstimate(cSpecs), p1Sizes = sizeEstimate(p1Specs), denseSizes = sizeEstimate(denseSpecs);
const packSizes = cSizes.map((s, i) => Math.max(s, p1Sizes[i], denseSizes[i]));
const GROUPS = packGroups(cSpecs, packSizes, TARGET_GROUP_BYTES);

const asmCommitted = assembleGrouped(cSpecs, GROUPS);
report('groth16-bls-grouped committed', asmCommitted);
const asmProof1 = assembleGrouped(p1Specs, GROUPS);
report('groth16-bls-grouped proof#1', asmProof1);
const asmDense = assembleGrouped(denseSpecs, GROUPS);
report('groth16-bls-grouped max-density', asmDense);

const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1;
const invalids = [invalidRun(cSpecs, GROUPS, Math.floor(cSpecs.length / 2)), invalidRun(cSpecs, GROUPS, firstBoundary)];

// Isolated semantic validation fixtures keep rejection attributable to the fused checks.
const isolated = (specs) => assembleGrouped(specs, packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES), true);
const negA = proof.a.negate().toAffine(), C = proof.c.toAffine();
const isolatedFirstMiller = (bad, forgedPrefix = []) => {
  const first = specsMiller(INSTANCES.committed, true, bad).specs[0];
  first.role = 'stage-final';
  if (forgedPrefix.length > 0) first.inLimbs = [...forgedPrefix, ...first.inLimbs];
  return isolated([first]);
};
const offCurveA = isolatedFirstMiller({ Ay: (negA.y + 1n) % P });
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
const offSubgroupB = isolated(offSubSpecs);

const forgedState = isolatedFirstMiller({}, Array.from({ length: 18 }, (_, i) => BigInt(i + 1)));
const rangeSpec = specsVkx(INSTANCES.committed)[0];
const outOfRange = isolated([{ ...rangeSpec, inLimbs: [Rord, PUBLIC_INPUTS[1]], role: 'stage-final' }]);

// Exact full-state seams reject proof splices and mutations of each proof component.
const vkxCount = specsVkx(INSTANCES.committed).length;
const millerGenesisIndex = vkxCount;
const hybrid = assembleGrouped([...cSpecs.slice(0, millerGenesisIndex), ...p1Specs.slice(millerGenesisIndex)], GROUPS, true);
const hybridGroup = hybrid.meta[millerGenesisIndex].group;
if (hybridGroup > 0) {
  const predecessor = hybrid.gmeta[hybridGroup - 1].outToken;
  if (!predecessor) throw new Error('proof-splice boundary has no predecessor token');
  hybrid.gmeta[hybridGroup].inToken.commit = Uint8Array.from(predecessor.commit);
}
const hybridInvalid = evaluateMutated(hybrid);
const proofMutations = [1 * W, 3 * W, 7 * W].map((offset) => mutateGroupedInput(asmCommitted, millerGenesisIndex, offset));

// A group hand-off also pins the actual successor P2SH32 locking, not only its state hash.
const lockTamperAsm = { ...asmCommitted, gmeta: asmCommitted.gmeta.map((g) => ({ ...g })) };
const handoff = lockTamperAsm.gmeta.find((g) => g.outLocking !== null);
if (!handoff) throw new Error('missing grouped hand-off fixture');
handoff.outLocking = Uint8Array.from(handoff.outLocking);
handoff.outLocking[handoff.outLocking.length - 1] ^= 0x01;
const lockTamper = evaluateMutated(lockTamperAsm);

const semantic = [offCurveA, offSubgroupB, offCurveC, forgedState, outOfRange];
const securityInvalids = [
  ...semantic.map(evaluateMutated),
  hybridInvalid,
  ...proofMutations,
  lockTamper,
];
const allInvalids = [...invalids, ...securityInvalids];
console.error(`  semantic/binding invalid runs rejected: ${allInvalids.map((r) => r.rejected).join(',')}`);
if (!asmCommitted.fits || !asmProof1.fits || !asmDense.fits || !allInvalids.every((r) => r.rejected)) {
  throw new Error('valid, dense, or invalid fixture failed; refusing to write vectors');
}

writeFileSync(verifierPath('src', 'bch', 'groth16-bls12381-grouped-vectors.json'), JSON.stringify({
  description: 'GROUPED BLS12-381 Groth16 verifier: canonical-range-checked vk_x -> exact (-A,B,C,vk_x) state -> input-validated prepared-VK Miller product -> final exponentiation -> verdict, packed into standard transactions. The first Miller chunk checks A/C and B on-curve; the final Miller chunk reuses its running R_B=[|x|]B for the guarded psi(B)==[-x]B subgroup check. Miller derives f=1 and R_B=B. Within a group every chunk forward-checks the entire successor blob; across groups a mutable NFT carries hash256(outBlob), and the boundary covenant pins the actual successor P2SH32 locking. Fixed gamma/delta lines and e(alpha,beta) are manifest-bound VK constants. Negative cases for off-curve, off-subgroup, forged-state, scalar-range, proof-splice, A/B/C mutation, and successor-lock inputs reject.',
  method: 'grouped', deployment: 'P2SH32', curve: 'BLS12-381', category: binToHex(CATEGORY),
  numInputs: asmCommitted.meta.length, numGroups: GROUPS.length, budgetPerInput: OP_BUDGET,
  groupSizes: GROUPS.map(([lo, hi]) => hi - lo + 1),
  groupBytes: asmCommitted.groupBytes,
  totalBytes: sum(asmCommitted.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(asmCommitted.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...asmCommitted.meta.map((m) => m.operationCost)),
  allFit: asmCommitted.fits, allAccept: asmCommitted.accepted,
  valid: toRun(asmCommitted),
  extraValidProofs: [toRun(asmProof1)],
  worstCaseProof: toRun(asmDense),
  invalid: allInvalids.map((r) => r.run),
  invalidInputs: [toRun(offCurveA), toRun(offSubgroupB)],
}, null, 2));
console.error(`wrote groth16-bls12381-grouped-vectors.json (${GROUPS.length} groups, ${asmCommitted.meta.length} inputs)`);
