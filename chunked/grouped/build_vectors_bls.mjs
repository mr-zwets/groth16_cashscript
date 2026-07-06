// GROUPED verifier vectors for BLS12-381 — the BLS counterpart of build_vectors.mjs.
// Same hybrid: the chunked computation is packed into a HANDFUL of standard (<100,000 B)
// transactions; WITHIN a group tx the inputs forward-check via OP_INPUTBYTECODE (intra-tx),
// ACROSS groups the running state rides a CashToken NFT commitment (covenant). The token
// thread chains all groups in order; boundaries sit only at within-stage full-state links.
//
// BLS specifics vs BN254: 48-byte limbs; the batched Miller carries FOUR running R's (no
// prepared-VK reduction) so the state is f(12)+4R(24); the final exponentiation's easy-part
// inverses ride as UNCOMMITTED witnesses (extra args after the inBlob); the Miller boundary
// is the conjugated f. The chunk graph (g2check -> vk_x -> batched Miller -> final exp) and
// the cross-stage cmp configs mirror the BLS intra-tx build; g2check is the covenant build's.
//
//   node build_vectors_bls.mjs -> verifier/src/bch/groth16-bls12381-grouped-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, millerBatchOps, f12limbs, r6limbs, pairsFor, ptLimbs, finalexpTrace,
  compileBytecode, commitBin, CATEGORY, le48, P, OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../bls12-381/_pairingmath.mjs';
import { PUBLIC_INPUTS, proof, bls12_381 } from '../../singleton/bls12-381/bls_instance.mjs';
import { vkxStateAt, vkxFinalZinv, computeVkx, compileFileBytecode, compileBytecodeRaw, compileFileBytecodeRaw } from '../bls12-381/_vkxmath.mjs';
import { g2checkAccAt } from '../bls12-381/gen_g2check.mjs';
import { transformChunk } from '../intratx/transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'bls12-381', 'generated');
const W = 48; // BLS12-381 limb width
const PRIME = P.toString();
import { hexToBin, binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBch2026 } from '@bitauth/libauth';
const realVm = createVirtualMachineBch2026(false);

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
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));
const OP_RETURN = Uint8Array.from([0x6a]);

// ---- per-group evaluation: one token-carrying tx for the group, evaluate input `index` ----
function tokenOf(t) {
  return t ? { amount: 0n, category: CATEGORY, nft: { capability: t.cap, commitment: t.commit } } : undefined;
}
function evalGroup(inputs, index, gm) {
  const st = realVm.evaluate({
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

// vk_x position inside the Miller genesis inBlob (4 running R's -> 36 state limbs; same PT_CFG as BN254)
const dummy = pairsFor(PUBLIC_INPUTS, proof);
const MILLER_STATE_LIMBS = 12 + 4 * 6;
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;

// ---- per-stage specs (g2check from the BLS covenant build; vk_x/miller/finalexp from the
// BLS intra-tx build so the cross-stage cmp configs + inverse witnesses come along) ----
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];
const g2sLimbs = (R, Bx, By, Ax, Ay, Cx, Cy) =>
  [R.x.c0, R.x.c1, R.y.c0, R.y.c1, R.z.c0, R.z.c1, Bx.c0, Bx.c1, By.c0, By.c1, Ax, Ay, Cx, Cy];

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bx = Ba.x, By = Ba.y, Ax = Aa.x, Ay = Aa.y, Cx = Ca.x, Cy = Ca.y;
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  return man.chunks.map((ch) => ({
    file: join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: g2sLimbs(g2checkAccAt(Bx, By, ch.lo), Bx, By, Ax, Ay, Cx, Cy),
    outLimbs: ch.last ? [] : g2sLimbs(g2checkAccAt(Bx, By, ch.hi), Bx, By, Ax, Ay, Cx, Cy),
    extras: [], role: ch.last ? 'terminal' : 'within',
    label: `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' psi(B)==[-x]B' : ''}`,
    checkpoint: ch.first ? 'validate-inputs' : undefined,
  }));
}
function specsVkx(inst) {
  const [in0, in1] = inst.inputs.map(BigInt);
  const vkxAff = computeVkx([in0, in1]).toAffine();
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inLimbs = [...vkxStateAt(in0, in1, ch.lo), in0, in1];
    if (ch.final) return {
      file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs,
      outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxFinalZinv(in0, in1)], role: 'cross',
      cmp: { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W },
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
    extras: [], role: ch.final ? 'cross' : 'within',
    cmp: ch.final ? { cmpExpr: `outBlob.split(${12 * W})[0]`, nextFullInLen: 12 * W, skip: 0, cmpLen: 12 * W } : null,
    label: `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' +conj=boundary' : ''}`,
    checkpoint: ch.final ? 'miller-boundary' : undefined,
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
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst);
  const { specs: miller, boundary } = specsMiller(inst);
  const fe = specsFinalexp(boundary);
  return [...g2, ...vkx, ...miller, ...fe];
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
// effective unlocking length a chunk needs, UNCAPPED (BLS redeems run close to the 10,000 B
// script caps, so an over-cap fixed part must lose the comparison rather than saturate);
// Infinity when the variant does not even accept.
const effLen = (fixed, op, ok) => (ok ? Math.max(fixed + 3, Math.ceil(op / 800) - 41 + 96) : Infinity);
function argBytesOf(spec) {
  const parts = [pd(blob(spec.inLimbs))];
  for (const e of [...spec.extras].reverse()) parts.push(pushInt(BigInt(e)));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}

function assembleGrouped(specs, groups) {
  const G = groups.length;
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

  const gmeta = groups.map(([lo, hi], gi) => {
    const inToken = gi === 0
      ? { cap: 'mutable', commit: new Uint8Array(0) }
      : { cap: 'mutable', commit: commitOf(specs[lo].inLimbs) };
    const outToken = gi === G - 1 ? null : { cap: 'mutable', commit: commitOf(specs[hi].outLimbs) };
    return { lo, hi, inToken, outToken, outLocking: null };
  });
  for (let gi = 0; gi < G - 1; gi++) gmeta[gi].outLocking = lockings[groups[gi + 1][0]];
  for (let gi = 0; gi < G - 1; gi++) {
    const a = binToHex(gmeta[gi].outToken.commit), b = binToHex(gmeta[gi + 1].inToken.commit);
    if (a !== b) throw new Error(`group ${gi} hand-off mismatch: ${a} != ${b}`);
  }

  const allInputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, TARGET_UNLOCK) }));
  const op1 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) op1[lo + k] = evalGroup(ins, k, gmeta[gi]); });

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
      const tR = effLen(argB[i].length + rpush[i].length, op1[i].operationCost, op1[i].accepted);
      const tB = effLen(rawFixed, rawOp.operationCost, rawOp.accepted);
      // both failing usually means a NEIGHBOUR is oversized (forward-checks push the
      // successor's whole unlocking) — defer to the reassembly
      if (tR === Infinity && tB === Infinity) continue;
      const useRaw = tB < tR;
      chosenCache.set(key, useRaw ? 'raw' : 'resched');
      if (useRaw) switched += 1;
    }
    if (switched) return assembleGrouped(specs, groups); // reassemble with final choices (cached -> recurses)
  }
  for (let i = 0; i < specs.length; i++) allInputs[i].unlocking = mkUnlock(i, tunedLen(argB[i].length + rpush[i].length, op1[i].operationCost));
  const op2 = [];
  groups.forEach(([lo, hi], gi) => { const ins = allInputs.slice(lo, hi + 1); for (let k = 0; k <= hi - lo; k++) op2[lo + k] = evalGroup(ins, k, gmeta[gi]); });

  const meta = specs.map((s, i) => ({
    label: s.label, checkpoint: s.checkpoint, group: cfgs[i].group,
    lockingBytes: allInputs[i].locking.length, unlockingBytes: allInputs[i].unlocking.length,
    operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error,
  }));
  const accepted = op2.every((o) => o.accepted);
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
// Pack ONCE using max(committed, proof#1) per-chunk sizes (no dense worst-case instance exists
// for BLS), with margin under 100,000 B; the partition (hence the lockings) is shared by both.
const TARGET_GROUP_BYTES = 84000;
const cSpecs = buildSpecs(INSTANCES.committed);
const p1Specs = buildSpecs(INSTANCES.proof1);
function sizeEstimate(specs) {
  const provisional = packGroups(specs, specs.map(() => 9000), TARGET_GROUP_BYTES);
  return assembleGrouped(specs, provisional).meta.map((m) => m.unlockingBytes);
}
const cSizes = sizeEstimate(cSpecs), p1Sizes = sizeEstimate(p1Specs);
const packSizes = cSizes.map((s, i) => Math.max(s, p1Sizes[i]));
const GROUPS = packGroups(cSpecs, packSizes, TARGET_GROUP_BYTES);

const asmCommitted = assembleGrouped(cSpecs, GROUPS);
report('groth16-bls-grouped committed', asmCommitted);
const asmProof1 = assembleGrouped(p1Specs, GROUPS);
report('groth16-bls-grouped proof#1', asmProof1);

const firstBoundary = GROUPS[1] ? GROUPS[1][0] : 1;
const invalids = [invalidRun(cSpecs, GROUPS, Math.floor(cSpecs.length / 2)), invalidRun(cSpecs, GROUPS, firstBoundary)];
console.error(`  invalid runs rejected: ${invalids.map((r) => r.rejected).join(',')}`);
if (!asmCommitted.accepted || !asmProof1.accepted || !invalids.every((r) => r.rejected)) {
  console.error('!! a run failed -- NOT writing vectors'); process.exit(1);
}

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-bls12381-grouped-vectors.json', JSON.stringify({
  description: 'GROUPED BLS12-381 Groth16 verifier: the full chunked computation (g2check EIP-197 input validation -> vk_x -> batched 4-pair Miller -> final exponentiation -> verdict==1) packed into a handful of STANDARD (<100,000 B) transactions. Within each group tx the chunks forward-check each other via OP_INPUTBYTECODE (intra-tx method); across groups the running state rides a CashToken NFT commitment (covenant method) — a group\'s last chunk commits hash256(outBlob) to output[0], the next group\'s first chunk binds its inBlob via require(tx.inputs[0].nftCommitment == hash256(inBlob)). The token thread chains all groups in order. The easy-part inverses ride as uncommitted witnesses. Same validated chunk math as bch-groth16-bls12381-chunked / -intratx; one fixed set of lockings verifies any proof for the VK.',
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
  invalid: invalids.map((r) => r.run),
}, null, 2));
console.error(`wrote groth16-bls12381-grouped-vectors.json (${GROUPS.length} groups, ${asmCommitted.meta.length} inputs)`);
