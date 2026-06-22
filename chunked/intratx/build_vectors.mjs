// Assemble the INTRA-TRANSACTION LINKED verifier vectors for BN254.
//
// The whole chunked Groth16 computation becomes the INPUTS of ONE transaction. Each
// chunk takes its incoming state as a raw byte blob in its witness, recomputes the
// outgoing state, and FORWARD-checks its successor: it `require`s the next input's
// incoming blob (read via tx.inputs[idx+1].unlockingBytecode) equals its own output.
// No NFT-commitment hand-off, no hashing, no 128-byte limit — and it all fits one
// (non-standard, <1MB) transaction instead of ~60 sequential transactions.
//
// Reuses the validated chunk MATH from chunked/pairing/generated/*.cash verbatim
// (the same files the covenant build consumes); transform.mjs only swaps the
// covIn/covOut prologue/epilogue for split-in / rebuild-out + forward-check.
//
//   node build_vectors.mjs        -> verifier/src/bch/{pairing,groth16}-intratx-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, bn254, millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileBytecode, ptLimbs, PT_CFG,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace, le40,
  OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt } from '../pairing/gen_g2check.mjs';
import { transformChunk, headerSize } from './transform.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 40; // BN254 limb width (bytes)
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

// ---- push helpers (minimal encoding; the consensus VM enforces it) ----
const pushInt = (n) => {
  const d = bigIntToVmNumber(BigInt(n));
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const pd = (data) => {
  const L = data.length;
  if (L <= 75) return Uint8Array.from([L, ...data]);
  if (L <= 255) return Uint8Array.from([0x4c, L, ...data]);
  return Uint8Array.from([0x4d, L & 0xff, (L >> 8) & 0xff, ...data]);
};
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le40(((BigInt(l) % P) + P) % P)]));
// trailing all-zero pad that buys op-cost budget; MINIMAL push header (the consensus
// VM rejects a non-minimal push, so a light chunk that needs <256 pad bytes must not
// use PUSHDATA2). Pad sits at the END of the unlocking, so its size never shifts the
// front inBlob a sibling's forward-check reads.
const padPush = (argLen, target) => {
  let budget = Math.max(2, target - argLen); // header + data bytes for the pad push
  let N, hdr;
  if (budget <= 76) { N = budget - 1; hdr = [N]; }
  else if (budget <= 257) { N = budget - 2; hdr = [0x4c, N]; }
  else { N = budget - 3; hdr = [OP_PUSHDATA2, N & 0xff, (N >> 8) & 0xff]; }
  return Uint8Array.from([...hdr, ...new Uint8Array(N)]);
};
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

// ---- multi-input evaluation: build ONE tx from all inputs, evaluate at `index` ----
function evalInput(inputs, index) {
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
  const st = realVm.evaluate(program);
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

// vk_x position inside the miller genesis inBlob (stateLimbs=36, then ptL; pair2's P
// is at ptL offset = lengths of pairs 0+1). Computed, not hardcoded.
const MILLER_STATE_LIMBS = 12 + 4 * 6; // f(12) + 4 R(6 each)
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) for one instance ----
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bpair = [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const tail = [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Aa.x, Aa.y, Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  return man.chunks.map((ch) => ({
    file: join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: sLimbs(g2checkAccAt(Bpair, ch.lo)),
    outLimbs: ch.last ? [] : sLimbs(g2checkAccAt(Bpair, ch.hi)),
    extras: [], role: ch.last ? 'terminal' : 'within',
    label: `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' [6x^2]B==psi(B)' : ''}`,
    checkpoint: ch.first ? 'validate-inputs' : undefined,
  }));
}
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs;
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const inLimbs = [...inAcc, in0, in1];
    if (ch.final) {
      return {
        file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxFinalZinv(in0, in1)],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    return {
      file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, outLimbs: [...vkxStateAt(in0, in1, ch.hi), in0, in1], extras: [], role: 'within',
      label: `vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
function specsMiller(inst, crossToFinalexp) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = millerBatchOps(pairs);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: [...stateLimbs(states[ch.opLo]), ...ptL],
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
const compileCache = new Map();
function compileSpec(s) {
  let forward = null;
  if (s.role === 'within') { const outLen = s.outLimbs.length * W; forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  // 'stage-final' and 'terminal' -> forward = null
  const key = `${s.file}|${s.role}|${JSON.stringify(forward)}`;
  let redeem = compileCache.get(key);
  if (!redeem) {
    const t = transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward });
    redeem = compileBytecode(t.src);
    compileCache.set(key, redeem);
  }
  return Uint8Array.from([OP_DROP, ...redeem]);
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
// op-cost (pad is appended last and never shifts the front inBlob, so it cannot
// disturb any sibling's forward-check). Returns { inputs, meta, fits, accepted }.
function assemble(specs) {
  const lockings = specs.map(compileSpec);
  const argB = specs.map(argBytesOf);
  // pass 1: full pad -> max budget so the real VM accepts and reports true op-cost
  let inputs = specs.map((s, i) => ({ locking: lockings[i], unlocking: Uint8Array.from([...argB[i], ...padPush(argB[i].length, TARGET_UNLOCK)]) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));
  // pass 2: shrink each pad to just cover its op-cost
  inputs = specs.map((s, i) => {
    const target = tunedLen(argB[i].length, op1[i].operationCost);
    return { locking: lockings[i], unlocking: Uint8Array.from([...argB[i], ...padPush(argB[i].length, target)]) };
  });
  const op2 = specs.map((_, i) => evalInput(inputs, i));
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted;
  return { inputs, meta, fits, accepted };
}

function buildFull(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const { specs: miller, boundary } = specsMiller(inst, true);
  const fe = specsFinalexp(boundary);
  return assemble([...g2, ...vkx, ...miller, ...fe]);
}
function buildPairing(inst) {
  const { specs } = specsMiller(inst, false); // miller-final = stage-final (boundary milestone)
  return assemble(specs);
}

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
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

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-intratx-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED BN254 Groth16 pairing to the Miller boundary. The batched 4-pair Miller chunks are the INPUTS of ONE transaction; each chunk takes its incoming Fp12+G2 state as a raw byte blob in its witness and FORWARD-checks its successor (require next input\'s blob == its recomputed output, read via OP_INPUTBYTECODE). No NFT-commitment hand-off, no hashing, no 128-byte limit. Reuses the same validated chunk math as bch-pairing-chunked.',
  method: 'intra-tx-linked', numInputs: pair0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(pair0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(pair0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...pair0.meta.map((m) => m.operationCost)),
  allFit: pair0.fits, allAccept: pair0.accepted,
  steps: toStepArr(pair0), extraValidProofs: [toStepArr(pair1)], worstCaseProof: toStepArr(pairWc),
  invalid: pairInvalid.map((r) => r.steps),
}, null, 2));
console.error('wrote pairing-intratx-vectors.json');

// ===================== FULL GROTH16 (single tx) =====================
const full0 = buildFull(INSTANCES.committed);
report('groth16 committed', full0);
const full1 = buildFull(INSTANCES.proof1);
const fullWc = buildFull(INSTANCES.worst);
report('groth16 proof#1', full1);
const fullInvalid = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];
console.error(`  groth16 invalid runs rejected: ${fullInvalid.map((r) => r.rejected).join(',')}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-intratx-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED full BN254 Groth16 verifier in ONE transaction: validate G2 inputs -> vk_x -> batched 4-pair Miller -> final exponentiation -> assert product==1, as the inputs of a single tx. State is passed as raw byte blobs through sibling-input introspection (OP_INPUTBYTECODE forward-checks), not NFT commitments — no hashing, arbitrary intermediate size. Cross-stage soundness links are bound where layouts allow: vk_x final binds the vk_x point into the Miller genesis input, and the Miller boundary is bound into the final-exponentiation genesis input. Reuses the same validated chunk math as bch-groth16-chunked.',
  method: 'intra-tx-linked', numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
}, null, 2));
console.error('wrote groth16-intratx-vectors.json');
