// Assemble the INTRA-TX LINKED + RESIDUE verifier for BN254 with LARGE (100 kB) input scripts.
//
// This is build_vectors_residue.mjs's cousin. IDENTICAL mechanism (each chunk is an INPUT
// whose witness carries its incoming state as a raw byte blob, and it require()s the next
// input's blob — read via tx.inputs[idx+1].unlockingBytecode — equals its recomputed output),
// IDENTICAL residue chunk graph (fast-G2 endo check / GLV vk_x / c^-(6x+2)-fused Miller with
// e(alpha,beta) skipped / witnessed-residue tail). The ONLY difference is the per-input budget:
//
//   the BCH op-cost budget an input gets is (41 + unlockingLen) * 800. The flagship residue
//   build sizes each chunk to a 10 kB unlocking (=> 8,032,800 op/input, ~33 inputs). Here we
//   size to a 100 kB unlocking (=> 80,032,800 op/input, ~10x), which collapses the same
//   ~202M-op verifier into a HANDFUL of fat inputs — one per stage floor:
//     fast-G2 subgroup check   1 input
//     GLV vk_x MSM             1 input    (one 128-iter loop window)
//     c^-(6x+2)-fused Miller   3 inputs   (~148M op op-bound; the LAST is terminal, see below)
//     residue final-exp tail   0 inputs   (verdict FUSED into the final Miller chunk)
//                              --------
//                              5 inputs   (still ONE non-standard <1 MB tx)
//
// op-cost and total bytes are CONSERVED (~202M / ~260 kB either way) — this is a STRUCTURAL
// simplification (fewer, fatter UTXOs in one tx), not a resource reduction. Each 100 kB input
// exceeds standard relay policy, so the tx is mine-direct — but the single-tx intratx bundle is
// already non-standard, so nothing new is given up. The chunks are regenerated at startup at the
// 100 kB budget by re-running the three stage generators with big OP_COST_TARGET / BYTE_BUDGET /
// TARGET_UNLOCK env (the tail is 1 fixed chunk, budget-independent).
//
// NOTE: this leaves chunked/pairing/generated/ holding LARGE-budget chunks. Before rebuilding a
// flagship (10 kB) build, regenerate the default-budget chunks:
//   node chunked/pairing/gen_g2check.mjs && node chunked/pairing/gen_vkx_glv.mjs && node chunked/pairing/gen_miller_residue.mjs
//
//   node build_vectors_residue_large.mjs  -> verifier/src/bch/groth16-intratx-residue-large-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileFileBytecode, compileFileBytecodeRaw, ptLimbs,
  vkxPoint, le40, OP_DROP,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv } from '../pairing/gen_g2check.mjs';
import { millerFusedOps, residueWitness, fp12limbsOf } from '../pairing/_residuemath.mjs';
import { glvDecompose, vkxGlvStateAt, vkxGlvZinv } from '../pairing/gen_vkx_glv.mjs';
import { transformChunk } from './transform.mjs';
import { regenGlvSafe } from '../regen_vkx_windows.mjs';

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
const PAIR = join(here, '..', 'pairing');
const GEN = join(PAIR, 'generated');

// Regenerate the variable-length stages at the 100 kB budget. g2check plans to 1 chunk on its own;
// fused Miller greedy-plans to 3 chunks (op-bound at ~85M each, then a small boundary/handoff chunk
// the fork compiler forces separate — merging it hits an UnusedVariableError on the dropped R
// accumulator, so Miller stays 3 for now). The residue tail is a single fixed chunk — not regenerated.
//
// Lever 2 (7 inputs -> 6): GLV vk_x as ONE loop window [0,128] via regenGlvSafe. The vk_x codegen
// LOOPS (not unrolled), so a single 128-iter window is only ~2.5 kB / ~21M op; the greedy planner
// split off a 1-iter zinv/assert final chunk only because that cross-bind final chunk measures
// accepted=false STANDALONE in the covenant model. regenGlvSafe writes the window directly (no
// planner) and the assembly below validates it against max-density on the real spec VM.
const GEN_ENV = { ...process.env, BCH_VM: 'spec', TARGET_UNLOCK: String(LARGE_UNLOCK), OP_COST_TARGET: '86000000', BYTE_BUDGET: '95000' };
console.error('\n== regenerating gen_g2check.mjs at 100 kB budget ==');
execFileSync(process.execPath, [join(PAIR, 'gen_g2check.mjs')], { env: GEN_ENV, stdio: 'inherit' });
console.error('\n== regenerating gen_miller_residue.mjs at 100 kB budget (FUSE_TAIL -> residue tail folded into the final Miller chunk) ==');
execFileSync(process.execPath, [join(PAIR, 'gen_miller_residue.mjs')], { env: { ...GEN_ENV, FUSE_TAIL: '1' }, stdio: 'inherit' });
console.error('\n== regenerating GLV vk_x as ONE window [0,128] (lever 2) ==');
regenGlvSafe(GEN, [0, 128]);

const PROBE = join(GEN, '_intratx_residue_large_probe.cash'); // transformed import-chunks compiled from here
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 40; // BN254 limb width (bytes)
import { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, createVirtualMachineBchSpec } from '@bitauth/libauth';
const realVm = createVirtualMachineBchSpec(false); // PROPOSED bch-spec VM (100 kB scripts, 88M-op inputs)

// Deploy each chunk as P2SH (same lever as the flagship build): the redeem rides in the scriptSig
// where it counts toward the op-cost budget ((41 + unlockingLen) * 800); the inBlob stays the
// FIRST scriptSig push (front offset preserved for sibling forward-checks).
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le40(((BigInt(l) % P) + P) % P)]));
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  // header size: 1 (<=75), 2 (PUSHDATA1 <=255), 3 (PUSHDATA2 <=65535), 5 (PUSHDATA4). Pick N so
  // encodeDataPush emits exactly `budget` bytes (header + N) — at 100 kB the header is 5, not 3.
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget <= 65538 ? budget - 3 : budget - 5;
  return encodeDataPush(new Uint8Array(N));
};
// minimal total unlocking length whose spec budget (10000+len)*800 covers opCost, +96 margin.
const tunedLen = (argLen, opCost) => Math.min(LARGE_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - DENSITY_BASE + 96));

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

// vk_x position inside the FUSED miller genesis inBlob. Layout f(12)+R0(6)+pts(10)+c(12)+cInv(12)
// = 52 limbs; vk_x (pair2 P) sits after f+R0+pair0 pts (c,cInv are appended at the END).
const MILLER_STATE_LIMBS = 12 + 6; // f(12) + R0(6)
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const PTL_LEN = dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length; // 10
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + PTL_LEN + 24; // + c(12) + cInv(12) = 52 (fused)
const TAIL_IN_LIMBS = 12 + 12 + 12; // [fF, c, cInv] hand-off from the fused miller's final chunk

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) — IDENTICAL to build_vectors_residue.mjs;
// only the assembly budget below differs (100 kB inputs). ----
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
// FINAL chunk hands off only [fF, c, cInv] (36) to the residue tail.
// The FINAL chunk has the residue-tail verdict FUSED in (manifest tailFused, FUSE_TAIL=1): it is
// TERMINAL (no hand-off; the verdict fF*w*c^q2==c^q*c^q3 runs inline on its own computed fF), with w
// as an uncommitted witness extra. Earlier chunks forward the full 52-limb state as usual.
function specsMillerFused(inst, c, cInv, w) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states } = millerFusedOps(pairs, c, cInv);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const full = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...ptL, ...f12limbs(s.c), ...f12limbs(s.cInv)]; // 52
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const file = join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`);
    if (ch.tailFused) {
      return {
        file, inLimbs: full(states[ch.opLo]), outLimbs: [], extras: fp12limbsOf(w), role: 'terminal', cmp: null,
        label: `fused-miller+tail ops[${ch.opLo},${ch.opHi}) -> verdict fF*w*c^q2==c^q*c^q3`, checkpoint: 'verify',
      };
    }
    return {
      file, inLimbs: full(states[ch.opLo]), outLimbs: full(states[ch.opHi]), extras: [], role: 'within', cmp: null,
      label: `fused-miller ops[${ch.opLo},${ch.opHi})`, checkpoint: undefined,
    };
  });
}
function buildSpecs(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { boundary: fRaw } = millerBatchOps(pairs);
  const { c, cInv, w } = residueWitness(fRaw);
  const miller = specsMillerFused(inst, c, cInv, w); // the residue tail is fused into miller's final chunk
  return [...g2, ...vkx, ...miller];
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
function argBytesOf(s) {
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(e));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
function assemble(specs) {
  const redeems = specs.map(compileSpec);
  const argB = specs.map(argBytesOf);
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + tailLen(i);
    const pad = padPush(0, Math.max(2, target - fixed));
    return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]);
  };
  // pass 1: full unlocking -> max budget so the real VM accepts and reports true op-cost
  let inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, LARGE_UNLOCK) }));
  const op1 = specs.map((_, i) => evalInput(inputs, i));

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
      const tR = tunedLen(argB[i].length + tailLen(i), op1[i].operationCost);
      const tB = rawOp.accepted ? tunedLen(rawFixed, rawOp.operationCost) : Infinity;
      chosenCache.set(key, tB < tR ? 'raw' : 'resched');
      if (tB < tR) switched += 1;
    }
    if (switched) return assemble(specs);
  }
  // pass 2: shrink the pad so the unlocking just covers its op-cost
  inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, tunedLen(argB[i].length + tailLen(i), op1[i].operationCost)) }));
  const op2 = specs.map((_, i) => evalInput(inputs, i));
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  // spec caps: locking/unlocking each <= 100 kB; op-cost <= the input's own (10000+unlockingLen)*800.
  const fits = meta.every((m) => m.lockingBytes <= LARGE_UNLOCK && m.unlockingBytes <= LARGE_UNLOCK && m.operationCost <= opBudgetFor(m.unlockingBytes)) && accepted;
  return { inputs, meta, fits, accepted };
}

function buildFull(inst) { return assemble(buildSpecs(inst)); }

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
function invalidRun(asm, idx) {
  const inputs = asm.inputs.map((inp, i) => (i === idx ? { ...inp, unlocking: (() => {
    const u = Uint8Array.from(inp.unlocking);
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
  asm.meta.forEach((m, i) => console.error(`  op[${String(i).padStart(2)}] ${String(m.operationCost).padStart(9)} lock=${m.lockingBytes} unlock=${m.unlockingBytes} ${m.accepted ? '' : 'REJECTED '}${m.label}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== FULL GROTH16 (residue, single tx, 100 kB inputs) =====================
const full0 = buildFull(INSTANCES.committed);
report('groth16-intratx-residue-large committed', full0);
const full1 = buildFull(INSTANCES.proof1);
const fullWc = buildFull(INSTANCES.worst);
report('groth16-intratx-residue-large proof#1', full1);
report('groth16-intratx-residue-large worst-case', fullWc);
const fullInvalid = [invalidRun(full0, 0), invalidRun(full0, Math.floor(full0.inputs.length / 2))];
console.error(`  invalid runs rejected: ${fullInvalid.map((r) => r.rejected).join(',')}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-intratx-residue-large-vectors.json', JSON.stringify({
  description: 'INTRA-TRANSACTION LINKED + RESIDUE full BN254 Groth16 verifier in ONE transaction with LARGE (100 kB) input scripts, targeting the PROPOSED bch-spec upgrade. Identical mechanism and residue chunk graph to bch-groth16-intratx-residue (OP_INPUTBYTECODE forward-checking, no NFT commitment, no hashing; fast-G2 endo subgroup check + GLV vk_x MSM + c^-(6x+2)-FUSED batched Miller with e(alpha,beta) skipped + witnessed-residue final-exp verdict), but each chunk is sized to a 100 kB unlocking instead of 10 kB. On bch-spec the op-cost budget an input receives is (10000 + unlockingLen) * 800, so a 100 kB input gets 88,000,000 op (~11x the 8,032,800 of a current-BCH 10 kB input); the same ~193M-op verifier therefore collapses from 33 inputs to 5: g2check 1, GLV vk_x 1 (one 128-iter loop window), and c^-(6x+2)-fused Miller 3 with the witnessed-residue final-exp verdict (fF*w*c^q2==c^q*c^q3) FOLDED into the last (terminal) Miller chunk — so the separate residue-tail input disappears. Total op-cost and bytes are conserved (a structural simplification, fewer/fatter UTXOs, not a resource reduction). Every input fits its own bch-spec input budget (op-cost <= 88,000,000, scripts <= 100,000 B) and the whole verifier is ONE non-standard (<1 MB) transaction; the residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in the fused verdict. NOT valid on current BCH (BCH_2026 caps scripts at 10,000 B). Deployed as P2SH32 so each chunk redeem rides in the scriptSig where it counts toward the op-cost budget.',
  method: 'intra-tx-linked-residue-large', deployment: 'P2SH32', numInputs: full0.inputs.length, budgetPerInput: LARGE_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  maxStepOperationCost: Math.max(...full0.meta.map((m) => m.operationCost)),
  allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0), extraValidProofs: [toStepArr(full1)], worstCaseProof: toStepArr(fullWc),
  invalid: fullInvalid.map((r) => r.steps),
}, null, 2));
console.error('\nwrote groth16-intratx-residue-large-vectors.json');
console.error('NOTE: generated/ now holds 100 kB-budget chunks. Regenerate the default-budget chunks before rebuilding a flagship 10 kB build:');
console.error('  node chunked/pairing/gen_g2check.mjs && node chunked/pairing/gen_vkx_glv.mjs && node chunked/pairing/gen_miller_residue.mjs');
