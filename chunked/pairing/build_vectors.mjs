// Assemble the GENERIC (proof-agnostic) covenant chunks into benchmark vectors.
// Each chunk carries NO baked state: the running-state HASH lives in the token's
// NFT commitment. Per step we emit a `covenant` context (category, in/out NFT
// commitments) so the harness drives it through a synthetic token tx; the unlocking
// pushes the raw state limbs + a zero pad that buys the op-cost budget. The SAME
// chunk lockings verify multiple proofs (runtime-general) — we replay proof #0 (the
// committed instance) and proof #1 (minted under the same VK, from the singleton
// multiproof vectors) through identical lockings -> extraValidProofs.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp12, Fp2, bn254, millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileBytecode, compileFileBytecode, commitBin, CATEGORY, ptLimbs,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace,
  TARGET_UNLOCK, OP_PUSHDATA2, OP_BUDGET,
} from './_millermath.mjs';
import { g2checkAccAt } from './gen_g2check.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, binToHex, bigIntToVmNumber, vmNumberToBigInt, hash256, encodeLockingBytecodeP2sh32, encodeDataPush, numberToBinUint16LE } = await import(LIBAUTH);
const { createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

// Deploy each covenant chunk as P2SH: the ~4-5 KB redeem (the bare contract) lives in
// the scriptSig, where it COUNTS toward the op-cost budget ((41+unlockingLen)*800) — so
// it does double duty (code AND budget) instead of sitting in the locking (which the
// budget ignores) next to an equal-sized dead pad. ~30% smaller on-chain; the SAME trick
// the intra-tx build uses. Unlike intra-tx, the covenant introspects the TOKEN
// (nftCommitment/tokenCategory), not sibling bytecode, so there are no scriptSig offsets
// to preserve — P2SH is a pure win here. INTRATX-style bare model via CHUNKED_BARE=1.
// Compute budget is bought by a trailing `bytes unused zeroPadding` spend param (the
// compiler drops it during stack cleanup), replacing the old hand-prepended OP_DROP.
const P2SH = process.env.CHUNKED_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem)); // OP_HASH256 <h> OP_EQUAL (35 B)
// all-zero pad whose TOTAL push length (libauth minimal header + data) == `total`; the
// consensus VM rejects a non-minimal push, and with P2SH the redeem offsets the budget so
// light chunks need a pad < 256 B (where PUSHDATA2 would be non-minimal).
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + 96));

const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// Build one covenant step: pad the unlocking to afford op-cost, attach the token
// covenant context, and verify it accepts (and that a tampered limb is rejected).
const compileCache = new Map();
// `commitLimbs` = the committed carried state (hashed into the NFT commitment, decl
// order). `allArgs` = everything the unlocking pushes (decl order) — usually ==
// commitLimbs, but e.g. the vk_x final chunk pushes an extra uncommitted zInv.
function buildCovStep(cashFile, commitLimbs, outLimbs, label, checkpoint, allArgs) {
  const inLimbs = commitLimbs;
  const pushArgs = allArgs ?? commitLimbs;
  let contract = compileCache.get(cashFile);
  // compileFile (not compileString) so the Miller chunks' relative library `import` resolves;
  // it compiles the inlined g2check/vkx/finalexp chunks identically.
  if (!contract) { contract = compileFileBytecode(cashFile); compileCache.set(cashFile, contract); }
  const redeem = Uint8Array.from([...contract]); // re-executed redeem; the chunk's trailing `bytes unused zeroPadding` param absorbs the pad (no OP_DROP)
  const rpush = encodeDataPush(redeem);                   // pushed LAST in the scriptSig (P2SH convention)
  const locking = P2SH ? p2shSpk(redeem) : redeem;        // P2SH scriptPubKey (35 B) or bare contract
  const tail = P2SH ? rpush.length : 0;                   // redeem in the scriptSig counts toward the budget
  const inCommit = commitBin(inLimbs.map(BigInt)), outCommit = commitBin(outLimbs.map(BigInt));
  const argBytes = Uint8Array.from([...pushArgs].reverse().flatMap((c) => [...pushInt(BigInt(c))]));
  // `zeroPadding` is the LAST spend param -> pushed FIRST -> the pad leads the unlocking and sits at
  // the bottom of the stack (cost-neutral). Layout: [pad][args...][redeem push (P2SH)].
  const mkUnlock = (target) => { const pad = padBytes(target - argBytes.length - tail); return P2SH ? Uint8Array.from([...pad, ...argBytes, ...rpush]) : Uint8Array.from([...pad, ...argBytes]); };
  const probe = evalCov(locking, mkUnlock(TARGET_UNLOCK), inCommit, outCommit);
  let target = tunedLen(argBytes.length + tail, probe.operationCost);
  let unlocking = mkUnlock(target);
  let real = evalCov(locking, unlocking, inCommit, outCommit);
  while (!real.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); unlocking = mkUnlock(target); real = evalCov(locking, unlocking, inCommit, outCommit); }
  // tamper a state limb: the args follow the leading pad, so the first arg push payload is at padLen + 1.
  const invalid = Uint8Array.from(unlocking); const padLen = unlocking.length - argBytes.length - tail; invalid[padLen + 1] ^= 0x01;
  const invReal = evalCov(locking, invalid, inCommit, outCommit);
  return {
    step: {
      label, locking: binToHex(locking), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalid), checkpoint,
      covenant: { category: binToHex(CATEGORY), capability: 'mutable', inCommitment: binToHex(inCommit), outCommitment: binToHex(outCommit), outLockingBytecode: binToHex(locking) },
      lockingBytes: locking.length, unlockingBytes: unlocking.length, operationCost: real.operationCost,
    },
    accepted: real.accepted, invalidRejected: !invReal.accepted, operationCost: real.operationCost,
    fits: locking.length <= 10000 && unlocking.length <= 10000 && real.operationCost <= OP_BUDGET && real.accepted,
  };
}

// ---- BATCHED Miller replay (flat op list; folded f IS the boundary, no combine) ----
// Prepared-VK: only the runtime pair's R0 is carried (fixed-VK pairs use baked line coeffs),
// matching gen_miller.mjs's stateLimbs — must stay in lockstep with it.
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];

// ---- parse a singleton-proof unlocking (pushes, reverse decl order) -> limbs ----
// decl order: Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1 (pushed reversed, in1 first).
function parseProofUnlocking(hex) {
  const b = hexToBin(hex); const vals = []; let i = 0;
  while (i < b.length) {
    const op = b[i++];
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; }
  }
  const d = vals.reverse(); // -> decl order
  return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] };
}

// ---- the two proof instances: #0 committed, #1 from the multiproof vectors ----
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
const INSTANCES = [
  { tag: 'committed', proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  { tag: 'proof#1', proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
];
// WORST-CASE instance: dense public inputs (2^253-1). The chunk WINDOWS are fixed
// (worst-case sized), so its step graph is identical to the committed run, but the
// vk_x steps do a double+add at (nearly) every position -> ~5-6x op-cost. Same VK ->
// same lockings; this run feeds each vector's `worstCaseProof` (benchmarks.worstCase).
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const WC_INSTANCE = { tag: 'worst-case', proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] };

// ---- build the Miller-boundary (pairing) steps for one instance ----
const stats = { maxLock: 0, maxUnlock: 0, allFit: true, allAccept: true, allInvalid: true };
function buildPairing(inst) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { ops, states, boundary } = millerBatchOps(pairs);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = [...stateLimbs(states[ch.opLo]), ...ptL];
    const outLimbs = [...stateLimbs(states[ch.opHi]), ...ptL]; // final: states[ops.length].f == boundary (no conjugate)
    const r = buildCovStep(join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs, `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' =boundary' : ''}`, ch.final ? 'miller-boundary' : undefined);
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
    steps.push(r.step);
  }
  return { steps, boundaryVal: boundary };
}

// ---- vk_x chunks (Shamir/Straus accumulator; public inputs at RUNTIME) ----
function buildVkx(inst) {
  const [in0, in1] = inst.inputs;
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const steps = [];
  for (const ch of man.chunks) {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const commitLimbs = [...inAcc, in0, in1];
    let outLimbs, allArgs;
    if (ch.final) { outLimbs = [vkxAff.x, vkxAff.y]; allArgs = [...commitLimbs, vkxFinalZinv(in0, in1)]; }
    else { outLimbs = [...vkxStateAt(in0, in1, ch.hi), in0, in1]; allArgs = commitLimbs; }
    const r = buildCovStep(join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`), commitLimbs, outLimbs, `vk_x [${ch.lo},${ch.hi})${ch.final ? ' assert vk_x' : ''}`, ch.final ? 'vk_x' : undefined, allArgs);
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
    steps.push(r.step);
  }
  return steps;
}

// ---- final exponentiation chunks (op-DAG re-evaluated on THIS proof's boundary) ----
function buildFinalexp(inst, boundaryVal) {
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  const tr = finalexpTrace(boundaryVal);
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = liveLimbs(ch.opLo);
    const outLimbs = ch.final ? [] : liveLimbs(ch.opHi);
    const r = buildCovStep(join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs, `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`, ch.final ? 'verify' : undefined);
    stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes);
    stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected;
    steps.push(r.step);
  }
  return steps;
}

// ---- G2 input-validation prologue (EIP-197): [6x^2]B == psi(B) + on-curve A,B,C ----
// `bad` (optional) overrides the point limbs {Bpair,B,A,C} with adversarial values
// (off-curve / off-subgroup) and disables stats tracking — for an invalidInputs run.
function buildG2check(inst, bad) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bpair = bad?.Bpair ?? [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const B4 = bad?.B ?? [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1];
  const A2 = bad?.A ?? [Aa.x, Aa.y], C2 = bad?.C ?? [Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const tail = [...B4, ...A2, ...C2]; // B(4)+A(2)+C(2)
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  const steps = [];
  for (const ch of man.chunks) {
    const inLimbs = sLimbs(g2checkAccAt(Bpair, ch.lo));
    const outLimbs = ch.last ? [] : sLimbs(g2checkAccAt(Bpair, ch.hi));
    const r = buildCovStep(join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`), inLimbs, outLimbs,
      `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' [6x^2]B==psi(B)' : ''}`, ch.first ? 'validate-inputs' : undefined);
    if (!bad) { stats.maxLock = Math.max(stats.maxLock, r.step.lockingBytes); stats.maxUnlock = Math.max(stats.maxUnlock, r.step.unlockingBytes); stats.allFit &&= r.fits; stats.allAccept &&= r.accepted; stats.allInvalid &&= r.invalidRejected; }
    steps.push(r.step);
  }
  return steps;
}

// ---- the FULL verifier chain: validate -> vk_x -> batched 4-pair Miller -> final exp ----
function buildGroth16(inst) {
  const g2Steps = buildG2check(inst);
  const vkxSteps = buildVkx(inst);
  const { steps: pairingSteps, boundaryVal } = buildPairing(inst);
  const feSteps = buildFinalexp(inst, boundaryVal);
  return { groth16: [...g2Steps, ...vkxSteps, ...pairingSteps, ...feSteps], pairing: pairingSteps, vkx: vkxSteps };
}

const g0 = buildGroth16(INSTANCES[0]);
const g1 = buildGroth16(INSTANCES[1]);
const gWc = buildGroth16(WC_INSTANCE); // dense inputs -> worst-case op-cost per stage

// adversarial input: an on-curve but OFF-SUBGROUP G2 point B. The validation prologue
// must REJECT it (the [6x^2]B == psi(B) check fails) -> populates inputValidation.
const b2c = Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n]));
let offSub = null;
for (let i = 1n; i < 400n && !offSub; i++) {
  const x = Fp2.fromBigTuple([i, 0n]); const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2c);
  let y; try { y = Fp2.sqrt(rhs); } catch { continue; }
  if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
  try { bn254.G2.Point.fromAffine({ x, y }).assertValidity(); } catch { offSub = { x, y }; } // on-curve, not torsion-free
}
const offSubRun = offSub
  ? buildG2check(INSTANCES[0], { Bpair: [[offSub.x.c0, offSub.x.c1], [offSub.y.c0, offSub.y.c1]], B: [offSub.x.c0, offSub.x.c1, offSub.y.c0, offSub.y.c1] })
  : null;
console.error(`adversarial off-subgroup B run: ${offSubRun ? offSubRun.length + ' steps (must reject)' : 'NONE'}`);
const pairing0 = g0.pairing, pairing1 = g1.pairing;
const sumOp = (a) => a.reduce((x, s) => x + s.operationCost, 0);
const maxOpOf = (a) => Math.max(...a.map((s) => s.operationCost));
console.error(`pairing(boundary): ${pairing0.length} steps/proof, op ${sumOp(pairing0).toLocaleString()}; proof#1 also built (${pairing1.length} steps)`);
console.error(`max lock ${stats.maxLock}B max unlock ${stats.maxUnlock}B | allFit=${stats.allFit} allAccept=${stats.allAccept} allInvalidRejected=${stats.allInvalid}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/pairing-chunked-vectors.json', JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BN254 Groth16 pairing to the Miller boundary (ONE batched 4-pair optimal-ate Miller loop with a shared fp12Sqr per step; the folded f IS the boundary, no separate combine), multi-tx. Generic covenant: running state in the token NFT commitment, NO baked proof. One fixed set of lockings verifies multiple proofs (runtime-general): proof #0 = committed instance, extraValidProofs = a distinct proof under the same VK.',
  proofBinding: 'runtime', numSteps: pairing0.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(pairing0), maxStepOperationCost: maxOpOf(pairing0),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: pairing0, extraValidProofs: [pairing1], worstCaseProof: gWc.pairing,
}, null, 2));
console.error('wrote src/bch/pairing-chunked-vectors.json (proof-agnostic, 2 proofs + worst-case)');

console.error(`groth16(full): ${g0.groth16.length} steps/proof, op ${sumOp(g0.groth16).toLocaleString()}; proof#1 also built (${g1.groth16.length} steps)`);
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-chunked-vectors.json', JSON.stringify({
  description: 'PROOF-AGNOSTIC full chunked BN254 Groth16 verifier: vk_x (on-chain from public inputs) -> ONE batched 4-pair Miller loop -> final exponentiation -> assert product==1, multi-tx. Generic covenant: state in the token NFT commitment, NO baked proof. One fixed set of lockings verifies multiple proofs (runtime-general): proof #0 = committed instance, extraValidProofs = a distinct proof minted under the same VK.',
  proofBinding: 'runtime', numSteps: g0.groth16.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(g0.groth16), maxStepOperationCost: maxOpOf(g0.groth16),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: g0.groth16, extraValidProofs: [g1.groth16], worstCaseProof: gWc.groth16,
  invalidInputs: offSubRun ? [[...offSubRun]] : undefined, // off-subgroup B -> validation must reject
}, null, 2));
console.error('wrote src/bch/groth16-chunked-vectors.json (proof-agnostic, 2 proofs + worst-case + adversarial input)');

// standalone vk_x aggregation entry (the first 3 chunks of the full verifier),
// PROOF-AGNOSTIC: the public inputs ride in the committed state (NFT commitment),
// so one fixed set of lockings computes vk_x = IC0+in0*IC1+in1*IC2 for ANY inputs.
console.error(`vk_x(covenant): ${g0.vkx.length} steps/proof, op ${sumOp(g0.vkx).toLocaleString()}; proof#1 also built (${g1.vkx.length} steps)`);
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/vkx-chunked-covenant-vectors.json', JSON.stringify({
  description: 'PROOF-AGNOSTIC chunked BN254 vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus), multi-tx. Generic covenant: the accumulator + public inputs live in the token NFT commitment, NO baked instance. One fixed set of lockings aggregates ANY public inputs (runtime-general): proof #0 = committed instance, extraValidProofs = distinct public inputs.',
  proofBinding: 'runtime', numSteps: g0.vkx.length, budgetPerInput: OP_BUDGET,
  totalOperationCost: sumOp(g0.vkx), maxStepOperationCost: maxOpOf(g0.vkx),
  allFit: stats.allFit, allAccept: stats.allAccept, allInvalidRejected: stats.allInvalid,
  steps: g0.vkx, extraValidProofs: [g1.vkx], worstCaseProof: gWc.vkx,
}, null, 2));
console.error('wrote src/bch/vkx-chunked-covenant-vectors.json (proof-agnostic, 2 proofs + worst-case)');
