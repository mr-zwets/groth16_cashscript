// Build + measure the OP-OPTIMIZED Groth16 singleton (groth16_minop.cash): lazy tower +
// QUOTIENT-TORUS residue Miller (6-limb u root, affine witnessed-slope runtime B, unit lines,
// endpoint-fused exact G2 subgroup check) + GLV vk_x. Reuses the verified chunked witness
// generators. FAIL-CLOSED: refuses to write unless the valid/worst proofs ACCEPT and every
// tamper fixture REJECTS. Writes verifier/src/bch/groth16-singleton-minop-vectors.json.
//   node build_vectors_groth16_minop.mjs            (full: torus)
//   CASH=groth16_minop_lazy   STAGE=lazy   node build_vectors_groth16_minop.mjs   (staged, legacy layout)
import { compileFile } from 'cashc';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, bigIntToVmNumber, vmNumberToBigInt, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const C = await import('../../chunked/pairing/_millermath.mjs');
const R = await import('../../chunked/pairing/_residuemath.mjs');
const G2 = await import('../../chunked/pairing/gen_g2check.mjs');
const GLV = await import('../../chunked/pairing/gen_vkx_glv.mjs');
const GA = await import('./_glv_affine.mjs');

const here = dirname(fileURLToPath(import.meta.url));
const STANDARD_BUDGET = (41 + 10_000) * 800;
const Pm = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const STAGE = process.env.STAGE ?? 'full';            // lazy | fastg2 | full
const CASH = process.env.CASH ?? 'groth16_minop';      // contract file (no ext)
const useFastG2 = STAGE !== 'lazy';
const useGlv = STAGE === 'full';

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const realVm = createVirtualMachineBch2026(false);
const evalPair = (vm, locking, unlocking) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: state.error, operationCost: state.metrics.operationCost };
};
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) =>
  a instanceof Uint8Array ? [...encodeDataPush(a)] : [...pushInt(a)]));
const canon = (x) => ((x % Pm) + Pm) % Pm;

const vec = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/checkpoints/pairing-vectors.json', 'utf8'));
const Baff = C.proof.b.toAffine();
const B = [[Baff.x.c0, Baff.x.c1], [Baff.y.c0, Baff.y.c1]];

// `pf` (a proof object for pairsFor) defaults to the committed proof; the worst-case run passes the
// dense proof parsed from the multiproof fixture so the GLV vk_x AND the residue witness that depends
// on it are measured on dense public inputs, exactly like the chunked builds. Without this the
// singleton was measured ONLY on the committed proof — the source of the apparent op-cost gap.
function residueWit(publicInputs, pf) {
  const pairs = C.pairsFor(publicInputs.map(BigInt), pf);
  const { boundary: fRaw } = C.millerBatchOps(pairs);
  const { c, cInv, w } = R.residueWitness(fRaw);
  return [...R.fp12limbsOf(c), ...R.fp12limbsOf(cInv), ...R.fp12limbsOf(w)].map(canon);
}
// QUOTIENT-TORUS witnesses: the 6-limb canonical residue root u ([c]=[1+u*W]) and the affine
// runtime-B slope witnesses (op order, one Fp2 per double/add, two for the endpoint). Slopes
// depend only on the PROOF (B walk), never on the public inputs; u depends on both.
const u6 = (u) => [u.c0.c0, u.c0.c1, u.c1.c0, u.c1.c1, u.c2.c0, u.c2.c1].map(canon);
function torusWit(publicInputs, pf) {
  const pairs = C.pairsFor(publicInputs.map(BigInt), pf);
  const { boundary: fRaw } = C.millerBatchOps(pairs);
  const root = R.residueTorusWitness(fRaw);
  const trace = R.millerFusedAffineOps(pairs, root.c, root.cInv, { unitLines: true, torusU: root.u });
  const slopes = trace.ops.flatMap((op) => (op.affineSlopes ?? []).flatMap((m) => [canon(m.c0), canon(m.c1)]));
  return { u: u6(root.u), slopes };
}
// spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, u[6], iAy,iVy,iCy, slopes[176], k10,k20,k11,k21,vkxZinv)
// (torus/full). The staged legacy layout keeps the old c/ci/w + zinv shape.
// `limbs`={Ax..Cy} are the proof's affine coords (unlocking), `Bpair`=[[Bxa,Bxb],[Bya,Byb]] for zinv.
function argsFor(publicInputs, wit, limbs, Bpair, pf = C.proof) {
  const base = [
    BigInt(limbs.Ax), BigInt(limbs.Ay),
    BigInt(limbs.Bxa), BigInt(limbs.Bxb), BigInt(limbs.Bya), BigInt(limbs.Byb),
    BigInt(limbs.Cx), BigInt(limbs.Cy),
    ...publicInputs.map(BigInt),
  ];
  if (STAGE === 'full') {
    // iVy inverts the y of the vk_x the CONTRACT computes for THESE public inputs, so tampered
    // inputs still pass the inverse gate and are rejected by the pairing verdict itself.
    const vkx = C.pairsFor(publicInputs.map(BigInt), pf)[2].P.toAffine();
    base.push(...wit.u);
    base.push(C.Fp.inv(BigInt(limbs.Ay)), C.Fp.inv(vkx.y), C.Fp.inv(BigInt(limbs.Cy)));
    base.push(...wit.slopes);
  } else {
    base.push(...wit);
    if (useFastG2) { const [za, zb] = G2.g2checkFastZinv(Bpair); base.push(canon(za), canon(zb)); }
  }
  if (STAGE === 'full') {
    // affine GLV witness: k-decomposition + top-bit index nb + witnessed slope blob.
    // Fail-closed sanity: the replay must land exactly on the pairing-side vk_x.
    const gw = GA.glvAffineWitness(BigInt(publicInputs[0]), BigInt(publicInputs[1]));
    const vkx = C.pairsFor(publicInputs.map(BigInt), pf)[2].P.toAffine();
    if (gw.vkx[0] !== vkx.x || gw.vkx[1] !== vkx.y) {
      throw new Error('fail-closed: affine GLV replay disagrees with the pairing-side vk_x');
    }
    base.push(gw.k10, gw.k20, gw.k11, gw.k21, gw.nb, hexToBin(gw.blobHex));
  } else if (useGlv) {
    const [k10, k20] = GLV.glvDecompose(BigInt(publicInputs[0]));
    const [k11, k21] = GLV.glvDecompose(BigInt(publicInputs[1]));
    const z = GLV.vkxGlvZinv(k10, k20, k11, k21);
    base.push(k10, k20, k11, k21, canon(z));
  }
  return base;
}
const cLimbs = { Ax: vec.proof.a.x, Ay: vec.proof.a.y, Bxa: vec.proof.b.x.c0, Bxb: vec.proof.b.x.c1, Bya: vec.proof.b.y.c0, Byb: vec.proof.b.y.c1, Cx: vec.proof.c.x, Cy: vec.proof.c.y };

// Parse the DENSE (near-r) worst-case proof shared by the chunked builds out of the multiproof
// fixture (its unlocking pushes Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, minimally encoded, reversed).
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
  return {
    limbs: { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7] },
    Bpair: [[d[2], d[3]], [d[4], d[5]]], publicInputs: [d[8], d[9]],
    proof: C.proofFromLimbs(d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]),
  };
}
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const wc = parseProofUnlocking(mp.worstCaseProof.unlocking);

const template = hexToBin(compileFile(join(here, `${CASH}.cash`), { rescheduleStacks: true }).debug.bytecode);
const rwValid = STAGE === 'full' ? torusWit(vec.publicInputs) : residueWit(vec.publicInputs);
const unlocking = unlockingFor(argsFor(vec.publicInputs, rwValid, cLimbs, B));
// invalid fixture: valid proof + valid witnesses, TAMPERED public inputs -> the pairing verdict
// itself must reject (every gate passes; iVy/GLV recomputed for the tampered inputs).
const invalidUnlocking = unlockingFor(argsFor(vec.invalid.publicInputs, rwValid, cLimbs, B));
// worst-case: the same dense proof the chunked entries use, through the SAME locking.
const wcWit = STAGE === 'full' ? torusWit(wc.publicInputs, wc.proof) : residueWit(wc.publicInputs, wc.proof);
const wcUnlocking = unlockingFor(argsFor(wc.publicInputs, wcWit, wc.limbs, wc.Bpair, wc.proof));
const wcAccept = evalPair(looseVm, template, wcUnlocking);

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

// ---- extra tamper fixtures (torus/full only): each MUST reject or the build refuses to write ----
const tamperChecks = [];
if (STAGE === 'full' && CASH === 'groth16_minop') {
  const validArgs = argsFor(vec.publicInputs, rwValid, cLimbs, B);
  const tweak = (idx, delta) => { const a = validArgs.slice(); a[idx] = a[idx] + delta; return a; };
  // arg indices: 0..7 proof limbs, 8..9 inputs, 10..15 u, 16..18 inverses, 19.. slopes
  tamperChecks.push(['off-curve B (Bya+1)', tweak(4, 1n)]);
  tamperChecks.push(['u alias (u0+p)', tweak(10, Pm)]);
  tamperChecks.push(['tampered slope (s0a+1)', tweak(19, 1n)]);
  tamperChecks.push(['tampered iAy (+1)', tweak(16, 1n)]);
  tamperChecks.push(['tampered GLV slope blob', (() => {
    const a = validArgs.slice();
    const blob = a[a.length - 1].slice();
    if (blob.length > 0) blob[0] = blob[0] ^ 1;
    a[a.length - 1] = blob;
    return a;
  })()]);
  // OFF-SUBGROUP B (on-curve, outside G2): honest generic-twist slope witnesses for the tampered
  // walk, so every slope gate passes and rejection happens at the ENDPOINT endomorphism relation
  // (the fused exact subgroup check).
  const offSub = C.invalidG2Overrides(C.proof, 1)[3];
  const osLimbs = { ...cLimbs, Bxa: offSub.Bx.c0, Bxb: offSub.Bx.c1, Bya: offSub.By.c0, Byb: offSub.By.c1 };
  const osProof = C.proofFromLimbs(...['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy'].map((k) => BigInt(osLimbs[k])));
  const osPairs = C.pairsFor(vec.publicInputs.map(BigInt), osProof);
  let osRoot;
  try { osRoot = R.residueTorusWitness(C.millerBatchOps(osPairs).boundary); }
  catch { osRoot = R.residueTorusWitness(C.millerBatchOps(C.pairsFor(vec.publicInputs.map(BigInt))).boundary); }
  const osTrace = R.millerFusedAffineOps(osPairs, osRoot.c, osRoot.cInv, { unitLines: true, torusU: osRoot.u });
  const osWit = { u: u6(osRoot.u), slopes: osTrace.ops.flatMap((op) => (op.affineSlopes ?? []).flatMap((m) => [canon(m.c0), canon(m.c1)])) };
  tamperChecks.push(['off-subgroup B (endpoint relation)', argsFor(vec.publicInputs, osWit, osLimbs, null, osProof)]);
}
const tamperResults = tamperChecks.map(([label, args]) => {
  const res = evalPair(looseVm, template, unlockingFor(args));
  console.log(`loosened: REJECT ${label} = ${!res.accepted}`);
  return res.accepted;
});

console.log(`=== Groth16VerifyMinOp [${CASH}, stage=${STAGE}] (${STAGE === 'full' ? 'lazy tower + quotient torus + affine/unit lines + endpoint-G2 + GLV' : `lazy tower${useFastG2 ? ' + fast-G2' : ''}${useGlv ? ' + GLV' : ''}`}) ===`);
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})  err=${looseAccept.error ?? '(none)'}`);
console.log(`loosened: ACCEPT worst = ${wcAccept.accepted}  (op-cost ${wcAccept.operationCost.toLocaleString()})  err=${wcAccept.error ?? '(none)'}   [+${(wcAccept.operationCost - opCost).toLocaleString()} vs committed]`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

if (STAGE === 'full' && CASH === 'groth16_minop') {
  // FAIL-CLOSED: refuse to write unless everything is exactly right.
  if (!looseAccept.accepted) throw new Error(`fail-closed: valid proof REJECTED (${looseAccept.error})`);
  if (!wcAccept.accepted) throw new Error(`fail-closed: worst-case proof REJECTED (${wcAccept.error})`);
  if (looseRejectInvalid.accepted) throw new Error('fail-closed: tampered-input fixture ACCEPTED');
  if (tamperResults.some((accepted) => accepted)) throw new Error('fail-closed: a tamper fixture was ACCEPTED');
  const out = {
    contract: 'Groth16VerifyMinOp (singleton/bn254/groth16_minop.cash)',
    description: 'op-optimized full Groth16 verifier: lazy-tower quotient-torus Miller (6-limb residue root u, affine witnessed-slope runtime B, unit lines, e(alpha,beta) baked) + endpoint-fused exact G2 subgroup check + projective cross-multiplied residue verdict + nb-bounded affine GLV vk_x (witnessed slopes)',
    lockingOK: binToHex(template),
    unlocking: binToHex(unlocking),
    invalidUnlocking: binToHex(invalidUnlocking),
    // worst-case: the same dense (near-r) proof the chunked entries measure, through the SAME
    // locking. Its op-cost is higher purely because the GLV vk_x MSM does an add nearly every
    // iteration for dense scalars; it's the fair apples-to-apples number vs the chunked builds.
    worstCaseUnlocking: binToHex(wcUnlocking),
    worstCaseOperationCost: wcAccept.operationCost,
    worstCaseAccept: wcAccept.accepted,
    lockingBytes: template.length,
    unlockingBytes: unlocking.length,
    operationCost: opCost,
    realAccepted: realAccept.accepted,
    realError: realAccept.error ?? null,
    inputsNeeded: Math.ceil(opCost / STANDARD_BUDGET),
    looseAccept: looseAccept.accepted,
    rejectInvalid: !looseRejectInvalid.accepted,
  };
  writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-minop-vectors.json', JSON.stringify(out, null, 2));
  console.log('wrote src/bch/groth16-singleton-minop-vectors.json');
}
