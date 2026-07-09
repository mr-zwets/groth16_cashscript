// Build + measure the OP-OPTIMIZED Groth16 singleton (groth16_minop.cash): lazy tower +
// residue tail + fast-endo G2 check + GLV vk_x. Reuses the verified chunked witness
// generators. Writes verifier/src/bch/groth16-singleton-minop-vectors.json.
//   node build_vectors_groth16_minop.mjs            (full: fast-G2 + GLV)
//   CASH=groth16_minop_lazy   STAGE=lazy   node build_vectors_groth16_minop.mjs   (staged)
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
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));
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
// spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, c[12],ci[12],w[12], [zinvA,zinvB], [k10,k20,k11,k21,vkxZinv])
// `limbs`={Ax..Cy} are the proof's affine coords (unlocking), `Bpair`=[[Bxa,Bxb],[Bya,Byb]] for zinv.
function argsFor(publicInputs, resWit, limbs, Bpair) {
  const base = [
    BigInt(limbs.Ax), BigInt(limbs.Ay),
    BigInt(limbs.Bxa), BigInt(limbs.Bxb), BigInt(limbs.Bya), BigInt(limbs.Byb),
    BigInt(limbs.Cx), BigInt(limbs.Cy),
    ...publicInputs.map(BigInt),
    ...resWit,
  ];
  if (useFastG2) { const [za, zb] = G2.g2checkFastZinv(Bpair); base.push(canon(za), canon(zb)); }
  if (useGlv) {
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
const rwValid = residueWit(vec.publicInputs);
const unlocking = unlockingFor(argsFor(vec.publicInputs, rwValid, cLimbs, B));
const invalidUnlocking = unlockingFor(argsFor(vec.invalid.publicInputs, rwValid, cLimbs, B));
// worst-case: the same dense proof the chunked entries use, through the SAME locking.
const wcUnlocking = unlockingFor(argsFor(wc.publicInputs, residueWit(wc.publicInputs, wc.proof), wc.limbs, wc.Bpair));
const wcAccept = evalPair(looseVm, template, wcUnlocking);

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log(`=== Groth16VerifyMinOp [${CASH}, stage=${STAGE}] (lazy tower${useFastG2 ? ' + fast-G2' : ''}${useGlv ? ' + GLV' : ''}) ===`);
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})  err=${looseAccept.error ?? '(none)'}`);
console.log(`loosened: ACCEPT worst = ${wcAccept.accepted}  (op-cost ${wcAccept.operationCost.toLocaleString()})  err=${wcAccept.error ?? '(none)'}   [+${(wcAccept.operationCost - opCost).toLocaleString()} vs committed]`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

if (STAGE === 'full' && CASH === 'groth16_minop') {
  const out = {
    contract: 'Groth16VerifyMinOp (singleton/bn254/groth16_minop.cash)',
    description: 'op-optimized full Groth16 verifier: lazy-tower Miller (3 reused single-pair, skip e(alpha,beta)) + witnessed residue final-exp + fast-endo 63-bit G2 check + GLV vk_x',
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
