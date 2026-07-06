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
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
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

function residueWit(publicInputs) {
  const pairs = C.pairsFor(publicInputs.map(BigInt));
  const { boundary: fRaw } = C.millerBatchOps(pairs);
  const { c, cInv, w } = R.residueWitness(fRaw);
  return [...R.fp12limbsOf(c), ...R.fp12limbsOf(cInv), ...R.fp12limbsOf(w)].map(canon);
}
// spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, c[12],ci[12],w[12], [zinvA,zinvB], [k10,k20,k11,k21,vkxZinv])
function argsFor(publicInputs, resWit) {
  const A = vec.proof.a, Bp = vec.proof.b, Cc = vec.proof.c;
  const base = [
    BigInt(A.x), BigInt(A.y),
    BigInt(Bp.x.c0), BigInt(Bp.x.c1), BigInt(Bp.y.c0), BigInt(Bp.y.c1),
    BigInt(Cc.x), BigInt(Cc.y),
    ...publicInputs.map(BigInt),
    ...resWit,
  ];
  if (useFastG2) { const [za, zb] = G2.g2checkFastZinv(B); base.push(canon(za), canon(zb)); }
  if (useGlv) {
    const [k10, k20] = GLV.glvDecompose(BigInt(publicInputs[0]));
    const [k11, k21] = GLV.glvDecompose(BigInt(publicInputs[1]));
    const z = GLV.vkxGlvZinv(k10, k20, k11, k21);
    base.push(k10, k20, k11, k21, canon(z));
  }
  return base;
}

const template = hexToBin(compileFile(join(here, `${CASH}.cash`), { rescheduleStacks: true }).debug.bytecode);
const rwValid = residueWit(vec.publicInputs);
const unlocking = unlockingFor(argsFor(vec.publicInputs, rwValid));
const invalidUnlocking = unlockingFor(argsFor(vec.invalid.publicInputs, rwValid));

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log(`=== Groth16VerifyMinOp [${CASH}, stage=${STAGE}] (lazy tower${useFastG2 ? ' + fast-G2' : ''}${useGlv ? ' + GLV' : ''}) ===`);
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})  err=${looseAccept.error ?? '(none)'}`);
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
