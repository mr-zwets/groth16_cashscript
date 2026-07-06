// Build + measure the OP-OPTIMIZED BLS12-381 Groth16 singleton (groth16_minop.cash):
// lazy tower + witnessed-residue tail + psi G2 check + phi G1 checks + GLV vk_x. Reuses
// the verified chunked witness generators (_pairingmath/_residuemath) and the GLV helpers
// exported by gen_singleton_minop.mjs.
// Writes verifier/src/bch/groth16-bls12381-singleton-minop-vectors.json.
//   node build_vectors_groth16_minop.mjs
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { PUBLIC_INPUTS } from './bls_instance.mjs';
import {
  hexToBin, binToHex, bigIntToVmNumber, encodeDataPush,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const C = await import('../../chunked/bls12-381/_pairingmath.mjs');
const R = await import('../../chunked/bls12-381/_residuemath.mjs');
const G = await import('./gen_singleton_minop.mjs');

const here = dirname(fileURLToPath(import.meta.url));
const CASHC = fileURLToPath(import.meta.resolve('cashc/dist/cashc-cli.js'));
const STANDARD_BUDGET = (41 + 10_000) * 800;
const Pm = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787n;

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

const Aaff = C.proof.a.toAffine(), Baff = C.proof.b.toAffine(), Caff = C.proof.c.toAffine();

function residueWit(publicInputs) {
  const pairs = C.pairsFor(publicInputs);
  const { boundary: g } = C.millerBatchOps(pairs); // UNCONJUGATED batched boundary
  const { c, cInv, w } = R.residueWitness(g);
  return [...R.fp12limbsOf(c), ...R.fp12limbsOf(cInv), ...R.fp12limbsOf(w)].map(canon);
}
// spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, c[12],ci[12],w[12], k10,k20,k11,k21,vkxZinv)
function argsFor(publicInputs, resWit) {
  const [k10, k20] = G.glvDecompose(publicInputs[0] % G.GLV_R);
  const [k11, k21] = G.glvDecompose(publicInputs[1] % G.GLV_R);
  const z = G.vkxGlvZinv(k10, k20, k11, k21);
  return [
    Aaff.x, Aaff.y,
    Baff.x.c0, Baff.x.c1, Baff.y.c0, Baff.y.c1,
    Caff.x, Caff.y,
    ...publicInputs,
    ...resWit,
    k10, k20, k11, k21, canon(z),
  ];
}

const template = hexToBin(execFileSync('node', [CASHC, join(here, 'groth16_minop.cash'), '-h'], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }).trim());
const rwValid = residueWit(PUBLIC_INPUTS);
const unlocking = unlockingFor(argsFor(PUBLIC_INPUTS, rwValid));
// invalid: tamper a public input but reuse the (now non-matching) valid witness
const invalidUnlocking = unlockingFor(argsFor([PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]], rwValid));

const looseAccept = evalPair(looseVm, template, unlocking);
const looseRejectInvalid = evalPair(looseVm, template, invalidUnlocking);
const realAccept = evalPair(realVm, template, unlocking);
const opCost = looseAccept.operationCost;

console.log('=== Groth16VerifyMinOp BLS12-381 (lazy tower + residue tail + psi/phi subgroup checks + GLV) ===');
console.log(`locking ${template.length}B  unlocking ${unlocking.length}B`);
console.log(`loosened: ACCEPT valid = ${looseAccept.accepted}  (op-cost ${opCost.toLocaleString()})  err=${looseAccept.error ?? '(none)'}`);
console.log(`loosened: REJECT invalid = ${!looseRejectInvalid.accepted}`);
console.log(`real BCH 2026: accepted = ${realAccept.accepted}  err = ${realAccept.error ?? '(none)'}`);
console.log(`inputsNeeded = ${Math.ceil(opCost / STANDARD_BUDGET)}`);

const out = {
  contract: 'Groth16VerifyMinOp (singleton/bls12-381/groth16_minop.cash)',
  description: 'op-optimized full BLS12-381 Groth16 verifier: lazy-tower fused Miller (1 runtime G2 pair, lines/e(alpha,beta) baked) + witnessed-residue final-exp (lambda=p+|x|) + psi G2 check + phi G1 checks (A,C) + GLV vk_x',
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
writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-bls12381-singleton-minop-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/groth16-bls12381-singleton-minop-vectors.json');
