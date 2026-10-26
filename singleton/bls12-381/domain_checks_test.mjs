// Domain-check rejection tests for the BLS12-381 singleton verifier (groth16.cash):
// coordinate range (0 <= v < p), curve equations for A, C (y^2 = x^3 + 4) and B
// (y^2 = x^3 + 4(1+u)), and the G2 subgroup check on B (psi(B) == [-x]B, fused into
// B's Miller walk with the Z != 0 guard). Valid proofs (the committed instance and the
// bench multiproof set) must still verify. The negative cases live in domain_cases.mjs.
//
// The op-cost at rejection shows where each case failed: the range and curve checks run
// first (tens of thousands), the subgroup check right after vk_x and B's Miller loop (~0.2B),
// the pairing verdict at the very end (~1B).
//
//   node singleton/bls12-381/domain_checks_test.mjs                 # compile groth16.cash (plain)
//   node singleton/bls12-381/domain_checks_test.mjs <vectors.json>  # test that file's lockingOK
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { compileFile } from 'cashc';
import { PUBLIC_INPUTS } from './bls_instance.mjs';
import { domainRejectCases, honestArgs, unlockingFor } from './domain_cases.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const VDIR = (process.env.BENCH_VDIR ?? join(here, '../../../zk-verifier-bench/src/bch')) + '/';

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const evalPair = (locking, unlocking) => {
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
  return { accepted, error: st.error, operationCost: st.metrics.operationCost };
};

const cases = domainRejectCases();
const arg = process.argv[2];
const locking = arg
  ? hexToBin(JSON.parse(readFileSync(arg, 'utf8')).lockingOK)
  : hexToBin(compileFile(join(here, 'groth16.cash'), { optimizeFor: 'size', rescheduleStacks: true }).debug.bytecode);
console.log(`locking ${locking.length} B (${arg ?? 'compiled groth16.cash'})`);

let fail = 0;
const expect = (label, args, want) => {
  const r = evalPair(locking, unlockingFor(args));
  const ok = r.accepted === want;
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${want ? 'accept' : 'reject'}  ${label.padEnd(44)} op-cost ${r.operationCost.toLocaleString()}${r.accepted ? '' : `  (${String(r.error).slice(0, 60)})`}`);
};

expect('honest proof (committed instance)', honestArgs, true);
let mp = null;
try { mp = JSON.parse(readFileSync(VDIR + 'groth16-bls12381-singleton-multiproof-vectors.json', 'utf8')); } catch { /* bench checkout absent */ }
if (mp) {
  mp.proofs.forEach((p, i) => {
    const a = evalPair(locking, hexToBin(p.unlocking)), r = evalPair(locking, hexToBin(p.invalidUnlocking));
    const ok = a.accepted && !r.accepted; if (!ok) fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  multiproof #${i} accept valid / reject tampered input`);
  });
}
expect('tampered public input', [...honestArgs.slice(0, 8), PUBLIC_INPUTS[0] + 1n, PUBLIC_INPUTS[1]], false);
for (const c of cases) expect(c.label, c.args, false);
console.log(fail === 0 ? 'ALL PASS' : `${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
