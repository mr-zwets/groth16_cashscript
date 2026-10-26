// Range-check rejection tests for the BN254 singleton verifier (groth16.cash): a valid proof
// with one coordinate replaced by v + P or v - P (same point mod P) must be REJECTED, and every
// valid proof (committed instance, bench multiproof set, zero-input proofs) must still verify.
// The op-cost at rejection shows the failure is at the early range check, not the pairing.
//
//   node singleton/bn254/range_checks_test.mjs                 # compile groth16.cash (plain)
//   node singleton/bn254/range_checks_test.mjs <vectors.json>  # test that file's lockingOK
//   ... --expect-accept-noncanonical                           # assert the cases are ACCEPTED
//                                                              # (demonstrates an unchecked build)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { compileFile } from 'cashc';
import { rangeRejectCases, committedArgs, unlockingFor } from './range_cases.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const BENCH = process.env.BENCH_DIR || join(here, '../../../zk-verifier-bench');
const VDIR = join(BENCH, 'src/bch') + '/';

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

const argv = process.argv.slice(2);
const expectAcceptNonCanonical = argv.includes('--expect-accept-noncanonical');
const file = argv.find((a) => !a.startsWith('--'));
const locking = file
  ? hexToBin(JSON.parse(readFileSync(file, 'utf8')).lockingOK)
  : hexToBin(compileFile(join(here, 'groth16.cash'), { optimizeFor: 'size', rescheduleStacks: true }).debug.bytecode);
console.log(`locking ${locking.length} B (${file ?? 'compiled groth16.cash'})`);

let fail = 0;
const report = (ok, what, label, r) => {
  if (!ok) fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what.padEnd(6)} ${label.padEnd(44)} op-cost ${r.operationCost.toLocaleString()}${r.accepted ? '' : `  (${String(r.error).slice(0, 50)})`}`);
};
const expect = (label, unlocking, want) => {
  const r = evalPair(locking, unlocking);
  report(r.accepted === want, want ? 'accept' : 'reject', label, r);
};

// valid proofs
expect('committed instance', unlockingFor(committedArgs(BENCH)), true);
const mp = JSON.parse(readFileSync(VDIR + 'groth16-singleton-multiproof-vectors.json', 'utf8'));
mp.proofs.filter((p) => !p.committed).forEach((p, i) => expect(`multiproof #${i + 1}`, hexToBin(p.unlocking), true));
const zero = JSON.parse(readFileSync(VDIR + 'groth16-singleton-zero-input-vectors.json', 'utf8'));
for (const p of zero.proofs) expect(`zero-input ${p.label}`, hexToBin(p.unlocking), true);

// non-canonical coordinates
for (const c of rangeRejectCases(BENCH)) expect(c.label, unlockingFor(c.args), expectAcceptNonCanonical);

console.log(fail === 0 ? 'ALL PASS' : `${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
