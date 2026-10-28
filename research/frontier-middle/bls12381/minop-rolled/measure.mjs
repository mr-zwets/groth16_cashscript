// Measure a minop-interface BLS12-381 contract (rolled research variant, or the reviewed minop for comparison)
// against the EXISTING bench vectors of bch-groth16-bls12381-singleton-minop (same spend() interface):
//   valid + 3 extra proofs + dense worst case must be accepted; invalidUnlocking, the range-invalid set and each
//   multiproof invalidUnlocking must be rejected. No new invalid inputs are constructed here.
//   node measure.mjs [contract.cash] [out.json]      (BENCH_DIR: zk-verifier-bench checkout with the vectors)
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { compileFile, utils } from 'cashc';
import {
  hexToBin, decodeAuthenticationInstructions, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

// BENCH_DIR default: the sibling of this repository's checkout, zk-verifier-bench/ (side-by-side clones) or bench/ (the
// work/<task>/{src,bench} worktree layout), whichever has the minop vectors
const REPO_PARENT = new URL('../../../../../', import.meta.url).pathname;
const BENCH = process.env.BENCH_DIR ?? (['zk-verifier-bench/', 'bench/'].map((d) => REPO_PARENT + d).find((d) => existsSync(d + 'src/bch/groth16-bls12381-singleton-minop-vectors.json')) ?? REPO_PARENT + 'zk-verifier-bench/');
const file = process.argv[2] ?? new URL('./groth16_minop_rolled.cash', import.meta.url).pathname;
const t0 = Date.now();
const locking = utils.asmToBytecode(compileFile(file, { rescheduleStacks: true }).bytecode);
const v = JSON.parse(readFileSync(BENCH + 'src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8'));
const mp = JSON.parse(readFileSync(BENCH + 'src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json', 'utf8'));
const HUGE = Number.MAX_SAFE_INTEGER;
// the bench's loosened BCH 2026 VM (src/harness/vm.ts loosenedConsensusBch2026)
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const run = (u) => { const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: hexToBin(u), valueSatoshis: 1000n }));
  const top = st.stack.at(-1); return { accepted: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, error: st.error ?? null, opCost: st.metrics.operationCost, unlockingBytes: hexToBin(u).length }; };
// OP_DEFINE bodies (BCHN charges each executed body as pushed bytes; libauth charges 100). Every OP_DEFINE here is in the
// straight-line prologue (asserted: no flow-control opcode precedes the last OP_DEFINE), so each executes exactly once.
const ins = decodeAuthenticationInstructions(locking); let defBody = 0, nDef = 0, lastDef = -1;
ins.forEach((x, i) => { if (x.opcode === 0x89) { const body = ins[i - 2]; defBody += body.data?.length ?? 0; nDef++; lastDef = i; } });
const flow = ins.slice(0, lastDef + 1).some((x) => [0x63, 0x64, 0x65, 0x66, 0x67, 0x68].includes(x.opcode)); if (flow) throw new Error('OP_DEFINE after flow control: adjust by trace');
const TXO = 87; // the harness tx overhead for this one-input, minop-interface spend (results.json minop score 58,841 = locking + unlocking + 87)
const rows = [];
const valid = [['committed', v.unlocking], ...mp.proofs.filter((p) => !p.committed).map((p, i) => [`multiproof #${i + 1} (${p.publicInputs.join(',')})`, p.unlocking]), ['worstCaseProof (dense inputs)', mp.worstCaseProof.unlocking]];
const invalid = [['invalidUnlocking (n0 + 1)', v.invalidUnlocking], ...v.rangeInvalidUnlockings.map((x) => [x.label, x.unlocking]), ...mp.proofs.map((p, i) => [`multiproof #${i} invalidUnlocking`, p.invalidUnlocking]), ['worstCaseProof invalidUnlocking', mp.worstCaseProof.invalidUnlocking]];
for (const [label, u] of valid) { const r = run(u); rows.push({ label, expect: 'accept', ...r, bchnAdjusted: r.opCost + defBody }); }
for (const [label, u] of invalid) { const r = run(u); rows.push({ label, expect: 'reject', ...r }); }
const ok = rows.every((r) => (r.expect === 'accept') === r.accepted);
const c = rows[0], w = rows.find((r) => r.label.startsWith('worstCase'));
const out = { contract: file.split('/').slice(-1)[0], lockingBytes: locking.length, lockingSha256: createHash('sha256').update(locking).digest('hex'),
  score: locking.length + c.unlockingBytes + TXO, opDefines: nDef, opDefineBodyBytes: defBody,
  committed: { opCost: c.opCost, bchnAdjusted: c.opCost + defBody }, worstCase: { opCost: w.opCost, bchnAdjusted: w.opCost + defBody, unlockingBytes: w.unlockingBytes },
  validAccepted: rows.filter((r) => r.expect === 'accept' && r.accepted).length + '/' + valid.length,
  invalidRejected: rows.filter((r) => r.expect === 'reject' && !r.accepted).length + '/' + invalid.length, allAsExpected: ok, rows, ms: Date.now() - t0 };
console.log(JSON.stringify({ ...out, rows: undefined }, null, 1));
for (const r of rows) console.log(r.expect.padEnd(6), r.accepted ? 'ACCEPT' : 'REJECT', String(r.opCost).padStart(10), r.label, r.error ? '| ' + r.error.slice(0, 60) : '');
if (process.argv[3]) writeFileSync(process.argv[3], JSON.stringify(out, null, 1) + '\n');
