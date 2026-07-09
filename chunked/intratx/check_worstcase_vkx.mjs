// Validate a written intratx vectors JSON's WORST-CASE proof: rebuild the single tx from its
// worstCaseProof steps, evaluate each input on the real BCH2026 VM, and report per-vk_x-step
// op-cost + whether every step fits the per-input budget. Used to gate vk_x replans, since
// vk_x op is public-input-scalar-density dependent and the plain build doesn't print fullWc.
//
//   node check_worstcase_vkx.mjs C:/Users/mathi/Desktop/verifier/src/bch/groth16-intratx-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin, createVirtualMachineBch2026 } from '@bitauth/libauth';

const OP_BUDGET = (41 + 10_000) * 800;
const vm = createVirtualMachineBch2026(false);
const path = process.argv[2];
const v = JSON.parse(readFileSync(path, 'utf8'));
const steps = v.worstCaseProof ?? v.steps;
const inputs = steps.map((s) => ({ locking: hexToBin(s.locking), unlocking: hexToBin(s.unlocking) }));

const evalInput = (index) => {
  const st = vm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })),
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, op: st.metrics.operationCost, error: st.error ?? null };
};

let maxOp = 0, anyReject = false, maxVkxOp = 0;
const rows = steps.map((s, i) => {
  const o = evalInput(i);
  maxOp = Math.max(maxOp, o.op);
  if (!o.accepted) anyReject = true;
  const isVkx = /vk_x/i.test(s.label);
  if (isVkx) maxVkxOp = Math.max(maxVkxOp, o.op);
  return { i, label: s.label, op: o.op, accepted: o.accepted, isVkx };
});
console.log(`worst-case: ${steps.length} inputs, maxOp ${maxOp.toLocaleString()} (budget ${OP_BUDGET.toLocaleString()}), allAccept ${!anyReject}, allFit ${maxOp <= OP_BUDGET && !anyReject}`);
console.log(`vk_x steps (max ${maxVkxOp.toLocaleString()} = ${(100 * maxVkxOp / OP_BUDGET).toFixed(1)}% of budget):`);
for (const r of rows.filter((r) => r.isVkx)) console.log(`  [${String(r.i).padStart(2)}] ${r.op.toLocaleString().padStart(10)} ${(100 * r.op / OP_BUDGET).toFixed(1).padStart(5)}%  ${r.accepted ? '' : 'REJECT '}${r.label}`);
