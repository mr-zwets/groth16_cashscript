// libauth bch-2026 runners: the 3-input transaction (every input spends P2SH32(R)), consensus and standard mode.
// The transaction shape mirrors zk-verifier-bench's intra-tx runner (outpoint n of a zero txid, one OP_RETURN output).
import {createVirtualMachineBch2026, encodeDataPush, hash256} from '@bitauth/libauth';
export const VMS = {consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true)};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
export const budgetOf = (unlocking) => (41 + unlocking.length) * 800;
export const programOf = (lockings, unlockings, inputIndex) => ({
  inputIndex,
  sourceOutputs: lockings.map((l) => ({lockingBytecode: Uint8Array.from(l), valueSatoshis: 1000n})),
  transaction: {version: 2, locktime: 0,
    inputs: unlockings.map((u, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: Uint8Array.from(u)})),
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]},
});
// evaluate every input; accepted = the VM's verify() result for that input (consensus or standard rules)
export function spendAll(lockings, unlockings, mode = 'consensus') {
  const vm = VMS[mode];
  return unlockings.map((u, i) => {
    const prog = programOf(lockings, unlockings, i); const st = vm.evaluate(prog);
    const ok = st.error === undefined && st.stack.length === 1 && st.stack[0].length === 1 && st.stack[0][0] === 1;
    return {accepted: ok, error: st.error ?? (ok ? null : 'final stack ' + st.stack.length), opCost: st.metrics.operationCost, budget: budgetOf(u), length: u.length};
  });
}
export const allAccepted = (rs) => rs.every((x) => x.accepted);
