// libauth bch-2026 runners for the 4-input transaction (consensus / standard), and a diagnostics VM.
import {createVirtualMachineBch2026, encodeDataPush, hash256, encodeTransactionBch} from '@bitauth/libauth';
export const VMS = {consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true)};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
export const budgetOf = (unlocking) => (41 + unlocking.length) * 800;
// the transaction: input j spends a P2SH32(R) output with unlocking = pushes_j | R; one OP_RETURN output
export function txOf(unlockings, lockings) {
  return {sourceOutputs: lockings.map((l) => ({lockingBytecode: l, valueSatoshis: 1000n})),
    transaction: {version: 2, locktime: 0, inputs: unlockings.map((u, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: u})),
      outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}};
}
export const unlockingsFor = (pushesPerInput, R) => pushesPerInput.map((ps) => encodeUnlocking([...ps, R]));
// evaluate every input (mode: consensus | standard); accepted = no error and a clean stack [0x01]
export function evalTx(ctx, mode = 'standard', only = null) {
  const vm = VMS[mode];
  return ctx.transaction.inputs.map((inp, i) => {
    if (only !== null && !only.includes(i)) return null;
    const st = vm.evaluate({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const top = st.stack.at(-1);
    const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    return {ok, error: st.error ?? (ok ? null : `stack ${st.stack.length}`), op: st.metrics.operationCost, budget: budgetOf(inp.unlockingBytecode), bytes: inp.unlockingBytecode.length};
  });
}
export const verifyTx = (ctx, mode = 'standard') => VMS[mode].verify(ctx);
export const txSize = (ctx) => encodeTransactionBch(ctx.transaction).length;
// diagnostics only (profile/layout measurement): bch-2026 with a huge density base, so an input that exceeds its real
// budget still runs to completion and reports its op cost. Never used for any acceptance claim.
import {createVirtualMachine, createInstructionSetBch2026, ripemd160, secp256k1, sha1, sha256} from '@bitauth/libauth';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
const consPath = createRequire(import.meta.url).resolve('@bitauth/libauth').replace(/index\.js$/, 'lib/vm/instruction-sets/bch/2026/bch-2026-consensus.js');
const {ConsensusBch2026} = await import(pathToFileURL(consPath).href);
const unl = (std) => createVirtualMachine(createInstructionSetBch2026(std, {consensus: {...ConsensusBch2026, densityControlBaseLength: 1_000_000}, ripemd160, secp256k1, sha1, sha256}));
export const VM_UNLIMITED = {standard: unl(true), consensus: unl(false)};
export function evalTxUnlimited(ctx, mode = 'standard') {
  const vm = VM_UNLIMITED[mode];
  return ctx.transaction.inputs.map((inp, i) => { const st = vm.evaluate({inputIndex: i, sourceOutputs: ctx.sourceOutputs, transaction: ctx.transaction});
    const top = st.stack.at(-1); const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
    return {ok, error: st.error ?? null, op: st.metrics.operationCost, budget: budgetOf(inp.unlockingBytecode), bytes: inp.unlockingBytecode.length}; });
}
