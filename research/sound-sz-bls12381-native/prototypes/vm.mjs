// libauth runners for kernel measurement (bch-spec VM: same op-cost formula as bch-2026, larger limits) and
// bch-2026 standard/consensus for whole-input checks.
import {createVirtualMachineBchSpec, createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt, hash256} from '@bitauth/libauth';
export const VM = {spec: createVirtualMachineBchSpec(false), std2026: createVirtualMachineBch2026(true), cons2026: createVirtualMachineBch2026(false)};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const pushes = (items) => Uint8Array.from(items.flatMap((b) => [...encodeDataPush(b instanceof Uint8Array ? b : bigIntToVmNumber(BigInt(b)))]));
export const program = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}], outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n}]}});
export const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false});
// run `code` as the locking with the given stack items pushed by the unlocking; returns op cost of the code alone
export function runBare(code, items, vm = VM.spec) {
  const u = pushes(items);
  const st = vm.evaluate(program(Uint8Array.from(code), u));
  const base = vm.evaluate(program(Uint8Array.of(0x61), u)); // OP_NOP
  const error = st.error && !/unexpected number of items on the stack/.test(st.error) ? st.error : undefined;
  return {error, op: st.metrics.operationCost - base.metrics.operationCost + 100, stack: st.stack.map(num)};
}
