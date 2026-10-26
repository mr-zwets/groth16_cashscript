// bch-2026 runners for kernel prototypes (bare evaluation: the code runs as the locking bytecode
// after the pushes; no clean-stack requirement). Op cost is reported net of the pushes.
import {createVirtualMachineBch2026, createVirtualMachineBchSpec, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt} from '@bitauth/libauth';

export const VMS = {
  consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true),
  spec: createVirtualMachineBchSpec(true),
};
const enc = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
const prog = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
export const numPush = (v) => bigIntToVmNumber(BigInt(v));
export const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false});
// run `code` with the given pushes (byte arrays); returns {error, opCost (net of the pushes), stack}
export function runBare(code, pushes, mode = 'standard') {
  const vm = VMS[mode]; const u = enc(pushes);
  const st = vm.evaluate(prog(Uint8Array.from(code), u));
  const base = vm.evaluate(prog(Uint8Array.of(0x61), u)); // OP_NOP: cost of the unlocking pushes + 1 instruction
  const error = st.error && /unexpected number of items/.test(st.error) ? undefined : st.error;
  return {error, opCost: st.metrics.operationCost - base.metrics.operationCost + 100, stack: st.stack};
}
