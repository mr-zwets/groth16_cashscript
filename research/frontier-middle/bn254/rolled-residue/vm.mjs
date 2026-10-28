// libauth BCH 2026 runners for the T2 research singleton (one P2SH32 input): `consensus` / `standard` loosen ONLY the
// density (op-cost) budget (densityControlBaseLength 1e9), every other BCH 2026 limit (10,000 B scripts, stack items,
// standard unlocking cap) applies; the *Strict VMs are stock libauth BCH 2026.
import {createVirtualMachine, createVirtualMachineBch2026, createInstructionSetBch2026, encodeDataPush, hash256, ripemd160, secp256k1, sha1, sha256} from '@bitauth/libauth';
import {ConsensusBch2026} from '../../../../node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/2026/bch-2026-consensus.js';
const loose = (standard) => createVirtualMachine(createInstructionSetBch2026(standard, {consensus: {...ConsensusBch2026, densityControlBaseLength: 1_000_000_000}, ripemd160, secp256k1, sha1, sha256}));
export const VMS = {consensus: loose(false), standard: loose(true), consensusStrict: createVirtualMachineBch2026(false), standardStrict: createVirtualMachineBch2026(true)};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
export const programOf = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
export function spend(locking, unlocking, mode = 'consensus') {
  const vm = VMS[mode]; const prog = programOf(locking, unlocking); const st = vm.evaluate(prog); const verified = vm.verify(prog);
  return {accepted: verified === true, error: verified === true ? null : String(verified), opCost: st.metrics.operationCost, stack: st.stack};
}
export function bare(code, pushes, mode = 'consensus') { const st = VMS[mode].evaluate(programOf(Uint8Array.from(code), encodeUnlocking(pushes))); return {error: st.error, opCost: st.metrics.operationCost, stack: st.stack, ip: st.ip}; }
