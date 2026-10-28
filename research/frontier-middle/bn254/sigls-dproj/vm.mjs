// libauth bch-spec runners: P2SH32 spend of the redeem (consensus / standard), and bare evaluation for debugging.
// dproj research copy: the design needs ~1.5x the bch-spec op-cost budget (k >= ~1.5), so `consensus` / `standard`
// are the bch-spec VM with ONLY the density budget loosened (densityControlBaseLength 1e9: every other bch-spec
// limit applies, as the bench grades the singletons on a loosened VM). The strict VMs stay available as *Strict.
import {createVirtualMachine, createVirtualMachineBchSpec, createInstructionSetBchSpec, encodeDataPush, hash256, vmNumberToBigInt, ripemd160, secp256k1, sha1, sha256} from '@bitauth/libauth';
import {ConsensusBchSpec} from '../../../../node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/spec/bch-spec-consensus.js';
const loose = (standard) => createVirtualMachine(createInstructionSetBchSpec(standard, {consensus: {...ConsensusBchSpec, densityControlBaseLength: 1_000_000_000}, ripemd160, secp256k1, sha1, sha256}));
export const VMS = {consensus: loose(false), standard: loose(true), consensusStrict: createVirtualMachineBchSpec(false), standardStrict: createVirtualMachineBchSpec(true)};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
export const unlockingFor = (WS, WQ, redeem) => encodeUnlocking([WQ, WS, redeem]);
export const programOf = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
export const budgetOf = (unlocking) => (10000 + unlocking.length) * 800;
export function spend(locking, unlocking, mode = 'consensus') {
  const vm = VMS[mode]; const prog = programOf(locking, unlocking);
  const st = vm.evaluate(prog); const verified = vm.verify(prog);
  return {accepted: verified === true, error: verified === true ? null : String(verified), opCost: st.metrics.operationCost, budget: budgetOf(unlocking), stack: st.stack};
}
// bare: run `code` as the locking with the given pushes; returns the final state (no clean-stack requirement)
export function bare(code, pushes, mode = 'consensus') {
  const vm = VMS[mode]; const st = vm.evaluate(programOf(Uint8Array.from(code), encodeUnlocking(pushes)));
  return {error: st.error, opCost: st.metrics.operationCost, stack: st.stack, ip: st.ip};
}
export const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false});
