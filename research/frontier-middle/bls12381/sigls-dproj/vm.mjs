// libauth bch-spec runners: P2SH32 spend of the redeem (consensus / standard), and bare evaluation for debugging.
import {createVirtualMachine, createInstructionSetBchSpec, ripemd160, secp256k1, sha1, sha256, createVirtualMachineBchSpec, encodeDataPush, hash256, vmNumberToBigInt} from '@bitauth/libauth';
// dproj research variant: the redeem needs a looser op budget than bch-spec gives (about 1.7x). Acceptance runs use
// the bch-spec VM with operationCostBudgetPerByte = 800 * OPK (default OPK = 2; OPK=1 is the stock bch-spec VM).
// Every other bch-spec limit is unchanged. budgetOf() reports the loosened budget.
export const OPK = Number(process.env.OPK ?? 2);
const specVmK = (standard, k) => (k === 1 ? createVirtualMachineBchSpec(standard)
  : createVirtualMachine(createInstructionSetBchSpec(standard, {consensus: {...ConsensusBchSpec, operationCostBudgetPerByte: Math.floor(800 * k)}, ripemd160, secp256k1, sha1, sha256})));
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
export const unlockingFor = (WS, WQ, redeem) => encodeUnlocking([WQ, WS, redeem]);
export const programOf = (locking, unlocking) => ({inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
  transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
export const budgetOf = (unlocking, k = OPK) => Math.floor((10000 + unlocking.length) * Math.floor(800 * k));
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
// diagnostics only (profile.mjs, debugging): the bch-spec VM with a 100x density base, so a spend that exceeds the
// real budget can still be run to completion and profiled. Never used for any acceptance claim.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
const specConsensusPath = createRequire(import.meta.url).resolve('@bitauth/libauth').replace(/index\.js$/, 'lib/vm/instruction-sets/bch/spec/bch-spec-consensus.js');
const {ConsensusBchSpec} = await import(pathToFileURL(specConsensusPath).href);
export const VMS = {consensus: specVmK(false, OPK), standard: specVmK(true, OPK)};
export const VMS_STOCK = {consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true)};
export const VM_UNLIMITED = createVirtualMachine(createInstructionSetBchSpec(true, {consensus: {...ConsensusBchSpec, densityControlBaseLength: 1_000_000}, ripemd160, secp256k1, sha1, sha256}));
