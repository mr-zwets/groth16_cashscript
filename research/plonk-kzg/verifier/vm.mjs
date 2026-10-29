// libauth runners for the three regimes (consensus and standard mode):
//   spec  : the proposed bch-spec VM (100,000-byte scripts, budget (10,000 + unlocking) * 800);
//   txv5  : BCH 2026 with the script and stack-item caps raised to 100,000 B and the density base kept at 41,
//           budget (41 + unlocking) * 800 (zk-verifier-bench src/harness/vm.ts consensusTxv5);
//   bch2026: today's rules (10,000-byte unlocking standard, 10,000-byte items, base 41).
import {createVirtualMachineBchSpec, createVirtualMachineBch2026, createVirtualMachine, createInstructionSetBch2026, ConsensusBch2025,
  encodeDataPush, hash256, sha256, ripemd160, secp256k1, sha1, vmNumberToBigInt} from '@bitauth/libauth';

const consensusBch2026 = {...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: 1000,
  maximumStandardLockingBytecodeLength: 201, maximumStandardUnlockingBytecodeLength: 10_000, maximumTokenCommitmentLength: 128};
const consensusTxv5 = {...consensusBch2026, maximumBytecodeLength: 100_000, maximumStackItemLength: 100_000, maximumStandardUnlockingBytecodeLength: 100_000};
const txv5 = (standard) => createVirtualMachine(createInstructionSetBch2026(standard, {consensus: consensusTxv5, ripemd160, secp256k1, sha1, sha256}));
export const VMS = {
  spec: {consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true), base: 10_000},
  txv5: {consensus: txv5(false), standard: txv5(true), base: 41},
  free: {consensus: createVirtualMachine(createInstructionSetBch2026(false, {consensus: {...consensusTxv5, densityControlBaseLength: 1e9}, ripemd160, secp256k1, sha1, sha256})),
    standard: createVirtualMachine(createInstructionSetBch2026(true, {consensus: {...consensusTxv5, densityControlBaseLength: 1e9}, ripemd160, secp256k1, sha1, sha256})), base: 1e9},
  bch2026: {consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true), base: 41},
};
export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const encodeUnlocking = (pushes) => Uint8Array.from(pushes.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));
const program = (inputs, outputs, inputIndex) => ({inputIndex, sourceOutputs: inputs.map((i) => ({lockingBytecode: i.locking, valueSatoshis: 10_000n})),
  transaction: {version: 2, locktime: 0, inputs: inputs.map((i, k) => ({outpointIndex: k, outpointTransactionHash: new Uint8Array(32).fill(k + 1), sequenceNumber: 0, unlockingBytecode: i.unlocking})),
    outputs: outputs ?? [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}});
// spend every input of a transaction; returns per-input results
export function spendTx(regime, mode, inputs, outputs) {
  const vm = VMS[regime][mode];
  return inputs.map((inp, k) => { const prog = program(inputs, outputs, k); const st = vm.evaluate(prog); const ok = vm.verify({sourceOutputs: prog.sourceOutputs, transaction: prog.transaction});
    return {accepted: ok === true && !st.error, error: st.error ?? (ok === true ? null : String(ok)), opCost: st.metrics.operationCost, budget: (VMS[regime].base + inp.unlocking.length) * 800, unlockingLen: inp.unlocking.length, metrics: st.metrics}; });
}
export const spend = (regime, mode, locking, unlocking) => spendTx(regime, mode, [{locking, unlocking}])[0];
// bare evaluation of `code` after the pushes (debugging): returns the final state
export function bare(regime, code, pushes, mode = 'consensus') { const vm = VMS[regime][mode]; const st = vm.evaluate(program([{locking: Uint8Array.from(code), unlocking: encodeUnlocking(pushes)}], null, 0)); return {error: st.error, opCost: st.metrics.operationCost, stack: st.stack, alt: st.alternateStack, ip: st.ip}; }
export const num = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false});
