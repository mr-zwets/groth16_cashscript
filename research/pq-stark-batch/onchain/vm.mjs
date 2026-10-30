// libauth 3.1.0-next.8 virtual machines (copied from Track 5 research/pq-stark/verifier/vm.mjs; regimes renamed):
//   bch (real BCH 2026 = today's relay rules, standard/consensus), loose (BCH 2026 with every ceiling lifted: a reject
//   is a failed check), spec (libauth BCH_SPEC: density base 10,000, 100,000 B scripts), r100 (BCH 2026 with the
//   per-input unlocking, bytecode and stack-item limits raised to 100,000 B; density base 41 and the 100,000 B
//   transaction limit unchanged: the "one 100 KB input" regime, i.e. relay/standardness limits raised) and r100u
//   (r100 with the density budget lifted: measures the op-cost an input needs).
// An optional OP_NOP counter locates a failure (opts.markers in the generator).
import {
  ConsensusBch2025, createInstructionSetBch2026, createInstructionSetBchSpec, createVirtualMachine, createVirtualMachineBch2026,
  createVirtualMachineBchSpec, createTestAuthenticationProgramBch, encodeDataPush, hash256, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const HUGE = Number.MAX_SAFE_INTEGER;
const crypto = {ripemd160, secp256k1, sha1, sha256};
export const consensusBch2026 = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: 1000,
  maximumStandardLockingBytecodeLength: 201, maximumStandardUnlockingBytecodeLength: 10_000, maximumTokenCommitmentLength: 128,
};
const loose = {
  ...consensusBch2026, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
  hashDigestIterationsPerByteStandard: HUGE, hashDigestIterationsPerByteNonstandard: HUGE,
};
export const consensusR100 = {...consensusBch2026, maximumBytecodeLength: 100_000, maximumStackItemLength: 100_000, maximumStandardUnlockingBytecodeLength: 100_000};

export let nopCount = 0;
export let snaps = [];
function withNop(is) {
  const nop = is.operations[0x61];
  return {...is, operations: {...is.operations, [0x61]: (s) => { nopCount++; const m = s.metrics; snaps.push({op: m.operationCost, instr: m.evaluatedInstructionCount, arith: m.arithmeticCost, pushed: m.stackPushedBytes, iters: m.hashDigestIterations, ...(globalThis.KEEPSTACK ? {stack: s.stack.map((x) => Buffer.from(x).toString("hex"))} : {})}); return nop(s); }}};
}
const mk = (standard, consensus) => createVirtualMachine(withNop(createInstructionSetBch2026(standard, {consensus, ...crypto})));
export const VMS = {
  looseStd: mk(true, loose), looseCons: mk(false, loose),
  bchStd: createVirtualMachine(withNop(createInstructionSetBch2026(true))), bchCons: createVirtualMachine(withNop(createInstructionSetBch2026(false))),
  specStd: createVirtualMachine(withNop(createInstructionSetBchSpec(true))), specCons: createVirtualMachine(withNop(createInstructionSetBchSpec(false))),
  r100Std: mk(true, consensusR100), r100Cons: mk(false, consensusR100),
  r100uStd: mk(true, {...consensusR100, densityControlBaseLength: 1_000_000_000}), r100uCons: mk(false, {...consensusR100, densityControlBaseLength: 1_000_000_000}),
};
void createVirtualMachineBch2026; void createVirtualMachineBchSpec;

export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const pushes = (items) => Uint8Array.from(items.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));

// a spending transaction: one input (the verifier) and the given outputs (they fix CTX)
export const FUND = {outpointTransactionHash: Uint8Array.from(Buffer.from('7438'.repeat(16), 'hex')), outpointIndex: 0};
export function spendProgram(locking, unlocking, outputs, value = 100_000n) {
  return {
    inputIndex: 0,
    sourceOutputs: [{lockingBytecode: locking, valueSatoshis: value}],
    transaction: {version: 2, locktime: 0, inputs: [{...FUND, sequenceNumber: 0, unlockingBytecode: unlocking}], outputs},
  };
}
// libauth whole-transaction verification (standardness of every input and output, tx size): true or an error string
export function verifyTx(vmName, program) { return VMS[vmName].verify({sourceOutputs: program.sourceOutputs, transaction: program.transaction}); }

export function evaluate(vmName, locking, unlocking, program) {
  nopCount = 0; snaps = [];
  const prog = program ?? createTestAuthenticationProgramBch({lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n});
  const st = VMS[vmName].evaluate(prog);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
  const m = st.metrics;
  return {accepted, error: st.error, markers: nopCount, opCost: m.operationCost, instr: m.evaluatedInstructionCount,
    arith: m.arithmeticCost, pushed: m.stackPushedBytes, iters: m.hashDigestIterations, snaps, stackTop: st.stack.slice(-6).map((x) => Buffer.from(x).toString('hex').slice(0, 64))};
}
