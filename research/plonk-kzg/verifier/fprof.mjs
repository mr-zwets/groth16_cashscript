// Function-level op-cost profile of a transaction input: steps the libauth VM and attributes the op-cost of every
// instruction to the stack of invoked functions (inclusive cost per function name, and self cost per role).
import {partiallyCloneProgramState, createInstructionSetBch2026, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, vmNumberToBigInt} from '@bitauth/libauth';
const cons = {...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: 1000,
  maximumStandardLockingBytecodeLength: 201, maximumStandardUnlockingBytecodeLength: 100_000, maximumTokenCommitmentLength: 128,
  maximumBytecodeLength: 100_000, maximumStackItemLength: 100_000, densityControlBaseLength: 1e9};
const IS = createInstructionSetBch2026(true, {consensus: cons, ripemd160, secp256k1, sha1, sha256});
const ops = Array.from({length: 256}, (_, i) => IS.operations[i] ?? IS.undefined);
// names: id -> name. Returns {total, incl: {name: op}, error}
export function fprof(inputs, k, names) {
  const prog = {inputIndex: k, sourceOutputs: inputs.map((i) => ({lockingBytecode: i.locking, valueSatoshis: 100_000n})),
    transaction: {version: 2, locktime: 0, inputs: inputs.map((i, j) => ({outpointIndex: j, outpointTransactionHash: new Uint8Array(32).fill(j + 1), sequenceNumber: 0, unlockingBytecode: i.unlocking})), outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}};
  const incl = {}; const shadow = []; const byOp = {}; let errAt = null;
  const fr = (st) => st.controlStack.filter((x) => typeof x === 'object').length;
  const ev = (state0) => { let state = partiallyCloneProgramState(state0); while (IS.continue(state)) {
      while (shadow.length > fr(state)) shadow.pop();
      const op = state.instructions[state.ip].opcode; let id = null;
      if (op === 0x8a) id = String(vmNumberToBigInt(state.stack[state.stack.length - 1], {requireMinimalEncoding: false}));
      const c0 = state.metrics.operationCost, f0 = fr(state);
      state = ops[op](state); state.metrics.evaluatedInstructionCount += 1; state = IS.every(state); state.ip += 1;
      const f1 = fr(state); if (state.error && !errAt) errAt = {frames: shadow.slice(), ip: state.ip, stackTop: state.stack.slice(-6).map((x) => x.length)};
      const d = state.metrics.operationCost - c0; const seen = new Set(); for (const n of shadow) if (!seen.has(n)) { seen.add(n); incl[n] = (incl[n] ?? 0) + d; }
      if (shadow.at(-1) === process.env.OPF) byOp[op] = (byOp[op] ?? 0) + d;
      if (f1 > f0) shadow.push(names[id] ?? 'f' + id);
    } return state; };
  const st = IS.evaluate(prog, {stateEvaluate: ev, stateInitialize: IS.initialize});
  return {total: st.metrics.operationCost, incl, error: st.error, byOp, errAt};
}
