import {createInstructionSetBch2026, createVirtualMachine, ripemd160, secp256k1, sha1, sha256, createTestAuthenticationProgramBch, vmNumberToBigInt} from '@bitauth/libauth';
import {consensusBch2026} from './vm.mjs';
import {loadVector, spendB} from './layout-b.mjs';
const HUGE = Number.MAX_SAFE_INTEGER;
const loose = {...consensusBch2026, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE, hashDigestIterationsPerByteStandard: HUGE, hashDigestIterationsPerByteNonstandard: HUGE};
const base = createInstructionSetBch2026(true, {consensus: loose, ripemd160, secp256k1, sha1, sha256});
const opc = (m) => 100 * m.evaluatedInstructionCount + m.arithmeticCost + m.stackPushedBytes + 192 * m.hashDigestIterations;
const incl = new Map(), excl = new Map(), calls = new Map();
let frames = [];   // [{id, instructions}]
let pendingId = null;
const ops = {};
for (const [k, f] of Object.entries(base.operations)) ops[k] = (s) => {
  if (pendingId !== null && s.instructions !== pendingId.caller) frames.push({id: pendingId.id, instructions: s.instructions});
  pendingId = null;
  while (frames.length && frames[frames.length - 1].instructions !== s.instructions) frames.pop();
  let id = null;
  if (+k === 0x8a) id = Number(vmNumberToBigInt(s.stack[s.stack.length - 1], {requireMinimalEncoding: false}));
  const callerInstr = s.instructions; const b = opc(s.metrics); const r = f(s); const d = opc(r.metrics) - b + 100;
  const seen = new Set();
  for (const fr of frames) if (!seen.has(fr.id)) { seen.add(fr.id); incl.set(fr.id, (incl.get(fr.id) ?? 0) + d); }
  const top = frames.length ? frames[frames.length - 1].id : 'main';
  excl.set(top, (excl.get(top) ?? 0) + d);
  if (id !== null) { calls.set(id, (calls.get(id) ?? 0) + 1); pendingId = {id, caller: callerInstr}; }
  return r; };
const vm = createVirtualMachine({...base, operations: ops});
const {prm, proof} = loadVector(process.argv[2]);
const sp = spendB(prm, proof.subarray(0, 16), proof, JSON.parse(process.argv[3] ?? '{}'));
const st = vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode: sp.locking, unlockingBytecode: sp.unlocking, valueSatoshis: 1000n}));
const names = new Map([...sp.built.fns].map(([n, f]) => [f.id, n]));
console.log('error', st.error, 'total', st.metrics && opc(st.metrics));
console.log('fn         calls   inclusive  excl.  incl/call  bytes');
for (const [id, d] of [...incl].sort((a, b) => b[1] - a[1])) { const n = calls.get(id); console.log((names.get(id) ?? id).toString().padEnd(10), String(n).padStart(6), String(d).padStart(10), String(excl.get(id) ?? 0).padStart(10), String(Math.round(d / n)).padStart(8), String(sp.built.fns.get(names.get(id))?.body.length).padStart(6)); }
console.log('main excl', excl.get('main'));
