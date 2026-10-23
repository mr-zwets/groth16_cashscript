// Measurement library v2 for the commit-all kernels (bch-spec VM, libauth).
//  - Kernels are written once against an abstract field-ops interface `k` and either built into
//    SSA (builder()) or evaluated directly on BigInts (evaluator()) for math checks.
//  - compile() turns SSA into straight-line stack code that updates a FRAME in place: the frame
//    is the list of named stack items at entry (bottom..top); items below the first modified slot
//    are only PICKed, never moved. p is either an inline 33-B push or PICKed from frame slot 'P'.
//  - run() evaluates a whole program (OP_DEFINE'd functions + main) in the bch-spec VM, in both
//    consensus and standard mode, and returns op-cost and final stack.
import assert from 'node:assert/strict';
import {createVirtualMachineBchSpec, bigIntToVmNumber, vmNumberToBigInt, encodeDataPush} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
export const P = bn254.fields.Fp.ORDER;
export const R = bn254.fields.Fr.ORDER;
export const mod = (x) => ((x % P) + P) % P;
export const num = (x) => Uint8Array.from(bigIntToVmNumber(BigInt(x)));
export const push = (b) => [...encodeDataPush(b)];
export const pushNum = (n) => { n = BigInt(n); return n === 0n ? [0x00] : n === -1n ? [0x4f] : n >= 1n && n <= 16n ? [0x50 + Number(n)] : push(num(n)); };
export const OP = {MUL: 0x95, ADD: 0x93, SUB: 0x94, MOD: 0x97, DIV: 0x96, PICK: 0x79, ROLL: 0x7a, DROP: 0x75, DUP: 0x76, OVER: 0x78, SWAP: 0x7c,
  ROT: 0x7b, NOT: 0x91, VERIFY: 0x69, BOOLOR: 0x9b, BOOLAND: 0x9a, SPLIT: 0x7f, BIN2NUM: 0x81, NUM2BIN: 0x80, CAT: 0x7e, TRUE: 0x51,
  NEGATE: 0x8f, DEFINE: 0x89, INVOKE: 0x8a, IF: 0x63, NOTIF: 0x64, ELSE: 0x67, ENDIF: 0x68, BEGIN: 0x65, UNTIL: 0x66, TOALT: 0x6b,
  FROMALT: 0x6c, NIP: 0x77, TUCK: 0x7d, SIZE: 0x82, SHA256: 0xa8, EQUAL: 0x87, EQUALVERIFY: 0x88, NUMEQUAL: 0x9c, NUMEQUALVERIFY: 0x9d,
  LESSTHAN: 0x9f, GREATERTHANOREQUAL: 0xa2, WITHIN: 0xa5, TWODROP: 0x6d, TWODUP: 0x6e, ZERONOTEQUAL: 0x92, ONEADD: 0x8b, ONESUB: 0x8c,
  RSHIFTNUM: 0x8e, LSHIFTNUM: 0x8d, AND: 0x84, DEPTH: 0x74, REVERSEBYTES: 0xbc, NUMNOTEQUAL: 0x9e, ABS: 0x90};

// ---------------- abstract field ops ----------------
const COMM = new Set(['mul', 'add']);
export function builder() {
  const prog = []; let ctr = 0;
  const e = (op, args, extra = {}) => { const dst = `t${ctr++}`; prog.push({op, dst, args, ...extra}); return dst; };
  const k = {
    prog,
    mul: (a, b) => e('mul', [a, b]), add: (a, b) => e('add', [a, b]), sub: (a, b) => e('sub', [a, b]), neg: (a) => e('neg', [a]),
    mod: (a) => e('mod', [a]), mulc: (a, c) => e('mulc', [a], {k: BigInt(c)}), konst: (c) => e('const', [], {k: BigInt(c)}),
    eqz: (a) => { prog.push({op: 'eqz', dst: null, args: [a]}); }, nz2: (a, b) => { prog.push({op: 'nz2', dst: null, args: [a, b]}); },
  };
  return k;
}
export function evaluator() { // same interface over BigInts (no reduction semantics needed beyond mod)
  return {
    mul: (a, b) => a * b, add: (a, b) => a + b, sub: (a, b) => a - b, neg: (a) => -a, mod: (a) => a % P, mulc: (a, c) => a * BigInt(c),
    konst: (c) => BigInt(c), eqz: (a) => { if (mod(a) !== 0n) throw new Error('eqz failed'); }, nz2: (a, b) => { if (mod(a) === 0n && mod(b) === 0n) throw new Error('nz2 failed'); },
  };
}

// ---------------- compiler: SSA -> in-place frame update ----------------
export function compile({frame, prog, out, pMode = 'inline'}) {
  let kc = 0; while (kc < frame.length && kc < out.length && frame[kc] === out[kc]) kc++;
  if (pMode === 'pick') assert(frame.indexOf('P') >= 0 && frame.indexOf('P') < kc, 'P must be a kept frame slot');
  const keep = new Set(frame.slice(0, kc));
  const last = new Map();
  prog.forEach((ins, i) => ins.args.forEach((a) => last.set(a, i)));
  out.slice(kc).forEach((o) => last.set(o, Infinity));
  keep.forEach((n) => last.set(n, Infinity));
  const stack = [...frame];
  const code = [];
  const depthOf = (n) => { const i = stack.lastIndexOf(n); assert(i >= 0, 'missing ' + n); return stack.length - 1 - i; };
  const pick = (d) => { if (d === 0) code.push(OP.DUP); else if (d === 1) code.push(OP.OVER); else code.push(...pushNum(d), OP.PICK); };
  const roll = (d) => { if (d === 0) return; if (d === 1) code.push(OP.SWAP); else if (d === 2) code.push(OP.ROT); else code.push(...pushNum(d), OP.ROLL); };
  // drop region items never used and not output
  for (const n of frame.slice(kc)) if (!last.has(n)) { const d = depthOf(n); roll(d); code.push(OP.DROP); stack.splice(stack.length - 1 - d, 1); }
  const fetch = (name, i, consumedLater) => {
    const d = depthOf(name);
    const isLast = last.get(name) === i && !consumedLater;
    if (isLast) { roll(d); stack.splice(stack.length - 1 - d, 1); stack.push(name); } else { pick(d); stack.push(name); }
  };
  const pushP = () => { if (pMode === 'pick') pick(depthOf('P')); else code.push(...push(num(P))); };
  prog.forEach((ins, i) => {
    const {op, dst} = ins;
    if (op === 'const') { code.push(...pushNum(ins.k)); stack.push(dst); return; }
    let args = ins.args;
    if (args.length === 2 && args[0] === args[1]) { fetch(args[0], i, false); code.push(OP.DUP); stack.push(args[0]); }
    else {
      // commutative: if the 2nd arg sits on top and dies here, fetch it first (saves a ROLL/PICK)
      if (COMM.has(op) && depthOf(args[1]) === 0 && last.get(args[1]) === i) args = [args[1], args[0]];
      args.forEach((a, j) => fetch(a, i, args.slice(j + 1).includes(a)));
    }
    if (op === 'mulc') { const c = ins.k; if (c === -1n) code.push(OP.NEGATE); else code.push(...pushNum(c), OP.MUL); stack.pop(); stack.push(dst); return; }
    if (op === 'neg') { code.push(OP.NEGATE); stack.pop(); stack.push(dst); return; }
    if (op === 'mod') { pushP(); code.push(OP.MOD); stack.pop(); stack.push(dst); return; }
    if (op === 'eqz') { pushP(); code.push(OP.MOD, OP.NOT, OP.VERIFY); stack.pop(); return; } // sign-safe: (a mod p) == 0
    if (op === 'nz2') { pushP(); code.push(OP.MOD, OP.SWAP); stack.pop(); stack.pop(); stack.push('_t'); pushP(); code.push(OP.MOD, OP.BOOLOR, OP.VERIFY); stack.pop(); return; }
    code.push({mul: OP.MUL, add: OP.ADD, sub: OP.SUB}[op]); stack.pop(); stack.pop(); stack.push(dst);
  });
  // arrange region outputs
  const target = out.slice(kc);
  let rest = stack.slice(kc);
  assert.deepEqual([...rest].sort(), [...target].sort(), 'region mismatch: ' + JSON.stringify({rest, target}));
  let i = 0; while (i < target.length && rest[i] === target[i]) i++;
  for (const t of target.slice(i)) { const d = depthOf(t); roll(d); stack.splice(stack.length - 1 - d, 1); stack.push(t); }
  assert.deepEqual(stack, out);
  return Uint8Array.from(code);
}
export const opCounts = (prog) => { const c = {}; prog.forEach((x) => (c[x.op] = (c[x.op] ?? 0) + 1)); return c; };

// ---------------- VM ----------------
const vms = {consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true)};
export const defineFn = (id, body) => [...push(Uint8Array.from(body)), ...pushNum(id), OP.DEFINE];
export const invoke = (id) => [...pushNum(id), OP.INVOKE];
// pad: size of a dummy unlocking push (raises the per-input budget (10,000 + unlockLen) * 800)
export function run({pushes = [], code, pad = 0}) {
  const pads = []; for (let left = pad; left > 0; left -= 10000) pads.push(...push(new Uint8Array(Math.min(10000, left))));
  const unlocking = Uint8Array.from([...pads, ...pushes.flatMap((b) => push(b))]);
  const lock2 = Uint8Array.from(code); // the pad push stays at the bottom of the stack, untouched
  const transaction = {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
    outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]};
  const sourceOutputs = [{lockingBytecode: lock2, valueSatoshis: 1000n}];
  const o = {unlockLen: unlocking.length};
  for (const [m, vm] of Object.entries(vms)) {
    const st = vm.evaluate({inputIndex: 0, sourceOutputs, transaction});
    o[m] = st.metrics.operationCost; o['err_' + m] = st.error; o.stack = st.stack;
  }
  return o;
}
export const vmNum = (b) => vmNumberToBigInt(b, {requireMinimalEncoding: false, maximumVmNumberByteLength: 10000});
