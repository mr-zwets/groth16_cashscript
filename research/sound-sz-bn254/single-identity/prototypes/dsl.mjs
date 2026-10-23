// dsl.mjs: straight-line BCH kernel compiler with an exact bch-spec op-cost simulator and a
// local-search instruction scheduler, plus a libauth bch-spec runner that executes the emitted
// code and checks every output against a BigInt simulation.
//
// Model of a kernel as it runs inside the verifier loop:
//   stack = [ ...env (read-only, never consumed: p, per-proof constants, tables) , ...inputs (mutable state) ]
//   after the kernel: [ ...env unchanged , ...outputs ]
// So the measured cost includes fetching env constants from their real depths (PICK) and leaves the
// stack in the shape the next loop iteration expects. MOD always reduces by env item 'p'.
//
// bch-spec cost (libauth 3.1.0-next.8, measureOperationCost): 100 per instruction + pushed bytes
// + arithmetic cost; MUL/MOD add lenA*lenB + 2*len(result); ADD/SUB add 2*len(result);
// ROLL pushes len+depth; SWAP/ROT push 0; PICK/DUP/OVER push len.
import {createVirtualMachineBchSpec, bigIntToVmNumber, encodeDataPush} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
export const P = bn254.fields.Fp.ORDER;
export const OP = {ADD: 0x93, SUB: 0x94, MUL: 0x95, MOD: 0x97, DUP: 0x76, OVER: 0x78, PICK: 0x79, ROLL: 0x7a, SWAP: 0x7c,
  ROT: 0x7b, DROP: 0x75, NIP: 0x77, NOP: 0x61, TRUE: 0x51, NUMEQUALVERIFY: 0x9d, NEGATE: 0x8f, VERIFY: 0x69, NUMEQUAL: 0x9c,
  TOALT: 0x6b, FROMALT: 0x6c, SPLIT: 0x7f, BIN2NUM: 0x81, NUM2BIN: 0x80, CAT: 0x7e, SHA256: 0xa8, SIZE: 0x82, LESSTHAN: 0x9f,
  EQUALVERIFY: 0x88, EQUAL: 0x87, NOT: 0x91, ZERONOTEQUAL: 0x92, TWODROP: 0x6d, TWODUP: 0x6e, IF: 0x63, ELSE: 0x67, ENDIF: 0x68,
  NOTIF: 0x64, WITHIN: 0xa5, GREATERTHANOREQUAL: 0xa2, REVERSEBYTES: 0xbc, AND: 0x84, DEFINE: 0x89, INVOKE: 0x8a};
export const pushNum = (n) => [...encodeDataPush(bigIntToVmNumber(BigInt(n)))];
export const numLen = (n) => bigIntToVmNumber(BigInt(n)).length;
const pushCost = (n) => 100 + numLen(n); // OP_n / short push: 100 + pushed bytes
const COMM = new Set(['add', 'mul']);

export class Kernel {
  constructor(envNames, inputNames) {
    this.nodes = [];
    this.env = envNames.map((n) => this.node('env', [], {name: n}));
    this.inputs = inputNames.map((n) => this.node('in', [], {name: n}));
    this.envOf = Object.fromEntries(envNames.map((n, i) => [n, this.env[i]]));
    this.inOf = Object.fromEntries(inputNames.map((n, i) => [n, this.inputs[i]]));
  }
  node(op, args, extra = {}) { const id = this.nodes.length; this.nodes.push({id, op, args, ...extra}); return id; }
  E(name) { const x = this.envOf[name]; if (x === undefined) throw new Error('no env ' + name); return x; }
  I(name) { const x = this.inOf[name]; if (x === undefined) throw new Error('no input ' + name); return x; }
  c(v) { return this.node('const', [], {value: BigInt(v)}); }
  add(a, b) { return this.node('add', [a, b]); }
  sub(a, b) { return this.node('sub', [a, b]); }
  mul(a, b) { return this.node('mul', [a, b]); }
  mod(a) { return this.node('mod', [a]); }
  neg(a) { return this.node('neg', [a]); }
  mm(a, b) { return this.mod(this.mul(a, b)); }
  small(a, k) { return k === 1 ? a : k === 2 ? this.add(a, a) : this.mul(a, this.c(k)); }
  sum(...xs) { return xs.reduce((a, b) => this.add(a, b)); }
  output(ids) { this.outs = ids; return this; }

  simulate(envVals, inVals) {
    const v = [];
    for (const n of this.nodes) {
      const a = n.args.map((x) => v[x]);
      v[n.id] = n.op === 'env' ? BigInt(envVals[this.env.indexOf(n.id)]) : n.op === 'in' ? BigInt(inVals[this.inputs.indexOf(n.id)])
        : n.op === 'const' ? n.value : n.op === 'add' ? a[0] + a[1] : n.op === 'sub' ? a[0] - a[1] : n.op === 'mul' ? a[0] * a[1]
        : n.op === 'neg' ? -a[0] : a[0] % P; // mod: BCH semantics (sign of dividend)
    }
    return v;
  }
  liveOrder() {
    const live = new Set(); const st = [...this.outs];
    while (st.length) { const x = st.pop(); if (live.has(x)) continue; live.add(x); st.push(...this.nodes[x].args); }
    const pId = this.envOf.p; if (pId !== undefined) live.add(pId);
    return this.nodes.filter((n) => live.has(n.id) && n.op !== 'env' && n.op !== 'in').map((n) => n.id);
  }

  // Emit (and cost) a given order. lens[id] = byte length of node value. Returns {code, cost}.
  emitOrder(order, lens, wantCode = true) {
    const N = this.nodes, uses = new Map(); const bump = (x) => uses.set(x, (uses.get(x) ?? 0) + 1);
    order.forEach((id) => N[id].args.forEach(bump)); this.outs.forEach(bump);
    const isEnv = (id) => N[id].op === 'env';
    const pId = this.envOf.p;
    const code = []; let cost = 0; const st = [...this.env, ...this.inputs];
    const bd = this.breakdown = {copy: 0, move: 0, mul: 0, mod: 0, addsub: 0, const: 0, nMul: 0, nMod: 0, nAdd: 0, nCopy: 0, nMove: 0};
    const em = (...b) => { if (wantCode) code.push(...b); };
    const depthOf = (id, skip = 0) => { for (let i = st.length - 1 - skip; i >= 0; i--) if (st[i] === id) return st.length - 1 - i; return -1; };
    // fetch cost (no mutation) for bringing id to top; move if last use and not env
    const fetchCost = (id, d, move) => {
      const L = lens[id];
      if (move) return d === 0 ? 0 : d <= 2 ? 100 : pushCost(d) + 100 + L + d;
      return d <= 1 ? 100 + L : pushCost(d) + 100 + L;
    };
    const fetch = (id) => {
      const last = !isEnv(id) && uses.get(id) === 1; uses.set(id, uses.get(id) - 1);
      const d = depthOf(id); if (d < 0) throw new Error('missing ' + id);
      const fc = fetchCost(id, d, last); cost += fc; if (last) { bd.move += fc; if (d) bd.nMove++; } else { bd.copy += fc; bd.nCopy++; }
      if (last) {
        if (d === 0) return; if (d === 1) em(OP.SWAP); else if (d === 2) em(OP.ROT); else em(...pushNum(d), OP.ROLL);
        st.splice(st.length - 1 - d, 1); st.push(id);
      } else {
        if (d === 0) em(OP.DUP); else if (d === 1) em(OP.OVER); else em(...pushNum(d), OP.PICK);
        st.push(id);
      }
    };
    // drop unused inputs
    for (const id of this.inputs) if (!uses.get(id)) { uses.set(id, 1); fetch(id); em(OP.DROP); cost += 100; st.pop(); }
    for (const id of order) {
      const n = N[id];
      if (n.op === 'const') { em(...pushNum(n.value)); cost += 100 + lens[id]; bd.const += 100 + lens[id]; st.push(id); continue; }
      if (n.op === 'mod' || n.op === 'neg') {
        fetch(n.args[0]);
        if (n.op === 'mod') { fetch(pId); em(OP.MOD); const mc = 100 + lens[n.args[0]] * lens[pId] + 2 * lens[id]; cost += mc; bd.mod += mc; bd.nMod++; st.pop(); }
        else { em(OP.NEGATE); cost += 100 + 2 * lens[id]; }
        st.pop(); st.push(id); continue;
      }
      let [a, b] = n.args;
      if (a === b) { // x op x
        if (!isEnv(a) && uses.get(a) === 2) { uses.set(a, 1); fetch(a); } else { fetch(a); uses.set(a, uses.get(a) - 1); }
        em(OP.DUP); cost += 100 + lens[a]; st.push(a);
      } else {
        if (COMM.has(n.op)) { // pick the cheaper argument order
          const c1 = this._pairCost(a, b, st, uses, lens, isEnv, fetchCost), c2 = this._pairCost(b, a, st, uses, lens, isEnv, fetchCost);
          if (c2 < c1) [a, b] = [b, a];
        }
        fetch(a); fetch(b);
      }
      const la = lens[a], lb = lens[b];
      em({add: OP.ADD, sub: OP.SUB, mul: OP.MUL}[n.op]);
      const ac = 100 + 2 * lens[id] + (n.op === 'mul' ? la * lb : 0); cost += ac;
      if (n.op === 'mul') { bd.mul += ac; bd.nMul++; } else { bd.addsub += ac; bd.nAdd++; }
      st.pop(); st.pop(); st.push(id);
    }
    for (const o of this.outs) fetch(o);
    const extra = st.length - this.env.length - this.outs.length;
    if (extra) throw new Error('leftover stack items ' + extra + ' ' + st.slice(this.env.length).map((x) => N[x].op).join(','));
    return {code: Uint8Array.from(code), cost};
  }
  _pairCost(a, b, st0, uses0, lens, isEnv, fetchCost) {
    const st = st0.slice(); let cost = 0;
    for (const [k, id] of [a, b].entries()) {
      const last = !isEnv(id) && uses0.get(id) === 1 && !(k === 1 && a === id);
      let d = -1; for (let i = st.length - 1; i >= 0; i--) if (st[i] === id) { d = st.length - 1 - i; break; }
      cost += fetchCost(id, d, last);
      if (last) st.splice(st.length - 1 - d, 1); st.push(id);
    }
    return cost;
  }

  // Local search over topological orders, minimizing simulated op-cost.
  optimize(envVals, inVals, iters = 20000, seed = 1) {
    const vals = this.simulate(envVals, inVals); const lens = vals.map((x) => numLen(x));
    const pos = (ord) => { const m = new Map(); ord.forEach((id, i) => m.set(id, i)); return m; };
    let order = this.liveOrder(); let best = this.emitOrder(order, lens, false).cost;
    const succ = new Map(); for (const id of order) for (const a of this.nodes[id].args) { if (!succ.has(a)) succ.set(a, []); succ.get(a).push(id); }
    let s = seed; const rnd = (n) => { s = (s * 1103515245 + 12345) % 2147483648; return s % n; };
    const start = best;
    for (let it = 0; it < iters; it++) {
      const i = rnd(order.length), id = order[i], pm = pos(order);
      let lo = 0, hi = order.length - 1;
      for (const a of this.nodes[id].args) if (pm.has(a)) lo = Math.max(lo, pm.get(a) + 1);
      for (const sId of succ.get(id) ?? []) if (pm.has(sId)) hi = Math.min(hi, pm.get(sId) - 1);
      if (hi <= lo) continue;
      const j = lo + rnd(hi - lo + 1); if (j === i) continue;
      const cand = order.slice(); cand.splice(i, 1); cand.splice(j > i ? j : j, 0, id);
      // validate deps (cheap check)
      const c = this.emitOrder(cand, lens, false).cost;
      if (c <= best) { best = c; order = cand; }
    }
    this.bestOrder = order; this.lens = lens;
    return {start, best};
  }
  emit(envVals, inVals) {
    const vals = this.simulate(envVals, inVals); const lens = vals.map((x) => numLen(x));
    return this.emitOrder(this.bestOrder ?? this.liveOrder(), lens, true);
  }
}

const vms = {standard: createVirtualMachineBchSpec(true), consensus: createVirtualMachineBchSpec(false)};
// Runs `body` with stack = env ++ inputs, checks top items == expect (mod p unless exact), returns exact op-cost
// of the body (between NOP markers, minus the marker itself).
export function runBody(body, stackVals, expect, {exact = false, mode = 'standard', remain = 0} = {}) {
  const tail = [];
  for (let i = expect.length - 1; i >= 0; i--) {
    if (exact) tail.push(...pushNum(expect[i]), OP.NUMEQUALVERIFY);
    else tail.push(...pushNum(expect[i]), OP.SUB, ...pushNum(P), OP.MOD, ...pushNum(0n), OP.NUMEQUALVERIFY);
  }
  for (let i = 0; i < remain; i++) tail.push(OP.DROP);
  tail.push(OP.TRUE);
  const locking = Uint8Array.from([OP.NOP, ...body, OP.NOP, ...tail]);
  const unlocking = Uint8Array.from(stackVals.flatMap((x) => [...encodeDataPush(x instanceof Uint8Array ? x : bigIntToVmNumber(BigInt(x)))]));
  const program = {inputIndex: 0, sourceOutputs: [{lockingBytecode: locking, valueSatoshis: 1000n}],
    transaction: {version: 2, locktime: 0, inputs: [{outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: unlocking}],
      outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]}};
  const vm = vms[mode];
  const trace = vm.debug(program);
  const final = trace[trace.length - 1];
  if (final.error) throw new Error('VM error: ' + final.error);
  const marks = [];
  for (const s of trace) { const ins = s.instructions?.[s.ip - 1]; if (ins && ins.opcode === OP.NOP && s.instructions[0]?.opcode === OP.NOP && s.instructions.length > 2) marks.push(s.metrics.operationCost); }
  if (marks.length < 2) throw new Error('markers not found ' + marks.length);
  return marks[marks.length - 1] - marks[0] - 100;
}

// Measure a kernel: optimize the schedule, emit, run in the VM with env ++ inputs, check outputs.
export function measureKernel(k, envVals, inVals, {iters = 20000, label = ''} = {}) {
  const naive = k.emitOrder(k.liveOrder(), k.simulate(envVals, inVals).map((x) => numLen(x)), false).cost;
  const o = iters ? k.optimize(envVals, inVals, iters) : {best: naive};
  const {code, cost} = k.emit(envVals, inVals);
  const vals = k.simulate(envVals, inVals);
  const expect = k.outs.map((o2) => vals[o2]);
  const vmCost = runBody(code, [...envVals, ...inVals], expect, {remain: envVals.length});
  return {label, naiveSim: naive, simCost: cost, opCost: vmCost, bytes: code.length, outputs: expect, breakdown: k.breakdown};
}
