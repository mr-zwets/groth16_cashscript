// Tiny SSA -> BCH stack-code compiler, assembler and bch-spec VM runner used by the measurement
// prototypes. Straight-line programs over named values; the compiler brings each argument to the
// top with DUP/OVER/PICK (still live) or SWAP/ROT/ROLL (last use), emits the op, and finally
// arranges the requested outputs in order on top of the untouched prefix of the region.
// A JS interpreter of the same SSA program (each op carries its semantics `f`) is used to check
// the VM results value-for-value.
import * as libauth from '@bitauth/libauth';
export const L = libauth;
const {encodeDataPush, bigIntToVmNumber, OpcodesBchSpec: O, createTestAuthenticationProgramBch, createVirtualMachineBchSpec} = L;
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const mod = (x) => ((x % P) + P) % P;
export const vmStd = createVirtualMachineBchSpec(true);
export const vmCons = createVirtualMachineBchSpec(false);

// ---------- assembler ----------
// tokens: 'ADD' (opcode without OP_), bigint/number (minimal number push), Uint8Array/Buffer (data push),
// {raw: Uint8Array} (verbatim bytes)
export const asm = (...xs) => {
  const out = [];
  for (const x of xs.flat(Infinity)) {
    if (typeof x === 'string') { const c = O['OP_' + x]; if (c === undefined) throw new Error('bad op ' + x); out.push(c); }
    else if (typeof x === 'bigint' || typeof x === 'number') out.push(...encodeDataPush(bigIntToVmNumber(BigInt(x))));
    else if (x instanceof Uint8Array) out.push(...encodeDataPush(x));
    else if (x && x.raw) out.push(...x.raw);
    else throw new Error('bad token ' + x);
  }
  return Uint8Array.from(out);
};
export const num = (x) => Uint8Array.from(bigIntToVmNumber(BigInt(x)));
export const vmToBig = (b) => L.vmNumberToBigInt(b, {maximumVmNumberByteLength: 100000, requireMinimalEncoding: false});

// ---------- SSA builder ----------
export class SSA {
  constructor(prefix = 't', pv = P) { this.prog = []; this.n = 0; this.prefix = prefix; this.pv = pv; }
  t() { return `_${this.prefix}${this.n++}`; }
  // generic op: code consumes args (in order, last on top) and leaves outs (last on top)
  op(code, f, args, {comm = false, nout = 1} = {}) {
    const outs = Array.from({length: nout}, () => this.t());
    this.prog.push({outs, code, args, comm, f});
    return nout === 1 ? outs[0] : outs;
  }
  check(code, f, args) { this.prog.push({outs: [], code, args, comm: false, f: (...a) => { const ok = f(...a); if (!ok) throw new Error('check failed: ' + code.join(' ')); return []; }}); }
  add(a, b) { return this.op(['ADD'], (x, y) => x + y, [a, b], {comm: true}); }
  sub(a, b) { return this.op(['SUB'], (x, y) => x - y, [a, b]); }
  mul(a, b) { return this.op(['MUL'], (x, y) => x * y, [a, b], {comm: true}); }
  neg(a) { return this.op(['NEGATE'], (x) => -x, [a]); }
  md(a) { return this.op(['MOD'], (x, p) => x % p, [a, this.pv]); }
  mulm(a, b) { return this.md(this.mul(a, b)); }
  zeroModP(a) { this.check(['MOD', 'NOT', 'VERIFY'], (x, p) => x % p === 0n, [a, this.pv]); }
  nonzero2(a) { const n0 = this.md(a[0]), n1 = this.md(a[1]); this.check(['BOOLOR', 'VERIFY'], (x, y) => x !== 0n || y !== 0n, [n0, n1]); }
  range(a, lo = 0n) { this.check(['WITHIN', 'VERIFY'], (x, l, p) => x >= l && x < p, [a, lo, this.pv]); return a; }
  // Fp2 helpers over pairs [a0, a1], u^2 = -1. `r` = reduce the result.
  f2add(a, b) { return [this.add(a[0], b[0]), this.add(a[1], b[1])]; }
  f2sub(a, b) { return [this.sub(a[0], b[0]), this.sub(a[1], b[1])]; }
  f2red(a) { return [this.md(a[0]), this.md(a[1])]; }
  f2mul(a, b, r = true, kara = false) {
    let c0, c1;
    if (kara) {
      const t0 = this.mul(a[0], b[0]), t1 = this.mul(a[1], b[1]);
      const m = this.mul(this.add(a[0], a[1]), this.add(b[0], b[1]));
      c0 = this.sub(t0, t1); c1 = this.sub(this.sub(m, t0), t1);
    } else {
      c0 = this.sub(this.mul(a[0], b[0]), this.mul(a[1], b[1]));
      c1 = this.add(this.mul(a[0], b[1]), this.mul(a[1], b[0]));
    }
    return r ? this.f2red([c0, c1]) : [c0, c1];
  }
  f2sqr(a, r = true) {
    const c0 = this.mul(this.add(a[0], a[1]), this.sub(a[0], a[1]));
    const c1 = this.mul(this.add(a[0], a[0]), a[1]);
    return r ? this.f2red([c0, c1]) : [c0, c1];
  }
  f2scale(a, k) { return [this.mul(a[0], k), this.mul(a[1], k)]; } // k small literal or scalar name
}

// ---------- compiler ----------
const pushDepth = (d) => [BigInt(d)];
export function compile({inputs, prog, outputs}) {
  const st = [...inputs];
  const remaining = new Map();
  const inc = (n) => remaining.set(n, (remaining.get(n) ?? 0) + 1);
  for (const ins of prog) for (const a of ins.args) if (typeof a === 'string') inc(a);
  for (const o of outputs) inc(o);
  const code = [];
  const idx = (n) => { const i = st.indexOf(n); if (i < 0) throw new Error('not on stack: ' + n); return i; };
  const dropAt = (i) => { const d = st.length - 1 - i; if (d === 0) code.push('DROP'); else if (d === 1) code.push('NIP'); else code.push(...pushDepth(d), 'ROLL', 'DROP'); st.splice(i, 1); };
  // drop unused inputs
  for (const n of [...st]) if (!remaining.get(n)) dropAt(idx(n));
  const bringCost = (n, consume, stk) => {
    if (typeof n !== 'string') return 1;
    const d = stk.length - 1 - stk.indexOf(n);
    if (consume) return d === 0 ? 0 : d <= 2 ? 1 : 2;
    return d <= 1 ? 1 : 2;
  };
  const bring = (n, consume) => {
    if (typeof n !== 'string') { code.push(n); st.push(null); return; }
    const i = idx(n), d = st.length - 1 - i;
    if (consume) {
      if (d === 1) code.push('SWAP'); else if (d === 2) code.push('ROT'); else if (d > 2) code.push(...pushDepth(d), 'ROLL');
      st.splice(i, 1); st.push(n + '#');
    } else {
      if (d === 0) code.push('DUP'); else if (d === 1) code.push('OVER'); else code.push(...pushDepth(d), 'PICK');
      st.push(n + '#');
    }
  };
  for (const ins of prog) {
    let args = ins.args;
    const plan = (order) => {
      // simulate to count instructions
      const s = [...st]; const rem = new Map(remaining); let c = 0;
      for (const a of order) {
        if (typeof a !== 'string') { c += 1; s.push(null); continue; }
        const r = rem.get(a) - 1; rem.set(a, r);
        const consume = r === 0;
        c += bringCost(a, consume, s);
        if (consume) s.splice(s.indexOf(a), 1);
        s.push(a + '#');
      }
      return c;
    };
    if (ins.comm && args.length === 2 && plan([args[1], args[0]]) < plan(args)) args = [args[1], args[0]];
    for (const a of args) {
      if (typeof a === 'string') { const r = remaining.get(a) - 1; remaining.set(a, r); bring(a, r === 0); }
      else bring(a, false);
    }
    code.push(...ins.code);
    st.splice(st.length - args.length, args.length);
    for (const o of ins.outs) st.push(o);
    for (const o of ins.outs) if (!remaining.get(o)) dropAt(idx(o));
  }
  // arrange outputs: keep the longest in-place prefix, roll the rest to the top in order
  const base = st.length - outputs.length;
  if (base < 0 || new Set(outputs).size !== outputs.length) throw new Error('bad outputs');
  const extra = st.filter((n) => !outputs.includes(n));
  if (extra.length) throw new Error('dead values left on stack: ' + extra.join(','));
  let k = 0; while (k < outputs.length && st[k] === outputs[k]) k++;
  for (let i = k; i < outputs.length; i++) {
    const j = idx(outputs[i]), d = st.length - 1 - j;
    if (d === 1) code.push('SWAP'); else if (d === 2) code.push('ROT'); else if (d > 2) code.push(...pushDepth(d), 'ROLL');
    st.splice(j, 1); st.push(outputs[i]);
  }
  return code;
}

// interpreter for checking: env maps input names -> values
export function interpret(prog, env) {
  const e = new Map(Object.entries(env));
  for (const ins of prog) {
    const vals = ins.args.map((a) => (typeof a === 'string' ? (() => { if (!e.has(a)) throw new Error('undef ' + a); return e.get(a); })() : BigInt(a)));
    let r = ins.f(...vals);
    if (!Array.isArray(r)) r = [r];
    ins.outs.forEach((o, i) => e.set(o, r[i]));
  }
  return e;
}

// ---------- VM runner ----------
export const PAD = 60000;
export function run(unlockingPushes, lockingTokens, {vm = vmStd, pad = PAD} = {}) {
  const unl = Uint8Array.from([...encodeDataPush(new Uint8Array(pad)), ...unlockingPushes.flatMap((x) => [...(x instanceof Uint8Array ? encodeDataPush(x) : encodeDataPush(num(x)))])]);
  const lock = lockingTokens instanceof Uint8Array ? lockingTokens : asm(lockingTokens);
  const st = vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode: lock, unlockingBytecode: unl, valueSatoshis: 1000n}));
  return {st, cost: st.metrics.operationCost, err: st.error, stack: st.stack, lockLen: lock.length, unlLen: unl.length};
}
SSA.prototype.copy = function (a) { return this.op([], (x) => x, [a]); };
SSA.prototype.lit = function (v) { return this.op([v], () => BigInt(v), []); };
