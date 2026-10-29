// Straight-line program compiler onto a symbolic stack (Stk), extended from the pq-hash kernels' lib/slp.mjs
// (wip/pq-hash-kernels). A program is a list of [name, expr]; name null means the expression leaves nothing
// (a *VERIFY check). Referenced items are copied (PICK) while they have later uses and moved (ROLL) at their last
// use; items in `keep` are never consumed. Constants are pushed literally.
import {Stk, fresh} from './asm.mjs';

export const V = (n) => ({t: 'v', n});
export const K = (c) => ({t: 'c', c: BigInt(c)});
export const op = (o, ...args) => ({t: 'op', o, args});
export const chk = (o, ...args) => ({t: 'op', o, args, nout: 0});
export const add = (a, b) => op('ADD', a, b);
export const sub = (a, b) => op('SUB', a, b);
export const mul = (a, b) => op('MUL', a, b);
export const modp = (a, p) => op('MOD', a, K(p));
export const sum = (...xs) => xs.reduce((a, b) => add(a, b));
// call node: [outNames[], call(id, args)] invokes function `id` with the evaluated args on top (first arg deepest)
export const call = (id, args) => ({t: 'call', id, args});
export const ex = (x) => (typeof x === 'string' ? V(x) : typeof x === 'bigint' || typeof x === 'number' ? K(x) : x);

function countUses(e, uses) {
  if (e.t === 'v') uses.set(e.n, (uses.get(e.n) ?? 0) + 1);
  else if (e.t === 'op' || e.t === 'call') e.args.forEach((x) => countUses(x, uses));
}
const COMM = new Set(['ADD', 'MUL', 'BOOLAND', 'BOOLOR', 'NUMEQUAL', 'MIN', 'MAX', 'NUMEQUALVERIFY', 'EQUALVERIFY', 'EQUAL']);

export function compileSlp(stk, prog, {keep = []} = {}) {
  const uses = new Map();
  for (const [, e] of prog) countUses(e, uses);
  const keepSet = new Set(keep);
  const emitE = (e) => {
    if (e.t === 'v') {
      const left = uses.get(e.n); uses.set(e.n, left - 1);
      if (left > 1 || keepSet.has(e.n)) stk.pick(e.n); else stk.roll(e.n);
      return;
    }
    if (e.t === 'c') { stk.push(e.c); return; }
    const n = e.args.length;
    const outs = e.nout === 0 ? [] : [fresh('x')];
    const dying = (x) => x.t === 'v' && uses.get(x.n) === 1 && !keepSet.has(x.n);
    if (e.args.every(dying) && new Set(e.args.map((x) => x.n)).size === n) {
      const topN = stk.st.slice(-n), names = e.args.map((x) => x.n);
      const inOrder = topN.every((x, i) => x === names[i]);
      const swapped = n === 2 && COMM.has(e.o) && topN[0] === names[1] && topN[1] === names[0];
      if (inOrder || swapped) { names.forEach((x) => uses.set(x, 0)); stk.op(e.o, n, ...outs); return; }
    }
    // commutative binary op whose second argument is a dying item already on top: evaluate the first and apply
    if (n === 2 && COMM.has(e.o) && dying(e.args[1]) && stk.top() === e.args[1].n && !(e.args[0].t === 'v' && e.args[0].n === e.args[1].n)) {
      uses.set(e.args[1].n, 0);
      emitE(e.args[0]);
      stk.op(e.o, 2, ...outs); return;
    }
    e.args.forEach(emitE);
    stk.op(e.o, n, ...outs);
  };
  for (const [name, e] of prog) {
    if (e.t === 'call') {
      const n = e.args.length;
      const dying = (x) => x.t === 'v' && uses.get(x.n) === 1 && !keepSet.has(x.n);
      const names = e.args.map((x) => x.n);
      const inPlace = e.args.every(dying) && new Set(names).size === n && stk.st.slice(-n).every((x, i) => x === names[i]);
      if (inPlace) names.forEach((x) => uses.set(x, 0));
      else {
        // in-place prefix: the first k args are dying names already contiguous and in order, and every item above them
        // is referenced by the remaining args (so evaluating those leaves exactly [prefix | rest] on top)
        let k = 0;
        for (let len = n; len >= 1 && !k; len--) {
          const pre = e.args.slice(0, len);
          if (!pre.every(dying) || new Set(pre.map((x) => x.n)).size !== len) continue;
          const at = stk.st.lastIndexOf(pre[0].n);
          if (at < 0 || !pre.every((x, i) => stk.st[at + i] === x.n)) continue;
          const above = stk.st.slice(at + len);
          const restNames = new Set();
          const collect = (x) => { if (x.t === 'v') restNames.add(x.n); else if (x.args) x.args.forEach(collect); };
          e.args.slice(len).forEach(collect);
          if (above.every((x) => restNames.has(x) && dying({t: 'v', n: x}))) k = len;
        }
        e.args.slice(0, k).forEach((x) => uses.set(x.n, 0));
        e.args.slice(k).forEach(emitE);
        if (k && stk.st.slice(-n, -n + k).some((x, i) => x !== e.args[i].n)) throw new Error('in-place prefix broken');
      }
      stk.raw([e.id, 'INVOKE'], n, name);
      continue;
    }
    emitE(e);
    if (name !== null) stk.st[stk.st.length - 1] = name;
  }
  // leftover uses must be zero (every referenced name consumed or kept)
  return stk;
}

// evaluate a program in JS (BigInt), mirroring CashVM integer semantics (DIV/MOD truncate toward zero)
export function evalSlp(prog, env) {
  const v = new Map(Object.entries(env));
  const ev = (e) => {
    if (e.t === 'v') { if (!v.has(e.n)) throw new Error('unbound ' + e.n); return v.get(e.n); }
    if (e.t === 'c') return e.c;
    const a = e.args.map(ev);
    switch (e.o) {
      case 'ADD': return a[0] + a[1]; case 'SUB': return a[0] - a[1]; case 'MUL': return a[0] * a[1];
      case 'DIV': return a[0] / a[1]; case 'MOD': return a[0] % a[1];
      case 'NUMEQUALVERIFY': if (a[0] !== a[1]) throw new Error('numequalverify'); return undefined;
      default: throw new Error('evalSlp: ' + e.o);
    }
  };
  for (const [n, e] of prog) { const r = ev(e); if (n !== null) v.set(n, r); }
  return v;
}

export {Stk};
