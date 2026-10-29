// AIR descriptions for the CashVM verifier, one per AIR the prover produced (prover/src/airs.rs). Each is the
// constraint list of Plonky3's eval() in order, as expression trees, so that the JS model and the script generator
// derive the AIR-specific code from the same description.
//
// Expression nodes: ['loc', i] | ['nxt', i] | ['pub', i] (base) | ['per', i] (periodic column i at zeta) |
//   ['k', c] (base constant) | ['let', name] | ['add'|'sub'|'mul', a, b]
// Constraint: [selector, expr] with selector 'first' | 'last' | 'trans' | null.
import {createHash} from 'node:crypto';

const P = 0xffffffff00000001n;
const L = (i) => ['loc', i], N = (i) => ['nxt', i], PU = (i) => ['pub', i];
const add = (a, b) => ['add', a, b], sub = (a, b) => ['sub', a, b], mul = (a, b) => ['mul', a, b];

export function mimcRoundConstants() {
  return Array.from({length: 8}, (_, j) => {
    const d = createHash('sha256').update(Buffer.concat([Buffer.from('verifier.cash/pq-hash/rc'), Buffer.from([j])])).digest();
    let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(d[i]); return v % P;
  });
}

export const AIRDEF = {
  fib: {
    width: 2, numPublic: 3, periodic: [], lets: {},
    constraints: [
      ['first', sub(L(0), PU(0))],
      ['first', sub(L(1), PU(1))],
      ['trans', sub(L(1), N(0))],
      ['trans', sub(add(L(0), L(1)), N(1))],
      ['last', sub(L(1), PU(2))],
    ],
  },
  mimc: {
    width: 3, numPublic: 2, periodic: [mimcRoundConstants()],
    lets: {s: add(L(0), ['per', 0])},
    constraints: [
      [null, sub(L(1), mul(mul(['let', 's'], ['let', 's']), ['let', 's']))],
      [null, sub(L(2), mul(L(1), L(1)))],
      ['trans', sub(N(0), mul(L(2), ['let', 's']))],
      ['first', sub(L(0), PU(0))],
      ['last', sub(L(0), PU(1))],
    ],
  },
};

// evaluate an expression with an extension-field object F (verify.mjs extField) and a context
export function evalExpr(F, e, c, lets = {}) {
  switch (e[0]) {
    case 'loc': return c.loc[e[1]];
    case 'nxt': return c.nxt[e[1]];
    case 'pub': return F.lift(c.pis[e[1]]);
    case 'per': return c.per[e[1]];
    case 'k': return F.lift(BigInt(e[1]));
    case 'let': return lets[e[1]];
    case 'add': return F.add(evalExpr(F, e[1], c, lets), evalExpr(F, e[2], c, lets));
    case 'sub': return F.sub(evalExpr(F, e[1], c, lets), evalExpr(F, e[2], c, lets));
    case 'mul': return F.mul(evalExpr(F, e[1], c, lets), evalExpr(F, e[2], c, lets));
    default: throw new Error('bad expr ' + e[0]);
  }
}
