// Setup section of commit-all on the bch-spec VM: statement parse (10 unsigned 32-B limbs,
// coordinates < p, n_i < r), curve checks (A, C on y^2 = x^3 + 3; B on y^2 = x^3 + b'), and the
// per-pair line constants for P = -A and P = C (yP, yP*u, xP*z, xP*z*u, 3xP*z, 6xP*z*u).
// Usage: node setup.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bn254} from '@noble/curves/bn254.js';
import {builder, compile, run, mod, P, R, push, pushNum, OP, vmNum} from './lib.mjs';
const F2 = bn254.fields.Fp2;
const fx = JSON.parse(readFileSync(new URL('../../../../chunked/bn254/densless-recovered/public-fixtures.json', import.meta.url)));
const pr = fx.fixtures[0].proof, n = fx.fixtures[0].publicInputs.map(BigInt);
const limbs = [pr.a.x, pr.a.y, pr.b.x.c0, pr.b.x.c1, pr.b.y.c0, pr.b.y.c1, pr.c.x, pr.c.y].map(BigInt);
const leB = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex').reverse();
const stmt = Buffer.concat([...limbs, ...n].map(leB));
const bp = F2.div({c0: 3n, c1: 0n}, {c0: 9n, c1: 1n});
const z = mod(123456789123456789n ** 3n), u = mod(z ** 6n - 9n);
// parse: [stmt] -> 10 numbers (A.x .. n1), each < p (coords) or < r (inputs)
const code = [...push(Uint8Array.from(pushNum(P).slice(1)))]; // P on stack first
code.push(OP.SWAP);
for (let i = 0; i < 10; i++) {
  const last = i === 9;
  if (!last) code.push(...pushNum(32), OP.SPLIT, OP.SWAP);
  code.push(...push(Uint8Array.of(0)), OP.CAT, OP.BIN2NUM, OP.DUP, ...(i < 8 ? [...pushNum(i + 3), OP.PICK] : push(Uint8Array.from(pushNum(R).slice(1)))), OP.LESSTHAN, OP.VERIFY);
  if (!last) code.push(OP.SWAP);
}
const parseEnd = code.length;
// arithmetic: frame P Ax Ay Bx0 Bx1 By0 By1 Cx Cy n0 n1 z u -> + constants
const names = ['P', 'Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy', 'n0', 'n1', 'z', 'u'];
code.push(...pushNum(z), ...pushNum(u));
const k = builder();
// A, C on curve: y^2 - x^3 - 3 == 0
for (const [x, y] of [['Ax', 'Ay'], ['Cx', 'Cy']]) k.eqz(k.sub(k.mul(y, y), k.add(k.mul(k.mod(k.mul(x, x)), x), k.konst(3))));
// B on twist: y^2 - x^3 - b' == 0 in Fp2
const sq = (a) => [k.mod(k.mul(k.add(a[0], a[1]), k.sub(a[0], a[1]))), k.mod(k.mul(k.add(a[0], a[0]), a[1]))];
const x2 = sq(['Bx0', 'Bx1']), y2 = [k.mul(k.add('By0', 'By1'), k.sub('By0', 'By1')), k.mul(k.add('By0', 'By0'), 'By1')];
const x3 = [k.sub(k.mul(x2[0], 'Bx0'), k.mul(x2[1], 'Bx1')), k.add(k.mul(x2[0], 'Bx1'), k.mul(x2[1], 'Bx0'))];
k.eqz(k.sub(k.sub(y2[0], x3[0]), k.konst(bp.c0))); k.eqz(k.sub(k.sub(y2[1], x3[1]), k.konst(bp.c1)));
// pair constants
const outs = [];
for (const [x, y, neg] of [['Ax', 'Ay', true], ['Cx', 'Cy', false]]) {
  const yP = neg ? k.neg(y) : y; const xz = k.mod(k.mul(x, 'z')), xzu = k.mod(k.mul(xz, 'u'));
  outs.push(yP, k.mod(k.mul(yP, 'u')), xz, xzu, k.mulc(xz, 3), k.mulc(xzu, 6));
}
const ar = compile({frame: names, prog: k.prog, out: ['P', 'z', 'u', ...outs], pMode: 'pick'});
code.push(...ar);
const full = run({pushes: [stmt], code}), base = run({pushes: [stmt], code: []}), mid = run({pushes: [stmt], code: code.slice(0, parseEnd)});
for (const m of ['consensus']) { const er = full['err_' + m]; if (er && !/clean|exactly one|unexpected number/i.test(String(er))) throw new Error(m + ': ' + er); }
const top = full.stack.slice(-12).map(vmNum).map(mod);
const Ax = limbs[0], Ay = limbs[1];
assert.equal(top[0], mod(-Ay)); assert.equal(top[2], mod(Ax * z));
console.log(JSON.stringify({op: {parseAndRange: mid.consensus - base.consensus, curveChecksAndPairConsts: full.consensus - mid.consensus, total: full.consensus - base.consensus}, bytes: code.length}));
