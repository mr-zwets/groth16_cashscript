// Zero-cost protocol assertions requested by the review: the eta X Frobenius shortcut on polynomials
// (Frob^2(f)(X) = f(eta X) for the baked eta, also Frob^6 = X -> -X) and its use for the R_{k,2}, R_{k,3}
// factors (evaluation at eta z equals evaluation of the Frob^2 image), on random Fp12 elements.
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
const {Fp, Fp12: T} = bn254.fields; const p = Fp.ORDER; const md = (x) => ((x % p) + p) % p;
const flat = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1, x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const poly = (x) => { const c = flat(x), out = Array(12).fill(0n); for (const [i, d] of [0, 2, 4, 1, 3, 5].entries()) { out[d] = md(c[2 * i] - 9n * c[2 * i + 1]); out[d + 6] = c[2 * i + 1]; } return out; };
const pmodM = (a) => { const r0 = a.slice(); for (let i = r0.length - 1; i >= 12; i--) { const v = r0[i]; r0[i] = 0n; r0[i - 6] = md(r0[i - 6] + 18n * v); r0[i - 12] = md(r0[i - 12] - 82n * v); } return r0.slice(0, 12); };
const subst = (a, s) => a.map((c, i) => md(c * s ** BigInt(i)));
const pev = (a, x) => a.reduceRight((acc, c) => md(acc * x + c), 0n);
// candidate eta: primitive 6th roots of unity in Fp
const g = (() => { for (let a = 2n; ; a++) { const e = Fp.pow(a, (p - 1n) / 6n); if (Fp.pow(e, 2n) !== 1n && Fp.pow(e, 3n) !== 1n) return e; } })();
const roots = [g, Fp.pow(g, 5n)];
let ctr = 0; const rand = () => T.fromBigTwelve(Array.from({length: 12}, () => md(BigInt(ctr++ * 7919 + 1) ** 37n)));
const ok = roots.filter((eta) => { for (let t = 0; t < 5; t++) { const el = rand(); if (pmodM(subst(poly(el), eta)).join() !== poly(T.frobeniusMap(el, 2)).join()) return false; } return true; });
assert.equal(ok.length, 1, 'exactly one primitive 6th root realizes Frob^2');
const eta = ok[0];
for (let t = 0; t < 5; t++) { const el = rand(); assert.equal(poly(T.frobeniusMap(el, 6)).join(), pmodM(subst(poly(el), p - 1n)).join(), 'Frob^6 = X -> -X'); }
// evaluation form used on-chain: for a reduced polynomial f, Frob^2(f) evaluated at z == f(eta z) only modulo M;
// the protocol bakes R_{k,2}(X) := R_{k,0}(eta X) as a polynomial (degree 6, unreduced is already reduced since eta^6 = 1 keeps it monic deg 6)
const z = 1234567891011n;
for (let t = 0; t < 3; t++) { const el = rand(); const f = poly(el); assert.equal(pev(subst(f, eta), z), pev(f, md(eta * z))); }
assert.equal(Fp.pow(eta, 6n), 1n); assert.equal(Fp.pow(eta, 3n), p - 1n);
console.log('eta =', eta.toString(), '\nFrob^2 == (X -> eta X) mod M, Frob^6 == (X -> -X): OK; eta^3 = -1 (so (eta z)^3 = -z^3)');
