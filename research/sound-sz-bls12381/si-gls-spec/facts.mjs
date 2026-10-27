// Prints the BLS12-381 facts the SI-GLS design relies on. Every one is asserted when blsmath.mjs loads.
//   node facts.mjs
import * as m from './blsmath.mjs';
const hex = (x) => '0x' + x.toString(16);
console.log(JSON.stringify({
  p: hex(m.p), r: hex(m.r), x: '-' + hex(m.AX),
  M: 'X^12 - 2 X^6 + 2 (irreducible over Fp: Rabin test, X^(p^12) = X, gcd(X^(p^6) - X, M) = gcd(X^(p^4) - X, M) = 1)',
  u: 'X^6 - 1', Phi: 'Phi(a0 + a1 u) = (a0 - a1) + a1 X^6',
  eta: hex(m.ETA) + ' = 2^((p-1)/6): Frob^2 = X -> eta X, eta^2 = eta - 1; Frob^6 = X -> -X',
  gamma1: {c0: hex(m.GAMMA1.c0), c1: hex(m.GAMMA1.c1), note: 'xi^((p-1)/6); Frob(X^j) = Phi(gamma1^j) X^j; Frob(X^6) = 2 - X^6'},
  psi: 'psi(x, y) = (conj(x) / gamma1^2, conj(y) / gamma1^3) (M-type twist)',
  millerLoop: {events: m.NE, additionsAfterEvents: m.ADD_EVENTS, sign: 'loop over |x|; FE(f_|x|) = e^-1, a nondegenerate pairing; no Frobenius end steps'},
  residue: {lambda: 'p + |x| = p - x', m: m.MRES.toString() + ' = (x-1)^2/3 = h1', gcdLambdaN6R: 1, threeDividesP6plus1: false, rSquaredDividesP6plus1: false},
  g2: {h2: m.FACTS.h2, normPsiMinusX: 'p - x = h1 r', gcdNormH2: m.FACTS.gcdNormH2, check: '[|x|]B = -psi(B) <=> (psi - [x]) B = O <=> B in G2 (B on the twist)'},
  g1: {h1: m.FACTS.h1, fact: m.G1_COFACTOR_FACT},
  gls: 'n = sum_i a_i |x|^i, 0 <= a_i < |x| < 2^64 (base-|x| digits, unique); |x|^i = (-p)^i (mod r); factor i = Frob^i(m)^((-1)^i): R0(X), R1(-X), R0(eta X), R1(-eta X)',
}, null, 1));
