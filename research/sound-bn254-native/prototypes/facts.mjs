// Number-theoretic facts the affine B walk relies on (asserted):
//  - E'(Fp2) has odd order (no 2-torsion): y_T != 0 for every affine point, so the tangent denominator 2y is invertible;
//  - -1 is a non-residue mod p (p = 3 mod 4): the Fp2 norm a0^2 + a1^2 vanishes only at 0, so t * N(d) = 1 forces d != 0;
//  - completeness: along the fixed NAF schedule, for B in G2 (order r) no addition is exceptional: the scalar k_e of T
//    before each addition with Q = +-B satisfies k_e != +-1 (mod r), and the two terminal additions (+psi(B) ~ p,
//    -psi^2(B) ~ -p^2 on G2) have k != +-p, k + p != +-p^2 (mod r); no intermediate multiple is 0 (mod r).
//   node research/sound-bn254-native/prototypes/facts.mjs
import assert from 'node:assert/strict';
import {p, r, BN_X, DIGITS, NE, FACTS} from '../../../chunked/bn254/sound-si-gls/math.mjs';
const mod = (a, m) => ((a % m) + m) % m;
assert.equal(p % 4n, 3n, 'p = 3 mod 4: -1 is a non-residue, the Fp2 norm is anisotropic');
assert.equal(BigInt(FACTS.g2Cofactor) % 2n, 1n);
let k = 1n; let adds = 0;
for (let e = 0; e < NE; e++) {
  k = 2n * k; assert.notEqual(mod(k, r), 0n);
  if (DIGITS[e]) { const q = BigInt(DIGITS[e]); assert.ok(mod(k - q, r) !== 0n && mod(k + q, r) !== 0n, 'exceptional addition at event ' + e); k += q; adds++; assert.notEqual(mod(k, r), 0n); }
}
assert.equal(k, 6n * BN_X + 2n);
const P1 = mod(p, r), P2 = mod(p * p, r), P3 = mod(p ** 3n, r);
assert.ok(mod(k - P1, r) && mod(k + P1, r), 'terminal add psi(B)'); k = mod(k + P1, r);
assert.ok(mod(k - P2, r) && mod(k + P2, r), 'terminal add -psi^2(B)'); k = mod(k - P2, r);
assert.equal(k, mod(-P3, r), 'endpoint: (6x+2) + p - p^2 = -p^3 (mod r), i.e. T_end = -psi^3(B)');
console.log(`ok: ${NE} doublings, ${adds} loop additions + 2 terminal additions, none exceptional for B in G2; p = 3 mod 4; odd #E'(Fp2)`);
