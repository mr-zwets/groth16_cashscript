// Number-theoretic facts the three sound-SZ designs rely on, checked numerically for BN254.
// Every line is an assertion; the script prints the values and exits non-zero if one fails.
// Usage (repo root): node research/sound-sz-bn254/facts.mjs
import assert from 'node:assert/strict';
import {bn254} from '@noble/curves/bn254.js';
const x = 4965661367192848881n, p = bn254.fields.Fp.ORDER, r = bn254.fields.Fr.ORDER;
const {Fp2} = bn254.fields;
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
const mod = (a, m) => ((a % m) + m) % m;
const out = {};

// Curve: trace t and the twist cofactor
const t = 6n * x * x + 1n;
assert.equal(p + 1n - t, r, '#E(Fp) = p + 1 - t = r');
const h2 = 2n * p - r; // #E'(Fp2) = r * (2p - r)
assert.equal(h2 % 2n, 1n, 'E\'(Fp2) has odd order (no 2-torsion: Y != 0 on every G2 point)');
assert.equal(gcd(h2, r), 1n);
out.twistCofactorOdd = true;

// Field tower: Fp12 = Fp[X]/M, M = X^12 - 18 X^6 + 82, i.e. X^6 = xi = 9 + u, u^2 = -1.
// M is irreducible iff -1 is a non-square in Fp and xi is neither a square nor a cube in Fp2.
assert.equal(p % 4n, 3n, '-1 is a non-square in Fp');
const xi = Fp2.fromBigTuple([9n, 1n]);
assert.ok(!Fp2.eql(Fp2.pow(xi, (p * p - 1n) / 2n), Fp2.ONE), 'xi is not a square in Fp2');
assert.ok(!Fp2.eql(Fp2.pow(xi, (p * p - 1n) / 3n), Fp2.ONE), 'xi is not a cube in Fp2');
out.MIrreducible = true;

// Miller schedule: NAF of 6x+2 without the leading digit (65 events, 21 nonzero)
const digits = []; for (let n = 6n * x + 2n; n > 1n; n >>= 1n) { if (!(n & 1n)) digits.unshift(0); else if ((n & 3n) === 3n) { digits.unshift(-1); n++; } else digits.unshift(1); }
assert.equal(digits.length, 65); assert.equal(digits.filter(Boolean).length, 21);
out.events = 65; out.nonzeroDigits = 21; out.negativeDigits = digits.filter((d) => d < 0).length;

// Residue exponent lambda = 6x + 2 + p - p^2 + p^3 = m r
const LAMBDA = 6n * x + 2n + p - p * p + p ** 3n;
assert.equal(LAMBDA % r, 0n, 'lambda = 0 mod r');
const m = LAMBDA / r;
// r | p^4 - p^2 + 1 | p^6 + 1, so (p^6 - 1) divides (p^12 - 1)/r: Fp6* dies under the final exponentiation
assert.equal((p ** 4n - p * p + 1n) % r, 0n);
assert.equal(((p ** 12n - 1n) / r) % (p ** 6n - 1n), 0n);
// The quotient G = Fp12*/Fp6* is cyclic of order p^6 + 1; the w-free residue needs:
const N6 = p ** 6n + 1n;
assert.notEqual(N6 % 3n, 0n, '3 does not divide p^6 + 1 (no cubic-residue selector needed)');
assert.equal(gcd(LAMBDA, N6 / r), 1n, 'gcd(lambda, (p^6+1)/r) = 1 (a torus residue root always exists)');
assert.equal(gcd(m, N6 / r), 1n, 'gcd(lambda/r, (p^6+1)/r) = 1');
assert.notEqual((N6 / r) % r, 0n, 'r does not divide (p^6+1)/r');
out.lambdaDivR = true; out.threeNotDivP6plus1 = true; out.gcdLambdaN6r = true; out.gcdLambdaOverRN6r = true;
out.rNotDivN6r = true; out.residueRootExists = true;

// G2 membership: phi = (6x+2) + psi - psi^2 + psi^3 on E'(Fp2), with psi^2 - t psi + p = 0
let c = [6n * x + 2n, 1n, -1n, 1n];
for (let i = 3; i >= 2; i--) { const v = c[i]; c[i] = 0n; c[i - 1] += t * v; c[i - 2] -= p * v; }
const [a, b] = c; // phi = a + b psi
assert.notEqual(mod(a, p), 0n, 'phi separable (a != 0 mod p)');
const norm = a * a + a * b * t + b * b * p;
assert.equal(norm % r, 0n);
assert.equal(gcd(norm, r * h2), r, 'gcd(N(phi), #E\'(Fp2)) = r');
assert.equal(gcd(norm / r, h2), 1n, 'gcd(N(phi)/r, 2p - r) = 1');
out.psiEndpointImpliesG2 = true;

// Hash-to-field: SHA256 output (256 bits, read as an unsigned integer) reduced mod p.
// Worst-case probability of a residue relative to uniform: ceil(2^256/p) / (2^256/p).
const q = (1n << 256n) / p, biasNum = (q + 1n) * p, bias = Number(biasNum * 10000n / (1n << 256n)) / 10000;
assert.ok(bias < 1.14);
out.hashToFpBias = bias;
out.log2p = +(Math.log2(Number(p >> 200n)) + 200).toFixed(2);

console.log(JSON.stringify(out));
