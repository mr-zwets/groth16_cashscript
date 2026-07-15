// Residue-method math for the witnessed final-exponentiation on BLS12-381 + the
// c^-|x|-fused Miller loop. BLS analog of chunked/pairing/_residuemath.mjs
// (ePrint 2024/640 adapted to BLS12-381). Built on _pairingmath (noble tower).
//
//   lambda = p + |x|   (p == x mod r and x = -|x| < 0, so r | lambda)
//   lambda = 3 * m'' * r  with  gcd(m'', r) = 1, v3(lambda/r) = 1  (asserted below)
//   witness (c, w):  c^lambda == g * w,  w in Fp6*
//
// g here is the UNCONJUGATED batched Miller boundary. The true pairing boundary is
// conj(g) (x < 0), but conj is a field automorphism, so conj(g)^h == 1 <=> g^h == 1
// (h = (p^12-1)/r): we witness g directly and the contract NEVER conjugates.
//
//   verifier relation (terminal tail):   gF * w == c^p == frob(c, 1)
//   where gF = g * c^-|x| (folded into the Miller loop over NAF(|x|)).
//   Proof: gF*w == c^p  <=>  g*w == c^(p+|x|) = c^lambda. Soundness: c^lambda = g*w
//   => g^h = c^(lambda*h) * w^-h = 1 because lambda is a multiple of r and every nonzero
//   Fp6 element has order dividing p^6-1, which divides h=(p^12-1)/r.
//
// KEY difference vs BN254: gcd(m'', p^12-1) = A = (|x|+1)/3 = 11*10177*859267*52437899
// (each prime with multiplicity exactly 1 in p^12-1), and REAL valid boundaries carry a
// nontrivial A-part in their order — so the witness scaling group must be extended from
// mu_27 to mu_(27A). The A-part of g is computable by ONE exponentiation (projection
// g^(alpha*(p^12-1)/A), alpha = ((p^12-1)/A)^-1 mod A) and its inverse joins w. The
// Both factors used by the construction live in Fp6: mu_A is contained in Fp because A | p-1,
// and ROOT27 has a zero upper Fp6 half. The verdict can therefore check the six upper limbs of w
// rather than exponentiating w. residueWitness verifies both the relation and this shape before
// returning, so a construction regression fails loudly at build time.
import {
  Fp, Fp2, Fp6, Fp12, ATE_NAF, pairsFor, millerBatchOps, singlePairMiller,
} from './_pairingmath.mjs';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const p = Fp.ORDER;
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n; // Fr
const P12 = p ** 12n - 1n;
const H = P12 / r;
export const BLS_X = 0xd201000000010000n; // |x|, x negative
export const LAMBDA = p + BLS_X;

// ---- Fp12 helpers (noble tower) ----
const tup = (a) => [a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0, a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1];
export const eq12 = (a, b) => { const x = tup(a), y = tup(b); return x.every((v, i) => v === y[i]); };
const isOne = (a) => eq12(a, Fp12.ONE);
const f6 = (t) => Fp6.create({ c0: Fp2.fromBigTuple([t[0], t[1]]), c1: Fp2.fromBigTuple([t[2], t[3]]), c2: Fp2.fromBigTuple([t[4], t[5]]) });
export const mk12 = (lo, hi) => Fp12.create({ c0: f6(lo), c1: f6(hi) });
const mul = (a, b) => Fp12.mul(a, b), inv = (a) => Fp12.inv(a), sqr = (a) => Fp12.sqr(a);
export const fp12limbsOf = tup;
const powExact = (a, e) => { let res = Fp12.ONE, base = a; while (e > 0n) { if (e & 1n) res = mul(res, base); base = sqr(base); e >>= 1n; } return res; };
export const frob = (a, n) => Fp12.frobeniusMap(a, n);
export const conj = (a) => Fp12.conjugate(a);

// ---- parameter facts (asserted once at import) ----
if (LAMBDA % r !== 0n) throw new Error('lambda not divisible by r');
if ((p ** 6n + 1n) % r !== 0n) throw new Error('r does not divide p^6+1');
if (P12 % r !== 0n) throw new Error('r does not divide p^12-1');
if (H % (p ** 6n - 1n) !== 0n) throw new Error('p^6-1 does not divide the final-exponent cofactor');
const m = LAMBDA / r;
if (m % 3n !== 0n || (m / 3n) % 3n === 0n) throw new Error('v3(lambda/r) != 1');
const m_ = m / 3n; // m''
if (P12 % 27n !== 0n || (P12 / 27n) % 3n === 0n) throw new Error('v3(p^12-1) != 3');

// ---- 27th root of unity (noble tower); sparse: only c0.c2.c1 nonzero ----
export const ROOT27 = mk12([0n, 0n, 0n, 0n, 0n,
  3023453454954651717291509996123911173014040409555280456829364348568359506157058966733147683919288067575841272260945n],
  [0n, 0n, 0n, 0n, 0n, 0n]);
if (!isOne(powExact(ROOT27, 27n)) || isOne(powExact(ROOT27, 9n))) throw new Error('ROOT27 order != 27');
if (tup(ROOT27).slice(6).some((x) => x !== 0n) || tup(sqr(ROOT27)).slice(6).some((x) => x !== 0n)) {
  throw new Error('ROOT27 coset generators are not embedded in Fp6');
}
// the baked 27-coset {ROOT27^j : j=0..26} used by the cube-root corrector
export const COSET27 = (() => { const a = []; let x = Fp12.ONE; for (let i = 0; i < 27; i++) { a.push(x); x = mul(x, ROOT27); } return a; })();

// ---- residue witness (gnark-style scaling + clean AMM cube-root) ----
const exp1 = P12 / 3n;
const modinv = (a, m2) => { let [or, rr] = [((a % m2) + m2) % m2, m2], [os, s] = [1n, 0n]; while (rr) { const qn = or / rr; [or, rr] = [rr, or - qn * rr]; [os, s] = [s, os - qn * s]; } return ((os % m2) + m2) % m2; };
const gcd = (a, b) => { while (b) { [a, b] = [b, a % b]; } return a; };
const rInv = modinv(r, P12 / r);
// A = gcd(m'', p^12-1) = (|x|+1)/3; every prime factor (11, 10177, 859267, 52437899) has
// multiplicity exactly 1 in p^12-1 (asserted), so P12 = A * M with gcd(A, M) = 1 and the
// A-part of any element is the clean projection x -> x^(ALPHA*(P12/A)).
export const A_COFACTOR = gcd(m_, P12);
if (A_COFACTOR !== (BLS_X + 1n) / 3n) throw new Error('unexpected gcd(m\'\', p^12-1)');
if ((p - 1n) % A_COFACTOR !== 0n) throw new Error('A does not divide p-1');
for (const q of [11n, 10177n, 859267n, 52437899n]) {
  if (A_COFACTOR % q !== 0n || (P12 / q) % q === 0n) throw new Error(`A-part prime ${q}: wrong multiplicity`);
}
const M = P12 / A_COFACTOR;
if (gcd(m_, M) !== 1n) throw new Error('m\'\' still shares a factor with M');
const mInv = modinv(m_, M);
const ALPHA = modinv(M, A_COFACTOR);
const U = P12 / 27n;
const kFac = (U % 3n === 2n) ? 1n : 2n;
const cubeExp = (kFac * U + 1n) / 3n;
function cubeRoot(Y) {
  const b = powExact(Y, U);
  let j = -1; for (let t = 0; t < 9; t++) if (eq12(COSET27[(3 * t) % 27], b)) { j = t; break; }
  if (j < 0) throw new Error('not a cube');
  const corr = ((-(kFac * BigInt(j))) % 27n + 27n) % 27n;
  return mul(powExact(Y, cubeExp), COSET27[Number(corr)]);
}
/** given the RAW (unconjugated) Miller boundary g, return { c, cInv, w } with
 *  c^lambda == g*w and w in Fp6* (w = A-part-killer * cubic-residue scaling). */
export function residueWitness(g) {
  // kill the A-part of g: wA = (A-part of g)^-1, an element of mu_A
  const wA = inv(powExact(g, ALPHA * M)); // g^(ALPHA*(P12/A)) is the A-part projection
  const gClean = mul(g, wA);
  if (!isOne(powExact(gClean, M))) throw new Error('A-part projection failed (g^h != 1?)');
  // cubic-residue scaling in mu_27
  let w27 = null, rw = null;
  for (const cand of [Fp12.ONE, ROOT27, sqr(ROOT27)]) { const t = mul(gClean, cand); if (isOne(powExact(t, exp1))) { w27 = cand; rw = t; break; } }
  if (!w27) throw new Error('no cubic-residue scaling');
  const target = rw;
  rw = powExact(rw, rInv);
  rw = powExact(rw, mInv);
  const c = cubeRoot(rw);
  if (!eq12(powExact(c, LAMBDA), target)) throw new Error('residue witness failed verification');
  const w = mul(wA, w27);
  if (!isOne(powExact(w, 27n * A_COFACTOR))) throw new Error('w outside mu_(27A)');
  if (tup(w).slice(6).some((x) => x !== 0n)) throw new Error('w is not embedded in Fp6');
  return { c, cInv: inv(c), w };
}

// A nontrivial r-th root has k^lambda=1 because r divides lambda. If a valid residue root is
// the quotient torus's unique infinity point, multiplying it by k preserves its lambda power
// and moves it into the finite chart because k.c1 is nonzero. Every accepting quotient class
// therefore has one six-limb representative [1+u*W].
const TORUS_KERNEL_SHIFT = bls12_381.pairing(
  bls12_381.G1.Point.BASE,
  bls12_381.G2.Point.BASE,
);
if (Fp6.eql(TORUS_KERNEL_SHIFT.c1, Fp6.ZERO) ||
  !eq12(powExact(TORUS_KERNEL_SHIFT, LAMBDA), Fp12.ONE)) {
  throw new Error('invalid BLS12-381 quotient-torus kernel shift');
}
export function residueTorusWitness(g) {
  const witness = residueWitness(g);
  const c = Fp6.eql(witness.c.c0, Fp6.ZERO)
    ? mul(witness.c, TORUS_KERNEL_SHIFT)
    : witness.c;
  if (Fp6.eql(c.c0, Fp6.ZERO)) {
    throw new Error('failed to move BLS12-381 residue root into the finite torus chart');
  }
  const u = Fp6.mul(c.c1, Fp6.inv(c.c0));
  return { ...witness, c, cInv: inv(c), u };
}

// ---- c^-|x|-FUSED batched Miller ----------------------------------------------------
// Same flat op list as millerBatchOps, but after each NAF-step squaring we fold one factor
// of c^-1 (digit +1) or c (digit -1) into the shared f, so that across the loop f accumulates
// c^-|x| alongside f_|x|. New op type {t:'cf', neg} (c-fold). The MSB term's fold is the
// GENESIS f = cInv (the loop's squarings carry it to c^-2^63). Pair 1 = e(alpha,beta) is a VK
// constant: its line-folds are dropped (skipPairs) and its UNCONJUGATED single-pair Miller
// value fAB is multiplied in once via a final 'cmul1' op. states[i] = {f, Rs, c, cInv}.
export function millerFusedOps(pairs, c, cInv) {
  const base = millerBatchOps(pairs, { skipPairs: new Set([1]) });
  const fAB = conj(singlePairMiller(pairs[1]).f); // baked UNCONJUGATED e(alpha,beta) Miller value
  const ops = []; const states = [];
  let cpow = cInv; let k = 0;
  for (let bi = 0; bi < base.ops.length; bi++) {
    const op = base.ops[bi];
    states.push({ f: mul(base.states[bi].f, cpow), Rs: base.states[bi].Rs.slice(), c, cInv });
    ops.push(op.t === 'sqr' ? { t: 'sqr' } : op);
    if (op.t === 'sqr') {
      cpow = sqr(cpow);
      const digit = ATE_NAF[k] ?? 0;
      if (digit !== 0) {
        states.push({ f: mul(base.states[bi + 1].f, cpow), Rs: base.states[bi + 1].Rs.slice(), c, cInv });
        ops.push({ t: 'cf', neg: digit === -1 }); // digit +1 -> xcInv ; -1 -> xc
        cpow = mul(cpow, digit === 1 ? cInv : c);
      }
      k++;
    }
  }
  // f after the loop = (f0*f2*f3) * c^-|x|; multiply in the baked fAB (one constant fp12Mul).
  const preF1 = mul(base.boundary, cpow);
  states.push({ f: preF1, Rs: base.states[base.states.length - 1].Rs.slice(), c, cInv });
  ops.push({ t: 'cmul1' }); // f *= fAB (baked constant)
  const boundary = mul(preF1, fAB);
  states.push({ f: boundary, Rs: base.states[base.states.length - 1].Rs.slice(), c, cInv });
  return { ops, states, boundary, baseBoundary: mul(base.boundary, fAB), cpowFinal: cpow, fAB };
}

const torusRepresentative = (u) => Fp12.create({ c0: Fp6.ONE, c1: u });
const torusMul = (value, u) => Fp12.create({
  c0: Fp6.add(value.c0, Fp6.mulByNonresidue(Fp6.mul(value.c1, u))),
  c1: Fp6.add(value.c1, Fp6.mul(value.c0, u)),
});

// Replay the same fixed Miller trace in Q=Fp12*/Fp6*. The residue root is the immutable finite
// coordinate u for [c]=[1+u*W], so [c^-1]=[1-u*W]. c-folds and the fixed alpha/beta fold use
// two Fp6 products rather than a full three-product Fp12 multiplication. Ordinary line folds
// stay unchanged; their Fp6 scaling is immaterial in Q.
export function millerFusedTorusOps(pairs, c, cInv, u) {
  const exact = millerFusedOps(pairs, c, cInv);
  if (Fp6.eql(exact.fAB.c0, Fp6.ZERO)) {
    throw new Error('fixed BLS12-381 alpha/beta Miller value has no finite torus coordinate');
  }
  const fAbU = Fp6.mul(exact.fAB.c1, Fp6.inv(exact.fAB.c0));
  const ops = exact.ops;
  const states = [];
  let f = torusRepresentative(Fp6.neg(u));
  for (let i = 0; i < ops.length; i++) {
    states.push({ f, Rs: exact.states[i].Rs.slice(), u });
    const op = ops[i];
    if (op.t === 'sqr') {
      f = sqr(f);
    } else if (op.t === 'cf') {
      f = torusMul(f, op.neg ? u : Fp6.neg(u));
    } else if (op.t === 'cmul1') {
      f = torusMul(f, fAbU);
    } else {
      const factor = mul(exact.states[i + 1].f, inv(exact.states[i].f));
      f = mul(f, factor);
    }
  }
  states.push({ f, Rs: exact.states[ops.length].Rs.slice(), u });
  return { ops, states, boundary: f, fAB: exact.fAB, fAbU };
}

// self-test when run directly
if (process.argv[1] && process.argv[1].endsWith('_residuemath.mjs')) {
  const { bls12_381 } = await import('./_vkxmath.mjs');
  const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
  const h = P12 / r;

  // several distinct VALID instances (same exponent-trick construction as bls_instance.mjs)
  const modR = (x) => ((x % r) + r) % r;
  const mkInstance = (a, b, g, d, cS, ic, ins) => {
    const vx = modR(ic[0] + ins[0] * ic[1] + ins[1] * ic[2]);
    const A = modR(a * b + vx * g + cS * d);
    return [
      { name: 'negA_B', P: G1.BASE.multiply(A).negate(), Q: G2.BASE },
      { name: 'alpha_beta', P: G1.BASE.multiply(a), Q: G2.BASE.multiply(b) },
      { name: 'vkx_gamma', P: G1.BASE.multiply(vx), Q: G2.BASE.multiply(g) },
      { name: 'C_delta', P: G1.BASE.multiply(cS), Q: G2.BASE.multiply(d) },
    ];
  };
  const instances = [
    pairsFor([123n, 456n]), // the committed repo instance
    mkInstance(17n, 19n, 23n, 29n, 31n, [8n, 10n, 12n], [999n, 1n]),
    mkInstance(101n, 7n, 13n, 3n, 271n, [5n, 9n, 21n], [(1n << 200n) + 12345n, (1n << 150n) - 1n]),
  ];
  for (let i = 0; i < instances.length; i++) {
    const pairs = instances[i];
    const { boundary: g } = millerBatchOps(pairs);
    console.log(`\n-- instance ${i} --`);
    console.log('g^h == 1 (valid) ?', isOne(powExact(g, h)));
    const { c, cInv, w } = residueWitness(g);
    console.log('c*cInv == 1 ?', isOne(mul(c, cInv)));
    console.log('w^(27A) == 1 ?', isOne(powExact(w, 27n * A_COFACTOR)));
    console.log('w upper Fp6 half == 0 ?', fp12limbsOf(w).slice(6).every((x) => x === 0n));
    // the on-chain form of the same check: ((w^|x|) * w)^9 == 1
    console.log('((w^x)*w)^9 == 1 ?', isOne(powExact(mul(powExact(w, BLS_X), w), 9n)));
    console.log('c^lambda == g*w ?', eq12(powExact(c, LAMBDA), mul(g, w)));
    const fused = millerFusedOps(pairs, c, cInv);
    const expectGF = mul(g, powExact(cInv, BLS_X));
    console.log('fused boundary == g*c^-|x| ?', eq12(fused.boundary, expectGF));
    console.log('cpowFinal == c^-|x| ?', eq12(fused.cpowFinal, powExact(cInv, BLS_X)));
    console.log('skip-pair reassembly: base*fAB == g ?', eq12(fused.baseBoundary, g));
    const tail = eq12(mul(fused.boundary, w), frob(c, 1));
    console.log('TAIL gF*w == frob(c,1) ?', tail);
    console.log('num fused ops =', fused.ops.length, 'cf ops =', fused.ops.filter((o) => o.t === 'cf').length);
  }
  // invalid instance must fail witness construction (no c can exist: g^h != 1)
  const badPairs = pairsFor([124n, 456n]);
  const { boundary: gBad } = millerBatchOps(badPairs);
  console.log('\n-- invalid instance --');
  console.log('g^h != 1 ?', !isOne(powExact(gBad, h)));
  let failed = false;
  try { residueWitness(gBad); } catch (e) { failed = true; console.log('residueWitness threw:', e.message); }
  console.log('witness construction failed as expected ?', failed);
}
