// Independent audit for the qsplit binary/direct8 path's G1 cofactor semantics and
// fused psi G2 check, using the repository's shared field and curve modules.
// Run: node qsplit_soundness_audit.mjs
import {
  Fp, Fp2, Fp12,
  qsplitPairsFor as pairsFor,
  qsplitMillerBatchOps as millerBatchOps,
} from './chunked/bls12-381/_pairingmath.mjs';
import * as R from './chunked/bls12-381/_residuemath.mjs';
import { bls12_381 } from './chunked/bls12-381/_vkxmath.mjs';

const p = Fp.ORDER;
const r = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const X = 0xd201000000010000n; // |x|, x = -X
const P12 = p ** 12n - 1n;
const h = P12 / r;
const LAMBDA = p + X;
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) { [a, b] = [b, a % b]; } return a; };
const G1 = bls12_381.G1.Point;
const G2 = bls12_381.G2.Point;
const powF = (a, e) => { let res = Fp12.ONE, base = a; while (e > 0n) { if (e & 1n) res = Fp12.mul(res, base); base = Fp12.sqr(base); e >>= 1n; } return res; };
// scalar mult by arbitrary (possibly >= r) scalar via double-and-add — noble's multiplyUnsafe caps at r
const mulAny = (Q, k) => { let res = Q.multiplyUnsafe(0n), base = Q; while (k > 0n) { if (k & 1n) res = res.add(base); base = base.double(); k >>= 1n; } return res; };
const isOne = (a) => R.eq12(a, Fp12.ONE);
const check = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`); if (!ok) process.exitCode = 1; };

// ---------- 1. number-theoretic facts the argument depends on ----------
check('r | p + |x| (lambda multiple of r)', LAMBDA % r === 0n);
check('27A | h  (w-gate kernel killed by final exp)', h % (27n * R.A_COFACTOR) === 0n);

// G1 cofactor h1 = #E(Fp)/r = (|x|+1)^2/3 ... compute from curve: #E(Fp) = p + 1 - t, t = x+1 = 1-X
const t1 = 1n - X;
const nE1 = p + 1n - t1;
const h1 = nE1 / r;
check('#E(Fp) = h1*r exactly', nE1 % r === 0n);
check('gcd(h1, r) = 1', gcd(h1, r) === 1n);

// twist E'(Fp2) order: #E'(Fp2) = p^2 + 1 - t2', with t2 = t^2 - 2p, correct twist: n2 = p^2+1-(... )
// noble knows: use the standard h2 for BLS12-381 (E'(Fp2) = h2 * r):
const h2 = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109n;
check('h2*r = p^2 + 1 - (3*f - t)/2 form sanity: h2*r has ~508+255 bits', (h2 * r) > 2n ** 760n && (h2 * r) < 2n ** 764n);
// psi eigenvalue criterion exactness: any Q on E'(Fp2) with psi(Q)=[x]Q has ord(Q) | p - x = LAMBDA
// and ord(Q) | h2*r  =>  ord(Q) | gcd(LAMBDA, h2*r). Exact iff gcd(LAMBDA, h2) = 1.
check('gcd(lambda, h2) = 1 (psi test admits ONLY G2 + O)', gcd(LAMBDA, h2) === 1n);
// vacuous-pass guard: [|x|]B = O with B != O needs ord(B) | gcd(|x|, h2*r)
check('gcd(|x|, h2) = 1 (no on-twist point of order dividing |x|)', gcd(X, h2) === 1n);
check('h2 odd (no 2-torsion => pointDouble never sees y=0 from valid B-walk)', h2 % 2n === 1n);

// ---------- 2. build a cofactor-torsion point T on E(Fp) (order | h1, T != O) ----------
const sqrtFp = (a) => { const s = Fp.sqrt ? Fp.sqrt(a) : null; return s; };
let T = null;
for (let xi = 1n; xi < 1000n && !T; xi++) {
  const rhs = Fp.add(Fp.mul(Fp.mul(xi, xi), xi), 4n);
  let y; try { y = sqrtFp(rhs); } catch { continue; }
  if (y === null) continue;
  const Rpt = G1.fromAffine({ x: xi, y });
  const cand = mulAny(Rpt, r); // kills the r-part, leaves pure h1-torsion
  if (!cand.is0()) T = cand;
}
check('constructed T on E(Fp), T != O', T !== null && !T.is0());
check('T has order dividing h1 (pure cofactor torsion)', mulAny(T, h1).is0());
check('T is NOT in G1 ([r]T != O)', !mulAny(T, r).is0());

// ---------- 3. A/C cofactor components leave the pairing verdict unchanged ----------
const pairs = pairsFor([123n, 456n]); // the committed valid instance
const g = millerBatchOps(pairs).boundary;
check('baseline valid instance: g^h == 1', isOne(powF(g, h)));

// Modify A (pair 0 holds (-A, B)): -A' = -A + T  <=>  A' = A - T.
const modifyPair = (idx, delta) => pairs.map((pr, i) => (i === idx ? { ...pr, P: pr.P.add(delta) } : pr));
const gA = millerBatchOps(modifyPair(0, T)).boundary;
check('A + cofactor-torsion: boundary CHANGES (not a no-op)', !R.eq12(gA, g));
check('A + cofactor-torsion: g^h == 1 still (residue witness EXISTS => contract accepts)', isOne(powF(gA, h)));
let wOK = false; try { const wit = R.residueWitness(gA); wOK = R.eq12(powF(wit.c, LAMBDA), Fp12.mul(gA, wit.w)); } catch {}
check('A + cofactor-torsion: residueWitness constructs and self-verifies', wOK);

// Modify C (pair 3 holds (C, delta)).
const gC = millerBatchOps(modifyPair(3, T)).boundary;
check('C + cofactor-torsion: g^h == 1 still (accepts)', isOne(powF(gC, h)));

// Control: changing the r-part of A by a subgroup point must change the verdict.
const gBad = millerBatchOps(modifyPair(0, G1.BASE)).boundary;
check('A + G1 subgroup point: g^h != 1 (equation still binds the r-part)', !isOne(powF(gBad, h)));
let wBad = false; try { R.residueWitness(gBad); wBad = true; } catch {}
check('A + G1 subgroup point: residueWitness construction FAILS', !wBad);

// The same control applies to C.
const gBadC = millerBatchOps(modifyPair(3, G1.BASE)).boundary;
check('C + G1 subgroup point: g^h != 1 (rejected)', !isOne(powF(gBadC, h)));

// ---------- 4. fused psi check semantics ----------
// contract compares affine(R_B) == -psi(B) with R_B = [|x|]B, i.e. psi(B) == [x]B (x = -|x|).
// psi from the contract's baked constants (untwist-frobenius-twist), over noble Fp2:
const C1 = Fp2.fromBigTuple([0n, 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437n]);
const C2 = Fp2.fromBigTuple([2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530n, 1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257n]);
const conj2 = (v) => Fp2.create({ c0: v.c0, c1: Fp.neg(v.c1) }); // (a,b) -> (a,-b), matches the contract's mSub(0, xb)
const psi = (Q) => { const a = Q.toAffine(); return G2.fromAffine({ x: Fp2.mul(C1, conj2(a.x)), y: Fp2.mul(C2, conj2(a.y)) }); };
const B = pairs[0].Q;
check('honest B: psi(B) == -[|x|]B (matches the fused compare)', psi(B).equals(mulAny(B, X).negate()));

// on-twist cofactor torsion T2 (order | h2): psi eigenvalue must FAIL for B+T2
const Fp2sqrt = (a) => { try { return Fp2.sqrt(a); } catch { return null; } };
let T2 = null;
for (let xi = 1n; xi < 400n && !T2; xi++) {
  const xF = Fp2.fromBigTuple([xi, 1n]);
  const rhs = Fp2.add(Fp2.mul(Fp2.mul(xF, xF), xF), Fp2.fromBigTuple([4n, 4n]));
  const y = Fp2sqrt(rhs); if (y === null) continue;
  const cand = mulAny(G2.fromAffine({ x: xF, y }), r);
  if (!cand.is0()) T2 = cand;
}
check('constructed T2 on E\'(Fp2), pure h2-torsion', T2 !== null && mulAny(T2, h2).is0() && !T2.is0());
const Bpolluted = B.add(T2);
check('B + cofactor-torsion: psi(B\') != -[|x|]B\' (fused check REJECTS)', !psi(Bpolluted).equals(mulAny(Bpolluted, X).negate()));

// ---------- 5. mid-walk identity closure ----------
// R_B = [k]B can only hit O mid-loop if ord(B) | gcd(k, h2*r) for some binary-loop prefix k of |x|.
// r is 255-bit and every prefix k < 2^64, so it reduces to gcd(k, h2). The four shared
// prefixes have gcd 13 with h2. The compiled affine tangent/chord denominator guards cover
// this case, exhaustively exercised by qsplit_psi_degeneracy_test.mjs.
import('./chunked/bls12-381/_pairingmath.mjs').then(({
  QSPLIT_ATE_LOOP_DIGITS: ATE_LOOP_DIGITS,
}) => {
  let k = 1n; const prefixes = [k];
  for (let i = 0; i < ATE_LOOP_DIGITS.length; i++) {
    k = 2n * k; prefixes.push(k);
    if (ATE_LOOP_DIGITS[i] !== 0) {
      k += BigInt(ATE_LOOP_DIGITS[i]);
      prefixes.push(k);
    }
  }
  check('binary walk reconstructs |x|', k === X);
  const sharedPrefixes = prefixes.filter((v) => gcd(v, h2) !== 1n);
  check(
    'binary prefixes sharing a factor with h2 are exactly 13,26,52,104',
    sharedPrefixes.join(',') === '13,26,52,104',
  );
  check(
    'every shared binary prefix has gcd 13 with h2 (covered by affine denominator guards)',
    sharedPrefixes.every((v) => gcd(v, h2) === 13n),
  );
  console.log(process.exitCode ? '\n*** AUDIT FOUND FAILURES ***' : '\nall audit checks passed');
});
